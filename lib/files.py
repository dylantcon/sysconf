"""File management with idempotent operations and templating."""

import grp
import hashlib
import os
import pwd
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional, Union

try:
    from jinja2 import Template
    HAS_JINJA2 = True
except ImportError:
    HAS_JINJA2 = False
    from string import Template


def _needs_sudo(path: Path) -> bool:
    """Check if we need sudo to write to a path."""
    # Check if path or its parent is writable
    check_path = path if path.exists() else path.parent
    return not os.access(check_path, os.W_OK)


def _needs_sudo_read(path: Path) -> bool:
    """Check if we need sudo to read a path."""
    return path.exists() and not os.access(path, os.R_OK)


def read_file(path: Union[str, Path]) -> str:
    """
    Read file content, using sudo if necessary.

    This is exported for use by other modules.
    """
    path = Path(path)
    if not path.exists():
        return ""
    if os.access(path, os.R_OK):
        return path.read_text()
    # Need sudo to read
    result = subprocess.run(
        ["sudo", "cat", str(path)],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def _read_file_bytes(path: Path) -> bytes:
    """Read file content as bytes, using sudo if necessary."""
    if not path.exists():
        return b""
    if os.access(path, os.R_OK):
        return path.read_bytes()
    # Need sudo to read
    result = subprocess.run(
        ["sudo", "cat", str(path)],
        capture_output=True,
        check=True,
    )
    return result.stdout


def _file_hash(path: Path) -> str:
    """Get SHA256 hash of a file, using sudo if needed."""
    if not path.exists():
        return ""
    content = _read_file_bytes(path)
    return hashlib.sha256(content).hexdigest()


def ensure_dir(
    path: Union[str, Path],
    owner: Optional[str] = None,
    group: Optional[str] = None,
    mode: Optional[int] = None,
) -> bool:
    """
    Idempotently ensure a directory exists with correct permissions.

    Returns:
        True if any changes were made
    """
    path = Path(path)
    changed = False

    if not path.exists():
        print(f"Creating directory: {path}")
        if _needs_sudo(path.parent):
            subprocess.run(["sudo", "mkdir", "-p", str(path)], check=True)
        else:
            path.mkdir(parents=True, exist_ok=True)
        changed = True

    if owner or group or mode:
        if set_permissions(path, owner=owner, group=group, mode=mode):
            changed = True

    return changed


def set_permissions_recursive(
    path: Union[str, Path],
    owner: Optional[str] = None,
    group: Optional[str] = None,
    mode: Optional[int] = None,
) -> bool:
    """
    Recursively set ownership and permissions on a directory tree.

    Returns:
        True if any changes were made
    """
    path = Path(path)
    if not path.exists():
        return False

    changed = False
    needs_sudo = _needs_sudo(path)

    if owner or group:
        chown_arg = f"{owner or ''}:{group or ''}"
        print(f"Setting ownership {chown_arg} recursively on {path}")
        cmd = ["sudo", "chown", "-R", chown_arg, str(path)] if needs_sudo else ["chown", "-R", chown_arg, str(path)]
        subprocess.run(cmd, check=True)
        changed = True

    if mode is not None:
        print(f"Setting mode {oct(mode)} recursively on {path}")
        cmd = ["sudo", "chmod", "-R", oct(mode)[2:], str(path)] if needs_sudo else ["chmod", "-R", oct(mode)[2:], str(path)]
        subprocess.run(cmd, check=True)
        changed = True

    return changed


def set_permissions(
    path: Union[str, Path],
    owner: Optional[str] = None,
    group: Optional[str] = None,
    mode: Optional[int] = None,
) -> bool:
    """
    Set ownership and permissions on a file or directory.

    Returns:
        True if any changes were made
    """
    path = Path(path)
    changed = False
    needs_sudo = _needs_sudo(path)

    if owner or group:
        stat = path.stat()
        current_owner = pwd.getpwuid(stat.st_uid).pw_name
        current_group = grp.getgrgid(stat.st_gid).gr_name

        target_owner = owner or current_owner
        target_group = group or current_group

        if current_owner != target_owner or current_group != target_group:
            print(f"Setting ownership {target_owner}:{target_group} on {path}")
            chown_arg = f"{target_owner}:{target_group}"
            if needs_sudo:
                subprocess.run(["sudo", "chown", chown_arg, str(path)], check=True)
            else:
                shutil.chown(path, user=target_owner, group=target_group)
            changed = True

    if mode is not None:
        current_mode = path.stat().st_mode & 0o777
        if current_mode != mode:
            print(f"Setting mode {oct(mode)} on {path}")
            if needs_sudo:
                subprocess.run(["sudo", "chmod", oct(mode)[2:], str(path)], check=True)
            else:
                path.chmod(mode)
            changed = True

    return changed


def ensure_file(
    path: Union[str, Path],
    content: str,
    owner: Optional[str] = None,
    group: Optional[str] = None,
    mode: Optional[int] = None,
    backup: bool = True,
) -> bool:
    """
    Idempotently ensure a file exists with specific content.

    Args:
        path: Target file path
        content: Desired file content
        owner: File owner
        group: File group
        mode: File permissions (e.g., 0o644)
        backup: Create timestamped backup if file changes

    Returns:
        True if any changes were made
    """
    path = Path(path)
    changed = False
    needs_sudo = _needs_sudo(path.parent if not path.exists() else path)

    # Check if content matches (using sudo-aware read)
    existing_content = read_file(path) if path.exists() else ""
    content_matches = existing_content == content

    if not content_matches:
        # Create timestamped backup to avoid overwriting previous backups
        if backup and path.exists():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = path.parent / f"{path.name}.{timestamp}.bak"
            print(f"Backing up {path} to {backup_path}")
            if needs_sudo:
                subprocess.run(["sudo", "cp", str(path), str(backup_path)], check=True)
            else:
                shutil.copy2(path, backup_path)

        print(f"Writing file: {path}")

        # Use atomic write: write to temp file, then move
        # Wrapped in try/finally to ensure temp file cleanup on failure
        tmp_path = None
        try:
            if needs_sudo:
                # Write to /tmp first (we can write there), then sudo mv
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.tmp') as tmp:
                    tmp.write(content)
                    tmp_path = tmp.name
                subprocess.run(["sudo", "mv", tmp_path, str(path)], check=True)
                tmp_path = None  # Successfully moved, no cleanup needed
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                # Atomic write for user-writable files
                with tempfile.NamedTemporaryFile(
                    mode='w',
                    dir=path.parent,
                    delete=False,
                    suffix='.tmp'
                ) as tmp:
                    tmp.write(content)
                    tmp_path = tmp.name
                Path(tmp_path).rename(path)
                tmp_path = None  # Successfully moved, no cleanup needed
        finally:
            # Clean up temp file if it still exists (operation failed)
            if tmp_path and Path(tmp_path).exists():
                try:
                    Path(tmp_path).unlink()
                except OSError:
                    pass  # Best effort cleanup
        changed = True

    if set_permissions(path, owner=owner, group=group, mode=mode):
        changed = True

    if not changed:
        print(f"File {path} already up to date")

    return changed


def ensure_symlink(
    link_path: Union[str, Path],
    target: Union[str, Path],
) -> bool:
    """
    Idempotently ensure a symlink exists.

    Returns:
        True if link was created or changed
    """
    link_path = Path(link_path)
    target = Path(target)
    needs_sudo = _needs_sudo(link_path.parent)

    print("Ensuring symlink: ", link_path)
    print(f"\t(has target {target})")
    print(f"\t(sudo reqd = {needs_sudo}")

    # Check current state
    if link_path.is_symlink():
        current_target = link_path.resolve()
        if current_target == target.resolve():
            print(f"Symlink {link_path} already points to {target}")
            return False

        # Wrong target - remove and recreate
        print(f"Updating symlink {link_path} -> {target}")
        if needs_sudo:
            subprocess.run(["sudo", "rm", str(link_path)], check=True)
        else:
            link_path.unlink()
    elif link_path.exists():
        raise ValueError(f"{link_path} exists but is not a symlink")

    print(f"Creating symlink {link_path} -> {target}")
    if needs_sudo:
        subprocess.run(["sudo", "ln", "-s", str(target), str(link_path)], check=True)
    else:
        link_path.symlink_to(target)

    return True


def render_template(
    template_path: Union[str, Path],
    context: dict,
) -> str:
    """
    Render a template file with variable substitution.

    Uses Jinja2 if available, falls back to string.Template.

    Args:
        template_path: Path to template file
        context: Dictionary of variables to substitute

    Returns:
        Rendered template content
    """
    template_path = Path(template_path)
    template_content = template_path.read_text()

    if HAS_JINJA2:
        template = Template(template_content)
        return template.render(**context)
    else:
        # Fallback to string.Template (uses $var syntax)
        template = Template(template_content)
        return template.safe_substitute(context)


def copy_tree(
    src: Union[str, Path],
    dest: Union[str, Path],
    owner: Optional[str] = None,
    group: Optional[str] = None,
) -> bool:
    """
    Recursively copy a directory tree.

    Handles both text and binary files appropriately.

    Returns:
        True if any files were copied
    """
    src = Path(src)
    dest = Path(dest)
    changed = False

    for src_file in src.rglob("*"):
        if src_file.is_file():
            rel_path = src_file.relative_to(src)
            dest_file = dest / rel_path

            # Check if file needs copying via hash comparison
            if not dest_file.exists() or _file_hash(src_file) != _file_hash(dest_file):
                ensure_dir(dest_file.parent, owner=owner, group=group)

                # Try to read as text first, fall back to binary copy
                try:
                    content = src_file.read_text()
                    if ensure_file(dest_file, content, owner=owner, group=group):
                        changed = True
                except UnicodeDecodeError:
                    # Binary file - use direct copy
                    print(f"Copying binary file: {dest_file}")
                    needs_sudo = _needs_sudo(dest_file.parent)
                    if needs_sudo:
                        subprocess.run(
                            ["sudo", "cp", str(src_file), str(dest_file)],
                            check=True
                        )
                    else:
                        shutil.copy2(src_file, dest_file)
                    if owner or group:
                        set_permissions(dest_file, owner=owner, group=group)
                    changed = True

    return changed
