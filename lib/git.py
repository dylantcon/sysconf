"""Git operations with stash handling for sysconf."""

import subprocess
from pathlib import Path
from typing import Optional, Tuple

from .prompts import pause


def get_default_branch(remote_url: str) -> Optional[str]:
    """
    Get the default branch for a git remote.

    Args:
        remote_url: Full git URL or GitHub shorthand (owner/repo)

    Returns:
        Default branch name, or None if unable to determine
    """
    # Normalize GitHub shorthand to full URL
    if "/" in remote_url and not remote_url.startswith(("http", "git@")):
        remote_url = f"https://github.com/{remote_url}.git"

    try:
        # git ls-remote --symref shows what HEAD points to
        result = subprocess.run(
            ["git", "ls-remote", "--symref", remote_url, "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            # Output: "ref: refs/heads/master\tHEAD"
            for line in result.stdout.splitlines():
                if line.startswith("ref: refs/heads/"):
                    return line.split("refs/heads/")[1].split()[0]
    except Exception:
        pass
    return None


def _run_git(repo_path: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run a git command in a repository."""
    cmd = ["git", "-C", str(repo_path)] + list(args)
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def has_local_changes(repo_path: Path) -> bool:
    """
    Check if a repository has local changes (staged or unstaged).

    Args:
        repo_path: Path to the git repository

    Returns:
        True if there are uncommitted changes
    """
    result = _run_git(repo_path, "status", "--porcelain", check=False)
    return bool(result.stdout.strip())


def get_changed_files(repo_path: Path) -> list[str]:
    """
    Get list of changed files in a repository.

    Args:
        repo_path: Path to the git repository

    Returns:
        List of changed file descriptions (e.g., "M  src/main.go")
    """
    result = _run_git(repo_path, "status", "--porcelain", check=False)
    return [line for line in result.stdout.strip().split("\n") if line]


def stash_changes(repo_path: Path, dry_run: bool = False) -> bool:
    """
    Stash local changes with user notification and pause.

    Shows changed files, prints restore command, and pauses for user
    acknowledgment before proceeding.

    Args:
        repo_path: Path to the git repository
        dry_run: If True, only show what would happen

    Returns:
        True if changes were stashed, False if no changes
    """
    if not has_local_changes(repo_path):
        return False

    changed_files = get_changed_files(repo_path)

    print(f"  Local changes detected in {repo_path}")
    print("  The following files have modifications:")
    for f in changed_files:
        print(f"    {f}")
    print()
    print("  Changes will be stashed. You can restore them with:")
    print(f"    cd {repo_path} && git stash pop")
    print()

    if dry_run:
        print("  [DRY-RUN] Would stash changes")
        return True

    pause("  Press Enter to stash and continue, or Ctrl+C to abort...")

    result = _run_git(repo_path, "stash", "push", "-m", "sysconf: auto-stash before update")
    if result.returncode == 0:
        print("  Changes stashed successfully")
        return True
    else:
        print(f"  WARNING: Failed to stash changes: {result.stderr}")
        return False


def clone_or_pull(
    repo_url: str,
    dest_path: Path,
    branch: Optional[str] = None,
    ssh_key_path: Optional[Path] = None,
    dry_run: bool = False,
) -> Tuple[bool, str]:
    """
    Clone a repository or pull latest changes if it exists.

    Determines URL format: SSH if key exists, else HTTPS.
    Calls stash_changes if pulling with local changes.

    Args:
        repo_url: Repository URL or shorthand (e.g., "user/repo")
        dest_path: Destination path for the clone
        branch: Branch to checkout (auto-detected from GitHub if not specified)
        ssh_key_path: Optional path to SSH key for authentication
        dry_run: If True, only show what would happen

    Returns:
        Tuple of (success, message)
    """
    # Normalize repo URL and extract owner/repo for API calls
    repo_shorthand = None
    if "/" in repo_url and not repo_url.startswith(("http", "git@")):
        # Shorthand format: user/repo
        repo_shorthand = repo_url
        if ssh_key_path and ssh_key_path.exists():
            full_url = f"git@github.com:{repo_url}.git"
        else:
            full_url = f"https://github.com/{repo_url}.git"
    else:
        full_url = repo_url

    # Auto-detect default branch if not specified
    # Use shorthand or original URL (not SSH URL) to avoid interactive prompts
    if branch is None:
        branch = get_default_branch(repo_shorthand or repo_url)
        if branch is None:
            return False, "Could not determine default branch"

    dest_path = Path(dest_path)

    if dest_path.exists() and (dest_path / ".git").exists():
        # Repository exists - pull updates
        return _pull_repo(dest_path, branch, ssh_key_path, dry_run)
    else:
        # Clone new repository
        return _clone_repo(full_url, dest_path, branch, ssh_key_path, dry_run)


def _get_git_env(ssh_key_path: Optional[Path]) -> dict:
    """Get environment variables for git commands with SSH key."""
    import os
    env = os.environ.copy()
    if ssh_key_path and ssh_key_path.exists():
        env["GIT_SSH_COMMAND"] = f"ssh -i {ssh_key_path} -o IdentitiesOnly=yes"
    return env


def _clone_repo(
    url: str,
    dest_path: Path,
    branch: str,
    ssh_key_path: Optional[Path],
    dry_run: bool,
) -> Tuple[bool, str]:
    """Clone a new repository."""
    print(f"  Cloning {url} to {dest_path}")

    if dry_run:
        return True, f"Would clone to {dest_path}"

    # Ensure parent directory exists
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    env = _get_git_env(ssh_key_path)
    cmd = ["git", "clone", "--branch", branch, url, str(dest_path)]

    result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if result.returncode == 0:
        # Get the current commit
        commit_result = subprocess.run(
            ["git", "-C", str(dest_path), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
        )
        commit = commit_result.stdout.strip() if commit_result.returncode == 0 else "unknown"
        return True, f"Cloned at commit {commit}"
    else:
        return False, f"Clone failed: {result.stderr}"


def _pull_repo(
    repo_path: Path,
    branch: str,
    ssh_key_path: Optional[Path],
    dry_run: bool,
) -> Tuple[bool, str]:
    """Pull updates in an existing repository."""
    env = _get_git_env(ssh_key_path)

    # Fetch first to see if there are upstream changes
    fetch_result = subprocess.run(
        ["git", "-C", str(repo_path), "fetch", "origin", branch],
        capture_output=True,
        text=True,
        env=env,
    )
    if fetch_result.returncode != 0:
        return False, f"Fetch failed: {fetch_result.stderr}"

    # Compare local HEAD with remote
    local_result = subprocess.run(
        ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
    )
    remote_result = subprocess.run(
        ["git", "-C", str(repo_path), "rev-parse", f"origin/{branch}"],
        capture_output=True,
        text=True,
    )

    local_head = local_result.stdout.strip()
    remote_head = remote_result.stdout.strip()

    if local_head == remote_head:
        return True, "Already up to date"

    # There are upstream changes - now we need to pull
    print(f"  Updates available for {repo_path}")

    if dry_run:
        return True, f"Would pull {remote_head[:7]} (currently at {local_head[:7]})"

    # Only stash if there are local changes AND we need to pull
    if has_local_changes(repo_path):
        stash_changes(repo_path, dry_run=False)

    # Pull changes
    print("  Pulling latest...")
    pull_result = subprocess.run(
        ["git", "-C", str(repo_path), "pull", "origin", branch],
        capture_output=True,
        text=True,
        env=env,
    )

    if pull_result.returncode == 0:
        commit = subprocess.run(
            ["git", "-C", str(repo_path), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
        ).stdout.strip()
        return True, f"Updated to commit {commit}"
    else:
        return False, f"Pull failed: {pull_result.stderr}"


def get_remote_url(repo_path: Path) -> Optional[str]:
    """Get the remote URL of a repository."""
    result = _run_git(repo_path, "remote", "get-url", "origin", check=False)
    if result.returncode == 0:
        return result.stdout.strip()
    return None


def is_git_repo(path: Path) -> bool:
    """Check if a path is a git repository."""
    return (path / ".git").exists()
