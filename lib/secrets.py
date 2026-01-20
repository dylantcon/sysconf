"""Secrets management with .env.example parsing for sysconf."""

import os
import re
import secrets
import socket
import string
import tomllib
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .base import BaseOrchestrator
from .paths import (
    CONFIGS_DIR,
    PROJECT_ROOT,
    SECRETS_DIR,
    SECRETS_EXAMPLE,
    SECRETS_FILE,
    get_canonical_env_path,
)
from .prompts import confirm, pause, prompt, prompt_secret, warn_missing


def substitute_domain(value: str, base_domain: str) -> str:
    """
    Substitute 'yourdomain' placeholder with the actual base domain.

    Handles patterns like:
    - yourdomain.dev -> dconn.dev
    - yourdomain.com -> dconn.dev
    - <yourdomain> -> dconn.dev

    Args:
        value: The value to process
        base_domain: The actual domain to substitute

    Returns:
        Value with domain substituted
    """
    if not base_domain:
        return value

    # Handle various placeholder patterns
    # yourdomain.dev, yourdomain.com, etc.
    value = re.sub(r'yourdomain\.[a-z]+', base_domain, value, flags=re.IGNORECASE)
    # <yourdomain> style
    value = re.sub(r'<yourdomain>', base_domain, value, flags=re.IGNORECASE)
    # Just 'yourdomain' as a standalone word
    value = re.sub(r'\byourdomain\b', base_domain, value, flags=re.IGNORECASE)

    return value


def parse_env_example(file_path: Path, base_domain: str = "") -> Dict[str, str]:
    """
    Parse a .env.example file into a dictionary.

    Args:
        file_path: Path to the .env.example file
        base_domain: Base domain for substituting 'yourdomain' placeholders

    Returns:
        Dictionary of key -> default value (empty string if no default)
    """
    env_vars = {}
    if not file_path.exists():
        return env_vars

    with open(file_path) as f:
        for line in f:
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue

            # Parse KEY=value or KEY=
            if "=" in line:
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                # Substitute domain placeholders
                if base_domain:
                    value = substitute_domain(value, base_domain)
                env_vars[key] = value

    return env_vars


def scan_repo_env_examples(base_path: Path, base_domain: str = "") -> Dict[str, Dict[str, str]]:
    """
    Scan a repository for .env.example files.

    Looks for:
    - .env.example in root
    - **/.env.example in subdirectories

    Args:
        base_path: Root path of the repository
        base_domain: Base domain for substituting 'yourdomain' placeholders

    Returns:
        Dictionary of relative_path -> env_vars dict
    """
    results = {}

    # Check root
    root_example = base_path / ".env.example"
    if root_example.exists():
        results["."] = parse_env_example(root_example, base_domain)

    # Check subdirectories (one level deep for common patterns)
    for subdir in base_path.iterdir():
        if subdir.is_dir() and not subdir.name.startswith("."):
            sub_example = subdir / ".env.example"
            if sub_example.exists():
                results[subdir.name] = parse_env_example(sub_example, base_domain)

    return results


def is_port_in_use(port: int) -> bool:
    """
    Check if a port is currently in use.

    Args:
        port: Port number to check

    Returns:
        True if port is in use
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


def find_available_port(start_port: int, max_attempts: int = 10) -> Optional[int]:
    """Find an available port starting from the given port."""
    for offset in range(max_attempts):
        port = start_port + offset
        if not is_port_in_use(port):
            return port
    return None


def generate_django_secret_key(length: int = 50) -> str:
    """
    Generate a secure Django secret key.

    Django's default secret key generation uses these characters.
    """
    chars = string.ascii_letters + string.digits + "!@#$%^&*(-_=+)"
    return "".join(secrets.choice(chars) for _ in range(length))


def classify_secret_type(key: str, value: str) -> str:
    """
    Classify the type of a secret based on its key name and default value.

    Args:
        key: The environment variable name
        value: The default value

    Returns:
        One of: 'django_secret', 'port', 'api_key', 'password', 'email', 'path', 'url', 'generic'
    """
    key_lower = key.lower()

    # Django secret key detection (check first, before generic "secret" match)
    # Matches: DJANGO_SECRET_KEY, SECRET_KEY, etc.
    if key_lower == "secret_key" or ("django" in key_lower and "secret" in key_lower):
        return "django_secret"

    # Port detection
    if "port" in key_lower:
        return "port"

    # API key detection
    if any(x in key_lower for x in ["api_key", "apikey", "api_secret", "token", "auth_token"]):
        return "api_key"

    # Password/secret detection
    if any(x in key_lower for x in ["password", "passwd", "secret", "key"]):
        return "password"

    # Email detection
    if "email" in key_lower:
        return "email"

    # Path detection
    if any(x in key_lower for x in ["path", "dir", "directory", "folder"]):
        return "path"

    # URL detection
    if any(x in key_lower for x in ["url", "uri", "endpoint", "host"]):
        return "url"

    # Check value patterns
    if value:
        if value.isdigit() and 1024 <= int(value) <= 65535:
            return "port"
        if "@" in value and "." in value:
            return "email"
        if value.startswith(("/", "~", "./")):
            return "path"
        if value.startswith(("http://", "https://", "ws://", "wss://")):
            return "url"

    return "generic"


def prompt_for_secret(
    key: str,
    default: str,
    secret_type: str,
    repo_name: str,
    dry_run: bool = False,
) -> Tuple[str, bool]:
    """
    Prompt user for a secret value with type-specific handling.

    Args:
        key: The environment variable name
        default: The default value
        secret_type: The classified type of the secret
        repo_name: Name of the repository (for context)
        dry_run: If True, just show what would be prompted

    Returns:
        Tuple of (value, was_skipped)
    """
    if dry_run:
        print(f"    Would prompt for {key} (type: {secret_type})")
        return default, False

    print(f"  {key}")

    if secret_type == "django_secret":
        # Auto-generate Django secret key if not already set
        if default and len(default) >= 40:
            # Already has a valid-looking key
            print(f"    (using existing key)")
            return default, False

        generated = generate_django_secret_key()
        print(f"    Auto-generated Django secret key")
        return generated, False

    elif secret_type == "port":
        # Port handling - validate and suggest alternatives
        # But skip "in use" warning if this is an existing configured value
        # (e.g., DB_PORT=5432 when PostgreSQL is correctly running on 5432)
        if default:
            try:
                port = int(default)
                port_in_use = is_port_in_use(port)
                # Only suggest alternative if this looks like a fresh default from .env.example
                # If the port is in use AND this is a DB port, that's likely correct
                is_db_port = "db" in key.lower() or "database" in key.lower() or "postgres" in key.lower()
                if port_in_use and not is_db_port:
                    alt_port = find_available_port(port + 1)
                    print(f"    Port {port} is in use!")
                    if alt_port:
                        print(f"    Suggested alternative: {alt_port}")
                        default = str(alt_port)
                elif port_in_use and is_db_port:
                    print(f"    Port {port} has a service listening (expected for database)")
            except ValueError:
                pass

        value = prompt(f"    Port number", default)
        if value:
            try:
                port = int(value)
                is_db_port = "db" in key.lower() or "database" in key.lower() or "postgres" in key.lower()
                if is_port_in_use(port) and not is_db_port:
                    print(f"    WARNING: Port {port} appears to be in use")
            except ValueError:
                print(f"    WARNING: '{value}' is not a valid port number")
        return value, False

    elif secret_type in ("api_key", "password"):
        # Sensitive values - use getpass
        print(f"    (input hidden, press Enter to skip)")
        value = prompt_secret(f"    {key}")
        if not value:
            return default, True
        return value, False

    elif secret_type == "email":
        value = prompt(f"    Email address", default)
        if value and "@" not in value:
            print(f"    WARNING: '{value}' doesn't look like an email address")
        return value, False

    else:
        # Generic handling
        value = prompt(f"    Value", default)
        return value, False


def read_existing_env(file_path: Path) -> Dict[str, str]:
    """
    Read an existing .env file into a dictionary.

    Args:
        file_path: Path to the .env file

    Returns:
        Dictionary of key -> value
    """
    env_vars = {}
    if not file_path.exists():
        return env_vars

    with open(file_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                env_vars[key] = value

    return env_vars


def generate_env_file(
    dest_path: Path,
    env_vars: Dict[str, str],
    dry_run: bool = False,
) -> bool:
    """
    Generate a .env file from a dictionary of values.

    Args:
        dest_path: Path for the .env file
        env_vars: Dictionary of key -> value pairs
        dry_run: If True, only show what would be done

    Returns:
        True if file was created/updated
    """
    if dry_run:
        print(f"  Would write .env to {dest_path}")
        return True

    lines = []
    for key, value in env_vars.items():
        # Quote values that contain spaces or special characters
        if " " in value or '"' in value or "'" in value:
            value = f'"{value}"'
        lines.append(f"{key}={value}")

    content = "\n".join(lines) + "\n"

    # Write with restrictive permissions
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    dest_path.write_text(content)
    os.chmod(dest_path, 0o600)

    print(f"  Created {dest_path} (mode 0600)")
    return True


def update_secrets_example(new_keys: Dict[str, List[str]]) -> bool:
    """
    Append new keys to secrets.toml.example under [repo_name] sections.

    Args:
        new_keys: Dictionary of repo_name -> list of new keys

    Returns:
        True if the file was updated
    """
    if not new_keys:
        return False

    # Read existing content
    if SECRETS_EXAMPLE.exists():
        existing = SECRETS_EXAMPLE.read_text()
    else:
        existing = ""

    additions = []
    for repo_name, keys in new_keys.items():
        # Check if section already exists
        section_marker = f"[{repo_name}]"
        if section_marker not in existing:
            additions.append(f"\n[{repo_name}]")
            for key in keys:
                additions.append(f'{key} = ""')

    if additions:
        with open(SECRETS_EXAMPLE, "a") as f:
            f.write("\n" + "\n".join(additions) + "\n")
        return True

    return False


def generate_canonical_env_file(
    webpage_name: str,
    env_vars: Dict[str, str],
    dry_run: bool = False,
) -> Optional[Path]:
    """
    Generate a canonical .env file in /etc/sysconf/secrets/.

    The canonical file serves as the single source of truth for the webpage's
    environment variables. Deployment symlinks point to this file.

    Args:
        webpage_name: Name of the webpage (e.g., 'countertrak')
        env_vars: Dictionary of key -> value pairs
        dry_run: If True, only show what would be done

    Returns:
        Path to the canonical file, or None if dry_run
    """
    from .paths import SYSTEM_SECRETS_DIR
    import subprocess
    import tempfile

    canonical_path = get_canonical_env_path(webpage_name)

    if dry_run:
        print(f"  Would write canonical .env to {canonical_path}")
        return None

    lines = []
    for key, value in env_vars.items():
        # Quote values that contain spaces or special characters
        if " " in value or '"' in value or "'" in value:
            value = f'"{value}"'
        lines.append(f"{key}={value}")

    content = "\n".join(lines) + "\n"

    # Ensure system secrets directory exists with proper permissions
    if not SYSTEM_SECRETS_DIR.exists():
        subprocess.run(["sudo", "mkdir", "-p", str(SYSTEM_SECRETS_DIR)], check=True)
        subprocess.run(["sudo", "chown", "root:www-data", str(SYSTEM_SECRETS_DIR)], check=True)
        subprocess.run(["sudo", "chmod", "750", str(SYSTEM_SECRETS_DIR)], check=True)

    # Write to temp file then move with sudo (atomic write)
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.env') as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    subprocess.run(["sudo", "mv", tmp_path, str(canonical_path)], check=True)
    subprocess.run(["sudo", "chown", "root:www-data", str(canonical_path)], check=True)
    subprocess.run(["sudo", "chmod", "640", str(canonical_path)], check=True)

    print(f"  Created canonical {canonical_path} (mode 0640, root:www-data)")
    return canonical_path


def symlink_env_file(
    webpage_name: str,
    dest_path: Path,
    dry_run: bool = False,
) -> bool:
    """
    Create a symlink from dest_path to the canonical .env file.

    Args:
        webpage_name: Name of the webpage (used to locate canonical file)
        dest_path: Where the symlink should be created
        dry_run: If True, only show what would be done

    Returns:
        True if symlink was created/updated
    """
    from .files import ensure_symlink

    canonical_path = get_canonical_env_path(webpage_name)

    if dry_run:
        print(f"  Would symlink {dest_path} -> {canonical_path}")
        return True

    if not canonical_path.exists():
        print(f"  WARNING: Canonical env file {canonical_path} does not exist")
        return False

    return ensure_symlink(dest_path, canonical_path)


def migrate_env_to_symlinks(
    webpage_name: str,
    existing_env_path: Path,
    dry_run: bool = False,
) -> bool:
    """
    Migrate an existing .env file to symlink-based management.

    Steps:
    1. Read existing .env content
    2. Write to canonical secrets/.env.<name>
    3. Replace original with symlink to canonical

    Args:
        webpage_name: Name of the webpage
        existing_env_path: Path to the existing .env file
        dry_run: If True, only show what would be done

    Returns:
        True if migration succeeded
    """
    if not existing_env_path.exists():
        print(f"  No existing .env at {existing_env_path}")
        return False

    if existing_env_path.is_symlink():
        print(f"  {existing_env_path} is already a symlink")
        return True

    # Read existing content
    env_vars = read_existing_env(existing_env_path)
    if not env_vars:
        print(f"  {existing_env_path} is empty or could not be read")
        return False

    canonical_path = get_canonical_env_path(webpage_name)

    if dry_run:
        print(f"  Would migrate {existing_env_path}:")
        print(f"    -> Write to {canonical_path}")
        print(f"    -> Replace with symlink")
        return True

    # Write to canonical location
    generate_canonical_env_file(webpage_name, env_vars, dry_run=False)

    # Remove original and create symlink
    existing_env_path.unlink()
    return symlink_env_file(webpage_name, existing_env_path, dry_run=False)


class SecretsManager(BaseOrchestrator):
    """Manager for secrets and .env file generation."""

    def __init__(self, dry_run: bool = False, verbose: bool = False):
        super().__init__(dry_run=dry_run, verbose=verbose)
        self.secrets = {}

    def load_or_create_secrets(self) -> Dict:
        """
        Load secrets from secrets.toml, creating from example if needed.

        Returns:
            Dictionary of secrets configuration
        """
        if SECRETS_FILE.exists():
            with open(SECRETS_FILE, "rb") as f:
                self.secrets = tomllib.load(f)
        elif SECRETS_EXAMPLE.exists():
            print(f"No {SECRETS_FILE} found, creating from example...")
            if not self.dry_run:
                import shutil
                SECRETS_DIR.mkdir(parents=True, exist_ok=True)
                shutil.copy(SECRETS_EXAMPLE, SECRETS_FILE)
            with open(SECRETS_EXAMPLE, "rb") as f:
                self.secrets = tomllib.load(f)
        else:
            self.secrets = {}

        return self.secrets

    def get_ssh_key_path(self) -> Optional[Path]:
        """Get the configured SSH key path, if any."""
        github_config = self.secrets.get("github", {})
        key_path = github_config.get("ssh_key_path", "")
        if key_path:
            path = Path(key_path).expanduser()
            if path.exists():
                return path
        return None

    def get_certbot_email(self) -> Optional[str]:
        """Get the configured certbot email, if any."""
        letsencrypt_config = self.secrets.get("letsencrypt", {})
        return letsencrypt_config.get("email", "") or None

    def get_base_domain(self) -> str:
        """Get the configured base domain for substitution."""
        domain_config = self.secrets.get("domain", {})
        return domain_config.get("base", "")

    def check_prerequisites(self) -> Dict[str, bool]:
        """
        Check for available prerequisites.

        Returns:
            Dictionary of feature -> is_available
        """
        return {
            "ssh_key": self.get_ssh_key_path() is not None,
            "certbot_email": self.get_certbot_email() is not None,
        }

    def report_missing_prerequisites(self) -> None:
        """Print warnings about missing prerequisites."""
        prereqs = self.check_prerequisites()

        if not prereqs["ssh_key"]:
            warn_missing(
                "SSH key",
                "Git will use HTTPS (read-only, no push capability)"
            )

        if not prereqs["certbot_email"]:
            warn_missing(
                "Certbot email",
                "SSL certificates will not be auto-provisioned"
            )

    def process_repo_secrets(
        self,
        repo_name: str,
        env_examples: Dict[str, Dict[str, str]],
        repo_path: Path,
    ) -> Dict[str, str]:
        """
        Process .env.example files for a repository.

        Args:
            repo_name: Name of the repository
            env_examples: Dictionary from scan_repo_env_examples
            repo_path: Path to the repository

        Returns:
            Dictionary of all processed secrets
        """
        all_secrets = {}

        for rel_path, env_vars in env_examples.items():
            if rel_path == ".":
                env_dest = repo_path / ".env"
                print(f"\n  Processing {repo_name} root .env.example")
            else:
                env_dest = repo_path / rel_path / ".env"
                print(f"\n  Processing {repo_name}/{rel_path}/.env.example")

            # Read existing .env values (for idempotency)
            existing_env = read_existing_env(env_dest)

            # Check if .env already exists
            if env_dest.exists() and not self.dry_run:
                if not confirm(f"    {env_dest} exists. Overwrite?", default=False):
                    print("    Skipping...")
                    continue

            # Get existing values from secrets.toml for this repo
            repo_secrets = self.secrets.get(repo_name, {})

            processed = {}
            for key, default in env_vars.items():
                # Priority: secrets.toml > existing .env > .env.example default
                if key in repo_secrets and repo_secrets[key]:
                    processed[key] = repo_secrets[key]
                    if self.verbose:
                        print(f"    {key}: using value from secrets.toml")
                    continue

                # Use existing .env value as the default if available
                effective_default = existing_env.get(key, default)

                secret_type = classify_secret_type(key, effective_default)
                value, skipped = prompt_for_secret(
                    key, effective_default, secret_type, repo_name, self.dry_run
                )

                if skipped:
                    print(f"    (skipped - service may not start without this)")
                processed[key] = value

            generate_env_file(env_dest, processed, self.dry_run)
            all_secrets.update(processed)

        return all_secrets

    def process_repo_secrets_with_symlinks(
        self,
        repo_name: str,
        env_examples: Dict[str, Dict[str, str]],
        repo_path: Path,
    ) -> Dict[str, str]:
        """
        Process .env.example files for a repository using symlinks.

        This method writes secrets to a canonical file in secrets/ and creates
        symlinks from the repo location to the canonical file.

        Args:
            repo_name: Name of the repository
            env_examples: Dictionary from scan_repo_env_examples
            repo_path: Path to the repository

        Returns:
            Dictionary of all processed secrets
        """
        all_secrets = {}

        for rel_path, env_vars in env_examples.items():
            if rel_path == ".":
                env_dest = repo_path / ".env"
                env_name_suffix = ""
                print(f"\n  Processing {repo_name} root .env.example")
            else:
                env_dest = repo_path / rel_path / ".env"
                env_name_suffix = f"-{rel_path}"
                print(f"\n  Processing {repo_name}/{rel_path}/.env.example")

            # Full webpage name for canonical file (handles subdirs)
            full_webpage_name = f"{repo_name}{env_name_suffix}"
            canonical_path = get_canonical_env_path(full_webpage_name)

            # Read existing values from canonical file (in /etc/sysconf/secrets)
            existing_env = {}
            if canonical_path.exists():
                try:
                    # Need sudo to read from /etc/sysconf/secrets
                    import subprocess
                    result = subprocess.run(
                        ["sudo", "cat", str(canonical_path)],
                        capture_output=True, text=True, check=True
                    )
                    for line in result.stdout.splitlines():
                        if "=" in line and not line.startswith("#"):
                            k, _, v = line.partition("=")
                            existing_env[k.strip()] = v.strip().strip('"').strip("'")
                except Exception:
                    pass

            # If canonical file exists and has all keys, just ensure symlink exists
            if existing_env and all(key in existing_env for key in env_vars.keys()):
                print(f"    Using existing secrets from {canonical_path}")
                symlink_env_file(full_webpage_name, env_dest, self.dry_run)
                all_secrets.update(existing_env)
                continue

            # Check if .env already exists and is not a symlink (migrate scenario)
            if env_dest.exists() and not env_dest.is_symlink() and not self.dry_run:
                # Offer to migrate existing file
                if confirm(f"    {env_dest} exists. Migrate to symlink?", default=True):
                    migrate_env_to_symlinks(full_webpage_name, env_dest, self.dry_run)
                    all_secrets.update(read_existing_env(canonical_path))
                    continue
                elif not confirm(f"    Overwrite?", default=False):
                    print("    Skipping...")
                    continue

            # Get existing values from secrets.toml for this repo
            repo_secrets = self.secrets.get(repo_name, {})

            processed = {}
            for key, default in env_vars.items():
                # Priority: secrets.toml > existing .env > .env.example default
                if key in repo_secrets and repo_secrets[key]:
                    processed[key] = repo_secrets[key]
                    if self.verbose:
                        print(f"    {key}: using value from secrets.toml")
                    continue

                # Use existing .env value as the default if available
                effective_default = existing_env.get(key, default)

                secret_type = classify_secret_type(key, effective_default)
                value, skipped = prompt_for_secret(
                    key, effective_default, secret_type, repo_name, self.dry_run
                )

                if skipped:
                    print(f"    (skipped - service may not start without this)")
                processed[key] = value

            # Generate canonical file and create symlink
            generate_canonical_env_file(full_webpage_name, processed, self.dry_run)
            symlink_env_file(full_webpage_name, env_dest, self.dry_run)
            all_secrets.update(processed)

        return all_secrets

    def run(self, base_path: Optional[Path] = None, scan_only: bool = False) -> None:
        """
        Run the secrets management workflow.

        Args:
            base_path: Base path to scan for repositories (default: /var/www)
            scan_only: If True, only scan and report, don't prompt
        """
        if base_path is None:
            base_path = Path("/var/www")

        self.log("=== Secrets Management ===")

        # Load secrets configuration
        self.load_or_create_secrets()
        self.report_missing_prerequisites()

        # Get base domain for placeholder substitution
        base_domain = self.get_base_domain()
        if base_domain:
            self.log(f"Using base domain: {base_domain}")

        # Scan for repositories with .env.example files
        if not base_path.exists():
            self.log(f"Base path {base_path} does not exist")
            return

        new_keys = {}  # Track keys to add to secrets.toml.example

        for repo_dir in base_path.iterdir():
            if not repo_dir.is_dir() or repo_dir.name.startswith("."):
                continue

            env_examples = scan_repo_env_examples(repo_dir, base_domain)
            if not env_examples:
                continue

            repo_name = repo_dir.name
            print(f"\n{repo_name}:")

            if scan_only:
                for rel_path, env_vars in env_examples.items():
                    location = f"{repo_name}/{rel_path}" if rel_path != "." else repo_name
                    print(f"  Found .env.example in {location}")
                    for key, default in env_vars.items():
                        secret_type = classify_secret_type(key, default)
                        default_display = f" (default: {default})" if default else ""
                        print(f"    {key} [{secret_type}]{default_display}")
                continue

            # Process the repo
            secrets = self.process_repo_secrets(repo_name, env_examples, repo_dir)

            # Track new keys for secrets.toml.example
            existing_keys = set(self.secrets.get(repo_name, {}).keys())
            new_repo_keys = [k for k in secrets.keys() if k not in existing_keys]
            if new_repo_keys:
                new_keys[repo_name] = new_repo_keys

        # Update secrets.toml.example with any new keys found
        if new_keys and not scan_only:
            if update_secrets_example(new_keys):
                self.log("\nUpdated secrets.toml.example with new keys")

        self.log("\nSecrets management complete")
