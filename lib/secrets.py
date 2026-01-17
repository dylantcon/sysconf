"""Secrets management with .env.example parsing for sysconf."""

import os
import re
import socket
import tomllib
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .prompts import confirm, pause, prompt, prompt_secret, warn_missing

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
CONFIGS_DIR = PROJECT_ROOT / "configs"
SECRETS_DIR = PROJECT_ROOT / "secrets"
SECRETS_FILE = SECRETS_DIR / "config.toml"
SECRETS_EXAMPLE = CONFIGS_DIR / "secrets.example.toml"


def parse_env_example(file_path: Path) -> Dict[str, str]:
    """
    Parse a .env.example file into a dictionary.

    Args:
        file_path: Path to the .env.example file

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
                env_vars[key] = value

    return env_vars


def scan_repo_env_examples(base_path: Path) -> Dict[str, Dict[str, str]]:
    """
    Scan a repository for .env.example files.

    Looks for:
    - .env.example in root
    - **/.env.example in subdirectories

    Args:
        base_path: Root path of the repository

    Returns:
        Dictionary of relative_path -> env_vars dict
    """
    results = {}

    # Check root
    root_example = base_path / ".env.example"
    if root_example.exists():
        results["."] = parse_env_example(root_example)

    # Check subdirectories (one level deep for common patterns)
    for subdir in base_path.iterdir():
        if subdir.is_dir() and not subdir.name.startswith("."):
            sub_example = subdir / ".env.example"
            if sub_example.exists():
                results[subdir.name] = parse_env_example(sub_example)

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


def classify_secret_type(key: str, value: str) -> str:
    """
    Classify the type of a secret based on its key name and default value.

    Args:
        key: The environment variable name
        value: The default value

    Returns:
        One of: 'port', 'api_key', 'password', 'email', 'path', 'url', 'generic'
    """
    key_lower = key.lower()

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

    if secret_type == "port":
        # Port handling - validate and suggest alternatives
        if default:
            port = int(default)
            if is_port_in_use(port):
                alt_port = find_available_port(port + 1)
                print(f"    Port {port} is in use!")
                if alt_port:
                    print(f"    Suggested alternative: {alt_port}")
                    default = str(alt_port)

        value = prompt(f"    Port number", default)
        if value:
            try:
                port = int(value)
                if is_port_in_use(port):
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


class SecretsManager:
    """Manager for secrets and .env file generation."""

    def __init__(self, dry_run: bool = False, verbose: bool = False):
        self.dry_run = dry_run
        self.verbose = verbose
        self.secrets = {}

    def log(self, msg: str) -> None:
        """Log a message."""
        prefix = "[DRY-RUN] " if self.dry_run else ""
        print(f"{prefix}{msg}")

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

            # Check if .env already exists
            if env_dest.exists() and not self.dry_run:
                if not confirm(f"    {env_dest} exists. Overwrite?", default=False):
                    print("    Skipping...")
                    continue

            # Get existing values from secrets.toml for this repo
            repo_secrets = self.secrets.get(repo_name, {})

            processed = {}
            for key, default in env_vars.items():
                # Use value from secrets.toml if available
                if key in repo_secrets and repo_secrets[key]:
                    processed[key] = repo_secrets[key]
                    if self.verbose:
                        print(f"    {key}: using value from secrets.toml")
                    continue

                secret_type = classify_secret_type(key, default)
                value, skipped = prompt_for_secret(
                    key, default, secret_type, repo_name, self.dry_run
                )

                if skipped:
                    print(f"    (skipped - service may not start without this)")
                processed[key] = value

            generate_env_file(env_dest, processed, self.dry_run)
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

        # Scan for repositories with .env.example files
        if not base_path.exists():
            self.log(f"Base path {base_path} does not exist")
            return

        new_keys = {}  # Track keys to add to secrets.toml.example

        for repo_dir in base_path.iterdir():
            if not repo_dir.is_dir() or repo_dir.name.startswith("."):
                continue

            env_examples = scan_repo_env_examples(repo_dir)
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
