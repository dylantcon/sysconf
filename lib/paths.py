"""Centralized path constants for sysconf.

This module provides all path constants used throughout sysconf,
ensuring consistency and making paths easy to update.
"""

from pathlib import Path

# Project paths (relative to this file's location)
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
CONFIGS_DIR = PROJECT_ROOT / "configs"
SECRETS_DIR = PROJECT_ROOT / "secrets"  # sysconf's own config (config.toml)
SECRETS_FILE = SECRETS_DIR / "config.toml"
SECRETS_EXAMPLE = PROJECT_ROOT / "secrets.example.toml"

# System secrets - canonical .env files for webpages (accessible by www-data)
SYSTEM_SECRETS_DIR = Path("/etc/sysconf/secrets")

# Config file paths
WEBPAGES_CONFIG = CONFIGS_DIR / "webpages.toml"
TOOLCHAINS_CONFIG = CONFIGS_DIR / "toolchains.toml"
TAILSCALE_CONFIG = CONFIGS_DIR / "tailscale.toml"

# System paths - nginx
NGINX_SITES_AVAILABLE = Path("/etc/nginx/sites-available")
NGINX_SITES_ENABLED = Path("/etc/nginx/sites-enabled")

# System paths - systemd
SYSTEMD_DIR = Path("/etc/systemd/system")

# System paths - web
WWW_BASE = Path("/var/www")

# System paths - SSL certificates
CERTBOT_LIVE = Path("/etc/letsencrypt/live")

# User paths
def get_user_home() -> Path:
    """
    Get real user's home directory (handles sudo).

    When running under sudo, returns the original user's home directory,
    not root's home.
    """
    import os
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        import pwd
        try:
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            pass
    return Path.home()


def get_dotfiles_dir() -> Path:
    """Get the dotfiles configuration directory."""
    return CONFIGS_DIR / "dotfiles"


def get_canonical_env_path(webpage_name: str) -> Path:
    """
    Get the canonical path for a webpage's .env file.

    Args:
        webpage_name: Name of the webpage (e.g., 'countertrak')

    Returns:
        Path to the canonical .env file in /etc/sysconf/secrets/
    """
    return SYSTEM_SECRETS_DIR / f".env.{webpage_name}"


def get_webpage_path(webpage_name: str, domain: str) -> Path:
    """
    Get the deployment path for a webpage.

    Args:
        webpage_name: Name of the webpage
        domain: Domain name (used as directory name)

    Returns:
        Path to the webpage deployment directory
    """
    return WWW_BASE / domain
