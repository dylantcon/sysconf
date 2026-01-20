"""Cleanup operations for sysconf deployments."""

import subprocess
import tomllib
from pathlib import Path
from typing import List, Optional

from .base import BaseOrchestrator
from .paths import (
    CERTBOT_LIVE,
    NGINX_SITES_AVAILABLE,
    NGINX_SITES_ENABLED,
    SYSTEMD_DIR,
    WEBPAGES_CONFIG,
    WWW_BASE,
    get_canonical_env_path,
)
from .prompts import confirm
from .setup import remove_postgres_db


class Cleaner(BaseOrchestrator):
    """Handles cleanup of deployed configurations."""

    def __init__(self, dry_run: bool = False, verbose: bool = False):
        super().__init__(dry_run=dry_run, verbose=verbose)

    def _load_webpages_config(self) -> dict:
        """Load webpages configuration."""
        if not WEBPAGES_CONFIG.exists():
            return {"defaults": {}, "webpages": {}}

        with open(WEBPAGES_CONFIG, "rb") as f:
            return tomllib.load(f)

    def _get_all_webpage_names(self) -> List[str]:
        """Get list of all webpage names from config."""
        config = self._load_webpages_config()
        return list(config.get("webpages", {}).keys())

    def _sudo_rm(self, path: Path) -> bool:
        """Remove a file or symlink with sudo."""
        if not path.exists() and not path.is_symlink():
            return False

        self.log(f"  Removing: {path}")
        if not self.dry_run:
            subprocess.run(["sudo", "rm", "-f", str(path)], check=True)
        return True

    def clean_webpage(self, name: str) -> bool:
        """
        Fully clean a webpage - the inverse of deploy_webpage().

        Removes everything:
        - Systemd services (stop, disable, remove)
        - Nginx config (sites-available + sites-enabled)
        - SSL certificate (unless shared/wildcard)
        - .env symlink and canonical file in secrets/
        - PostgreSQL database and user (if configured)
        - Repository directory

        Args:
            name: Webpage name (from webpages.toml)

        Returns:
            True if cleanup was performed
        """
        config = self._load_webpages_config()
        wp_config = config.get("webpages", {}).get(name)

        if not wp_config:
            self.log(f"ERROR: Webpage '{name}' not found in config")
            self.log(f"Available: {', '.join(self._get_all_webpage_names())}")
            return False

        domain = wp_config.get("domain", name)
        ssl_cert_domain = wp_config.get("ssl_cert_domain")
        services = [svc.get("name", name) for svc in wp_config.get("services", [])]
        setup_config = wp_config.get("setup", {})
        webpage_path = WWW_BASE / domain

        self.log(f"\n=== Cleaning: {name} ({domain}) ===")

        # Confirm before destructive operations
        if not self.dry_run:
            if not confirm(f"Remove all configuration for {name}?", default=False):
                self.log("Skipped.")
                return False

        # 1. Stop and remove systemd services
        for svc_name in services:
            svc_file = SYSTEMD_DIR / f"{svc_name}.service"
            if svc_file.exists() or self.dry_run:
                self.log(f"  Stopping service: {svc_name}")
                if not self.dry_run:
                    subprocess.run(["sudo", "systemctl", "stop", svc_name], capture_output=True)
                    subprocess.run(["sudo", "systemctl", "disable", svc_name], capture_output=True)
                if self._sudo_rm(svc_file):
                    self.record_change(f"Removed service: {svc_name}")

        # 2. Remove nginx config
        enabled = NGINX_SITES_ENABLED / domain
        available = NGINX_SITES_AVAILABLE / domain
        if self._sudo_rm(enabled):
            self.record_change(f"Removed nginx enabled: {domain}")
        if self._sudo_rm(available):
            self.record_change(f"Removed nginx config: {domain}")

        # 3. Remove SSL certificate (skip if using shared/wildcard)
        if ssl_cert_domain and ssl_cert_domain != domain:
            self.log(f"  Skipping SSL: uses shared cert from {ssl_cert_domain}")
        else:
            cert_path = CERTBOT_LIVE / domain
            cert_exists = False
            try:
                cert_exists = cert_path.exists()
            except PermissionError:
                result = subprocess.run(["sudo", "test", "-d", str(cert_path)], capture_output=True)
                cert_exists = result.returncode == 0

            if cert_exists:
                self.log(f"  Removing SSL certificate: {domain}")
                if not self.dry_run:
                    result = subprocess.run(
                        ["sudo", "certbot", "delete", "--cert-name", domain, "--non-interactive"],
                        capture_output=True, text=True,
                    )
                    if result.returncode == 0:
                        self.record_change(f"Removed SSL cert: {domain}")
                    else:
                        self.log(f"  WARNING: certbot delete failed: {result.stderr}")

        # 4. Remove .env files (canonical in /etc/sysconf/secrets + symlinks)
        canonical = get_canonical_env_path(name)
        if canonical.exists():
            if self._sudo_rm(canonical):
                self.record_change(f"Removed .env: {name}")

        # Check common subdirs for env files
        for subdir in ["", "backend"]:
            env_path = webpage_path / subdir / ".env" if subdir else webpage_path / ".env"
            if env_path.is_symlink():
                self._sudo_rm(env_path)

            if subdir:
                subdir_canonical = get_canonical_env_path(f"{name}-{subdir}")
                if subdir_canonical.exists():
                    if self._sudo_rm(subdir_canonical):
                        self.record_change(f"Removed .env: {name}-{subdir}")

        # 5. Remove PostgreSQL database/user if configured
        postgres_config = setup_config.get("postgres", {})
        if postgres_config:
            db_name = postgres_config.get("db", name)
            db_user = postgres_config.get("user", name)
            self.log(f"  Removing PostgreSQL: db={db_name}, user={db_user}")
            if remove_postgres_db(db_name, db_user, self.dry_run):
                self.record_change(f"Removed PostgreSQL: {db_name}")

        # 6. Remove repository directory
        if webpage_path.exists():
            self.log(f"  Removing directory: {webpage_path}")
            if not self.dry_run:
                subprocess.run(["sudo", "rm", "-rf", str(webpage_path)], check=True)
            self.record_change(f"Removed directory: {webpage_path}")

        # Reload daemons
        if not self.dry_run and self.changes:
            subprocess.run(["sudo", "systemctl", "daemon-reload"], check=True)
            subprocess.run(["sudo", "systemctl", "reload", "nginx"], capture_output=True)

        return True

    def run(self, targets: Optional[List[str]] = None) -> None:
        """
        Run cleanup operations.

        Args:
            targets: Specific webpage names to clean. If empty/None, cleans all.
        """
        self.log("=== Sysconf Cleanup ===")

        # Determine what to clean
        if targets:
            to_clean = targets
        else:
            to_clean = self._get_all_webpage_names()
            if not to_clean:
                self.log("No webpages configured.")
                return
            self.log(f"Cleaning all webpages: {', '.join(to_clean)}")

        # Clean each target
        for name in to_clean:
            self.clean_webpage(name)

        self.summarize()
