"""Cleanup operations for sysconf deployments."""

import subprocess
import tomllib
from pathlib import Path
from typing import List

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
CONFIGS_DIR = PROJECT_ROOT / "configs"
WEBPAGES_CONFIG = CONFIGS_DIR / "webpages.toml"

# System paths
NGINX_SITES_AVAILABLE = Path("/etc/nginx/sites-available")
NGINX_SITES_ENABLED = Path("/etc/nginx/sites-enabled")
SYSTEMD_DIR = Path("/etc/systemd/system")


class Cleaner:
    """Handles cleanup of deployed configurations."""

    def __init__(self, dry_run: bool = False, verbose: bool = False):
        self.dry_run = dry_run
        self.verbose = verbose
        self.changes = []

    def log(self, msg: str) -> None:
        """Log a message."""
        prefix = "[DRY-RUN] " if self.dry_run else ""
        print(f"{prefix}{msg}")

    def record_change(self, description: str) -> None:
        """Record a change that was made."""
        self.changes.append(description)

    def _sudo_rm(self, path: Path) -> bool:
        """Remove a file or symlink with sudo."""
        if not path.exists() and not path.is_symlink():
            return False

        self.log(f"  Removing: {path}")
        if not self.dry_run:
            subprocess.run(["sudo", "rm", "-f", str(path)], check=True)
        return True

    def _sudo_rm_rf(self, path: Path) -> bool:
        """Remove a directory recursively with sudo."""
        if not path.exists():
            return False

        self.log(f"  Removing directory: {path}")
        if not self.dry_run:
            subprocess.run(["sudo", "rm", "-rf", str(path)], check=True)
        return True

    def _get_webpage_domains(self) -> List[str]:
        """Get list of domains from webpages.toml."""
        if not WEBPAGES_CONFIG.exists():
            return []

        with open(WEBPAGES_CONFIG, "rb") as f:
            config = tomllib.load(f)

        domains = []
        for name, wp_config in config.get("webpages", {}).items():
            domain = wp_config.get("domain", name)
            domains.append(domain)
        return domains

    def _get_webpage_services(self) -> List[str]:
        """Get list of service names from webpages.toml."""
        if not WEBPAGES_CONFIG.exists():
            return []

        with open(WEBPAGES_CONFIG, "rb") as f:
            config = tomllib.load(f)

        services = []
        for name, wp_config in config.get("webpages", {}).items():
            for svc in wp_config.get("services", []):
                svc_name = svc.get("name", name)
                services.append(svc_name)
        return services

    def clean_webpages(self) -> None:
        """Remove nginx configs and systemd services for webpages."""
        self.log("\n=== Cleaning Webpages ===")

        domains = self._get_webpage_domains()
        services = self._get_webpage_services()

        if not domains and not services:
            self.log("No webpages configured")
            return

        # Remove nginx configs
        self.log("\nRemoving nginx configurations...")
        for domain in domains:
            enabled = NGINX_SITES_ENABLED / domain
            available = NGINX_SITES_AVAILABLE / domain

            if self._sudo_rm(enabled):
                self.record_change(f"Removed nginx enabled: {domain}")
            if self._sudo_rm(available):
                self.record_change(f"Removed nginx config: {domain}")

        # Remove systemd services
        self.log("\nRemoving systemd services...")
        for svc_name in services:
            svc_file = SYSTEMD_DIR / f"{svc_name}.service"

            # Stop and disable service first
            if svc_file.exists():
                self.log(f"  Stopping service: {svc_name}")
                if not self.dry_run:
                    subprocess.run(
                        ["sudo", "systemctl", "stop", svc_name],
                        capture_output=True,
                    )
                    subprocess.run(
                        ["sudo", "systemctl", "disable", svc_name],
                        capture_output=True,
                    )

                if self._sudo_rm(svc_file):
                    self.record_change(f"Removed service: {svc_name}")

        # Reload systemd and nginx
        if not self.dry_run and self.changes:
            self.log("\nReloading daemons...")
            subprocess.run(["sudo", "systemctl", "daemon-reload"], check=True)
            subprocess.run(
                ["sudo", "systemctl", "reload", "nginx"],
                capture_output=True,
            )

    def clean_dotfiles(self) -> None:
        """Remove deployed dotfile symlinks."""
        self.log("\n=== Cleaning Dotfiles ===")

        home = Path.home()
        dotfiles_dir = CONFIGS_DIR / "dotfiles"

        if not dotfiles_dir.exists():
            self.log("No dotfiles directory found")
            return

        # Check each dotfile
        for dotfile in dotfiles_dir.iterdir():
            if dotfile.is_file():
                target = home / f".{dotfile.name}"

                # Only remove if it's a symlink pointing to our dotfile
                if target.is_symlink():
                    link_target = target.resolve()
                    if link_target == dotfile.resolve():
                        self.log(f"  Removing symlink: {target}")
                        if not self.dry_run:
                            target.unlink()
                        self.record_change(f"Removed dotfile: {target.name}")

    def clean_services(self) -> None:
        """Remove deployed systemd services (non-webpage)."""
        self.log("\n=== Cleaning Services ===")
        # This would clean services deployed by services command
        # For now, just a placeholder since most services are webpage-related
        self.log("No standalone services to clean")

    def run(
        self,
        webpages: bool = False,
        dotfiles: bool = False,
        services: bool = False,
    ) -> None:
        """Run cleanup operations."""
        if not any([webpages, dotfiles, services]):
            self.log("No cleanup targets specified. Use --webpages, --dotfiles, --services, or --all")
            return

        self.log("=== Sysconf Cleanup ===")

        if webpages:
            self.clean_webpages()

        if dotfiles:
            self.clean_dotfiles()

        if services:
            self.clean_services()

        # Summary
        self.log("\n" + "=" * 60)
        if self.dry_run:
            self.log("Dry-run complete - no changes were made")
        elif self.changes:
            self.log(f"Changes made: {len(self.changes)}")
            for change in self.changes:
                self.log(f"  - {change}")
        else:
            self.log("No changes needed - nothing to clean")
