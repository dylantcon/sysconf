#!/usr/bin/env python3
"""
sysconf - DIY configuration management for Linux systems.

A minimal, idempotent configuration management tool inspired by Ansible,
but designed for personal systems with Python-native configuration.

Usage:
    ./sysconf.py apply              # Apply full configuration
    ./sysconf.py apply --dry-run    # Show what would change
    ./sysconf.py packages           # Install packages only
    ./sysconf.py dotfiles           # Deploy dotfiles only
    ./sysconf.py services           # Configure services only
    ./sysconf.py security           # Apply security hardening only
    ./sysconf.py nginx              # Deploy nginx sites (SSL if certs exist)
    ./sysconf.py nginx --bootstrap  # Bootstrap: HTTP -> certbot -> SSL
"""

import argparse
import os
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import TypedDict

# Add lib to path
sys.path.insert(0, str(Path(__file__).parent))

from lib.packages import (
    PackageManager,
    detect_pm,
    ensure_packages,
    load_package_manifest,
    update_system,
)
from lib.services import (
    daemon_reload,
    enable_service,
    ensure_service_file,
    reload_service,
    restart_service,
)
from lib.files import (
    copy_tree,
    ensure_dir,
    ensure_file,
    ensure_symlink,
    read_file,
    render_template,
)
from lib.security import (
    harden_ssh,
    setup_fail2ban,
    setup_unattended_upgrades,
)

# Project paths
PROJECT_ROOT = Path(__file__).parent.resolve()
CONFIGS_DIR = PROJECT_ROOT / "configs"
SECRETS_DIR = PROJECT_ROOT / "secrets"

# Nginx paths
NGINX_SITES_AVAILABLE = Path("/etc/nginx/sites-available")
NGINX_SITES_ENABLED = Path("/etc/nginx/sites-enabled")


class SiteConfig(TypedDict, total=False):
    """Type definition for site configuration."""
    domain: str
    upstream_port: int
    static_root: str


def load_sites_config() -> dict[str, SiteConfig]:
    """Load site definitions from sites.toml."""
    sites_file = CONFIGS_DIR / "nginx" / "sites.toml"
    if not sites_file.exists():
        return {}

    with open(sites_file, "rb") as f:
        data = tomllib.load(f)

    return data.get("sites", {})


def get_secret(name: str) -> str:
    """
    Get a secret from environment or secrets file.

    Security: Validates that the secret name doesn't escape the secrets directory.
    """
    # Sanitize name: only allow alphanumeric, dash, underscore
    import re
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        raise ValueError(f"Invalid secret name '{name}': only alphanumeric, dash, underscore allowed")

    # Try environment variable first
    env_name = name.upper().replace("-", "_")
    if val := os.environ.get(env_name):
        return val

    # Try secrets file (with path traversal protection)
    secret_file = (SECRETS_DIR / name).resolve()

    # Ensure the resolved path is still within SECRETS_DIR
    try:
        secret_file.relative_to(SECRETS_DIR.resolve())
    except ValueError:
        raise ValueError(f"Invalid secret name '{name}': path traversal detected")

    if secret_file.exists():
        return secret_file.read_text().strip()

    raise ValueError(f"Secret '{name}' not found in env or {SECRETS_DIR}")


class SysConf:
    """Main configuration management class."""

    def __init__(self, dry_run: bool = False, verbose: bool = False):
        self.dry_run = dry_run
        self.verbose = verbose
        self.pm = detect_pm()
        self.changes = []

    def log(self, msg: str) -> None:
        """Log a message."""
        prefix = "[DRY-RUN] " if self.dry_run else ""
        print(f"{prefix}{msg}")

    def record_change(self, description: str) -> None:
        """Record a change that was made."""
        self.changes.append(description)

    # -------------------------------------------------------------------------
    # Package Management
    # -------------------------------------------------------------------------

    def install_packages(self, groups: list[str] | None = None) -> None:
        """Install packages from manifest."""
        self.log("=== Installing Packages ===")

        manifest_path = PROJECT_ROOT / "packages.toml"
        if not manifest_path.exists():
            self.log("packages.toml not found, skipping")
            return

        packages = load_package_manifest(manifest_path, groups=groups, pm=self.pm)
        self.log(f"Package groups: {groups or 'all'}")
        self.log(f"Packages to ensure: {len(packages)}")
        for p_idx in range(len(packages)):
            self.log(f"\tPackage {p_idx + 1}: {packages[p_idx]}")

        if self.verbose:
            for pkg in packages:
                self.log(f"  - {pkg}")

        if not self.dry_run:
            installed = ensure_packages(packages, self.pm)
            if installed:
                self.record_change(f"Installed {len(installed)} packages")

    # -------------------------------------------------------------------------
    # Dotfiles
    # -------------------------------------------------------------------------

    def deploy_dotfiles(self) -> None:
        """Deploy user dotfiles via symlinks."""
        self.log("=== Deploying Dotfiles ===")

        dotfiles_dir = CONFIGS_DIR / "dotfiles"
        if not dotfiles_dir.exists():
            self.log("No dotfiles directory found, skipping")
            return

        home = Path.home()

        # Map of source -> destination
        dotfile_map = {
            "bashrc": home / ".bashrc",
            "bash_aliases": home / ".bash_aliases",
            "profile": home / ".profile",
            "vimrc": home / ".vimrc",
            "gitconfig": home / ".gitconfig",
            "tmux.conf": home / ".tmux.conf",
        }

        for src_name, dest_path in dotfile_map.items():
            src_path = dotfiles_dir / src_name
            if src_path.exists():
                self.log(f"Linking {dest_path} -> {src_path}")
                if not self.dry_run:
                    if ensure_symlink(dest_path, src_path):
                        self.record_change(f"Linked {dest_path}")

    # -------------------------------------------------------------------------
    # SSH Hardening
    # -------------------------------------------------------------------------

    def harden_ssh(self) -> None:
        """Apply SSH hardening configuration."""
        self.log("=== Hardening SSH ===")

        # Copy our hardening config
        src = CONFIGS_DIR / "ssh" / "hardening.conf"
        dest = Path("/etc/ssh/sshd_config.d/99-sysconf.conf")

        if src.exists():
            self.log(f"Deploying SSH config to {dest}")
            if not self.dry_run:
                content = src.read_text()
                if ensure_file(dest, content, owner="root", group="root", mode=0o644):
                    # Validate config before reload
                    result = subprocess.run(["sudo", "sshd", "-t"], capture_output=True)
                    if result.returncode != 0:
                        self.log(f"WARNING: SSH config invalid, skipping reload")
                        return

                    self.record_change("Updated SSH hardening config")
                    # Use reload (not restart) to avoid dropping connections
                    # Detect correct service name (ssh on Debian, sshd on others)
                    ssh_svc = "ssh" if Path("/lib/systemd/system/ssh.service").exists() else "sshd"
                    reload_service(ssh_svc)

    # -------------------------------------------------------------------------
    # Fail2ban
    # -------------------------------------------------------------------------

    def setup_fail2ban(self) -> None:
        """Configure fail2ban with rollback on failure."""
        self.log("=== Configuring Fail2ban ===")

        src = CONFIGS_DIR / "fail2ban" / "jail.local"
        dest = Path("/etc/fail2ban/jail.local")

        if src.exists():
            self.log(f"Deploying fail2ban config to {dest}")
            if not self.dry_run:
                ensure_packages(["fail2ban"], self.pm)

                # Save original config for rollback
                original_content = read_file(dest) if dest.exists() else None

                content = src.read_text()
                if ensure_file(dest, content, owner="root", group="root", mode=0o644):
                    # Validate config before restart
                    result = subprocess.run(
                        ["sudo", "fail2ban-client", "-t"],
                        capture_output=True,
                    )
                    if result.returncode != 0:
                        self.log(f"WARNING: fail2ban config invalid")
                        self.log(result.stderr.decode() if result.stderr else "Unknown error")
                        # Rollback to original
                        if original_content:
                            self.log("Rolling back fail2ban config...")
                            subprocess.run(
                                ["sudo", "tee", str(dest)],
                                input=original_content.encode(),
                                stdout=subprocess.DEVNULL,
                                check=True,
                            )
                        return

                    self.record_change("Updated fail2ban config")
                    enable_service("fail2ban")

                    # Try restart with rollback on failure
                    try:
                        restart_service("fail2ban")
                    except subprocess.CalledProcessError:
                        self.log("ERROR: fail2ban restart failed, rolling back...")
                        if original_content:
                            subprocess.run(
                                ["sudo", "tee", str(dest)],
                                input=original_content.encode(),
                                stdout=subprocess.DEVNULL,
                                check=True,
                            )
                            restart_service("fail2ban")

    # -------------------------------------------------------------------------
    # Nginx
    # -------------------------------------------------------------------------

    def setup_nginx(self, bootstrap: bool = False) -> None:
        """Configure nginx with sites from sites.toml."""
        self.log("=== Configuring Nginx ===")

        if not self.dry_run:
            ensure_packages(["nginx"], self.pm)

        # Deploy main nginx.conf
        self._deploy_nginx_conf()

        # Deploy sites from sites.toml
        sites = load_sites_config()
        if not sites:
            self.log("No sites defined in sites.toml")
            return

        self.log(f"Found {len(sites)} site(s) to configure")

        for name, site in sites.items():
            domain = site.get("domain", name)
            self.log(f"  - {domain}" + (" (bootstrap/HTTP-only)" if bootstrap else ""))

            if not self.dry_run:
                self._deploy_site(name, site, bootstrap=bootstrap)

        # Validate and reload nginx
        if not self.dry_run:
            if self._validate_nginx():
                try:
                    reload_service("nginx")
                    self.record_change("Reloaded nginx")
                except subprocess.CalledProcessError:
                    self.log("ERROR: nginx reload failed")
            else:
                self.log("WARNING: nginx config invalid, skipping reload")

    def _deploy_nginx_conf(self) -> None:
        """Deploy main nginx.conf."""
        src = CONFIGS_DIR / "nginx" / "nginx.conf"
        dest = Path("/etc/nginx/nginx.conf")

        if not src.exists():
            return

        self.log(f"Deploying nginx.conf to {dest}")
        if not self.dry_run:
            original_content = read_file(dest) if dest.exists() else None
            content = src.read_text()

            if ensure_file(dest, content, owner="root", group="root", mode=0o644):
                if not self._validate_nginx():
                    self.log("WARNING: nginx.conf invalid, rolling back")
                    if original_content:
                        subprocess.run(
                            ["sudo", "tee", str(dest)],
                            input=original_content.encode(),
                            stdout=subprocess.DEVNULL,
                            check=True,
                        )
                    return
                self.record_change("Updated nginx.conf")

    def _deploy_site(self, name: str, site: SiteConfig, bootstrap: bool = False) -> None:
        """Deploy a single site configuration."""
        domain = site.get("domain", name)
        template_name = "site-bootstrap.conf.j2" if bootstrap else "site.conf.j2"
        template_path = CONFIGS_DIR / "nginx" / template_name

        if not template_path.exists():
            self.log(f"  Template {template_name} not found")
            return

        # Check if SSL certs exist (skip SSL template if not)
        cert_path = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
        cert_exists = False
        try:
            cert_exists = cert_path.exists()
        except PermissionError:
            result = subprocess.run(
                ["sudo", "test", "-f", str(cert_path)],
                capture_output=True,
            )
            cert_exists = result.returncode == 0

        if not bootstrap and not cert_exists:
            self.log(f"  SSL cert not found for {domain}, using bootstrap mode")
            template_path = CONFIGS_DIR / "nginx" / "site-bootstrap.conf.j2"

        # Render template
        template_vars = {
            "domain": domain,
            "upstream_port": site.get("upstream_port", 8080),
            "static_root": site.get("static_root", ""),
        }
        content = render_template(template_path, template_vars)

        # Write to sites-available
        site_file = NGINX_SITES_AVAILABLE / domain
        if ensure_file(site_file, content, owner="root", group="root", mode=0o644):
            self.record_change(f"Deployed site config: {domain}")

        # Symlink to sites-enabled
        enabled_link = NGINX_SITES_ENABLED / domain
        if ensure_symlink(enabled_link, site_file):
            self.record_change(f"Enabled site: {domain}")

    def _validate_nginx(self) -> bool:
        """Validate nginx configuration."""
        result = subprocess.run(
            ["sudo", "nginx", "-t"],
            capture_output=True,
        )
        if result.returncode != 0:
            self.log(result.stderr.decode() if result.stderr else "Unknown error")
        return result.returncode == 0

    def run_certbot(self, domains: list[str] | None = None) -> None:
        """Run certbot to obtain SSL certificates."""
        self.log("=== Running Certbot ===")

        if not self.dry_run:
            ensure_packages(["certbot", "python3-certbot-nginx"], self.pm)

        # Get domains from sites.toml if not specified
        if not domains:
            sites = load_sites_config()
            domains = [site.get("domain", name) for name, site in sites.items()]

        if not domains:
            self.log("No domains to configure")
            return

        for domain in domains:
            cert_path = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
            # Check cert existence (may need sudo to access /etc/letsencrypt)
            cert_exists = False
            try:
                cert_exists = cert_path.exists()
            except PermissionError:
                # Try with sudo
                result = subprocess.run(
                    ["sudo", "test", "-f", str(cert_path)],
                    capture_output=True,
                )
                cert_exists = result.returncode == 0

            if cert_exists:
                self.log(f"  {domain}: cert already exists, skipping")
                continue

            self.log(f"  {domain}: obtaining certificate...")
            if not self.dry_run:
                result = subprocess.run(
                    [
                        "sudo", "certbot", "certonly",
                        "--nginx",
                        "-d", domain,
                        "--non-interactive",
                        "--agree-tos",
                        "--register-unsafely-without-email",
                    ],
                    capture_output=True,
                )
                if result.returncode == 0:
                    self.record_change(f"Obtained SSL cert for {domain}")
                else:
                    self.log(f"  ERROR: certbot failed for {domain}")
                    self.log(result.stderr.decode() if result.stderr else "Unknown error")

    def nginx_bootstrap(self) -> None:
        """Bootstrap nginx: deploy HTTP-only configs, run certbot, then deploy SSL configs."""
        self.log("=== Nginx Bootstrap ===")
        self.log("Phase 1: Deploy HTTP-only site configs")
        self.setup_nginx(bootstrap=True)

        self.log("")
        self.log("Phase 2: Obtain SSL certificates")
        self.run_certbot()

        self.log("")
        self.log("Phase 3: Deploy full SSL site configs")
        self.setup_nginx(bootstrap=False)

    # -------------------------------------------------------------------------
    # Services
    # -------------------------------------------------------------------------

    def setup_services(self) -> None:
        """Enable and configure system services."""
        self.log("=== Configuring Services ===")

        # List of services to enable
        services_to_enable = [
            "chrony",      # Time synchronization
            "fail2ban",    # Intrusion prevention
            "nginx",       # Web server
            "rsyslog",     # Logging
            "auditd",      # Security auditing
            "unattended-upgrades",  # Auto security updates
        ]

        for service in services_to_enable:
            self.log(f"Ensuring {service} is enabled")
            if not self.dry_run:
                if enable_service(service, start=True):
                    self.record_change(f"Enabled {service}")

    # -------------------------------------------------------------------------
    # Security
    # -------------------------------------------------------------------------

    def apply_security(self) -> None:
        """Apply all security hardening."""
        self.log("=== Applying Security Hardening ===")

        self.harden_ssh()
        self.setup_fail2ban()

        # Unattended upgrades
        if not self.dry_run:
            self.log("Configuring unattended upgrades")
            if setup_unattended_upgrades(auto_reboot=False):
                self.record_change("Configured unattended upgrades")

    # -------------------------------------------------------------------------
    # Full Apply
    # -------------------------------------------------------------------------

    def apply_all(self, groups: list[str] | None = None) -> None:
        """Apply full configuration."""
        self.log("=" * 60)
        self.log("sysconf - Full Configuration Apply")
        self.log("=" * 60)
        self.log(f"Package Manager: {self.pm.name}")
        self.log(f"Dry Run: {self.dry_run}")
        self.log("")

        self.install_packages(groups)
        self.deploy_dotfiles()
        self.apply_security()
        self.setup_nginx()
        self.setup_services()

        self.log("")
        self.log("=" * 60)
        if self.dry_run:
            self.log("Dry-run complete - no changes were made")
        elif self.changes:
            self.log(f"Changes made: {len(self.changes)}")
            for change in self.changes:
                self.log(f"  - {change}")
        else:
            self.log("No changes needed - system is up to date")
        self.log("=" * 60)


def main():
    # Common flags shared by all subcommands
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument(
        "-n", "--dry-run",
        action="store_true",
        help="Show what would be done without making changes",
    )
    common_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    parser = argparse.ArgumentParser(
        description="sysconf - DIY configuration management for Linux systems",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
        parents=[common_parser],
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # apply command
    apply_parser = subparsers.add_parser(
        "apply", help="Apply full configuration", parents=[common_parser]
    )
    apply_parser.add_argument(
        "--groups",
        type=str,
        help="Comma-separated list of package groups to install",
    )

    # packages command
    pkg_parser = subparsers.add_parser(
        "packages", help="Install packages only", parents=[common_parser]
    )
    pkg_parser.add_argument(
        "--groups",
        type=str,
        help="Comma-separated list of package groups",
    )
    pkg_parser.add_argument(
        "--update",
        action="store_true",
        help="Update system packages before installing",
    )

    # dotfiles command
    subparsers.add_parser("dotfiles", help="Deploy dotfiles only", parents=[common_parser])

    # services command
    subparsers.add_parser("services", help="Configure services only", parents=[common_parser])

    # security command
    subparsers.add_parser("security", help="Apply security hardening only", parents=[common_parser])

    # nginx command
    nginx_parser = subparsers.add_parser(
        "nginx", help="Configure nginx sites", parents=[common_parser]
    )
    nginx_parser.add_argument(
        "--bootstrap",
        action="store_true",
        help="Bootstrap mode: deploy HTTP-only, run certbot, then deploy SSL",
    )
    nginx_parser.add_argument(
        "--certbot-only",
        action="store_true",
        help="Only run certbot for defined sites",
    )

    # info command
    subparsers.add_parser("info", help="Show system information", parents=[common_parser])

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    conf = SysConf(dry_run=args.dry_run, verbose=args.verbose)

    try:
        if args.command == "apply":
            groups = args.groups.split(",") if args.groups else None
            conf.apply_all(groups)

        elif args.command == "packages":
            if args.update and not args.dry_run:
                update_system(conf.pm)
            groups = args.groups.split(",") if args.groups else None
            conf.install_packages(groups)

        elif args.command == "dotfiles":
            conf.deploy_dotfiles()

        elif args.command == "services":
            conf.setup_services()

        elif args.command == "security":
            conf.apply_security()

        elif args.command == "nginx":
            if args.certbot_only:
                conf.run_certbot()
            elif args.bootstrap:
                conf.nginx_bootstrap()
            else:
                conf.setup_nginx()

        elif args.command == "info":
            print(f"Package Manager: {conf.pm.name}")
            print(f"Project Root: {PROJECT_ROOT}")
            print(f"Configs Dir: {CONFIGS_DIR}")
            print(f"Python: {sys.version}")

    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
