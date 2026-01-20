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
    ./sysconf.py tailscale          # Configure Tailscale VPN
    ./sysconf.py webpages           # Deploy web applications
    ./sysconf.py secrets            # Manage secrets and .env files
"""

import argparse
import os
import subprocess
import sys
import tomllib
from pathlib import Path

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
    enable_service,
    reload_service,
    restart_service,
)
from lib.files import (
    ensure_file,
    read_file,
)
from lib.security import (
    harden_ssh,
    setup_fail2ban,
    setup_unattended_upgrades,
)
from lib.tailscale import (
    is_tailscale_authenticated,
    setup_tailscale,
    tailscale_logout,
)

# Import centralized paths
from lib.paths import PROJECT_ROOT, CONFIGS_DIR, SECRETS_DIR


def require_sudo(command: str) -> None:
    """
    Check for sudo privileges, fail fast with clear message if missing.

    Args:
        command: Name of command being run (for error message)
    """
    if os.geteuid() == 0:
        return  # Already root

    # Check if we can sudo without password (cached credentials)
    result = subprocess.run(
        ["sudo", "-n", "true"],
        capture_output=True,
    )
    if result.returncode == 0:
        return  # sudo available

    print(f"ERROR: '{command}' requires superuser privileges", file=sys.stderr)
    print(f"", file=sys.stderr)
    print(f"Run with sudo:", file=sys.stderr)
    print(f"  sudo ./sysconf.py {command}", file=sys.stderr)
    sys.exit(1)


def load_tailscale_config() -> dict:
    """Load Tailscale configuration from tailscale.toml."""
    config_file = CONFIGS_DIR / "tailscale.toml"
    if not config_file.exists():
        return {}

    with open(config_file, "rb") as f:
        data = tomllib.load(f)

    return data.get("tailscale", {})


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
        try:
            if 'root' == os.environ['SUDO_USER']:
                home = Path.home()
            else:
                home = Path(f"/home/{os.environ.get('SUDO_USER')}/")
        except (KeyError, RuntimeError) as e:
                print(f"Issue(s) with path construction: {e}")
                home = Path(os.path.expanduser('~'))
            

        dotfiles_dir = CONFIGS_DIR / u"dotfiles"
        if not dotfiles_dir.exists():
            self.log("No dotfiles directory found, skipping")
            return

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
    # Tailscale
    # -------------------------------------------------------------------------

    def setup_tailscale_vpn(self, logout: bool = False) -> None:
        """Configure Tailscale VPN for remote access."""
        self.log("=== Configuring Tailscale ===")

        if logout:
            self.log("Logging out of Tailscale...")
            if not self.dry_run:
                if tailscale_logout():
                    self.record_change("Logged out of Tailscale")
                else:
                    self.log("WARNING: Tailscale logout failed")
            return

        config = load_tailscale_config()
        if not config.get("enabled", True):
            self.log("Tailscale disabled in config, skipping")
            return

        # Install tailscale
        if not self.dry_run:
            ensure_packages(["tailscale"], self.pm)
            enable_service("tailscaled")

        # Check authentication status
        if is_tailscale_authenticated():
            self.log("Tailscale already authenticated")
        else:
            self.log("Tailscale not authenticated, will authenticate...")

        # Get auth key
        try:
            auth_key = get_secret("tailscale-authkey")
        except ValueError:
            if self.dry_run:
                auth_key = "dry-run-placeholder"
                self.log("Would authenticate with auth key from secrets/tailscale-authkey")
            else:
                self.log("ERROR: No Tailscale auth key found")
                self.log("  Set TAILSCALE_AUTHKEY env var or create secrets/tailscale-authkey")
                return

        # Log configuration
        hostname = config.get("hostname", "")
        ssh = config.get("ssh", True)
        accept_dns = config.get("accept_dns", True)
        accept_routes = config.get("accept_routes", False)

        self.log(f"  Hostname: {hostname or '(default)'}")
        self.log(f"  Tailscale SSH: {ssh}")
        self.log(f"  Accept DNS: {accept_dns}")
        self.log(f"  Accept routes: {accept_routes}")

        if not self.dry_run:
            if setup_tailscale(
                auth_key=auth_key,
                hostname=hostname,
                ssh=ssh,
                accept_dns=accept_dns,
                accept_routes=accept_routes,
                exit_node=config.get("exit_node", False),
                advertise_routes=config.get("advertise_routes"),
            ):
                self.record_change("Configured Tailscale")
            else:
                self.log("WARNING: Tailscale setup may have failed")

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

    # tailscale command
    tailscale_parser = subparsers.add_parser(
        "tailscale", help="Configure Tailscale VPN", parents=[common_parser]
    )
    tailscale_parser.add_argument(
        "--logout",
        action="store_true",
        help="Logout from Tailscale tailnet",
    )

    # info command
    subparsers.add_parser("info", help="Show system information", parents=[common_parser])

    # webpages command
    webpages_parser = subparsers.add_parser(
        "webpages", help="Deploy web applications", parents=[common_parser]
    )
    webpages_parser.add_argument(
        "--certbot-only",
        action="store_true",
        help="Only run certbot for configured domains",
    )

    # secrets command
    secrets_parser = subparsers.add_parser(
        "secrets", help="Manage secrets and .env files", parents=[common_parser]
    )
    secrets_parser.add_argument(
        "--scan-only",
        action="store_true",
        help="Only scan for .env.example files, don't prompt",
    )

    # toolchains command
    toolchains_parser = subparsers.add_parser(
        "toolchains", help="Install development toolchains (Go, Rust, Node, etc.)", parents=[common_parser]
    )
    toolchains_parser.add_argument(
        "names",
        nargs="*",
        help="Specific toolchains to install (default: all configured)",
    )

    # clean command
    clean_parser = subparsers.add_parser(
        "clean", help="Remove deployed configurations", parents=[common_parser]
    )
    clean_parser.add_argument(
        "targets",
        nargs="*",
        help="Webpages to clean (e.g., countertrak learn). Omit for all.",
    )

    # cron command
    cron_parser = subparsers.add_parser(
        "cron", help="Manage auto-push cron job", parents=[common_parser]
    )
    cron_parser.add_argument(
        "--enable",
        action="store_true",
        help="Enable auto-push cron job (runs every 30 minutes)",
    )
    cron_parser.add_argument(
        "--disable",
        action="store_true",
        help="Disable auto-push cron job",
    )
    cron_parser.add_argument(
        "--status",
        action="store_true",
        help="Show current cron job status",
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    conf = SysConf(dry_run=args.dry_run, verbose=args.verbose)

    try:
        if args.command == "apply":
            if not args.dry_run:
                require_sudo("apply")
            groups = args.groups.split(",") if args.groups else None
            conf.apply_all(groups)

        elif args.command == "packages":
            if not args.dry_run:
                require_sudo("packages")
            if args.update and not args.dry_run:
                update_system(conf.pm)
            groups = args.groups.split(",") if args.groups else None
            conf.install_packages(groups)

        elif args.command == "dotfiles":
            conf.deploy_dotfiles()

        elif args.command == "services":
            if not args.dry_run:
                require_sudo("services")
            conf.setup_services()

        elif args.command == "security":
            if not args.dry_run:
                require_sudo("security")
            conf.apply_security()

        elif args.command == "tailscale":
            if not args.dry_run:
                require_sudo("tailscale")
            conf.setup_tailscale_vpn(logout=args.logout)

        elif args.command == "info":
            print(f"Package Manager: {conf.pm.name}")
            print(f"Project Root: {PROJECT_ROOT}")
            print(f"Configs Dir: {CONFIGS_DIR}")
            print(f"Python: {sys.version}")

        elif args.command == "webpages":
            if not args.dry_run:
                require_sudo("webpages")
            from lib.webpages import WebpageDeployer
            deployer = WebpageDeployer(dry_run=args.dry_run, verbose=args.verbose)
            if args.certbot_only:
                deployer.run_certbot()
            else:
                deployer.run()

        elif args.command == "secrets":
            from lib.secrets import SecretsManager
            manager = SecretsManager(dry_run=args.dry_run, verbose=args.verbose)
            manager.run(scan_only=args.scan_only)

        elif args.command == "toolchains":
            from lib.toolchains import ToolchainManager
            manager = ToolchainManager(dry_run=args.dry_run, verbose=args.verbose)
            manager.run(toolchains=args.names if args.names else None)

        elif args.command == "clean":
            if not args.dry_run:
                require_sudo("clean")
            from lib.clean import Cleaner
            cleaner = Cleaner(dry_run=args.dry_run, verbose=args.verbose)
            cleaner.run(targets=args.targets if args.targets else None)

        elif args.command == "cron":
            from lib.cron import CronManager
            manager = CronManager(dry_run=args.dry_run, verbose=args.verbose)
            manager.run(
                enable=args.enable,
                disable=args.disable,
                show_status=args.status or (not args.enable and not args.disable),
            )

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
