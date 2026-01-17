"""Webpage deployment orchestration for sysconf."""

import re
import subprocess
import tomllib
from pathlib import Path
from typing import Dict, List, Optional

from .files import ensure_dir, ensure_file, ensure_symlink, render_template, set_permissions_recursive
from .git import clone_or_pull
from .prompts import warn_missing
from .secrets import SecretsManager
from .services import daemon_reload, enable_service, ensure_service_file, reload_service
from .toolchains import ToolchainManager

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
CONFIGS_DIR = PROJECT_ROOT / "configs"
WEBPAGES_CONFIG = CONFIGS_DIR / "webpages.toml"

# System paths
NGINX_SITES_AVAILABLE = Path("/etc/nginx/sites-available")
NGINX_SITES_ENABLED = Path("/etc/nginx/sites-enabled")
SYSTEMD_DIR = Path("/etc/systemd/system")


def load_webpages_config() -> dict:
    """
    Load webpage definitions from webpages.toml.

    Returns:
        Dictionary with 'defaults' and 'webpages' keys
    """
    if not WEBPAGES_CONFIG.exists():
        return {"defaults": {}, "webpages": {}}

    with open(WEBPAGES_CONFIG, "rb") as f:
        return tomllib.load(f)


def expand_template_vars(value: str, context: Dict[str, str]) -> str:
    """
    Expand {path}, {domain} style variables in config values.

    Args:
        value: String that may contain {var} placeholders
        context: Dictionary of variable names to values

    Returns:
        String with placeholders expanded
    """
    for key, val in context.items():
        value = value.replace(f"{{{key}}}", str(val))
    return value


class WebpageDeployer:
    """Orchestrator for webpage deployments."""

    def __init__(self, dry_run: bool = False, verbose: bool = False):
        self.dry_run = dry_run
        self.verbose = verbose
        self.changes = []
        self.secrets_manager = SecretsManager(dry_run=dry_run, verbose=verbose)
        self.toolchain_manager = ToolchainManager(dry_run=dry_run, verbose=verbose)

    def log(self, msg: str) -> None:
        """Log a message."""
        prefix = "[DRY-RUN] " if self.dry_run else ""
        print(f"{prefix}{msg}")

    def record_change(self, description: str) -> None:
        """Record a change that was made."""
        self.changes.append(description)

    def _validate_nginx(self) -> bool:
        """Validate nginx configuration."""
        result = subprocess.run(
            ["sudo", "nginx", "-t"],
            capture_output=True,
        )
        if result.returncode != 0:
            self.log(f"  nginx validation failed: {result.stderr.decode()}")
        return result.returncode == 0

    def _check_ssl_cert(self, domain: str, ssl_cert_domain: Optional[str] = None) -> bool:
        """Check if SSL certificate exists for a domain."""
        cert_domain = ssl_cert_domain or domain
        cert_path = Path(f"/etc/letsencrypt/live/{cert_domain}/fullchain.pem")

        try:
            return cert_path.exists()
        except PermissionError:
            # Try with sudo
            result = subprocess.run(
                ["sudo", "test", "-f", str(cert_path)],
                capture_output=True,
            )
            return result.returncode == 0

    def _deploy_nginx_config(
        self,
        name: str,
        config: dict,
        webpage_path: Path,
        bootstrap: bool = False,
    ) -> bool:
        """
        Deploy nginx configuration for a webpage.

        Args:
            name: Webpage identifier
            config: Webpage configuration dict
            webpage_path: Path to the deployed webpage
            bootstrap: If True, deploy HTTP-only config

        Returns:
            True if config was deployed
        """
        domain = config.get("domain", name)
        aliases = config.get("aliases", [])
        server_names = " ".join([domain] + aliases)

        # Determine SSL availability
        ssl_cert_domain = config.get("ssl_cert_domain")
        ssl_available = not bootstrap and self._check_ssl_cert(domain, ssl_cert_domain)

        if not bootstrap and not ssl_available:
            self.log(f"  SSL cert not found for {domain}, using HTTP-only config")

        # Build upstream name (sanitized for nginx)
        upstream_name = re.sub(r"[^a-zA-Z0-9]", "_", name)

        # Check if SSL is handled by upstream proxy (e.g., Cloudflare Tunnel)
        proxy_ssl = config.get("proxy_ssl", False)

        # Prepare template context
        context = {
            "domain": domain,
            "server_names": server_names,
            "ssl_available": ssl_available,
            "ssl_cert_domain": ssl_cert_domain or domain,
            "proxy_ssl": proxy_ssl,
            "upstream_name": upstream_name,
            "upstream": config.get("upstream"),
            "locations": [],
            "static": config.get("static", False),
            "static_cache": config.get("static_cache", []),
            "webpage_path": str(webpage_path),
        }

        # Process locations with variable expansion
        path_context = {"path": str(webpage_path), "domain": domain}
        for loc in config.get("locations", []):
            processed_loc = {}
            for key, value in loc.items():
                if isinstance(value, str):
                    processed_loc[key] = expand_template_vars(value, path_context)
                else:
                    processed_loc[key] = value
            context["locations"].append(processed_loc)

        # Render template
        template_path = CONFIGS_DIR / "nginx" / "site.conf.j2"
        if not template_path.exists():
            self.log(f"  Template not found: {template_path}")
            return False

        content = render_template(template_path, context)

        if self.dry_run:
            self.log(f"  Would deploy nginx config for {domain}")
            if self.verbose:
                print("--- nginx config preview ---")
                print(content)
                print("--- end preview ---")
            return True

        # Write to sites-available
        site_file = NGINX_SITES_AVAILABLE / domain
        if ensure_file(site_file, content, owner="root", group="root", mode=0o644):
            self.record_change(f"Deployed nginx config: {domain}")

        # Symlink to sites-enabled
        enabled_link = NGINX_SITES_ENABLED / domain
        if ensure_symlink(enabled_link, site_file):
            self.record_change(f"Enabled site: {domain}")

        return True

    def _deploy_systemd_services(
        self,
        name: str,
        config: dict,
        webpage_path: Path,
    ) -> bool:
        """
        Deploy systemd service files for a webpage.

        Args:
            name: Webpage identifier
            config: Webpage configuration dict
            webpage_path: Path to the deployed webpage

        Returns:
            True if services were deployed
        """
        services = config.get("services", [])
        if not services:
            return True

        template_path = CONFIGS_DIR / "systemd" / "app.service.j2"
        if not template_path.exists():
            self.log(f"  Service template not found: {template_path}")
            return False

        path_context = {"path": str(webpage_path), "domain": config.get("domain", name)}

        for svc in services:
            svc_name = svc.get("name", name)
            self.log(f"  Deploying service: {svc_name}")

            # Expand variables in exec_start
            exec_start = expand_template_vars(svc.get("exec_start", ""), path_context)

            # Process environment variables
            env = {}
            for key, value in svc.get("environment", {}).items():
                env[key] = expand_template_vars(str(value), path_context)

            # Build template context
            context = {
                "name": svc_name,
                "description": svc.get("description", f"{svc_name} service"),
                "user": svc.get("user", "www-data"),
                "group": svc.get("group", "www-data"),
                "working_dir": str(webpage_path),
                "exec_start": exec_start,
                "environment": env,
                "requires": svc.get("requires", ""),
                "write_paths": svc.get("write_paths", []),
            }

            content = render_template(template_path, context)

            if self.dry_run:
                self.log(f"    Would deploy service file: {svc_name}.service")
                continue

            if ensure_service_file(svc_name, content, enable=True, restart=False):
                self.record_change(f"Deployed service: {svc_name}")

        return True

    def _run_build(self, webpage_path: Path, build_cmd: str) -> bool:
        """
        Run a build command in the webpage directory.

        Automatically detects and installs required toolchains first.

        Args:
            webpage_path: Path to the webpage
            build_cmd: Build command to run

        Returns:
            True if build succeeded
        """
        if not build_cmd:
            return True

        # Ensure required toolchains are installed
        required = self.toolchain_manager.detect_required(webpage_path)
        if required:
            self.log(f"  Required toolchains: {', '.join(required)}")
            if not self.toolchain_manager.ensure_for_project(webpage_path):
                self.log("  Failed to install required toolchains")
                return False

        self.log(f"  Running build: {build_cmd}")

        if self.dry_run:
            return True

        # Build environment with toolchain paths
        import os
        env = os.environ.copy()
        toolchain_paths = self.toolchain_manager.get_paths()
        if toolchain_paths:
            env["PATH"] = ":".join(toolchain_paths) + ":" + env.get("PATH", "")

        result = subprocess.run(
            build_cmd,
            shell=True,
            cwd=webpage_path,
            capture_output=True,
            text=True,
            env=env,
        )

        if result.returncode != 0:
            self.log(f"  Build failed: {result.stderr}")
            return False

        self.record_change(f"Built {webpage_path.name}")
        return True

    def deploy_webpage(
        self,
        name: str,
        config: dict,
        base_path: Path,
        bootstrap: bool = False,
    ) -> bool:
        """
        Deploy a single webpage.

        Args:
            name: Webpage identifier
            config: Webpage configuration dict
            base_path: Base path for deployments
            bootstrap: If True, deploy HTTP-only configs

        Returns:
            True if deployment succeeded
        """
        domain = config.get("domain", name)
        self.log(f"\nDeploying {domain}...")

        # Determine webpage path
        webpage_path = base_path / domain

        # Clone or update repository
        repo = config.get("repo")
        if repo:
            ssh_key = self.secrets_manager.get_ssh_key_path()
            branch = config.get("branch")  # None = auto-detect from remote

            success, msg = clone_or_pull(
                repo,
                webpage_path,
                branch=branch,
                ssh_key_path=ssh_key,
                dry_run=self.dry_run,
            )

            if not success:
                self.log(f"  Repository operation failed: {msg}")
                return False
            self.log(f"  {msg}")

            # Set proper ownership and permissions on cloned/pulled repo
            if not self.dry_run:
                set_permissions_recursive(webpage_path, owner="dev", group="www-data", mode=0o755)

        # Ensure directory exists (for non-repo cases)
        if not self.dry_run:
            ensure_dir(webpage_path, owner="dev", group="www-data", mode=0o755)

        # Run build if specified
        build_cmd = config.get("build")
        if build_cmd and not self._run_build(webpage_path, build_cmd):
            self.log("  Build failed, continuing with deployment...")

        # Deploy nginx config
        self._deploy_nginx_config(name, config, webpage_path, bootstrap)

        # Deploy systemd services
        self._deploy_systemd_services(name, config, webpage_path)

        return True

    def _deploy_all(self, bootstrap: bool = False) -> None:
        """
        Deploy all webpages from config.

        Args:
            bootstrap: If True, deploy HTTP-only configs
        """
        config = load_webpages_config()
        defaults = config.get("defaults", {})
        webpages = config.get("webpages", {})

        if not webpages:
            self.log("No webpages defined in webpages.toml")
            return

        base_path = Path(defaults.get("base_path", "/var/www"))

        # Deploy each webpage (merge defaults into config)
        for name, wp_config in webpages.items():
            merged_config = {**defaults, **wp_config}
            self.deploy_webpage(name, merged_config, base_path, bootstrap)

        # Validate and reload nginx
        if not self.dry_run:
            self.log("\nValidating nginx configuration...")
            if self._validate_nginx():
                try:
                    reload_service("nginx")
                    self.record_change("Reloaded nginx")
                except subprocess.CalledProcessError:
                    self.log("ERROR: nginx reload failed")
            else:
                self.log("WARNING: nginx config invalid, skipping reload")

    def _health_check(self) -> None:
        """
        Perform health checks on deployed services.

        Checks:
        - Systemd service status (active/failed)
        - Port availability for upstreams
        """
        config = load_webpages_config()
        webpages = config.get("webpages", {})

        if not webpages:
            return

        self.log("\n--- Health Check ---")
        all_healthy = True

        for name, wp_config in webpages.items():
            domain = wp_config.get("domain", name)
            services = wp_config.get("services", [])
            upstream = wp_config.get("upstream", {})

            # Check systemd services
            for svc in services:
                svc_name = svc.get("name", name)
                result = subprocess.run(
                    ["systemctl", "is-active", svc_name],
                    capture_output=True,
                    text=True,
                )
                status = result.stdout.strip()

                if status == "active":
                    self.log(f"  [OK] {svc_name} is running")
                else:
                    self.log(f"  [FAIL] {svc_name} is {status}")
                    all_healthy = False

                    # Get failure reason
                    if status == "failed":
                        reason = subprocess.run(
                            ["systemctl", "status", svc_name, "--no-pager", "-n", "5"],
                            capture_output=True,
                            text=True,
                        )
                        for line in reason.stdout.splitlines()[-3:]:
                            self.log(f"        {line.strip()}")

            # Check upstream port if defined
            if upstream and upstream.get("port"):
                port = upstream["port"]
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                try:
                    result = sock.connect_ex(("127.0.0.1", port))
                    if result == 0:
                        self.log(f"  [OK] {domain} port {port} is listening")
                    else:
                        self.log(f"  [FAIL] {domain} port {port} not responding")
                        all_healthy = False
                except socket.error:
                    self.log(f"  [FAIL] {domain} port {port} connection error")
                    all_healthy = False
                finally:
                    sock.close()

        if all_healthy:
            self.log("\nAll services healthy")
        else:
            self.log("\nSome services need attention")

    def _needs_bootstrap(self) -> bool:
        """Check if any configured domain is missing SSL certs."""
        config = load_webpages_config()
        webpages = config.get("webpages", {})

        for name, wp_config in webpages.items():
            domain = wp_config.get("domain", name)
            ssl_cert_domain = wp_config.get("ssl_cert_domain")
            if not self._check_ssl_cert(domain, ssl_cert_domain):
                return True
        return False

    def run(self) -> None:
        """
        Run the full webpage deployment workflow.

        Automatically detects if bootstrap is needed (missing SSL certs)
        and runs the 3-phase workflow if so.
        """
        self.log("=== Webpage Deployment ===")

        # Load secrets for SSH key and other config
        self.secrets_manager.load_or_create_secrets()
        self.secrets_manager.report_missing_prerequisites()

        config = load_webpages_config()
        defaults = config.get("defaults", {})
        webpages = config.get("webpages", {})

        if not webpages:
            self.log("No webpages defined in webpages.toml")
            return

        base_path = Path(defaults.get("base_path", "/var/www"))
        self.log(f"Base path: {base_path}")
        self.log(f"Webpages to deploy: {len(webpages)}")

        # Check if we need to bootstrap (any domain missing certs)
        needs_bootstrap = self._needs_bootstrap()

        if needs_bootstrap:
            self.log("SSL certs missing for one or more domains, running bootstrap...")

            self.log("\n--- Phase 1: Deploy HTTP-only configs ---")
            self._deploy_all(bootstrap=True)

            self.log("\n--- Phase 2: Obtain SSL certificates ---")
            self.run_certbot()

            self.log("\n--- Phase 3: Deploy SSL configs ---")
            self._deploy_all(bootstrap=False)
        else:
            self._deploy_all(bootstrap=False)

        # Health check (skip in dry-run)
        if not self.dry_run:
            self._health_check()

        # Summary
        self.log("\n" + "=" * 60)
        if self.dry_run:
            self.log("Dry-run complete - no changes were made")
        elif self.changes:
            self.log(f"Changes made: {len(self.changes)}")
            for change in self.changes:
                self.log(f"  - {change}")
        else:
            self.log("No changes needed - webpages are up to date")

    def run_certbot(self, domains: Optional[List[str]] = None) -> None:
        """
        Run certbot to obtain SSL certificates.

        Args:
            domains: Optional list of domains (uses config if not specified)
        """
        self.log("=== Running Certbot ===")

        # Get certbot email
        self.secrets_manager.load_or_create_secrets()
        email = self.secrets_manager.get_certbot_email()

        if not email:
            warn_missing(
                "Certbot email",
                "Certificates will be registered without email notification"
            )

        # Get domains from config if not specified
        if not domains:
            config = load_webpages_config()
            webpages = config.get("webpages", {})
            domains = []
            for name, wp_config in webpages.items():
                domain = wp_config.get("domain", name)
                # Skip if using another domain's cert (wildcard)
                if "ssl_cert_domain" not in wp_config:
                    domains.append(domain)
                    # Add aliases
                    domains.extend(wp_config.get("aliases", []))

        if not domains:
            self.log("No domains to configure")
            return

        # Deduplicate while preserving order
        seen = set()
        unique_domains = []
        for d in domains:
            if d not in seen:
                seen.add(d)
                unique_domains.append(d)
        domains = unique_domains

        self.log(f"Domains to certify: {', '.join(domains)}")

        for domain in domains:
            # Check if cert already exists
            if self._check_ssl_cert(domain):
                self.log(f"  {domain}: cert already exists, skipping")
                continue

            self.log(f"  {domain}: obtaining certificate...")

            if self.dry_run:
                continue

            # Build certbot command
            cmd = [
                "sudo", "certbot", "certonly",
                "--nginx",
                "-d", domain,
                "--non-interactive",
                "--agree-tos",
            ]

            if email:
                cmd.extend(["--email", email])
            else:
                cmd.append("--register-unsafely-without-email")

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                self.record_change(f"Obtained SSL cert for {domain}")
            else:
                self.log(f"  ERROR: certbot failed for {domain}")
                self.log(f"  {result.stderr}")
