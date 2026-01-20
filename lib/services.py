"""Systemd service management with idempotent operations."""

import subprocess
from pathlib import Path
from typing import Optional

from .files import read_file


def _systemctl(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run a systemctl command."""
    cmd = ["sudo", "systemctl"] + list(args)
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def is_enabled(service: str) -> bool:
    """Check if a service is enabled."""
    result = _systemctl("is-enabled", service, check=False)
    return result.returncode == 0


def is_active(service: str) -> bool:
    """Check if a service is currently running."""
    result = _systemctl("is-active", service, check=False)
    return result.returncode == 0


def enable_service(service: str, start: bool = True) -> bool:
    """
    Idempotently enable a systemd service.

    Args:
        service: Service name (e.g., "nginx" or "nginx.service")
        start: Also start the service if not running

    Returns:
        True if any action was taken, False if already in desired state
    """
    changed = False

    if not is_enabled(service):
        print(f"Enabling {service}")
        _systemctl("enable", service)
        changed = True

    if start and not is_active(service):
        print(f"Starting {service}")
        _systemctl("start", service)
        changed = True

    if not changed:
        print(f"Service {service} already enabled and running")

    return changed


def disable_service(service: str, stop: bool = True) -> bool:
    """
    Idempotently disable a systemd service.

    Returns:
        True if any action was taken, False if already in desired state
    """
    changed = False

    if stop and is_active(service):
        print(f"Stopping {service}")
        _systemctl("stop", service)
        changed = True

    if is_enabled(service):
        print(f"Disabling {service}")
        _systemctl("disable", service)
        changed = True

    if not changed:
        print(f"Service {service} already disabled and stopped")

    return changed


def restart_service(service: str) -> None:
    """Restart a service."""
    print(f"Restarting {service}")
    _systemctl("restart", service)


def reload_service(service: str) -> None:
    """Reload a service configuration without full restart."""
    print(f"Reloading {service}")
    _systemctl("reload", service)


def daemon_reload() -> None:
    """Reload systemd daemon after unit file changes."""
    print("Reloading systemd daemon")
    _systemctl("daemon-reload")


def ensure_service_file(
    name: str,
    content: str,
    system: bool = True,
    enable: bool = True,
    restart: bool = True,
) -> bool:
    """
    Idempotently install a systemd service file.

    Args:
        name: Service name (without .service extension)
        content: Full content of the service file
        system: If True, install to /etc/systemd/system/, else ~/.config/systemd/user/
        enable: Enable the service after installing
        restart: Restart the service if the file changed

    Returns:
        True if any changes were made
    """
    if system:
        service_dir = Path("/etc/systemd/system")
    else:
        service_dir = Path.home() / ".config/systemd/user"
        service_dir.mkdir(parents=True, exist_ok=True)

    service_file = service_dir / f"{name}.service"

    # Check if file needs updating (using sudo-aware read)
    needs_update = True
    if service_file.exists():
        existing = read_file(service_file)
        if existing == content:
            needs_update = False

    changed = False

    if needs_update:
        print(f"Writing service file: {service_file}")
        if system:
            # Need sudo for system services
            subprocess.run(
                ["sudo", "tee", str(service_file)],
                input=content.encode(),
                stdout=subprocess.DEVNULL,
                check=True,
            )
        else:
            service_file.write_text(content)

        daemon_reload()
        changed = True

        if restart and is_active(f"{name}.service"):
            restart_service(f"{name}.service")

    if enable:
        if enable_service(f"{name}.service", start=True):
            changed = True

    return changed


def get_service_status(service: str) -> dict:
    """Get detailed status of a service."""
    result = _systemctl("show", service, "--no-page", check=False)

    status = {}
    for line in result.stdout.strip().split("\n"):
        if "=" in line:
            key, value = line.split("=", 1)
            status[key] = value

    return status


def list_enabled_services() -> list[str]:
    """List all enabled services."""
    result = _systemctl("list-unit-files", "--state=enabled", "--type=service", "--no-legend")
    services = []
    for line in result.stdout.strip().split("\n"):
        if line:
            services.append(line.split()[0])
    return services
