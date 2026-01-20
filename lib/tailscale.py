"""
Tailscale VPN configuration module.

Provides idempotent Tailscale setup and management.
"""

import json
import subprocess
from pathlib import Path
from typing import Optional


def get_tailscale_status() -> Optional[dict]:
    """
    Get current Tailscale status.

    Returns:
        Dict with status info if connected, None if not running/authenticated
    """
    try:
        result = subprocess.run(
            ["tailscale", "status", "--json"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return None


def is_tailscale_authenticated() -> bool:
    """Check if Tailscale is authenticated to a tailnet."""
    status = get_tailscale_status()
    if not status:
        return False
    # BackendState "Running" means authenticated and connected
    return status.get("BackendState") == "Running"


def get_current_tailscale_config() -> dict:
    """Get current Tailscale preferences/settings."""
    status = get_tailscale_status()
    if not status:
        return {}

    # Extract relevant settings from Self node
    self_node = status.get("Self", {})
    return {
        "hostname": self_node.get("HostName", ""),
        "ssh": status.get("CurrentTailnet", {}).get("MagicDNSSuffix", "") != ""
               and self_node.get("CapMap", {}).get("ssh", False),
        "accept_dns": True,  # Hard to detect, assume true if MagicDNS works
        "accept_routes": False,  # Would need to check prefs
    }


def setup_tailscale(
    auth_key: str,
    hostname: str = "",
    ssh: bool = True,
    accept_dns: bool = True,
    accept_routes: bool = False,
    exit_node: bool = False,
    advertise_routes: Optional[list[str]] = None,
) -> bool:
    """
    Configure and authenticate Tailscale.

    This is idempotent - safe to run multiple times.

    Args:
        auth_key: Tailscale auth key (reusable recommended)
        hostname: Device hostname in Tailscale
        ssh: Enable Tailscale SSH
        accept_dns: Use Tailscale DNS (MagicDNS)
        accept_routes: Accept routes from other nodes
        exit_node: Advertise as exit node
        advertise_routes: List of CIDR ranges to advertise

    Returns:
        True if configuration changed, False if already configured
    """
    # Build tailscale up command
    cmd = ["sudo", "tailscale", "up"]

    # Auth key (only needed if not already authenticated)
    if not is_tailscale_authenticated():
        cmd.extend(["--authkey", auth_key])

    # Hostname
    if hostname:
        cmd.extend(["--hostname", hostname])

    # SSH
    if ssh:
        cmd.append("--ssh")

    # DNS
    if accept_dns:
        cmd.append("--accept-dns")
    else:
        cmd.append("--accept-dns=false")

    # Routes
    if accept_routes:
        cmd.append("--accept-routes")

    # Exit node
    if exit_node:
        cmd.append("--advertise-exit-node")

    # Advertise routes
    if advertise_routes:
        cmd.extend(["--advertise-routes", ",".join(advertise_routes)])

    # Reset to avoid conflicts with previous settings
    cmd.append("--reset")

    # Run tailscale up
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"Tailscale setup failed: {result.stderr}")
        return False

    return True


def tailscale_logout() -> bool:
    """Disconnect from Tailscale tailnet."""
    result = subprocess.run(
        ["sudo", "tailscale", "logout"],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def tailscale_down() -> bool:
    """Bring Tailscale connection down (but stay authenticated)."""
    result = subprocess.run(
        ["sudo", "tailscale", "down"],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0
