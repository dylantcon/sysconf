"""Security hardening routines."""

import os
import socket
import subprocess
import time
from pathlib import Path
from typing import Optional

from .files import ensure_file, ensure_dir, read_file
from .packages import ensure_packages
from .services import enable_service, reload_service, restart_service


def _get_ssh_service_name() -> str:
    """
    Get the correct SSH service name for this distro.

    Debian/Ubuntu use 'ssh', RHEL/Fedora/Arch use 'sshd'.
    """
    result = subprocess.run(
        ["systemctl", "list-unit-files", "ssh.service"],
        capture_output=True,
        text=True,
    )
    if "ssh.service" in result.stdout:
        return "ssh"
    return "sshd"


def _get_current_ssh_port() -> int:
    """Get the currently configured SSH port."""
    # Check sshd_config and drop-ins for Port directive
    config_paths = [Path("/etc/ssh/sshd_config")]
    drop_in_dir = Path("/etc/ssh/sshd_config.d")
    if drop_in_dir.exists():
        config_paths.extend(drop_in_dir.glob("*.conf"))

    for config_path in config_paths:
        if config_path.exists():
            content = read_file(config_path)
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("Port ") and not line.startswith("#"):
                    try:
                        return int(line.split()[1])
                    except (IndexError, ValueError):
                        pass
    return 22  # Default SSH port


def _test_ssh_connectivity(port: int, timeout: float = 5.0) -> bool:
    """
    Test if SSH is accepting connections on the given port.

    Uses a raw socket connection test (faster than full SSH handshake).
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()
        return result == 0
    except (socket.error, OSError):
        return False


def _test_ssh_auth(port: int, timeout: int = 10) -> bool:
    """
    Test if SSH authentication works (more thorough than port check).

    Attempts an actual SSH connection to localhost.
    """
    result = subprocess.run(
        [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=5",
            "-o", "StrictHostKeyChecking=no",
            "-o", f"Port={port}",
            "localhost",
            "exit", "0",
        ],
        capture_output=True,
        timeout=timeout,
    )
    # Exit code 0 = success, 255 = connection failed
    # Other codes (1, etc.) mean connected but auth failed - still means SSH is working
    return result.returncode != 255


def _rollback_ssh_config(config_path: Path, backup_content: Optional[str]) -> None:
    """Rollback SSH config to previous state."""
    print("ROLLING BACK SSH CONFIG...")

    if backup_content:
        # Restore from our saved content
        subprocess.run(
            ["sudo", "tee", str(config_path)],
            input=backup_content.encode(),
            stdout=subprocess.DEVNULL,
            check=True,
        )
        print(f"Restored previous config to {config_path}")
    else:
        # No previous config existed, just remove
        if config_path.exists():
            subprocess.run(["sudo", "rm", str(config_path)], check=True)
            print(f"Removed {config_path}")

    # Reload SSH to apply rollback
    ssh_service = _get_ssh_service_name()
    reload_service(ssh_service)
    print("SSH service reloaded with previous config")


def harden_ssh(
    port: int = 22,
    permit_root: str = "prohibit-password",
    password_auth: bool = False,
    pubkey_auth: bool = True,
    x11_forwarding: bool = False,
    max_auth_tries: int = 3,
    extra_config: Optional[str] = None,
    connectivity_check: bool = True,
) -> bool:
    """
    Configure SSH with security hardening.

    Creates a drop-in config at /etc/ssh/sshd_config.d/99-sysconf.conf
    to avoid modifying the main sshd_config.

    SAFETY: This function includes lockout prevention:
    - Validates config syntax before applying
    - Tests SSH connectivity after reload
    - Automatically rolls back if SSH becomes unreachable

    Args:
        port: SSH port number
        permit_root: PermitRootLogin value (no, yes, prohibit-password, forced-commands-only)
        password_auth: Allow password authentication
        pubkey_auth: Allow public key authentication
        x11_forwarding: Allow X11 forwarding
        max_auth_tries: Maximum authentication attempts
        extra_config: Additional configuration lines to append
        connectivity_check: Test SSH connectivity after changes (recommended!)

    Returns:
        True if configuration was changed
    """
    config_lines = [
        "# SSH hardening - managed by sysconf",
        f"Port {port}",
        "Protocol 2",
        f"PermitRootLogin {permit_root}",
        f"PubkeyAuthentication {'yes' if pubkey_auth else 'no'}",
        f"PasswordAuthentication {'yes' if password_auth else 'no'}",
        "ChallengeResponseAuthentication no",
        f"X11Forwarding {'yes' if x11_forwarding else 'no'}",
        "AllowAgentForwarding no",
        "AllowTcpForwarding no",
        f"MaxAuthTries {max_auth_tries}",
        "MaxSessions 2",
        "LogLevel VERBOSE",
        "",
        "# Strong crypto only",
        "KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512",
        "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com",
        "MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com",
    ]

    if extra_config:
        config_lines.append("")
        config_lines.append(extra_config)

    config_content = "\n".join(config_lines) + "\n"

    # Ensure drop-in directory exists
    ensure_dir("/etc/ssh/sshd_config.d", mode=0o755)

    config_path = Path("/etc/ssh/sshd_config.d/99-sysconf.conf")

    # SAFETY: Save current config BEFORE making changes
    old_port = _get_current_ssh_port()
    backup_content = read_file(config_path) if config_path.exists() else None

    # Check if content actually needs changing
    current_content = read_file(config_path) if config_path.exists() else ""
    if current_content == config_content:
        print(f"SSH config {config_path} already up to date")
        return False

    # Deploy new config (ensure_file handles backup)
    changed = ensure_file(
        config_path,
        config_content,
        owner="root",
        group="root",
        mode=0o644,
        backup=True,
    )

    if changed:
        # SAFETY CHECK 1: Validate syntax
        result = subprocess.run(["sudo", "sshd", "-t"], capture_output=True)
        if result.returncode != 0:
            print(f"ERROR: SSH config syntax invalid: {result.stderr.decode()}")
            _rollback_ssh_config(config_path, backup_content)
            return False

        # Reload SSH service
        ssh_service = _get_ssh_service_name()
        reload_service(ssh_service)

        # SAFETY CHECK 2: Verify SSH is still accessible
        if connectivity_check:
            print("Testing SSH connectivity after config change...")

            # Give SSH a moment to reload
            time.sleep(2)

            # Test on the NEW port (what we just configured)
            new_port_ok = _test_ssh_connectivity(port, timeout=5.0)

            # Also check old port in case reload hasn't fully applied
            old_port_ok = _test_ssh_connectivity(old_port, timeout=2.0) if old_port != port else False

            if new_port_ok:
                print(f"SUCCESS: SSH responding on port {port}")
            elif old_port_ok:
                print(f"SSH still on old port {old_port}, reload may be pending")
            else:
                print(f"ERROR: SSH not responding on port {port}!")
                print("INITIATING AUTOMATIC ROLLBACK...")
                _rollback_ssh_config(config_path, backup_content)

                # Verify rollback worked
                time.sleep(2)
                if _test_ssh_connectivity(old_port, timeout=5.0):
                    print(f"ROLLBACK SUCCESSFUL: SSH responding on port {old_port}")
                else:
                    print("WARNING: SSH may still be inaccessible. Check manually!")

                return False

    return changed


def setup_fail2ban(
    bantime: str = "1h",
    findtime: str = "10m",
    maxretry: int = 5,
    ssh_maxretry: int = 3,
    enable_nginx: bool = False,
) -> bool:
    """
    Install and configure fail2ban with sensible defaults.

    Args:
        bantime: Default ban duration
        findtime: Time window for counting failures
        maxretry: Default max failures before ban
        ssh_maxretry: Max SSH failures before ban
        enable_nginx: Enable nginx jails

    Returns:
        True if configuration was changed
    """
    ensure_packages(["fail2ban"])

    jail_local = f"""# fail2ban configuration - managed by sysconf
[DEFAULT]
bantime = {bantime}
findtime = {findtime}
maxretry = {maxretry}
backend = auto

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = {ssh_maxretry}
"""

    if enable_nginx:
        jail_local += """
[nginx-http-auth]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log

[nginx-botsearch]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log
"""

    changed = ensure_file(
        "/etc/fail2ban/jail.local",
        jail_local,
        owner="root",
        group="root",
        mode=0o644,
    )

    enable_service("fail2ban")

    if changed:
        restart_service("fail2ban")

    return changed


def setup_unattended_upgrades(
    auto_reboot: bool = False,
    reboot_time: str = "02:00",
    mail_to: Optional[str] = None,
) -> bool:
    """
    Configure unattended security upgrades.

    Returns:
        True if configuration was changed
    """
    ensure_packages(["unattended-upgrades"])

    config = f"""// Unattended upgrades - managed by sysconf
Unattended-Upgrade::Allowed-Origins {{
    "${{distro_id}}:${{distro_codename}}";
    "${{distro_id}}:${{distro_codename}}-security";
    "${{distro_id}}ESMApps:${{distro_codename}}-apps-security";
    "${{distro_id}}ESM:${{distro_codename}}-infra-security";
}};

Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "{str(auto_reboot).lower()}";
Unattended-Upgrade::Automatic-Reboot-Time "{reboot_time}";
"""

    if mail_to:
        config += f'Unattended-Upgrade::Mail "{mail_to}";\n'
        config += 'Unattended-Upgrade::MailReport "on-change";\n'

    changed = ensure_file(
        "/etc/apt/apt.conf.d/50unattended-upgrades",
        config,
        owner="root",
        group="root",
        mode=0o644,
    )

    enable_service("unattended-upgrades")

    return changed


def setup_basic_firewall(
    ssh_port: int = 22,
    http: bool = True,
    https: bool = True,
    extra_ports: Optional[list[int]] = None,
) -> bool:
    """
    Configure basic nftables firewall.

    Returns:
        True if configuration was changed
    """
    ensure_packages(["nftables"])

    extra_ports = extra_ports or []

    tcp_ports = [ssh_port]
    if http:
        tcp_ports.append(80)
    if https:
        tcp_ports.append(443)
    tcp_ports.extend(extra_ports)

    ports_str = ", ".join(str(p) for p in tcp_ports)

    nft_config = f"""#!/usr/sbin/nft -f
# nftables firewall - managed by sysconf

flush ruleset

table inet filter {{
    chain input {{
        type filter hook input priority 0; policy drop;

        # Allow established/related connections
        ct state established,related accept

        # Allow loopback
        iif lo accept

        # Allow ICMP
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept

        # Allow specified TCP ports
        tcp dport {{ {ports_str} }} accept

        # Log and drop everything else
        log prefix "nftables drop: " drop
    }}

    chain forward {{
        type filter hook forward priority 0; policy drop;
    }}

    chain output {{
        type filter hook output priority 0; policy accept;
    }}
}}
"""

    changed = ensure_file(
        "/etc/nftables.conf",
        nft_config,
        owner="root",
        group="root",
        mode=0o755,
    )

    enable_service("nftables")

    if changed:
        subprocess.run(["sudo", "nft", "-f", "/etc/nftables.conf"], check=True)

    return changed
