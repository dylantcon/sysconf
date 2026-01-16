"""sysconf - DIY configuration management for Linux systems."""

from .packages import PackageManager, detect_pm, install, ensure_packages
from .services import enable_service, disable_service, restart_service, ensure_service_file
from .files import ensure_file, ensure_symlink, render_template, ensure_dir, set_permissions, read_file
from .security import harden_ssh, setup_fail2ban

__all__ = [
    "PackageManager",
    "detect_pm",
    "install",
    "ensure_packages",
    "enable_service",
    "disable_service",
    "restart_service",
    "ensure_service_file",
    "ensure_file",
    "ensure_symlink",
    "render_template",
    "ensure_dir",
    "set_permissions",
    "read_file",
    "harden_ssh",
    "setup_fail2ban",
]
