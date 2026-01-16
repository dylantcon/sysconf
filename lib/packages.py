"""Cross-distro package management with idempotent operations."""

import shutil
import subprocess
from enum import Enum, auto
from pathlib import Path
from typing import Optional

try:
    import tomllib
except ImportError:
    import tomli as tomllib


class PackageManager(Enum):
    APT = auto()
    PACMAN = auto()
    DNF = auto()


# Track if we've updated package lists this session
_apt_updated_this_session = False


def detect_pm() -> PackageManager:
    """Detect the system's package manager."""
    if shutil.which("apt"):
        return PackageManager.APT
    if shutil.which("pacman"):
        return PackageManager.PACMAN
    if shutil.which("dnf"):
        return PackageManager.DNF
    raise RuntimeError("Unknown package manager")


def _get_install_cmd(pm: PackageManager) -> list[str]:
    """Get the install command for a package manager."""
    return {
        PackageManager.APT: ["sudo", "apt", "install", "-y"],
        PackageManager.PACMAN: ["sudo", "pacman", "-S", "--noconfirm"],
        PackageManager.DNF: ["sudo", "dnf", "install", "-y"],
    }[pm]


def _get_check_cmd(pm: PackageManager, package: str) -> list[str]:
    """Get command to check if a package is installed."""
    return {
        PackageManager.APT: ["dpkg", "-s", package],
        PackageManager.PACMAN: ["pacman", "-Q", package],
        PackageManager.DNF: ["rpm", "-q", package],
    }[pm]


def is_installed(package: str, pm: Optional[PackageManager] = None) -> bool:
    """Check if a package is already installed."""
    pm = pm or detect_pm()
    result = subprocess.run(
        _get_check_cmd(pm, package),
        capture_output=True,
    )
    return result.returncode == 0


def _get_installed_packages_apt() -> set[str]:
    """
    Get all installed packages for APT-based systems.

    More efficient than checking each package individually.
    """
    result = subprocess.run(
        ["dpkg-query", "-W", "-f=${Package}\n"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return set()
    return set(result.stdout.strip().split("\n"))


def _get_installed_packages_pacman() -> set[str]:
    """Get all installed packages for Pacman-based systems."""
    result = subprocess.run(
        ["pacman", "-Qq"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return set()
    return set(result.stdout.strip().split("\n"))


def _get_installed_packages_dnf() -> set[str]:
    """Get all installed packages for DNF-based systems."""
    result = subprocess.run(
        ["rpm", "-qa", "--queryformat", "%{NAME}\n"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return set()
    return set(result.stdout.strip().split("\n"))


def get_installed_packages(pm: Optional[PackageManager] = None) -> set[str]:
    """Get all installed packages (batch query - more efficient)."""
    pm = pm or detect_pm()
    return {
        PackageManager.APT: _get_installed_packages_apt,
        PackageManager.PACMAN: _get_installed_packages_pacman,
        PackageManager.DNF: _get_installed_packages_dnf,
    }[pm]()


def _ensure_apt_updated() -> None:
    """Ensure apt package lists are updated (once per session)."""
    global _apt_updated_this_session
    if not _apt_updated_this_session:
        print("Updating package lists...")
        subprocess.run(["sudo", "apt", "update"], check=True)
        _apt_updated_this_session = True


def install(packages: list[str], pm: Optional[PackageManager] = None) -> None:
    """Install packages (not idempotent - use ensure_packages instead)."""
    pm = pm or detect_pm()
    if not packages:
        return

    # For APT, ensure package lists are fresh
    if pm == PackageManager.APT:
        _ensure_apt_updated()

    cmd = _get_install_cmd(pm) + packages
    subprocess.run(cmd, check=True)


def ensure_packages(
    packages: list[str],
    pm: Optional[PackageManager] = None,
    auto_update: bool = True,
) -> list[str]:
    """
    Idempotently ensure packages are installed.

    Args:
        packages: List of package names to ensure are installed
        pm: Package manager to use (auto-detected if not specified)
        auto_update: For APT, update package lists before installing (once per session)

    Returns:
        List of packages that were newly installed
    """
    pm = pm or detect_pm()

    # Use batch query for efficiency
    installed = get_installed_packages(pm)
    to_install = [p for p in packages if p not in installed]

    if to_install:
        print(f"Installing: {', '.join(to_install)}")
        install(to_install, pm)
    else:
        print("All packages already installed")

    return to_install


def load_package_manifest(
    manifest_path: Path,
    groups: Optional[list[str]] = None,
    pm: Optional[PackageManager] = None,
) -> list[str]:
    """
    Load packages from a TOML manifest file.

    Args:
        manifest_path: Path to packages.toml
        groups: List of groups to include (e.g., ["common", "server"])
                If None, includes all groups.
        pm: Package manager to use for alias resolution

    Returns:
        List of package names resolved for the current distro
    """
    pm = pm or detect_pm()

    with open(manifest_path, "rb") as f:
        manifest = tomllib.load(f)

    # Get alias mapping for current package manager
    pm_name = pm.name.lower()
    aliases = manifest.get("aliases", {}).get(pm_name, {})

    packages = []
    groups_to_process = groups or [
        k for k in manifest.keys()
        if k not in ("aliases",) and isinstance(manifest[k], dict) and "packages" in manifest[k]
    ]

    for group in groups_to_process:
        if group in manifest and "packages" in manifest[group]:
            for pkg in manifest[group]["packages"]:
                # Resolve alias or use package name directly
                resolved = aliases.get(pkg, pkg)
                if resolved and resolved not in packages:
                    packages.append(resolved)

    return packages


def update_system(pm: Optional[PackageManager] = None) -> None:
    """Update package lists and upgrade installed packages."""
    pm = pm or detect_pm()

    cmds = {
        PackageManager.APT: [
            ["sudo", "apt", "update"],
            ["sudo", "apt", "upgrade", "-y"],
        ],
        PackageManager.PACMAN: [
            ["sudo", "pacman", "-Syu", "--noconfirm"],
        ],
        PackageManager.DNF: [
            ["sudo", "dnf", "upgrade", "-y"],
        ],
    }

    for cmd in cmds[pm]:
        print(f"Running: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)
