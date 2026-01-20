"""Toolchain management for sysconf - Go, Rust, Node, etc."""

import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.request import urlopen

from .base import BaseOrchestrator
from .paths import CONFIGS_DIR, PROJECT_ROOT, TOOLCHAINS_CONFIG, get_user_home


def get_arch() -> str:
    """Get system architecture."""
    import platform
    return platform.machine()


def load_toolchains_config() -> dict:
    """Load toolchain definitions from toolchains.toml."""
    if not TOOLCHAINS_CONFIG.exists():
        return {}
    with open(TOOLCHAINS_CONFIG, "rb") as f:
        return tomllib.load(f)


class ToolchainManager(BaseOrchestrator):
    """Manages installation of development toolchains."""

    def __init__(self, dry_run: bool = False, verbose: bool = False):
        super().__init__(dry_run=dry_run, verbose=verbose)
        self.config = load_toolchains_config()
        self.arch = get_arch()

    def _check_installed(self, name: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a toolchain is installed and get its version.

        Checks both PATH and known install locations.

        Returns:
            Tuple of (is_installed, version_string)
        """
        tc = self.config.get(name, {})
        check_cmd = tc.get("check_cmd")
        if not check_cmd:
            return False, None

        # Build environment with toolchain paths included
        env = os.environ.copy()
        path_add = tc.get("path_add", "")
        if path_add:
            user_home = str(self._get_user_home())
            path_add = path_add.replace("$HOME", user_home)
            if Path(path_add).exists():
                env["PATH"] = path_add + ":" + env.get("PATH", "")

        try:
            result = subprocess.run(
                check_cmd,
                shell=True,
                capture_output=True,
                text=True,
                env=env,
            )
            if result.returncode != 0:
                return False, None

            # Extract version
            version_regex = tc.get("version_regex")
            if version_regex:
                match = re.search(version_regex, result.stdout + result.stderr)
                if match:
                    return True, match.group(1)
            return True, None
        except Exception:
            return False, None

    def _compare_versions(self, installed: str, minimum: str) -> bool:
        """Check if installed version meets minimum requirement."""
        try:
            inst_parts = [int(x) for x in installed.split(".")[:2]]
            min_parts = [int(x) for x in minimum.split(".")[:2]]
            return inst_parts >= min_parts
        except (ValueError, AttributeError):
            return True  # If we can't parse, assume it's fine

    def _get_latest_version(self, name: str) -> Optional[str]:
        """Fetch the latest version of a toolchain."""
        tc = self.config.get(name, {})
        latest_url = tc.get("latest_url")
        if not latest_url:
            return None

        try:
            with urlopen(latest_url, timeout=10) as resp:
                content = resp.read().decode("utf-8")

            # Try regex first
            latest_regex = tc.get("latest_regex")
            if latest_regex:
                match = re.search(latest_regex, content)
                if match:
                    return match.group(1)

            # Try jq-style for JSON (simple implementation)
            latest_jq = tc.get("latest_jq")
            if latest_jq and latest_jq == ".[0].version":
                import json
                data = json.loads(content)
                return data[0]["version"].lstrip("v")

            return content.strip()
        except Exception as e:
            if self.verbose:
                self.log(f"  Failed to fetch latest version: {e}")
            return None

    def _install_tarball(self, name: str, version: str) -> bool:
        """Install a toolchain from a tarball."""
        tc = self.config.get(name, {})

        # Map architecture
        arch_map = tc.get("arch_map", {})
        arch = arch_map.get(self.arch, self.arch)

        # Build URL
        url_template = tc.get("install_url", "")
        url = url_template.format(version=version, arch=arch)
        install_path = Path(tc.get("install_path", f"/usr/local/{name}"))

        self.log(f"  Downloading {url}")
        if self.dry_run:
            return True

        try:
            # Download to temp file
            with tempfile.NamedTemporaryFile(delete=False, suffix=".tar.gz") as tmp:
                with urlopen(url, timeout=60) as resp:
                    shutil.copyfileobj(resp, tmp)
                tmp_path = tmp.name

            # Remove existing installation
            if install_path.exists():
                self.log(f"  Removing existing {install_path}")
                subprocess.run(["sudo", "rm", "-rf", str(install_path)], check=True)

            # Extract
            self.log(f"  Extracting to {install_path}")
            subprocess.run(["sudo", "mkdir", "-p", str(install_path.parent)], check=True)

            # Determine compression
            if url.endswith(".tar.xz"):
                subprocess.run(
                    ["sudo", "tar", "-xJf", tmp_path, "-C", str(install_path.parent)],
                    check=True,
                )
            else:
                subprocess.run(
                    ["sudo", "tar", "-xzf", tmp_path, "-C", str(install_path.parent)],
                    check=True,
                )

            # Cleanup
            os.unlink(tmp_path)

            # Handle Go's nested directory structure
            if name == "go":
                # Go extracts to 'go/' directory, which becomes /usr/local/go
                pass  # Already correct
            elif name == "node":
                # Node extracts to node-v{version}-linux-{arch}/
                extracted = install_path.parent / f"node-v{version}-linux-{arch}"
                if extracted.exists():
                    subprocess.run(
                        ["sudo", "mv", str(extracted), str(install_path)],
                        check=True,
                    )

            return True
        except Exception as e:
            self.log(f"  ERROR: {e}")
            return False

    def _install_script(self, name: str) -> bool:
        """Install a toolchain via install script."""
        tc = self.config.get(name, {})
        script = tc.get("install_script", "")

        self.log(f"  Running install script")
        if self.dry_run:
            if self.verbose:
                self.log(f"    {script}")
            return True

        try:
            result = subprocess.run(
                script,
                shell=True,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                self.log(f"  Script failed: {result.stderr}")
                return False
            return True
        except Exception as e:
            self.log(f"  ERROR: {e}")
            return False

    def _get_user_home(self) -> Path:
        """Get real user's home directory (handles sudo)."""
        return get_user_home()

    def _update_path(self, name: str) -> None:
        """Ensure toolchain is in PATH (updates shell profile)."""
        tc = self.config.get(name, {})
        path_add = tc.get("path_add")
        if not path_add:
            return

        user_home = self._get_user_home()

        # Expand $HOME
        path_add = path_add.replace("$HOME", str(user_home))

        # Check if already in PATH
        if path_add in os.environ.get("PATH", ""):
            return

        self.log(f"  Adding {path_add} to PATH")

        # Add to .bashrc if not already there
        bashrc = user_home / ".bashrc"
        if bashrc.exists():
            content = bashrc.read_text()
            export_line = f'export PATH="{path_add}:$PATH"'
            if path_add not in content:
                if not self.dry_run:
                    with open(bashrc, "a") as f:
                        f.write(f'\n# Added by sysconf for {name}\n{export_line}\n')
                self.log(f"  Added to .bashrc")

    def ensure_toolchain(self, name: str) -> bool:
        """
        Ensure a toolchain is installed and meets version requirements.

        Returns:
            True if toolchain is available (installed or was installed)
        """
        if name not in self.config:
            self.log(f"Unknown toolchain: {name}")
            return False

        tc = self.config[name]
        self.log(f"\nChecking {name}...")

        # Check if installed
        installed, version = self._check_installed(name)
        if installed:
            min_version = tc.get("min_version")
            if version and min_version:
                if self._compare_versions(version, min_version):
                    self.log(f"  {name} {version} is installed (>= {min_version})")
                    return True
                else:
                    self.log(f"  {name} {version} is too old (need >= {min_version})")
            else:
                self.log(f"  {name} is installed")
                return True

        # Need to install
        self.log(f"  {name} not found, installing...")

        # Get version to install
        version = self._get_latest_version(name)
        if not version and tc.get("install_type") == "tarball":
            self.log(f"  Could not determine latest version")
            return False

        # Install based on type
        install_type = tc.get("install_type", "script")
        if install_type == "tarball":
            success = self._install_tarball(name, version)
        elif install_type == "script":
            success = self._install_script(name)
        else:
            self.log(f"  Unknown install type: {install_type}")
            return False

        if success:
            self._update_path(name)
            self.record_change(f"Installed {name}")
            return True
        return False

    def get_paths(self) -> List[str]:
        """
        Get all toolchain bin paths for PATH augmentation.

        Handles sudo by using SUDO_USER's home for user-specific paths.

        Returns:
            List of paths that should be added to PATH
        """
        user_home = str(self._get_user_home())

        paths = []
        for name, tc in self.config.items():
            if not isinstance(tc, dict):
                continue
            path_add = tc.get("path_add")
            if path_add:
                # Expand $HOME to real user's home
                path_add = path_add.replace("$HOME", user_home)
                # Check if the path exists
                if Path(path_add).exists():
                    paths.append(path_add)
        return paths

    def detect_required(self, project_path: Path) -> List[str]:
        """
        Detect which toolchains are required for a project.

        Args:
            project_path: Path to the project directory

        Returns:
            List of toolchain names
        """
        required = []
        for name, tc in self.config.items():
            if name == "arch_map":  # Skip nested tables
                continue
            detect_files = tc.get("detect", [])
            for detect_file in detect_files:
                if (project_path / detect_file).exists():
                    required.append(name)
                    break
        return required

    def ensure_for_project(self, project_path: Path) -> bool:
        """
        Ensure all required toolchains for a project are installed.

        Returns:
            True if all toolchains are available
        """
        required = self.detect_required(project_path)
        if not required:
            return True

        self.log(f"Project requires: {', '.join(required)}")

        all_ok = True
        for name in required:
            if not self.ensure_toolchain(name):
                all_ok = False

        return all_ok

    def run(self, toolchains: Optional[List[str]] = None) -> None:
        """
        Run toolchain installation.

        Args:
            toolchains: Specific toolchains to install, or None for all
        """
        self.log("=== Toolchain Management ===")

        if toolchains:
            names = toolchains
        else:
            names = [k for k in self.config.keys() if isinstance(self.config[k], dict)]

        for name in names:
            self.ensure_toolchain(name)

        # Summary
        self.log("\n" + "=" * 60)
        if self.dry_run:
            self.log("Dry-run complete - no changes were made")
        elif self.changes:
            self.log(f"Changes made: {len(self.changes)}")
            for change in self.changes:
                self.log(f"  - {change}")
        else:
            self.log("All toolchains already installed")
