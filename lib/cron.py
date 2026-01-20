"""Cron job management for sysconf auto-push functionality."""

import subprocess
from pathlib import Path
from typing import Optional

from .base import BaseOrchestrator
from .paths import PROJECT_ROOT

# Marker to identify sysconf cron entries
CRON_MARKER = "# sysconf-auto-push"


def get_cron_line() -> str:
    """
    Get the cron line for auto-push.

    Returns:
        Cron entry string that runs every 30 minutes
    """
    # Run every 30 minutes: git add, commit if changes, push
    return (
        f'*/30 * * * * cd {PROJECT_ROOT} && '
        f'git add -A && '
        f'git diff --cached --quiet || '
        f'git commit -m "auto: $(date +\\%Y-\\%m-\\%d\\ \\%H:\\%M)" && '
        f'git push {CRON_MARKER}'
    )


def get_current_crontab() -> str:
    """
    Get the current user's crontab.

    Returns:
        Current crontab content, or empty string if none
    """
    try:
        result = subprocess.run(
            ["crontab", "-l"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return result.stdout
        return ""
    except Exception:
        return ""


def set_crontab(content: str) -> bool:
    """
    Set the user's crontab content.

    Args:
        content: New crontab content

    Returns:
        True if crontab was updated successfully
    """
    try:
        result = subprocess.run(
            ["crontab", "-"],
            input=content,
            text=True,
            capture_output=True,
        )
        return result.returncode == 0
    except Exception:
        return False


def is_cron_enabled() -> bool:
    """
    Check if the sysconf auto-push cron job is enabled.

    Returns:
        True if the cron job is present in the crontab
    """
    crontab = get_current_crontab()
    return CRON_MARKER in crontab


def enable_cron(dry_run: bool = False) -> bool:
    """
    Install the auto-push cron job.

    Args:
        dry_run: If True, only show what would be done

    Returns:
        True if cron job was installed or already exists
    """
    if is_cron_enabled():
        print("Auto-push cron job is already enabled")
        return True

    cron_line = get_cron_line()

    if dry_run:
        print(f"Would add cron job:")
        print(f"  {cron_line}")
        return True

    # Get existing crontab and append new line
    existing = get_current_crontab()

    # Ensure trailing newline
    if existing and not existing.endswith("\n"):
        existing += "\n"

    new_crontab = existing + cron_line + "\n"

    if set_crontab(new_crontab):
        print("Auto-push cron job installed")
        print(f"  Schedule: Every 30 minutes")
        print(f"  Project: {PROJECT_ROOT}")
        return True
    else:
        print("ERROR: Failed to install cron job")
        return False


def disable_cron(dry_run: bool = False) -> bool:
    """
    Remove the auto-push cron job.

    Args:
        dry_run: If True, only show what would be done

    Returns:
        True if cron job was removed or didn't exist
    """
    if not is_cron_enabled():
        print("Auto-push cron job is not enabled")
        return True

    if dry_run:
        print("Would remove auto-push cron job")
        return True

    # Get existing crontab and remove our line
    existing = get_current_crontab()
    lines = existing.splitlines()

    # Filter out our cron line
    new_lines = [line for line in lines if CRON_MARKER not in line]
    new_crontab = "\n".join(new_lines)

    # Ensure trailing newline if there's content
    if new_crontab and not new_crontab.endswith("\n"):
        new_crontab += "\n"

    if set_crontab(new_crontab):
        print("Auto-push cron job removed")
        return True
    else:
        print("ERROR: Failed to remove cron job")
        return False


def get_cron_status() -> dict:
    """
    Get detailed status of the auto-push cron job.

    Returns:
        Dictionary with status information
    """
    enabled = is_cron_enabled()

    status = {
        "enabled": enabled,
        "project_root": str(PROJECT_ROOT),
        "schedule": "*/30 * * * * (every 30 minutes)" if enabled else None,
        "cron_line": None,
    }

    if enabled:
        crontab = get_current_crontab()
        for line in crontab.splitlines():
            if CRON_MARKER in line:
                status["cron_line"] = line
                break

    return status


class CronManager(BaseOrchestrator):
    """Manager for sysconf cron jobs."""

    def __init__(self, dry_run: bool = False, verbose: bool = False):
        super().__init__(dry_run=dry_run, verbose=verbose)

    def enable(self) -> bool:
        """Enable the auto-push cron job."""
        self.log("=== Enabling Auto-Push Cron Job ===")

        if enable_cron(dry_run=self.dry_run):
            if not self.dry_run:
                self.record_change("Enabled auto-push cron job")
            return True
        return False

    def disable(self) -> bool:
        """Disable the auto-push cron job."""
        self.log("=== Disabling Auto-Push Cron Job ===")

        if disable_cron(dry_run=self.dry_run):
            if not self.dry_run:
                self.record_change("Disabled auto-push cron job")
            return True
        return False

    def status(self) -> None:
        """Show the status of the auto-push cron job."""
        self.log("=== Auto-Push Cron Status ===")

        status = get_cron_status()

        if status["enabled"]:
            self.log(f"  Status: ENABLED")
            self.log(f"  Schedule: {status['schedule']}")
            self.log(f"  Project: {status['project_root']}")
            if self.verbose and status["cron_line"]:
                self.log(f"  Cron line: {status['cron_line']}")
        else:
            self.log(f"  Status: DISABLED")
            self.log(f"  Use './sysconf.py cron --enable' to enable auto-push")

    def run(
        self,
        enable: bool = False,
        disable: bool = False,
        show_status: bool = False,
    ) -> None:
        """
        Run cron management operations.

        Args:
            enable: Enable the auto-push cron job
            disable: Disable the auto-push cron job
            show_status: Show current status
        """
        if enable:
            self.enable()
        elif disable:
            self.disable()
        elif show_status:
            self.status()
        else:
            # Default to showing status
            self.status()

        if self.changes:
            self.summarize()
