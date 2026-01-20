"""Base orchestrator class for sysconf components."""

from typing import List


class BaseOrchestrator:
    """
    Base class for sysconf orchestrator components.

    Provides common functionality for dry-run mode, logging, and change tracking.
    All orchestrator classes (SysConf, WebpageDeployer, SecretsManager, etc.)
    should inherit from this class.
    """

    def __init__(self, dry_run: bool = False, verbose: bool = False):
        """
        Initialize the orchestrator.

        Args:
            dry_run: If True, only show what would be done without making changes
            verbose: If True, enable verbose output
        """
        self.dry_run = dry_run
        self.verbose = verbose
        self.changes: List[str] = []

    def log(self, msg: str) -> None:
        """
        Log a message with optional dry-run prefix.

        Args:
            msg: Message to log
        """
        prefix = "[DRY-RUN] " if self.dry_run else ""
        print(f"{prefix}{msg}")

    def log_verbose(self, msg: str) -> None:
        """
        Log a message only if verbose mode is enabled.

        Args:
            msg: Message to log
        """
        if self.verbose:
            self.log(msg)

    def record_change(self, description: str) -> None:
        """
        Record a change that was made.

        Args:
            description: Description of the change
        """
        self.changes.append(description)

    def summarize(self, title: str = "Summary") -> None:
        """
        Print a summary of changes made.

        Args:
            title: Title for the summary section
        """
        self.log("")
        self.log("=" * 60)
        if self.dry_run:
            self.log("Dry-run complete - no changes were made")
        elif self.changes:
            self.log(f"Changes made: {len(self.changes)}")
            for change in self.changes:
                self.log(f"  - {change}")
        else:
            self.log(f"No changes needed - system is up to date")
        self.log("=" * 60)
