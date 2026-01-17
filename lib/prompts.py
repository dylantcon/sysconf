"""User interaction utilities for sysconf."""

import getpass
import sys
from typing import Optional


def prompt(message: str, default: str = "") -> str:
    """
    Prompt the user for input with an optional default value.

    Args:
        message: The prompt message to display
        default: Default value if user presses Enter

    Returns:
        User input or default value
    """
    if default:
        display = f"{message} [{default}]: "
    else:
        display = f"{message}: "

    try:
        response = input(display).strip()
        return response if response else default
    except EOFError:
        print()
        return default


def prompt_secret(message: str, required: bool = False) -> str:
    """
    Prompt for a secret value without echoing input.

    Args:
        message: The prompt message to display
        required: If True, keep prompting until a value is provided

    Returns:
        The secret value (may be empty if not required)
    """
    while True:
        try:
            value = getpass.getpass(f"{message}: ").strip()
            if value or not required:
                return value
            print("  This value is required. Please enter a value or Ctrl+C to abort.")
        except EOFError:
            print()
            if required:
                continue
            return ""


def pause(message: str = "Press Enter to continue...") -> None:
    """
    Pause execution until user presses Enter.

    Args:
        message: Message to display
    """
    try:
        input(message)
    except EOFError:
        print()


def confirm(message: str, default: bool = False) -> bool:
    """
    Ask the user for confirmation.

    Args:
        message: The question to ask
        default: Default answer if user presses Enter

    Returns:
        True if user confirmed, False otherwise
    """
    if default:
        prompt_suffix = "[Y/n]"
    else:
        prompt_suffix = "[y/N]"

    while True:
        try:
            response = input(f"{message} {prompt_suffix}: ").strip().lower()
        except EOFError:
            print()
            return default

        if not response:
            return default
        if response in ("y", "yes"):
            return True
        if response in ("n", "no"):
            return False
        print("  Please answer 'y' or 'n'")


def warn_missing(feature: str, consequence: str) -> None:
    """
    Print a warning about a missing feature with its consequence.

    Args:
        feature: The missing feature (e.g., "SSH key")
        consequence: What happens without it (e.g., "Git will use HTTPS")
    """
    print(f"  WARNING: {feature} not configured")
    print(f"           {consequence}")
