"""Special setup handlers for sysconf webpages (postgres, venv, pip, django)."""

import os
import subprocess
from pathlib import Path
from typing import Dict, Optional

try:
    import pexpect
    HAS_PEXPECT = True
except ImportError:
    HAS_PEXPECT = False

from .base import BaseOrchestrator
from .paths import get_canonical_env_path
from .prompts import prompt, prompt_secret


class SetupHandler(BaseOrchestrator):
    """
    Handler for special setup tasks.

    Supports:
    - PostgreSQL database/user creation
    - Python virtual environment creation
    - pip requirements installation
    - Django management commands (migrate, collectstatic)
    """

    def __init__(self, dry_run: bool = False, verbose: bool = False):
        super().__init__(dry_run=dry_run, verbose=verbose)

    def _run_command(
        self,
        cmd: list,
        cwd: Optional[Path] = None,
        env: Optional[dict] = None,
        check: bool = True,
        capture: bool = True,
    ) -> subprocess.CompletedProcess:
        """
        Run a command with optional environment and working directory.

        Args:
            cmd: Command and arguments
            cwd: Working directory
            env: Environment variables (merged with current env)
            check: Raise on non-zero exit
            capture: Capture stdout/stderr

        Returns:
            CompletedProcess result
        """
        run_env = os.environ.copy()
        if env:
            run_env.update(env)

        return subprocess.run(
            cmd,
            cwd=cwd,
            env=run_env,
            capture_output=capture,
            text=True,
            check=check,
        )

    def _postgres_db_exists(self, db_name: str) -> bool:
        """Check if a PostgreSQL database exists."""
        try:
            result = self._run_command(
                ["sudo", "-u", "postgres", "psql", "-lqt"],
                check=False,
            )
            if result.returncode == 0:
                # Parse psql output: dbname | owner | encoding | ...
                for line in result.stdout.splitlines():
                    if line.strip().startswith(db_name + " ") or line.strip().startswith(db_name + "|"):
                        return True
            return False
        except Exception:
            return False

    def _postgres_user_exists(self, username: str) -> bool:
        """Check if a PostgreSQL user exists."""
        try:
            result = self._run_command(
                ["sudo", "-u", "postgres", "psql", "-tAc",
                 f"SELECT 1 FROM pg_roles WHERE rolname='{username}'"],
                check=False,
            )
            return result.returncode == 0 and "1" in result.stdout
        except Exception:
            return False

    def _create_postgres_user_pexpect(self, db_user: str, db_password: str) -> bool:
        """Create PostgreSQL user using pexpect for secure password handling."""
        try:
            child = pexpect.spawn(f"sudo -u postgres createuser -P {db_user}")
            child.expect("Enter password for new role:")
            child.sendline(db_password)
            child.expect("Enter it again:")
            child.sendline(db_password)
            child.expect(pexpect.EOF)
            child.close()
            return child.exitstatus == 0
        except Exception as e:
            self.log(f"    ERROR: pexpect failed: {e}")
            return False

    def setup_postgres(
        self,
        webpage_name: str,
        db_name: str,
        db_user: str,
        webpage_path: Path,
    ) -> bool:
        """
        Set up PostgreSQL database and user.

        Creates the user and database if they don't exist, and stores
        DATABASE_URL in the canonical .env file.

        Args:
            webpage_name: Name of the webpage (for env file)
            db_name: Database name to create
            db_user: Database user to create
            webpage_path: Path to webpage (for env file symlink)

        Returns:
            True if setup succeeded
        """
        self.log(f"  Setting up PostgreSQL: db={db_name}, user={db_user}")

        # Check if user exists
        user_exists = self._postgres_user_exists(db_user)
        db_exists = self._postgres_db_exists(db_name)

        if user_exists and db_exists:
            self.log(f"    Database and user already exist")
            return True

        if self.dry_run:
            if not user_exists:
                self.log(f"    Would create PostgreSQL user: {db_user}")
            if not db_exists:
                self.log(f"    Would create PostgreSQL database: {db_name}")
            return True

        # Prompt for password if creating new user
        db_password = None
        if not user_exists:
            if not HAS_PEXPECT:
                self.log("    ERROR: pexpect module required for PostgreSQL user creation")
                self.log("    Install with: pip install pexpect")
                return False

            print(f"    Creating PostgreSQL user '{db_user}'")
            db_password = prompt_secret(f"    Enter password for {db_user}", required=True)
            if not db_password:
                self.log("    ERROR: Password is required for new database user")
                return False

            # Create user with pexpect (password never in process list)
            if not self._create_postgres_user_pexpect(db_user, db_password):
                self.log(f"    ERROR: Failed to create user {db_user}")
                return False
            self.record_change(f"Created PostgreSQL user: {db_user}")

        # Create database
        if not db_exists:
            self.log(f"    Creating PostgreSQL database: {db_name}")
            result = self._run_command(
                ["sudo", "-u", "postgres", "psql", "-c",
                 f"CREATE DATABASE {db_name} OWNER {db_user}"],
                check=False,
            )
            if result.returncode != 0:
                self.log(f"    ERROR: Failed to create database: {result.stderr}")
                return False
            self.record_change(f"Created PostgreSQL database: {db_name}")

        # Update canonical .env with DATABASE_URL if we have a password
        if db_password:
            self._update_env_database_url(webpage_name, db_name, db_user, db_password)

        return True

    def _update_env_database_url(
        self,
        webpage_name: str,
        db_name: str,
        db_user: str,
        db_password: str,
    ) -> None:
        """Update or append DATABASE_URL to the canonical .env file."""
        canonical_path = get_canonical_env_path(webpage_name)
        database_url = f"postgresql://{db_user}:{db_password}@localhost:5432/{db_name}"

        if canonical_path.exists():
            content = canonical_path.read_text()
            lines = content.splitlines()

            # Check if DATABASE_URL already exists
            found = False
            for i, line in enumerate(lines):
                if line.startswith("DATABASE_URL="):
                    lines[i] = f"DATABASE_URL={database_url}"
                    found = True
                    break

            if not found:
                lines.append(f"DATABASE_URL={database_url}")

            canonical_path.write_text("\n".join(lines) + "\n")
        else:
            # Create new file
            canonical_path.parent.mkdir(parents=True, exist_ok=True)
            canonical_path.write_text(f"DATABASE_URL={database_url}\n")
            os.chmod(canonical_path, 0o600)

        self.log(f"    Updated DATABASE_URL in {canonical_path}")

    def setup_venv(
        self,
        webpage_path: Path,
        venv_path: str = "venv",
        python: str = "python3",
    ) -> bool:
        """
        Create a Python virtual environment.

        Args:
            webpage_path: Path to the webpage directory
            venv_path: Relative path for venv (default: "venv")
            python: Python interpreter to use (default: "python3")

        Returns:
            True if venv exists or was created
        """
        full_venv_path = webpage_path / venv_path

        if full_venv_path.exists():
            self.log(f"  Virtual environment already exists: {full_venv_path}")
            return True

        self.log(f"  Creating virtual environment: {full_venv_path}")

        if self.dry_run:
            return True

        try:
            result = self._run_command(
                [python, "-m", "venv", str(full_venv_path)],
                check=False,
            )
            if result.returncode != 0:
                self.log(f"    ERROR: Failed to create venv: {result.stderr}")
                return False

            self.record_change(f"Created venv: {full_venv_path}")
            return True
        except Exception as e:
            self.log(f"    ERROR: {e}")
            return False

    def setup_pip(
        self,
        webpage_path: Path,
        venv_path: str = "venv",
        requirements: str = "requirements.txt",
    ) -> bool:
        """
        Install pip requirements.

        Args:
            webpage_path: Path to the webpage directory
            venv_path: Relative path to venv
            requirements: Path to requirements file (relative to webpage_path)

        Returns:
            True if requirements were installed
        """
        full_venv_path = webpage_path / venv_path
        pip_path = full_venv_path / "bin" / "pip"
        req_path = webpage_path / requirements

        if not full_venv_path.exists():
            self.log(f"  ERROR: Virtual environment not found: {full_venv_path}")
            return False

        if not req_path.exists():
            self.log(f"  No requirements file found: {req_path}")
            return True

        self.log(f"  Installing pip requirements from {requirements}")

        if self.dry_run:
            return True

        try:
            # Don't capture output so user sees pip progress
            result = subprocess.run(
                [str(pip_path), "install", "-r", str(req_path)],
                cwd=webpage_path,
                check=False,
            )
            if result.returncode != 0:
                self.log(f"    ERROR: pip install failed")
                return False

            self.record_change(f"Installed pip requirements: {requirements}")
            return True
        except Exception as e:
            self.log(f"    ERROR: {e}")
            return False

    def setup_django(
        self,
        webpage_path: Path,
        manage_py: str = "manage.py",
        venv_path: str = "venv",
        migrate: bool = True,
        collectstatic: bool = True,
    ) -> bool:
        """
        Run Django management commands.

        Args:
            webpage_path: Path to the webpage directory
            manage_py: Path to manage.py (relative to webpage_path)
            venv_path: Path to virtual environment
            migrate: Run migrations
            collectstatic: Run collectstatic

        Returns:
            True if commands succeeded
        """
        full_venv_path = webpage_path / venv_path
        python_path = full_venv_path / "bin" / "python"
        manage_path = webpage_path / manage_py

        if not python_path.exists():
            self.log(f"  ERROR: Python not found in venv: {python_path}")
            return False

        if not manage_path.exists():
            self.log(f"  ERROR: manage.py not found: {manage_path}")
            return False

        success = True

        # Run migrations
        if migrate:
            self.log(f"  Running Django migrations...")

            if self.dry_run:
                self.log(f"    Would run: {python_path} {manage_path} migrate")
            else:
                try:
                    result = self._run_command(
                        [str(python_path), str(manage_path), "migrate", "--no-input"],
                        cwd=webpage_path,
                        check=False,
                    )
                    if result.returncode != 0:
                        self.log(f"    WARNING: migrate failed: {result.stderr}")
                        success = False
                    else:
                        self.record_change("Ran Django migrations")
                except Exception as e:
                    self.log(f"    ERROR: {e}")
                    success = False

        # Run collectstatic
        if collectstatic:
            self.log(f"  Running Django collectstatic...")

            if self.dry_run:
                self.log(f"    Would run: {python_path} {manage_path} collectstatic")
            else:
                try:
                    result = self._run_command(
                        [str(python_path), str(manage_path), "collectstatic", "--no-input"],
                        cwd=webpage_path,
                        check=False,
                    )
                    if result.returncode != 0:
                        self.log(f"    WARNING: collectstatic failed: {result.stderr}")
                        success = False
                    else:
                        self.record_change("Ran Django collectstatic")
                except Exception as e:
                    self.log(f"    ERROR: {e}")
                    success = False

        return success

    def run_setup(
        self,
        webpage_name: str,
        webpage_path: Path,
        setup_config: Dict,
    ) -> bool:
        """
        Run all setup tasks for a webpage.

        Setup tasks are run in order: postgres -> venv -> pip -> django

        Args:
            webpage_name: Name of the webpage
            webpage_path: Path to the webpage directory
            setup_config: Setup configuration dict from webpages.toml

        Returns:
            True if all setup tasks succeeded
        """
        if not setup_config:
            return True

        self.log(f"\n  Running special setup for {webpage_name}...")
        success = True

        # PostgreSQL setup
        postgres_config = setup_config.get("postgres")
        if postgres_config:
            db_name = postgres_config.get("db", webpage_name)
            db_user = postgres_config.get("user", webpage_name)
            if not self.setup_postgres(webpage_name, db_name, db_user, webpage_path):
                success = False

        # Virtual environment setup
        venv_config = setup_config.get("venv")
        if venv_config:
            venv_path = venv_config.get("path", "venv")
            python = venv_config.get("python", "python3")
            if not self.setup_venv(webpage_path, venv_path, python):
                return False  # Fail-fast: pip and django depend on venv

        # Pip requirements
        pip_config = setup_config.get("pip")
        if pip_config:
            venv_path = setup_config.get("venv", {}).get("path", "venv")
            requirements = pip_config.get("requirements", "requirements.txt")
            if not self.setup_pip(webpage_path, venv_path, requirements):
                return False  # Fail-fast: django depends on pip

        # Django setup
        django_config = setup_config.get("django")
        if django_config:
            venv_path = setup_config.get("venv", {}).get("path", "venv")
            manage_py = django_config.get("manage_py", "manage.py")
            migrate = django_config.get("migrate", True)
            collectstatic = django_config.get("collectstatic", True)
            if not self.setup_django(webpage_path, manage_py, venv_path, migrate, collectstatic):
                success = False

        return success


def remove_postgres_db(db_name: str, db_user: str, dry_run: bool = False) -> bool:
    """
    Remove a PostgreSQL database and user.

    Args:
        db_name: Database name to remove
        db_user: User to remove
        dry_run: If True, only show what would be done

    Returns:
        True if cleanup succeeded
    """
    if dry_run:
        return True

    # Drop database
    result = subprocess.run(
        ["sudo", "-u", "postgres", "psql", "-c", f"DROP DATABASE IF EXISTS {db_name}"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"  WARNING: Failed to drop database: {result.stderr}")

    # Drop user
    result = subprocess.run(
        ["sudo", "-u", "postgres", "psql", "-c", f"DROP USER IF EXISTS {db_user}"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"  WARNING: Failed to drop user: {result.stderr}")

    return True
