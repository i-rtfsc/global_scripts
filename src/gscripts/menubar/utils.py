"""
Menu Bar Utilities

Provides process management and auto-start functionality for menu bar.
"""

import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import Optional
import logging

logger = logging.getLogger(__name__)


def get_pid_file() -> Path:
    """Get PID file path"""
    config_dir = Path.home() / ".config" / "global-scripts"
    return config_dir / "menubar.pid"


def is_menubar_running() -> bool:
    """
    Check if menu bar app is currently running

    Returns:
        True if running, False otherwise
    """
    pid_file = get_pid_file()

    if not pid_file.exists():
        return False

    try:
        pid = int(pid_file.read_text().strip())

        # Check if process exists
        try:
            os.kill(pid, 0)  # Signal 0 doesn't kill, just checks existence
            return True
        except OSError:
            # Process doesn't exist, clean up stale PID file
            logger.debug(f"Stale PID file found: {pid}")
            pid_file.unlink()
            return False

    except (ValueError, FileNotFoundError) as e:
        logger.debug(f"Invalid PID file: {e}")
        return False


def start_menubar() -> bool:
    """
    Start menu bar app as detached background process

    Returns:
        True if started successfully, False otherwise
    """
    if is_menubar_running():
        logger.debug("Menu bar already running")
        return True

    try:
        # Get log file path
        log_dir = Path.home() / ".config" / "global-scripts" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "menubar.log"

        # Start as detached process
        # Use python -m to run module directly
        cmd = [sys.executable, "-m", "gscripts.menubar"]

        with open(log_file, "a") as logf:
            process = subprocess.Popen(
                cmd,
                stdout=logf,
                stderr=logf,
                stdin=subprocess.DEVNULL,
                start_new_session=True,  # Detach from parent
            )

        logger.info(f"Menu bar started with PID: {process.pid}")
        return True

    except Exception as e:
        logger.error(f"Failed to start menu bar: {e}", exc_info=True)
        return False


def stop_menubar(timeout: float = 5.0) -> bool:
    """
    Stop menu bar app gracefully

    Args:
        timeout: Seconds to wait before force kill

    Returns:
        True if stopped successfully, False otherwise
    """
    pid_file = get_pid_file()

    if not pid_file.exists():
        logger.debug("Menu bar not running (no PID file)")
        return True

    try:
        pid = int(pid_file.read_text().strip())

        # Send SIGTERM for graceful shutdown
        try:
            os.kill(pid, signal.SIGTERM)
            logger.info(f"Sent SIGTERM to menu bar (PID: {pid})")

            # Wait for process to exit
            import time

            elapsed = 0.0
            while elapsed < timeout:
                try:
                    os.kill(pid, 0)  # Check if still exists
                    time.sleep(0.1)
                    elapsed += 0.1
                except OSError:
                    # Process exited
                    logger.info("Menu bar stopped gracefully")
                    break
            else:
                # Timeout - force kill
                logger.warning(f"Menu bar didn't stop after {timeout}s, force killing")
                os.kill(pid, signal.SIGKILL)

            # Clean up PID file
            if pid_file.exists():
                pid_file.unlink()

            return True

        except OSError as e:
            logger.debug(f"Process {pid} not found: {e}")
            # Clean up stale PID file
            if pid_file.exists():
                pid_file.unlink()
            return True

    except (ValueError, FileNotFoundError) as e:
        logger.warning(f"Invalid PID file: {e}")
        return False


def ensure_menubar_running(config: dict) -> bool:
    """
    Ensure menu bar is running if enabled in config

    Args:
        config: Global Scripts configuration dict

    Returns:
        True if menu bar running or successfully started, False otherwise
    """
    # Check if menubar feature is supported (macOS only)
    if sys.platform != "darwin":
        logger.debug("Menu bar not supported on non-macOS platform")
        return False

    # Check if enabled in config
    menubar_config = config.get("menubar", {})
    if not menubar_config.get("enabled", False):
        logger.debug("Menu bar disabled in config")
        return False

    # Check if rumps is available
    try:
        import rumps  # noqa: F401
    except ImportError:
        logger.warning(
            "rumps not installed. Install with: uv sync (menu bar feature unavailable)"
        )
        return False

    # Start if not running
    if not is_menubar_running():
        logger.info("Auto-starting menu bar")
        return start_menubar()

    return True
