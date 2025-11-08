"""
macOS Menu Bar Status Indicator Module

This module provides a macOS menu bar status indicator that displays:
- Command execution progress from terminal
- System metrics (CPU temperature, memory usage)
- Real-time status updates via IPC

Platform: macOS only (gracefully degrades on other platforms)
"""

import sys
from typing import Optional

__all__ = [
    "is_supported",
    "MenuBarApp",
    "IPCServer",
    "IPCClient",
    "CommandStatus",
    "CPUTemperatureMonitor",
    "MemoryMonitor",
]

# Platform detection
IS_MACOS = sys.platform == "darwin"


def is_supported() -> bool:
    """Check if menu bar is supported on current platform"""
    if not IS_MACOS:
        return False

    try:
        import rumps  # noqa: F401
        return True
    except ImportError:
        return False


# Conditional imports for macOS-only modules
if is_supported():
    from .app import MenuBarApp
    from .ipc import IPCServer, IPCClient
    from .status_manager import CommandStatus
    from .monitors import CPUTemperatureMonitor, MemoryMonitor
else:
    # Provide stub classes for non-macOS platforms
    MenuBarApp = None  # type: ignore
    IPCServer = None  # type: ignore
    IPCClient = None  # type: ignore
    CommandStatus = None  # type: ignore
    CPUTemperatureMonitor = None  # type: ignore
    MemoryMonitor = None  # type: ignore
