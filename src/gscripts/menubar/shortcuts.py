"""
Shortcuts Manager

Manages user-defined command shortcuts for the menu bar.
"""

import logging
import subprocess
from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Callable
from enum import Enum

logger = logging.getLogger(__name__)


class ExecutionMode(Enum):
    """Shortcut execution mode"""

    TERMINAL = "terminal"  # Open in Terminal.app
    BACKGROUND = "background"  # Run in background


@dataclass
class Shortcut:
    """Shortcut configuration"""

    label: str  # Display label in menu
    command: str  # Command to execute
    execution_mode: ExecutionMode  # How to execute

    def __post_init__(self):
        """Validate shortcut after initialization"""
        if not self.label:
            raise ValueError("Shortcut label cannot be empty")
        if not self.command:
            raise ValueError("Shortcut command cannot be empty")


class ShortcutManager:
    """
    Manages command shortcuts

    Features:
    - Load shortcuts from configuration
    - Validate shortcut definitions
    - Execute shortcuts in terminal or background mode
    - Hot-reload configuration
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        on_background_start: Optional[Callable[[str, str], None]] = None,
        on_background_complete: Optional[Callable[[bool, float, Optional[str]], None]] = None,
    ):
        """
        Initialize shortcut manager

        Args:
            config: Menu bar configuration dict
            on_background_start: Callback when background shortcut starts (label, command)
            on_background_complete: Callback when background shortcut completes (success, duration, error)
        """
        self.config = config or {}
        self.on_background_start = on_background_start
        self.on_background_complete = on_background_complete
        self._shortcuts: Dict[str, Shortcut] = {}
        self._load_shortcuts()

    def _load_shortcuts(self) -> None:
        """Load shortcuts from configuration"""
        self._shortcuts.clear()

        # Check if shortcuts are enabled
        if not self.config.get("enable_shortcuts", False):
            logger.info("Shortcuts disabled in configuration")
            return

        # Load shortcut definitions
        shortcuts_config = self.config.get("shortcuts", {})

        if not shortcuts_config:
            logger.info("No shortcuts defined in configuration")
            return

        # Parse and validate each shortcut
        for label, shortcut_def in shortcuts_config.items():
            try:
                self._load_shortcut(label, shortcut_def)
            except Exception as e:
                logger.warning(f"Failed to load shortcut '{label}': {e}")
                continue

        logger.info(f"Loaded {len(self._shortcuts)} shortcuts")

    def _load_shortcut(self, label: str, shortcut_def: Dict[str, Any]) -> None:
        """
        Load and validate a single shortcut

        Args:
            label: Shortcut display label
            shortcut_def: Shortcut definition dict

        Raises:
            ValueError: If shortcut is invalid
        """
        # Validate required fields
        if not isinstance(shortcut_def, dict):
            raise ValueError("Shortcut definition must be a dictionary")

        command = shortcut_def.get("command")
        if not command or not isinstance(command, str) or not command.strip():
            raise ValueError("Shortcut must have a non-empty 'command' field")

        execution_mode_str = shortcut_def.get("execution_mode")
        if not execution_mode_str:
            raise ValueError("Shortcut must have 'execution_mode' field")

        # Parse execution mode
        try:
            execution_mode = ExecutionMode(execution_mode_str)
        except ValueError:
            raise ValueError(
                f"Invalid execution_mode '{execution_mode_str}'. "
                f"Must be one of: {', '.join(e.value for e in ExecutionMode)}"
            )

        # Warn about dangerous commands (but don't block)
        self._check_dangerous_command(label, command)

        # Create shortcut
        shortcut = Shortcut(
            label=label, command=command.strip(), execution_mode=execution_mode
        )

        self._shortcuts[label] = shortcut
        logger.debug(f"Loaded shortcut: {label} -> {command} ({execution_mode.value})")

    def _check_dangerous_command(self, label: str, command: str) -> None:
        """
        Check if command contains dangerous operations (log warning, don't block)

        Args:
            label: Shortcut label
            command: Command string
        """
        dangerous_patterns = [
            "rm -rf",
            "rm -fr",
            "dd if=",
            "mkfs",
            "format",
            ":(){:|:&};:",  # Fork bomb
            "> /dev/sd",
            "chmod -R 777",
        ]

        for pattern in dangerous_patterns:
            if pattern in command:
                logger.warning(
                    f"Shortcut '{label}' contains potentially dangerous command: '{pattern}'"
                )
                break

    def get_shortcuts(self) -> Dict[str, Shortcut]:
        """
        Get all loaded shortcuts

        Returns:
            Dict mapping label to Shortcut
        """
        return self._shortcuts.copy()

    def get_sorted_labels(self) -> List[str]:
        """
        Get shortcut labels sorted alphabetically

        Returns:
            List of shortcut labels
        """
        return sorted(self._shortcuts.keys())

    def execute_shortcut(self, label: str) -> bool:
        """
        Execute a shortcut by label

        Args:
            label: Shortcut label

        Returns:
            True if execution started successfully, False otherwise
        """
        if label not in self._shortcuts:
            logger.error(f"Shortcut '{label}' not found")
            return False

        shortcut = self._shortcuts[label]

        try:
            if shortcut.execution_mode == ExecutionMode.TERMINAL:
                return self._execute_terminal(shortcut)
            elif shortcut.execution_mode == ExecutionMode.BACKGROUND:
                return self._execute_background(shortcut)
            else:
                logger.error(f"Unknown execution mode: {shortcut.execution_mode}")
                return False
        except Exception as e:
            logger.error(f"Failed to execute shortcut '{label}': {e}", exc_info=True)
            return False

    def _execute_terminal(self, shortcut: Shortcut) -> bool:
        """
        Execute shortcut in Terminal.app

        Args:
            shortcut: Shortcut to execute

        Returns:
            True if terminal opened successfully
        """
        # Escape single quotes in command for AppleScript
        escaped_command = shortcut.command.replace("'", "'\\''")

        # Build AppleScript to open Terminal and run command
        applescript = f'tell application "Terminal" to do script "{escaped_command}"'

        try:
            subprocess.run(
                ["osascript", "-e", applescript],
                check=True,
                capture_output=True,
                text=True,
            )
            logger.info(f"Opened terminal for shortcut: {shortcut.label}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(
                f"Failed to open terminal for '{shortcut.label}': {e.stderr}", exc_info=True
            )
            return False

    def _execute_background(self, shortcut: Shortcut) -> bool:
        """
        Execute shortcut in background

        Args:
            shortcut: Shortcut to execute

        Returns:
            True if background process started successfully
        """
        import time
        import threading

        # Notify start
        if self.on_background_start:
            self.on_background_start(shortcut.label, shortcut.command)

        start_time = time.time()

        def run_background():
            """Background thread to execute command"""
            try:
                # Execute command in shell
                result = subprocess.run(
                    shortcut.command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=300,  # 5 minute timeout
                )

                duration = time.time() - start_time
                success = result.returncode == 0

                # Notify completion
                if self.on_background_complete:
                    error = None if success else result.stderr or f"Exit code: {result.returncode}"
                    self.on_background_complete(success, duration, error)

                if success:
                    logger.info(
                        f"Background shortcut '{shortcut.label}' completed successfully in {duration:.1f}s"
                    )
                else:
                    logger.error(
                        f"Background shortcut '{shortcut.label}' failed after {duration:.1f}s: {result.stderr}"
                    )

            except subprocess.TimeoutExpired:
                duration = time.time() - start_time
                logger.error(f"Background shortcut '{shortcut.label}' timed out after {duration:.1f}s")
                if self.on_background_complete:
                    self.on_background_complete(False, duration, "Command timed out")

            except Exception as e:
                duration = time.time() - start_time
                logger.error(
                    f"Background shortcut '{shortcut.label}' failed: {e}", exc_info=True
                )
                if self.on_background_complete:
                    self.on_background_complete(False, duration, str(e))

        # Start background thread
        thread = threading.Thread(target=run_background, daemon=True, name=f"Shortcut-{shortcut.label}")
        thread.start()

        logger.info(f"Started background shortcut: {shortcut.label}")
        return True

    def reload_config(self, new_config: Dict[str, Any]) -> int:
        """
        Reload shortcuts from new configuration

        Args:
            new_config: New menu bar configuration dict

        Returns:
            Number of shortcuts loaded
        """
        self.config = new_config
        self._load_shortcuts()
        return len(self._shortcuts)

    def is_enabled(self) -> bool:
        """
        Check if shortcuts feature is enabled

        Returns:
            True if enabled and shortcuts are defined
        """
        return self.config.get("enable_shortcuts", False) and len(self._shortcuts) > 0


__all__ = ["ShortcutManager", "Shortcut", "ExecutionMode"]
