"""
Command History Manager

Manages persistent command history for menu bar replay functionality.
"""

import json
import logging
import os
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional
from threading import Lock

logger = logging.getLogger(__name__)


@dataclass
class HistoryEntry:
    """Represents a single command history entry"""
    command: str
    timestamp: float
    success: bool
    duration: float
    error: Optional[str] = None

    def format_duration(self) -> str:
        """Format duration as human-readable string"""
        if self.duration < 1:
            return f"{self.duration:.1f}s"
        elif self.duration < 60:
            return f"{int(self.duration)}s"
        else:
            minutes = int(self.duration // 60)
            secs = int(self.duration % 60)
            return f"{minutes}m{secs:02d}s"


class CommandHistoryManager:
    """
    Manages command execution history with persistent storage.

    Features:
    - Persistent JSON storage (~/.config/global-scripts/menubar_history.json)
    - Atomic writes to prevent corruption
    - FIFO eviction (max 50 entries)
    - Thread-safe operations
    """

    def __init__(self, history_file: Optional[Path] = None, max_entries: int = 50):
        """
        Initialize history manager.

        Args:
            history_file: Path to history JSON file (default: ~/.config/global-scripts/menubar_history.json)
            max_entries: Maximum number of entries to keep (default: 50)
        """
        if history_file is None:
            config_dir = Path.home() / ".config" / "global-scripts"
            config_dir.mkdir(parents=True, exist_ok=True)
            history_file = config_dir / "menubar_history.json"

        self.history_file = history_file
        self.max_entries = max_entries
        self._entries: List[HistoryEntry] = []
        self._lock = Lock()

        # Load existing history
        self.load()

    def add_command(
        self,
        command: str,
        timestamp: float,
        success: bool,
        duration: float,
        error: Optional[str] = None
    ) -> None:
        """
        Add a command to history.

        Args:
            command: Command name (e.g., "android.build")
            timestamp: Unix timestamp when command started
            success: Whether command completed successfully
            duration: Execution duration in seconds
            error: Error message if command failed
        """
        with self._lock:
            entry = HistoryEntry(
                command=command,
                timestamp=timestamp,
                success=success,
                duration=duration,
                error=error
            )

            # Add to beginning (most recent first)
            self._entries.insert(0, entry)

            # Evict oldest if exceeds limit
            if len(self._entries) > self.max_entries:
                self._entries = self._entries[:self.max_entries]

            # Persist to disk
            self.save()

            logger.debug(
                f"Added to history: {command} (success={success}, duration={duration:.2f}s)"
            )

    def get_recent(self, limit: int = 5) -> List[HistoryEntry]:
        """
        Get recent command history.

        Args:
            limit: Maximum number of entries to return

        Returns:
            List of recent HistoryEntry objects (most recent first)
        """
        with self._lock:
            return self._entries[:limit]

    def clear(self) -> None:
        """Clear all history entries."""
        with self._lock:
            self._entries = []
            self.save()
            logger.info("History cleared")

    def load(self) -> None:
        """Load history from JSON file."""
        if not self.history_file.exists():
            logger.debug(f"History file not found: {self.history_file}")
            return

        try:
            with open(self.history_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Validate schema
            if not isinstance(data, dict) or 'commands' not in data:
                logger.warning("Invalid history file format, starting fresh")
                return

            # Parse entries
            entries = []
            for item in data.get('commands', []):
                try:
                    entry = HistoryEntry(
                        command=item['command'],
                        timestamp=item['timestamp'],
                        success=item['success'],
                        duration=item['duration'],
                        error=item.get('error')
                    )
                    entries.append(entry)
                except (KeyError, TypeError) as e:
                    logger.warning(f"Skipping invalid history entry: {e}")
                    continue

            with self._lock:
                self._entries = entries[:self.max_entries]

            logger.info(f"Loaded {len(self._entries)} history entries")

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse history file: {e}")
            logger.warning("Starting with empty history")
        except Exception as e:
            logger.error(f"Failed to load history: {e}", exc_info=True)

    def save(self) -> None:
        """Save history to JSON file with atomic write."""
        try:
            # Prepare data
            data = {
                'version': '1.0',
                'commands': [asdict(entry) for entry in self._entries]
            }

            # Write to temporary file
            temp_file = self.history_file.with_suffix('.json.tmp')
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())  # Ensure data is written to disk

            # Atomic rename
            temp_file.replace(self.history_file)

            logger.debug(f"Saved {len(self._entries)} history entries")

        except Exception as e:
            logger.error(f"Failed to save history: {e}", exc_info=True)

    def __len__(self) -> int:
        """Return number of entries in history."""
        with self._lock:
            return len(self._entries)
