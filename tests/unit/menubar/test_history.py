"""
Unit tests for CommandHistoryManager
"""

import json
import pytest
import tempfile
import time
from pathlib import Path

from src.gscripts.menubar.history import CommandHistoryManager, HistoryEntry


class TestHistoryEntry:
    """Tests for HistoryEntry dataclass"""

    def test_format_duration_subsecond(self):
        """Test duration formatting for < 1 second"""
        entry = HistoryEntry(
            command="test",
            timestamp=time.time(),
            success=True,
            duration=0.5
        )
        assert entry.format_duration() == "0.5s"

    def test_format_duration_seconds(self):
        """Test duration formatting for seconds"""
        entry = HistoryEntry(
            command="test",
            timestamp=time.time(),
            success=True,
            duration=15.3
        )
        assert entry.format_duration() == "15s"

    def test_format_duration_minutes(self):
        """Test duration formatting for minutes"""
        entry = HistoryEntry(
            command="test",
            timestamp=time.time(),
            success=True,
            duration=135.0  # 2m15s
        )
        assert entry.format_duration() == "2m15s"


class TestCommandHistoryManager:
    """Tests for CommandHistoryManager"""

    @pytest.fixture
    def temp_history_file(self):
        """Create temporary history file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = Path(f.name)
        yield temp_path
        # Cleanup
        if temp_path.exists():
            temp_path.unlink()

    @pytest.fixture
    def history_manager(self, temp_history_file):
        """Create history manager with temp file"""
        return CommandHistoryManager(history_file=temp_history_file, max_entries=50)

    def test_init_creates_manager(self, temp_history_file):
        """Test CommandHistoryManager initialization"""
        manager = CommandHistoryManager(history_file=temp_history_file)
        assert manager.history_file == temp_history_file
        assert manager.max_entries == 50
        assert len(manager) == 0

    def test_add_command_single(self, history_manager):
        """Test adding a single command"""
        history_manager.add_command(
            command="android.build",
            timestamp=time.time(),
            success=True,
            duration=10.5
        )

        assert len(history_manager) == 1

        recent = history_manager.get_recent(limit=1)
        assert len(recent) == 1
        assert recent[0].command == "android.build"
        assert recent[0].success is True
        assert recent[0].duration == 10.5

    def test_add_command_multiple(self, history_manager):
        """Test adding multiple commands"""
        commands = ["cmd1", "cmd2", "cmd3"]

        for cmd in commands:
            history_manager.add_command(
                command=cmd,
                timestamp=time.time(),
                success=True,
                duration=1.0
            )

        assert len(history_manager) == 3

        recent = history_manager.get_recent(limit=10)
        assert len(recent) == 3
        # Most recent first
        assert recent[0].command == "cmd3"
        assert recent[1].command == "cmd2"
        assert recent[2].command == "cmd1"

    def test_add_command_with_error(self, history_manager):
        """Test adding failed command with error"""
        history_manager.add_command(
            command="failing.command",
            timestamp=time.time(),
            success=False,
            duration=0.5,
            error="Command not found"
        )

        recent = history_manager.get_recent(limit=1)
        assert recent[0].success is False
        assert recent[0].error == "Command not found"

    def test_get_recent_limit(self, history_manager):
        """Test get_recent respects limit"""
        # Add 10 commands
        for i in range(10):
            history_manager.add_command(
                command=f"cmd{i}",
                timestamp=time.time(),
                success=True,
                duration=1.0
            )

        # Get only 5 recent
        recent = history_manager.get_recent(limit=5)
        assert len(recent) == 5
        # Verify most recent
        assert recent[0].command == "cmd9"
        assert recent[4].command == "cmd5"

    def test_max_entries_eviction(self, temp_history_file):
        """Test FIFO eviction when exceeding max_entries"""
        manager = CommandHistoryManager(history_file=temp_history_file, max_entries=5)

        # Add 10 commands
        for i in range(10):
            manager.add_command(
                command=f"cmd{i}",
                timestamp=time.time(),
                success=True,
                duration=1.0
            )

        # Should only keep last 5
        assert len(manager) == 5

        recent = manager.get_recent(limit=10)
        assert len(recent) == 5
        # Oldest kept should be cmd5
        assert recent[4].command == "cmd5"
        # Newest should be cmd9
        assert recent[0].command == "cmd9"

    def test_clear(self, history_manager):
        """Test clearing history"""
        # Add some commands
        for i in range(5):
            history_manager.add_command(
                command=f"cmd{i}",
                timestamp=time.time(),
                success=True,
                duration=1.0
            )

        assert len(history_manager) == 5

        # Clear
        history_manager.clear()

        assert len(history_manager) == 0
        assert history_manager.get_recent() == []

    def test_save_and_load(self, temp_history_file):
        """Test persistence - save and load"""
        # Create manager and add commands
        manager1 = CommandHistoryManager(history_file=temp_history_file)
        manager1.add_command("cmd1", time.time(), True, 1.0)
        manager1.add_command("cmd2", time.time(), False, 2.0, "Error")

        # Create new manager with same file
        manager2 = CommandHistoryManager(history_file=temp_history_file)

        # Should load previous data
        assert len(manager2) == 2
        recent = manager2.get_recent()
        assert recent[0].command == "cmd2"
        assert recent[0].success is False
        assert recent[1].command == "cmd1"
        assert recent[1].success is True

    def test_load_nonexistent_file(self, temp_history_file):
        """Test loading when file doesn't exist"""
        temp_history_file.unlink()  # Remove file

        manager = CommandHistoryManager(history_file=temp_history_file)
        assert len(manager) == 0

    def test_load_invalid_json(self, temp_history_file):
        """Test loading corrupted JSON file"""
        # Write invalid JSON
        temp_history_file.write_text("{ invalid json }")

        # Should gracefully handle and start fresh
        manager = CommandHistoryManager(history_file=temp_history_file)
        assert len(manager) == 0

    def test_load_invalid_schema(self, temp_history_file):
        """Test loading file with invalid schema"""
        # Write valid JSON but wrong schema
        temp_history_file.write_text('{"wrong": "schema"}')

        # Should gracefully handle and start fresh
        manager = CommandHistoryManager(history_file=temp_history_file)
        assert len(manager) == 0

    def test_atomic_write(self, temp_history_file):
        """Test that save uses atomic writes"""
        manager = CommandHistoryManager(history_file=temp_history_file)
        manager.add_command("test", time.time(), True, 1.0)

        # Temp file should not exist after save
        temp_file = temp_history_file.with_suffix('.json.tmp')
        assert not temp_file.exists()

        # History file should exist and be valid
        assert temp_history_file.exists()
        data = json.loads(temp_history_file.read_text())
        assert 'version' in data
        assert 'commands' in data
        assert len(data['commands']) == 1

    def test_thread_safety(self, history_manager):
        """Test concurrent access (basic thread safety test)"""
        import threading

        def add_commands(prefix):
            for i in range(10):
                history_manager.add_command(
                    command=f"{prefix}_{i}",
                    timestamp=time.time(),
                    success=True,
                    duration=1.0
                )

        # Run two threads concurrently
        thread1 = threading.Thread(target=add_commands, args=("thread1",))
        thread2 = threading.Thread(target=add_commands, args=("thread2",))

        thread1.start()
        thread2.start()

        thread1.join()
        thread2.join()

        # Should have 20 commands total
        assert len(history_manager) == 20
