"""
Unit tests for menubar status_manager module
"""

import pytest
import time


class TestCommandStatus:
    """Tests for CommandStatus dataclass"""

    @pytest.mark.unit
    def test_initial_state(self):
        """Test CommandStatus initial state"""
        from gscripts.menubar.status_manager import CommandStatus

        status = CommandStatus()

        assert status.command == ""
        assert status.is_running is False
        assert status.progress is None
        assert status.start_time is None
        assert status.end_time is None
        assert status.success is None
        assert status.error is None

    @pytest.mark.unit
    def test_format_idle_status(self):
        """Test format_status when idle"""
        from gscripts.menubar.status_manager import CommandStatus

        status = CommandStatus()
        result = status.format_status()

        assert result == "GS"

    @pytest.mark.unit
    def test_format_running_without_progress(self):
        """Test format_status when running without progress"""
        from gscripts.menubar.status_manager import CommandStatus

        status = CommandStatus()
        status.command = "android.adb.devices"
        status.is_running = True
        status.start_time = time.time() - 5.0  # Started 5 seconds ago

        result = status.format_status()

        assert result.startswith("GS android.adb")  # Note: no colon after GS
        assert "5s" in result or "4s" in result  # Allow for timing variance
        assert "%" not in result  # No progress percentage

    @pytest.mark.unit
    def test_format_running_with_progress(self):
        """Test format_status when running with progress"""
        from gscripts.menubar.status_manager import CommandStatus

        status = CommandStatus()
        status.command = "android.build.aosp"
        status.is_running = True
        status.start_time = time.time() - 135.0  # Started 2m15s ago
        status.progress = 45

        result = status.format_status()

        assert result.startswith("GS android.build")  # Note: no colon after GS
        assert "45%" in result
        assert "2m" in result  # Should show minutes

    @pytest.mark.unit
    def test_format_success(self):
        """Test format_status when command succeeded"""
        from gscripts.menubar.status_manager import CommandStatus

        status = CommandStatus()
        status.command = "system.prompt.set"
        status.is_running = False
        status.success = True
        status.start_time = time.time() - 1.23
        status.end_time = time.time()

        result = status.format_status()

        assert "✓" in result
        assert "system.prompt" in result
        assert "s" in result  # Should show duration

    @pytest.mark.unit
    def test_format_failure(self):
        """Test format_status when command failed"""
        from gscripts.menubar.status_manager import CommandStatus

        status = CommandStatus()
        status.command = "android.build.aosp"
        status.is_running = False
        status.success = False
        status.start_time = time.time() - 30.0
        status.end_time = time.time()
        status.error = "Build failed"

        result = status.format_status()

        assert "✗" in result
        assert "android.build" in result
        assert "30s" in result or "29s" in result

    @pytest.mark.unit
    def test_format_duration_seconds(self):
        """Test format_duration for seconds"""
        from gscripts.menubar.status_manager import CommandStatus

        status = CommandStatus()

        assert status.format_duration(0.5) == "0.5s"
        assert status.format_duration(1.23) == "1s"  # >= 1s rounds to int
        assert status.format_duration(5.0) == "5s"
        assert status.format_duration(59.9) == "59s"

    @pytest.mark.unit
    def test_format_duration_minutes(self):
        """Test format_duration for minutes"""
        from gscripts.menubar.status_manager import CommandStatus

        status = CommandStatus()

        assert status.format_duration(60.0) == "1m00s"
        assert status.format_duration(125.0) == "2m05s"
        assert status.format_duration(135.0) == "2m15s"

    @pytest.mark.unit
    def test_get_elapsed_time(self):
        """Test get_elapsed_time calculation"""
        from gscripts.menubar.status_manager import CommandStatus

        status = CommandStatus()
        status.start_time = time.time() - 10.0

        elapsed = status.get_elapsed_time()

        assert 9.5 < elapsed < 10.5  # Allow for timing variance

    @pytest.mark.unit
    def test_get_elapsed_time_with_end_time(self):
        """Test get_elapsed_time when command completed"""
        from gscripts.menubar.status_manager import CommandStatus

        status = CommandStatus()
        start = time.time()
        status.start_time = start
        status.end_time = start + 5.0

        elapsed = status.get_elapsed_time()

        assert 4.9 < elapsed < 5.1

    @pytest.mark.unit
    def test_get_elapsed_time_no_start(self):
        """Test get_elapsed_time when never started"""
        from gscripts.menubar.status_manager import CommandStatus

        status = CommandStatus()
        elapsed = status.get_elapsed_time()

        assert elapsed == 0.0

    @pytest.mark.unit
    def test_clear(self):
        """Test clear resets all fields"""
        from gscripts.menubar.status_manager import CommandStatus

        status = CommandStatus()
        status.command = "test.command"
        status.is_running = True
        status.progress = 50
        status.start_time = time.time()
        status.success = True
        status.error = "Some error"

        status.clear()

        assert status.command == ""
        assert status.is_running is False
        assert status.progress is None
        assert status.start_time is None
        assert status.end_time is None
        assert status.success is None
        assert status.error is None

    @pytest.mark.unit
    def test_command_name_truncation(self):
        """Test command name is truncated correctly"""
        from gscripts.menubar.status_manager import CommandStatus

        status = CommandStatus()
        status.command = "very.long.plugin.name.with.many.parts"
        status.is_running = True
        status.start_time = time.time()

        result = status.format_status()

        # Should only show first two parts
        assert "very.long" in result
        assert "plugin.name" not in result

    @pytest.mark.unit
    def test_initial_state_includes_current_stage(self):
        """Test CommandStatus includes current_stage field"""
        from gscripts.menubar.status_manager import CommandStatus

        status = CommandStatus()

        assert status.current_stage is None

    @pytest.mark.unit
    def test_format_running_with_stage(self):
        """Test format_status shows stage when running with stage"""
        from gscripts.menubar.status_manager import CommandStatus

        status = CommandStatus()
        status.command = "android.build.aosp"
        status.is_running = True
        status.start_time = time.time() - 10.0
        status.current_stage = "编译中"

        result = status.format_status()

        assert "[编译中]" in result
        assert "android.build" in result
        assert "10s" in result or "9s" in result

    @pytest.mark.unit
    def test_format_running_with_stage_and_progress(self):
        """Test format_status shows stage and progress together"""
        from gscripts.menubar.status_manager import CommandStatus

        status = CommandStatus()
        status.command = "system.upgrade"
        status.is_running = True
        status.start_time = time.time() - 60.0
        status.current_stage = "下载中"
        status.progress = 35

        result = status.format_status()

        assert "[下载中]" in result
        assert "35%" in result
        assert "system.upgrade" in result
        assert "1m" in result

    @pytest.mark.unit
    def test_format_stage_priority_over_output(self):
        """Test stage has priority over output in display"""
        from gscripts.menubar.status_manager import CommandStatus

        status = CommandStatus()
        status.command = "test.command"
        status.is_running = True
        status.start_time = time.time()
        status.current_stage = "准备中"
        status.output = "Some output"  # Should be ignored when stage is present

        result = status.format_status()

        assert "[准备中]" in result
        # output should not be shown when stage is present
        assert "Some output" not in result

    @pytest.mark.unit
    def test_clear_resets_current_stage(self):
        """Test clear() resets current_stage"""
        from gscripts.menubar.status_manager import CommandStatus

        status = CommandStatus()
        status.command = "test.command"
        status.current_stage = "编译中"
        status.is_running = True

        status.clear()

        assert status.current_stage is None
        assert status.command == ""
        assert status.is_running is False

    @pytest.mark.unit
    def test_multiple_stage_transitions(self):
        """Test status display updates correctly through multiple stages"""
        from gscripts.menubar.status_manager import CommandStatus

        status = CommandStatus()
        status.command = "build.project"
        status.is_running = True
        status.start_time = time.time()

        # Stage 1: Preparing
        status.current_stage = "准备中"
        status.progress = 10
        result1 = status.format_status()
        assert "[准备中]" in result1
        assert "10%" in result1

        # Stage 2: Compiling
        status.current_stage = "编译中"
        status.progress = 50
        result2 = status.format_status()
        assert "[编译中]" in result2
        assert "50%" in result2
        assert "[准备中]" not in result2  # Previous stage should not appear

        # Stage 3: Packaging
        status.current_stage = "打包中"
        status.progress = 90
        result3 = status.format_status()
        assert "[打包中]" in result3
        assert "90%" in result3
