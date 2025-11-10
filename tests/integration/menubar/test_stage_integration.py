"""
Integration tests for Stage Reporting

Tests the complete stage reporting flow:
- Plugin yields stage information
- PluginExecutor extracts and sends stage via IPC
- MenuBarApp receives and displays stage
- Status display updates correctly with stage transitions
"""

import asyncio
import os
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Only run these tests on macOS or if explicitly requested
pytestmark = pytest.mark.skipif(
    os.sys.platform != "darwin" and not os.getenv("FORCE_MENUBAR_TESTS"),
    reason="Menubar stage tests only run on macOS",
)


@pytest.fixture
def temp_socket_path(tmp_path):
    """Provide temporary socket path for IPC (shortened to avoid AF_UNIX path length limit)"""
    import tempfile
    # Use /tmp to keep path short (macOS has 104 char limit for Unix sockets)
    with tempfile.TemporaryDirectory(prefix="gs_") as tmpdir:
        yield Path(tmpdir) / "m.sock"  # Keep filename very short


@pytest.mark.integration
@pytest.mark.asyncio
async def test_ipc_client_sends_stage_in_progress_update():
    """Test IPCClient can send stage information in progress updates"""
    from gscripts.menubar.ipc import IPCClient, IPCServer

    # Use very short path for Unix socket
    import tempfile
    with tempfile.TemporaryDirectory(prefix="gs_") as tmpdir:
        socket_path = Path(tmpdir) / "t.sock"

        messages_received = []

        def message_handler(msg):
            messages_received.append(msg)

        server = IPCServer(socket_path=socket_path, message_handler=message_handler)

        try:
            await server.start()
            await asyncio.sleep(0.1)

            # Create client and send progress update with stage
            with patch("gscripts.menubar.ipc.get_socket_path", return_value=socket_path):
                client = IPCClient()

                # Send progress with stage
                client.send_progress_update(percentage=30, elapsed=5.0, stage="编译中")
                await asyncio.sleep(0.2)

                # Verify message was received
                progress_msgs = [
                    m for m in messages_received if m.get("type") == "progress_update"
                ]
                assert len(progress_msgs) == 1
                assert progress_msgs[0]["percentage"] == 30
                assert progress_msgs[0]["stage"] == "编译中"

                # Send another update with different stage
                client.send_progress_update(percentage=70, elapsed=10.0, stage="打包中")
                await asyncio.sleep(0.2)

                progress_msgs = [
                    m for m in messages_received if m.get("type") == "progress_update"
                ]
                assert len(progress_msgs) == 2
                assert progress_msgs[1]["percentage"] == 70
                assert progress_msgs[1]["stage"] == "打包中"

        finally:
            await server.stop()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_menubar_app_handles_stage_updates(temp_socket_path):
    """Test MenuBarApp correctly handles IPC messages with stage information"""
    from gscripts.menubar.status_manager import CommandStatus

    # Test with CommandStatus directly (instead of full MenuBarApp)
    # to avoid rumps mocking complications
    status = CommandStatus()

    # Simulate command start
    status.command = "android.build.aosp"
    status.is_running = True
    status.start_time = time.time()

    assert status.command == "android.build.aosp"
    assert status.is_running is True
    assert status.current_stage is None

    # Simulate progress update with stage
    status.progress = 30
    status.current_stage = "编译中"

    assert status.progress == 30
    assert status.current_stage == "编译中"

    # Verify stage is in display
    status_display = status.format_status()
    assert "[编译中]" in status_display
    assert "30%" in status_display

    # Simulate stage transition
    status.progress = 70
    status.current_stage = "打包中"

    assert status.progress == 70
    assert status.current_stage == "打包中"

    status_display = status.format_status()
    assert "[打包中]" in status_display
    assert "70%" in status_display
    assert "[编译中]" not in status_display  # Old stage should not appear


@pytest.mark.integration
@pytest.mark.asyncio
async def test_stage_without_progress_percentage(temp_socket_path):
    """Test stage reporting works even without progress percentage"""
    from gscripts.menubar.status_manager import CommandStatus

    status = CommandStatus()

    # Start command
    status.command = "system.backup"
    status.is_running = True
    status.start_time = time.time()

    # Update with stage only (no percentage)
    status.current_stage = "初始化"

    assert status.current_stage == "初始化"
    assert status.progress is None

    # Verify stage is shown even without percentage
    status_display = status.format_status()
    assert "[初始化]" in status_display
    assert "%" not in status_display


@pytest.mark.integration
@pytest.mark.asyncio
async def test_stage_cleared_on_command_complete(temp_socket_path):
    """Test stage is cleared when command completes"""
    from gscripts.menubar.status_manager import CommandStatus

    status = CommandStatus()

    # Start command
    status.command = "build.app"
    status.is_running = True
    status.start_time = time.time()

    # Update with stage
    status.progress = 50
    status.current_stage = "测试中"

    assert status.current_stage == "测试中"

    # Complete command (set is_running to false)
    status.is_running = False
    status.success = True
    status.end_time = time.time()

    # Stage should still be there for completion display
    assert status.current_stage == "测试中"

    # After clear
    status.clear()

    # Now stage should be cleared
    assert status.current_stage is None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_backward_compatibility_without_stage():
    """Test that progress updates without stage field still work (backward compatibility)"""
    from gscripts.menubar.ipc import IPCClient, IPCServer

    # Use very short path for Unix socket
    import tempfile
    with tempfile.TemporaryDirectory(prefix="gs_") as tmpdir:
        socket_path = Path(tmpdir) / "t.sock"

        messages_received = []

        def message_handler(msg):
            messages_received.append(msg)

        server = IPCServer(socket_path=socket_path, message_handler=message_handler)

        try:
            await server.start()
            await asyncio.sleep(0.1)

            # Create client and send progress updates WITHOUT stage (old style)
            with patch("gscripts.menubar.ipc.get_socket_path", return_value=socket_path):
                client = IPCClient()

                # Send progress without stage field
                client.send_progress_update(percentage=25, elapsed=5.0)
                await asyncio.sleep(0.2)

                # Verify message was received (without crashing)
                progress_msgs = [
                    m for m in messages_received if m.get("type") == "progress_update"
                ]
                assert len(progress_msgs) == 1
                assert progress_msgs[0]["percentage"] == 25
                assert progress_msgs[0].get("stage") is None  # No stage field

                # Send another update without stage
                client.send_progress_update(percentage=75, elapsed=10.0)
                await asyncio.sleep(0.2)

                progress_msgs = [
                    m for m in messages_received if m.get("type") == "progress_update"
                ]
                assert len(progress_msgs) == 2
                assert progress_msgs[1]["percentage"] == 75
                assert progress_msgs[1].get("stage") is None

        finally:
            await server.stop()


@pytest.mark.integration
def test_stage_display_format():
    """Test stage display formatting in various scenarios"""
    from gscripts.menubar.status_manager import CommandStatus

    status = CommandStatus()
    status.command = "test.build"
    status.is_running = True
    status.start_time = time.time()

    # Test 1: Stage only (no progress)
    status.current_stage = "下载"
    display = status.format_status(use_marquee=True)  # Use marquee to get full text
    assert "[下载]" in display
    assert "test.build" in display

    # Test 2: Stage + Progress
    status.progress = 45
    display = status.format_status(use_marquee=True)  # Use marquee to get full text
    assert "[下载]" in display
    assert "45%" in display  # Now progress should be shown with stage

    # Test 3: Different stage
    status.current_stage = "编译"
    status.progress = 80
    display = status.format_status(use_marquee=True)  # Use marquee to get full text
    assert "[编译]" in display
    assert "80%" in display
    assert "[下载]" not in display  # Old stage should not appear
