"""
Unit tests for menubar IPC module
"""

import asyncio
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Only run these tests on macOS or if explicitly requested
pytestmark = pytest.mark.skipif(
    os.sys.platform != "darwin" and not os.getenv("FORCE_MENUBAR_TESTS"),
    reason="Menubar tests only run on macOS",
)


@pytest.fixture
def temp_socket_path(tmp_path):
    """Provide temporary socket path"""
    return tmp_path / "test_menubar.sock"


class TestIPCClient:
    """Tests for IPCClient"""

    @pytest.mark.unit
    def test_send_message_socket_not_found(self, temp_socket_path):
        """Test send_message when socket doesn't exist"""
        from gscripts.menubar.ipc import IPCClient

        client = IPCClient(socket_path=temp_socket_path)
        result = client.send_message({"type": "test"})

        assert result is False

    @pytest.mark.unit
    def test_send_command_start(self, temp_socket_path):
        """Test send_command_start constructs correct message"""
        from gscripts.menubar.ipc import IPCClient

        client = IPCClient(socket_path=temp_socket_path)

        with patch.object(client, "send_message") as mock_send:
            mock_send.return_value = True
            result = client.send_command_start("android.adb.devices")

            assert result is True
            mock_send.assert_called_once()
            args = mock_send.call_args[0]
            message = args[0]

            assert message["type"] == "command_start"
            assert message["command"] == "android.adb.devices"
            assert "timestamp" in message

    @pytest.mark.unit
    def test_send_progress_update(self, temp_socket_path):
        """Test send_progress_update constructs correct message"""
        from gscripts.menubar.ipc import IPCClient

        client = IPCClient(socket_path=temp_socket_path)

        with patch.object(client, "send_message") as mock_send:
            mock_send.return_value = True
            result = client.send_progress_update(45, 15.3)

            assert result is True
            mock_send.assert_called_once_with(
                {"type": "progress_update", "percentage": 45, "elapsed": 15.3}
            )

    @pytest.mark.unit
    def test_send_command_complete_success(self, temp_socket_path):
        """Test send_command_complete for successful command"""
        from gscripts.menubar.ipc import IPCClient

        client = IPCClient(socket_path=temp_socket_path)

        with patch.object(client, "send_message") as mock_send:
            mock_send.return_value = True
            result = client.send_command_complete(True, 1.23)

            assert result is True
            mock_send.assert_called_once_with(
                {"type": "command_complete", "success": True, "duration": 1.23, "error": None}
            )

    @pytest.mark.unit
    def test_send_command_complete_failure(self, temp_socket_path):
        """Test send_command_complete for failed command"""
        from gscripts.menubar.ipc import IPCClient

        client = IPCClient(socket_path=temp_socket_path)

        with patch.object(client, "send_message") as mock_send:
            mock_send.return_value = True
            result = client.send_command_complete(False, 0.5, "Error message")

            assert result is True
            mock_send.assert_called_once_with(
                {
                    "type": "command_complete",
                    "success": False,
                    "duration": 0.5,
                    "error": "Error message",
                }
            )


class TestIPCServer:
    """Tests for IPCServer"""

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_server_start_creates_socket(self, temp_socket_path):
        """Test server start creates socket file"""
        from gscripts.menubar.ipc import IPCServer

        server = IPCServer(socket_path=temp_socket_path)

        try:
            await server.start()

            assert temp_socket_path.exists()
            assert server.is_running()
        finally:
            await server.stop()

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_server_stop_removes_socket(self, temp_socket_path):
        """Test server stop removes socket file"""
        from gscripts.menubar.ipc import IPCServer

        server = IPCServer(socket_path=temp_socket_path)

        await server.start()
        assert temp_socket_path.exists()

        await server.stop()
        assert not temp_socket_path.exists()
        assert not server.is_running()

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_server_handles_message(self, temp_socket_path):
        """Test server receives and handles messages"""
        from gscripts.menubar.ipc import IPCServer, IPCClient

        messages_received = []

        def handler(message):
            messages_received.append(message)

        server = IPCServer(socket_path=temp_socket_path, message_handler=handler)

        try:
            await server.start()

            # Give server time to start listening
            await asyncio.sleep(0.1)

            # Send message from client
            client = IPCClient(socket_path=temp_socket_path)
            result = client.send_message({"type": "test", "data": "hello"})

            assert result is True

            # Give server time to process
            await asyncio.sleep(0.1)

            # Verify message was received
            assert len(messages_received) == 1
            assert messages_received[0]["type"] == "test"
            assert messages_received[0]["data"] == "hello"
        finally:
            await server.stop()

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_server_handles_invalid_json(self, temp_socket_path):
        """Test server gracefully handles invalid JSON"""
        from gscripts.menubar.ipc import IPCServer

        messages_received = []

        def handler(message):
            messages_received.append(message)

        server = IPCServer(socket_path=temp_socket_path, message_handler=handler)

        try:
            await server.start()
            await asyncio.sleep(0.1)

            # Send invalid JSON manually
            import socket as sock
            client_sock = sock.socket(sock.AF_UNIX, sock.SOCK_STREAM)
            client_sock.connect(str(temp_socket_path))
            client_sock.sendall(b"invalid json\n")
            client_sock.close()

            await asyncio.sleep(0.1)

            # Should not crash, no messages received
            assert len(messages_received) == 0
        finally:
            await server.stop()

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_server_removes_stale_socket(self, temp_socket_path):
        """Test server removes stale socket on start"""
        from gscripts.menubar.ipc import IPCServer

        # Create stale socket file
        temp_socket_path.parent.mkdir(parents=True, exist_ok=True)
        temp_socket_path.touch()

        server = IPCServer(socket_path=temp_socket_path)

        try:
            await server.start()

            # Should have removed stale socket and created new one
            assert temp_socket_path.exists()
            assert server.is_running()
        finally:
            await server.stop()
