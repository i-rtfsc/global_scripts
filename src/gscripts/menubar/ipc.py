"""
IPC Communication Module

Provides Unix domain socket-based IPC for CLI ↔ Menu Bar communication.
"""

import asyncio
import json
import os
import socket
from pathlib import Path
from typing import Dict, Any, Optional, Callable
import logging

logger = logging.getLogger(__name__)


def get_socket_path() -> Path:
    """Get Unix socket path"""
    config_dir = Path.home() / ".config" / "global-scripts"
    return config_dir / "menubar.sock"


class IPCClient:
    """IPC client for sending messages from CLI to menu bar"""

    def __init__(self, socket_path: Optional[Path] = None):
        self.socket_path = socket_path or get_socket_path()

    def send_message(self, message: Dict[str, Any], timeout: float = 1.0) -> bool:
        """
        Send message to menu bar app

        Args:
            message: Message dict (will be JSON-encoded)
            timeout: Connection timeout in seconds

        Returns:
            True if sent successfully, False otherwise
        """
        if not self.socket_path.exists():
            logger.debug(f"Socket not found: {self.socket_path}")
            return False

        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            try:
                sock.connect(str(self.socket_path))
                data = json.dumps(message).encode("utf-8")
                sock.sendall(data + b"\n")
                return True
            finally:
                sock.close()

        except (socket.timeout, ConnectionRefusedError, FileNotFoundError) as e:
            logger.debug(f"IPC send failed: {e}")
            return False
        except Exception as e:
            logger.warning(f"Unexpected IPC error: {e}")
            return False

    def send_command_start(self, command: str) -> bool:
        """Send command_start message"""
        import time

        return self.send_message(
            {"type": "command_start", "command": command, "timestamp": time.time()}
        )

    def send_progress_update(self, percentage: int, elapsed: float) -> bool:
        """Send progress_update message"""
        return self.send_message(
            {"type": "progress_update", "percentage": percentage, "elapsed": elapsed}
        )

    def send_command_complete(
        self, success: bool, duration: float, error: Optional[str] = None
    ) -> bool:
        """Send command_complete message"""
        return self.send_message(
            {
                "type": "command_complete",
                "success": success,
                "duration": duration,
                "error": error,
            }
        )


class IPCServer:
    """IPC server for receiving messages in menu bar app"""

    def __init__(
        self, socket_path: Optional[Path] = None, message_handler: Optional[Callable] = None
    ):
        self.socket_path = socket_path or get_socket_path()
        self.message_handler = message_handler or self._default_handler
        self.server: Optional[asyncio.Server] = None
        self._running = False

    def _default_handler(self, message: Dict[str, Any]) -> None:
        """Default message handler (logs messages)"""
        logger.info(f"Received IPC message: {message}")

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle incoming client connection"""
        try:
            # Read message (terminated by newline)
            data = await reader.readline()
            if not data:
                return

            # Decode and parse JSON
            message = json.loads(data.decode("utf-8"))

            # Call handler
            if self.message_handler:
                self.message_handler(message)

        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON message: {e}")
        except Exception as e:
            logger.error(f"Error handling IPC message: {e}", exc_info=True)
        finally:
            writer.close()
            await writer.wait_closed()

    async def start(self) -> None:
        """Start IPC server"""
        if self._running:
            logger.warning("IPC server already running")
            return

        # Remove stale socket file
        if self.socket_path.exists():
            try:
                self.socket_path.unlink()
            except Exception as e:
                logger.warning(f"Failed to remove stale socket: {e}")

        # Ensure parent directory exists
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)

        # Start Unix socket server
        self.server = await asyncio.start_unix_server(
            self.handle_client, path=str(self.socket_path)
        )

        self._running = True
        logger.info(f"IPC server started: {self.socket_path}")

    async def stop(self) -> None:
        """Stop IPC server"""
        if not self._running:
            return

        self._running = False

        if self.server:
            self.server.close()
            await self.server.wait_closed()

        # Clean up socket file
        if self.socket_path.exists():
            try:
                self.socket_path.unlink()
            except Exception as e:
                logger.warning(f"Failed to remove socket: {e}")

        logger.info("IPC server stopped")

    def is_running(self) -> bool:
        """Check if server is running"""
        return self._running
