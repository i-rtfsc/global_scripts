"""
Menu Bar Application

Main rumps application for macOS menu bar status indicator.
"""

import asyncio
import os
import threading
import time
import logging
from pathlib import Path
from typing import Dict, Any, Optional

import rumps

from .status_manager import CommandStatus
from .monitors import CPUTemperatureMonitor, MemoryMonitor
from .ipc import IPCServer, get_socket_path
from .sentence_api import get_sentence_api, SentenceType
from .icon import MENUBAR_ICON

logger = logging.getLogger(__name__)


class MenuBarApp(rumps.App):
    """
    macOS menu bar application for Global Scripts

    Displays:
    - Command execution status in title
    - System metrics (CPU temp, memory) in dropdown
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        # Create menu bar app (template=True for dark mode compatibility)
        # NOTE: Activation policy must be set in main() BEFORE creating this instance
        super().__init__(MENUBAR_ICON, icon=None, template=True, quit_button=None)

        # Configuration
        self.config = config or {}
        self.refresh_interval = self.config.get("refresh_interval", 5)
        self.show_cpu_temp = self.config.get("show_cpu_temp", True)
        self.show_memory = self.config.get("show_memory", True)
        self.sentence_type = self.config.get("sentence_type", "一言")  # 一言类型
        self.sentence_refresh_interval = self.config.get("sentence_refresh_interval", 300)  # 5分钟
        self.marquee_update_interval = self.config.get("marquee_update_interval", 0.2)  # 跑马灯更新频率

        # State
        self.status = CommandStatus()
        self.cpu_monitor = CPUTemperatureMonitor()
        self.memory_monitor = MemoryMonitor()

        # Sentence API
        sentence_type_enum = self._parse_sentence_type(self.sentence_type)
        self.sentence_api = get_sentence_api(sentence_type_enum)

        # IPC
        self.ipc_server: Optional[IPCServer] = None
        self.ipc_loop: Optional[asyncio.AbstractEventLoop] = None
        self.ipc_thread: Optional[threading.Thread] = None

        # Status clear timer
        self._status_clear_timer: Optional[threading.Timer] = None

        # Build menu
        self._build_menu()

        # Start background tasks
        self._start_metric_updater()
        self._start_sentence_updater()  # 启动一言更新
        self._start_marquee_updater()   # 启动跑马灯动画
        self._start_ipc_server()

    def _parse_sentence_type(self, type_str: str) -> SentenceType:
        """Parse sentence type string to enum"""
        type_map = {
            "一言": SentenceType.YIYAN,
            "毒鸡汤": SentenceType.DUJITANG,
            "社会语录": SentenceType.SHEHUIYULU,
            "舔狗日记": SentenceType.TIANGOURIJI,
            "诗词": SentenceType.SHICI,
        }
        return type_map.get(type_str, SentenceType.YIYAN)

    def _build_menu(self) -> None:
        """Build dropdown menu"""
        # Add metric items
        if self.show_cpu_temp:
            self.cpu_item = rumps.MenuItem("CPU: --")
            self.menu.add(self.cpu_item)

        if self.show_memory:
            self.memory_item = rumps.MenuItem("Memory: --")
            self.menu.add(self.memory_item)

        # Add separator if metrics shown
        if self.show_cpu_temp or self.show_memory:
            self.menu.add(rumps.separator)

        # Add Quit button
        self.menu.add(rumps.MenuItem("Quit", callback=self.quit_handler))

    def _start_metric_updater(self) -> None:
        """Start background thread for metric updates"""

        def update_loop():
            while True:
                try:
                    self._update_metrics()
                except Exception as e:
                    logger.error(f"Error updating metrics: {e}", exc_info=True)

                time.sleep(self.refresh_interval)

        thread = threading.Thread(target=update_loop, daemon=True, name="MetricUpdater")
        thread.start()
        logger.info("Metric updater started")

    def _update_metrics(self) -> None:
        """Update system metrics in menu"""
        try:
            if self.show_cpu_temp and hasattr(self, "cpu_item"):
                cpu_text = self.cpu_monitor.get_display_text()
                self.cpu_item.title = f"CPU: {cpu_text}"

            if self.show_memory and hasattr(self, "memory_item"):
                mem_text = self.memory_monitor.get_display_text()
                self.memory_item.title = f"Memory: {mem_text}"

        except Exception as e:
            logger.error(f"Error updating metrics: {e}", exc_info=True)

    def _start_sentence_updater(self) -> None:
        """Start background thread for sentence (一言) updates"""

        def update_loop():
            # Fetch initial sentence
            try:
                sentence = self.sentence_api.fetch_sentence_sync(timeout=5.0)
                if sentence:
                    self.status.set_idle_sentence(sentence)
                    self._update_status_display()
                    logger.info(f"Initial sentence fetched: {sentence[:50]}...")
            except Exception as e:
                logger.error(f"Error fetching initial sentence: {e}", exc_info=True)

            # Periodic updates
            while True:
                try:
                    time.sleep(self.sentence_refresh_interval)

                    # Only fetch if idle
                    if not self.status.is_running and self.status.command == "":
                        sentence = self.sentence_api.fetch_sentence_sync(timeout=5.0)
                        if sentence:
                            self.status.set_idle_sentence(sentence)
                            self._update_status_display()
                            logger.info(f"Sentence updated: {sentence[:50]}...")

                except Exception as e:
                    logger.error(f"Error updating sentence: {e}", exc_info=True)

        thread = threading.Thread(target=update_loop, daemon=True, name="SentenceUpdater")
        thread.start()
        logger.info("Sentence updater started")

    def _start_marquee_updater(self) -> None:
        """Start background thread for marquee animation updates"""

        def update_loop():
            while True:
                try:
                    # Only update if marquee scrolling is needed
                    if self.status.needs_marquee_update():
                        self._update_status_display()

                    time.sleep(self.marquee_update_interval)

                except Exception as e:
                    logger.error(f"Error updating marquee: {e}", exc_info=True)

        thread = threading.Thread(target=update_loop, daemon=True, name="MarqueeUpdater")
        thread.start()
        logger.info("Marquee updater started")

    def _start_ipc_server(self) -> None:
        """Start IPC server in background thread"""

        def run_ipc_loop():
            # Create new event loop for this thread
            self.ipc_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.ipc_loop)

            # Create and start IPC server
            self.ipc_server = IPCServer(
                socket_path=get_socket_path(), message_handler=self._handle_ipc_message
            )

            try:
                self.ipc_loop.run_until_complete(self.ipc_server.start())
                # Run event loop indefinitely
                self.ipc_loop.run_forever()
            except Exception as e:
                logger.error(f"IPC server error: {e}", exc_info=True)
            finally:
                if self.ipc_server:
                    self.ipc_loop.run_until_complete(self.ipc_server.stop())
                self.ipc_loop.close()

        self.ipc_thread = threading.Thread(target=run_ipc_loop, daemon=True, name="IPCServer")
        self.ipc_thread.start()
        logger.info("IPC server thread started")

    def _handle_ipc_message(self, message: Dict[str, Any]) -> None:
        """
        Handle IPC message from CLI

        Message types:
        - command_start: {"type": "command_start", "command": "android.adb.devices", "timestamp": 123}
        - progress_update: {"type": "progress_update", "percentage": 45, "elapsed": 15.3}
        - command_complete: {"type": "command_complete", "success": true, "duration": 1.23}
        """
        try:
            msg_type = message.get("type")

            if msg_type == "command_start":
                self._handle_command_start(message)
            elif msg_type == "progress_update":
                self._handle_progress_update(message)
            elif msg_type == "command_complete":
                self._handle_command_complete(message)
            else:
                logger.warning(f"Unknown IPC message type: {msg_type}")

        except Exception as e:
            logger.error(f"Error handling IPC message: {e}", exc_info=True)

    def _handle_command_start(self, message: Dict[str, Any]) -> None:
        """Handle command_start message"""
        command = message.get("command", "")
        timestamp = message.get("timestamp", time.time())

        # Cancel any pending clear timer
        if self._status_clear_timer:
            self._status_clear_timer.cancel()

        # Update status
        self.status.command = command
        self.status.is_running = True
        self.status.start_time = timestamp
        self.status.progress = None

        # Update display
        self._update_status_display()
        logger.info(f"Command started: {command}")

    def _handle_progress_update(self, message: Dict[str, Any]) -> None:
        """Handle progress_update message"""
        percentage = message.get("percentage")
        if percentage is not None and 0 <= percentage <= 100:
            self.status.progress = percentage

        # Update output if provided
        output = message.get("output")
        if output:
            self.status.set_output(output)

        self._update_status_display()

    def _handle_command_complete(self, message: Dict[str, Any]) -> None:
        """Handle command_complete message"""
        success = message.get("success", False)
        duration = message.get("duration", 0.0)
        error = message.get("error")
        output = message.get("output")  # 获取命令输出结果

        # Update status
        self.status.is_running = False
        self.status.success = success
        self.status.error = error
        self.status.end_time = (
            self.status.start_time + duration if self.status.start_time else time.time()
        )

        # Set output if provided
        if output:
            self.status.set_output(output)

        # Update display
        self._update_status_display()
        logger.info(f"Command completed: {self.status.command} (success={success})")

        # Schedule status clear after 5 seconds
        self._status_clear_timer = threading.Timer(5.0, self._clear_status)
        self._status_clear_timer.start()

    def _update_status_display(self) -> None:
        """Update menu bar title with current status"""
        try:
            self.title = self.status.format_status()
        except Exception as e:
            logger.error(f"Error updating status display: {e}", exc_info=True)

    def _clear_status(self) -> None:
        """Clear status back to idle"""
        self.status.clear()
        self._update_status_display()
        logger.debug("Status cleared to idle")

    def _handle_custom_message(self, message: Dict[str, Any]) -> None:
        """Handle custom_message to display user-defined text"""
        text = message.get("text", "")

        if not text:
            logger.warning("Received empty custom message")
            return

        # Cancel any pending clear timer
        if self._status_clear_timer:
            self._status_clear_timer.cancel()

        # Display custom message
        self.title = f"GS: {text}"
        logger.info(f"Displaying custom message: {text}")

        # Clear after 10 seconds (longer than command completion)
        self._status_clear_timer = threading.Timer(10.0, self._clear_status)
        self._status_clear_timer.start()

    @rumps.clicked("Quit")
    def quit_handler(self, _) -> None:
        """Handle quit button"""
        logger.info("Quit requested")
        self._cleanup()
        rumps.quit_application()

    def _cleanup(self) -> None:
        """Cleanup resources before quit"""
        try:
            # Cancel status clear timer
            if self._status_clear_timer:
                self._status_clear_timer.cancel()

            # Stop IPC server
            if self.ipc_server and self.ipc_loop:
                asyncio.run_coroutine_threadsafe(self.ipc_server.stop(), self.ipc_loop)
                self.ipc_loop.call_soon_threadsafe(self.ipc_loop.stop)

            # Remove PID file
            pid_file = Path.home() / ".config" / "global-scripts" / "menubar.pid"
            if pid_file.exists():
                pid_file.unlink()

            logger.info("Cleanup completed")
        except Exception as e:
            logger.error(f"Error during cleanup: {e}", exc_info=True)


def main():
    """Entry point for menu bar app"""
    # CRITICAL: Set activation policy BEFORE any app initialization
    # This must happen before rumps creates the NSApplication
    try:
        import AppKit
        # Get shared application instance (creates if doesn't exist)
        app = AppKit.NSApplication.sharedApplication()
        # Set as accessory (menu bar only, no Dock icon)
        app.setActivationPolicy_(AppKit.NSApplicationActivationPolicyAccessory)
        logger_temp = logging.getLogger(__name__)
        logger_temp.info("Set NSApplicationActivationPolicyAccessory (menu bar only)")
    except Exception as e:
        # If this fails, app will appear in Dock
        import sys
        print(f"WARNING: Could not set activation policy: {e}", file=sys.stderr)
        print("App will appear in Dock", file=sys.stderr)

    # Setup logging
    log_dir = Path.home() / ".config" / "global-scripts" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "menubar.log"

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(),
        ],
    )

    # Write PID file
    pid_file = Path.home() / ".config" / "global-scripts" / "menubar.pid"
    pid_file.parent.mkdir(parents=True, exist_ok=True)
    pid_file.write_text(str(os.getpid()))

    logger.info("Starting menu bar app")

    # Load config
    try:
        import json

        config_file = Path.home() / ".config" / "global-scripts" / "config" / "gs.json"
        if config_file.exists():
            config = json.loads(config_file.read_text())
            menubar_config = config.get("menubar", {})
        else:
            menubar_config = {}
    except Exception as e:
        logger.warning(f"Failed to load config: {e}")
        menubar_config = {}

    # Create and run app
    app = MenuBarApp(config=menubar_config)
    app.run()


if __name__ == "__main__":
    import os

    main()
