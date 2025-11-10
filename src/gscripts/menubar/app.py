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
from .monitors import (
    CPUTemperatureMonitor,
    MemoryMonitor,
    CPUUsageMonitor,
    CPUMetricsCollector,
    MemoryMetricsCollector,
    DiskMetricsCollector,
    BatteryMetricsCollector,
    PortMonitor,
)
from .ipc import IPCServer, get_socket_path
from .sentence_api import get_sentence_api, SentenceType
from .icon import MENUBAR_ICON
from .history import CommandHistoryManager
from .shortcuts import ShortcutManager
from .icon_states import IconStateManager, IconState
from ..utils.i18n import get_i18n_manager

logger = logging.getLogger(__name__)

# Get i18n manager
_i18n = get_i18n_manager()

# Global variable to track if MenuDelegate class has been defined
_MenuDelegateClass = None


def _create_menu_delegate_class():
    """
    Create the MenuDelegate class only once (singleton pattern).

    PyObjC doesn't allow redefining Objective-C classes, so we create it once
    and reuse it for all instances.
    """
    global _MenuDelegateClass

    if _MenuDelegateClass is not None:
        return _MenuDelegateClass

    import AppKit
    import objc

    class MenuDelegate(AppKit.NSObject):
        def initWithApp_(self, app):
            self = objc.super(MenuDelegate, self).init()
            if self is None:
                return None
            self.app = app
            return self

        def menuWillOpen_(self, menu):
            """Called when menu is about to open"""
            try:
                logger.info("menuWillOpen_ called!")
                self.app._on_menu_will_open()
            except Exception as e:
                logger.error(f"Error in menuWillOpen: {e}", exc_info=True)

    _MenuDelegateClass = MenuDelegate
    return _MenuDelegateClass


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

        # Track when menu was last opened for on-demand updates
        self._last_menu_open_time: Optional[float] = None

        # Configuration
        self.config = config or {}
        self.refresh_interval = self.config.get("refresh_interval", 5)
        self.show_cpu_temp = self.config.get("show_cpu_temp", True)
        self.show_memory = self.config.get("show_memory", True)
        self.sentence_type = self.config.get("sentence_type", "一言")  # 一言类型
        self.sentence_refresh_interval = self.config.get("sentence_refresh_interval", 300)  # 5分钟
        self.marquee_update_interval = self.config.get("marquee_update_interval", 0.2)  # 跑马灯更新频率
        self.high_cpu_threshold = self.config.get("high_cpu_threshold", 80.0)  # 高 CPU 警告阈值

        # History configuration
        self.enable_history = self.config.get("enable_history", False)
        history_max_entries = self.config.get("history_max_entries", 50)

        # Enhanced monitoring configuration (Phase 5)
        self.show_top_processes = self.config.get("show_top_processes", False)

        # On-demand monitoring configuration (Phase 6.1)
        self.on_demand_monitoring = self.config.get("on_demand_monitoring", True)

        # Disk monitoring configuration (Phase 6.2)
        self.show_disk = self.config.get("show_disk", True)

        # Battery monitoring configuration (Phase 3)
        self.show_battery = self.config.get("show_battery", True)

        # Port monitoring configuration (Phase 5)
        self.show_ports = self.config.get("show_ports", False)  # Default disabled
        monitored_ports = self.config.get("monitored_ports", [3000, 8080, 80, 443, 5432, 3306, 6379, 27017])

        # Temperature alert configuration (Phase 6)
        self.show_temp_alert = self.config.get("show_temp_alert", True)
        self.temp_warning_threshold = self.config.get("temp_warning_threshold", 60.0)
        self.temp_critical_threshold = self.config.get("temp_critical_threshold", 75.0)

        # State
        self.status = CommandStatus()
        self.cpu_monitor = CPUTemperatureMonitor(
            warning_threshold=self.temp_warning_threshold,
            critical_threshold=self.temp_critical_threshold
        )
        self.memory_monitor = MemoryMonitor()
        self.cpu_usage_monitor = CPUUsageMonitor(threshold=self.high_cpu_threshold)
        self.icon_manager = IconStateManager()

        # Enhanced metrics collectors (Phase 5 + 6.2 + Phase 3 + Phase 5)
        self.cpu_metrics_collector = CPUMetricsCollector(temp_monitor=self.cpu_monitor)
        self.memory_metrics_collector = MemoryMetricsCollector()
        self.disk_metrics_collector = DiskMetricsCollector()
        self.battery_metrics_collector = BatteryMetricsCollector()
        self.port_monitor = PortMonitor(monitored_ports=monitored_ports)

        # History manager (only if enabled)
        self.history_manager = None
        if self.enable_history:
            try:
                self.history_manager = CommandHistoryManager(max_entries=history_max_entries)
                logger.info(f"History manager initialized ({len(self.history_manager)} entries loaded)")
            except Exception as e:
                logger.error(f"Failed to initialize history manager: {e}", exc_info=True)

        # Shortcut manager (with callbacks for background execution)
        self.shortcut_manager = ShortcutManager(
            config=self.config,  # Pass config directly (it's already the menubar config)
            on_background_start=self._on_shortcut_background_start,
            on_background_complete=self._on_shortcut_background_complete,
        )

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
        if not self.on_demand_monitoring:
            # Legacy mode: continuous background monitoring
            self._start_metric_updater()
        else:
            # On-demand mode: lightweight menu-open detector
            self._start_menu_open_detector()
        # Always start these (not related to metrics)
        self._start_sentence_updater()  # 启动一言更新
        self._start_marquee_updater()   # 启动跑马灯动画
        self._start_icon_animation()    # 启动图标动画
        self._start_ipc_server()

        # Set up menu delegate AFTER everything is initialized (Phase 6.1)
        # This must be done after menu is fully built
        if self.on_demand_monitoring:
            # Use a timer to set up delegate after rumps is ready
            rumps.Timer(self._setup_menu_delegate_delayed, 0.5).start()

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

    def _setup_menu_delegate_delayed(self, _) -> None:
        """
        Delayed setup of menu delegate (called via Timer after initialization).

        This is needed because rumps menu structure isn't fully ready during __init__.
        """
        self._setup_menu_delegate()

    def _setup_menu_delegate(self) -> None:
        """
        Setup NSMenu delegate to detect when menu is opened (on-demand monitoring).

        Uses PyObjC to set a delegate that will be called when the menu is about to be displayed.
        """
        try:
            logger.info("Setting up menu delegate for on-demand monitoring...")

            # Get the MenuDelegate class (created once globally)
            MenuDelegateClass = _create_menu_delegate_class()

            # Create delegate instance
            self._menu_delegate = MenuDelegateClass.alloc().initWithApp_(self)
            logger.info(f"Created delegate instance: {self._menu_delegate}")

            # Get the NSMenu object from rumps
            logger.info(f"self.menu type: {type(self.menu)}")
            logger.info(f"self.menu._menu: {getattr(self.menu, '_menu', 'NO _menu attribute')}")

            if hasattr(self.menu, '_menu') and self.menu._menu is not None:
                self.menu._menu.setDelegate_(self._menu_delegate)
                current_delegate = self.menu._menu.delegate()
                logger.info(f"Menu delegate set successfully! Current delegate: {current_delegate}")
            else:
                logger.error("Could not set menu delegate - menu._menu not available")
                logger.info(f"Available attributes: {[a for a in dir(self.menu) if not a.startswith('_')]}")

        except Exception as e:
            logger.error(f"Failed to set up menu delegate: {e}", exc_info=True)

    def _on_menu_will_open(self) -> None:
        """
        Callback when menu is about to open (on-demand monitoring).

        Updates all metric submenus with fresh data.
        """
        import time
        current_time = time.time()

        # Avoid updating too frequently (debounce: max once per second)
        if (self._last_menu_open_time is not None and
            current_time - self._last_menu_open_time < 1.0):
            logger.info(f"Skipping update (debounced): {current_time - self._last_menu_open_time:.2f}s since last")
            return

        self._last_menu_open_time = current_time
        logger.info("Menu opened, updating metrics on-demand")

        # Update all metric menus
        if self.show_cpu_temp and hasattr(self, "cpu_menu"):
            logger.info("Updating CPU menu...")
            self._update_cpu_menu()

        if self.show_memory and hasattr(self, "memory_menu"):
            logger.info("Updating Memory menu...")
            self._update_memory_menu()

        if self.show_disk and hasattr(self, "disk_menu"):
            logger.info("Updating Disk menu...")
            self._update_disk_menu()

        if self.show_battery and hasattr(self, "battery_menu"):
            logger.info("Updating Battery menu...")
            self._update_battery_menu()

        if self.show_ports and hasattr(self, "ports_menu"):
            logger.info("Updating Ports menu...")
            self._update_ports_menu()

        logger.info("Metrics update complete")

    def _start_menu_open_detector(self) -> None:
        """
        Fallback: Start lightweight detector for menu opens (if delegate setup failed).

        This is a backup method that polls to detect when menu might be open.
        """
        # This method is no longer needed if _setup_menu_delegate works
        # Keeping it as a stub for compatibility
        pass

    def _build_menu(self) -> None:
        """Build dropdown menu"""
        logger.info(f"Building menu: history_enabled={self.enable_history}, shortcuts_enabled={self.shortcut_manager.is_enabled()}")

        # Add History submenu (if enabled)
        if self.enable_history:
            logger.info("Adding History submenu")
            self.history_menu = rumps.MenuItem(_i18n.get_message("menubar.menu.recent_commands"))
            self.menu.add(self.history_menu)
            self._update_history_menu()
            self.menu.add(rumps.separator)

        # Add Shortcuts submenu (if enabled)
        if self.shortcut_manager.is_enabled():
            logger.info("Adding Shortcuts submenu")
            self.shortcuts_menu = rumps.MenuItem(_i18n.get_message("menubar.menu.shortcuts"))
            self.menu.add(self.shortcuts_menu)
            self._update_shortcuts_menu()
            self.menu.add(rumps.separator)

        # Add enhanced metric submenus (Phase 5.5 & 5.6 + 6.1 on-demand + 6.2 disk) with dynamic titles
        if self.show_cpu_temp:
            self.cpu_menu = rumps.MenuItem("CPU: --")
            self.menu.add(self.cpu_menu)
            # Always update once to populate menu structure
            self._update_cpu_menu()

        if self.show_memory:
            self.memory_menu = rumps.MenuItem("Memory: --")
            self.menu.add(self.memory_menu)
            # Always update once to populate menu structure
            self._update_memory_menu()

        if self.show_disk:
            self.disk_menu = rumps.MenuItem("Disk: --")
            self.menu.add(self.disk_menu)
            # Always update once to populate menu structure
            self._update_disk_menu()

        if self.show_battery:
            self.battery_menu = rumps.MenuItem("Battery: --")
            self.menu.add(self.battery_menu)
            # Always update once to populate menu structure
            self._update_battery_menu()

        if self.show_ports:
            ports_title = _i18n.get_message("menubar.menu.ports_title")
            self.ports_menu = rumps.MenuItem(f"{ports_title}: --")
            self.menu.add(self.ports_menu)
            # Always update once to populate menu structure
            self._update_ports_menu()

        # Add separator if metrics shown
        if self.show_cpu_temp or self.show_memory or self.show_disk or self.show_battery or self.show_ports:
            self.menu.add(rumps.separator)

        # Note: Quit button is automatically added by @rumps.clicked("Quit") decorator
        # We cannot translate it without breaking the decorator binding

        logger.info("Menu building completed")

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
        """Update system metrics in menu (Phase 5.7 - optimized with caching)"""
        try:
            # Schedule UI updates on main thread using rumps timer
            # This prevents crashes from updating UI on background thread
            def update_on_main_thread(_):
                try:
                    # Update enhanced CPU submenu (uses cached data from collector)
                    if self.show_cpu_temp and hasattr(self, "cpu_menu"):
                        self._update_cpu_menu()

                    # Update enhanced Memory submenu (uses cached data from collector)
                    if self.show_memory and hasattr(self, "memory_menu"):
                        self._update_memory_menu()

                    # Update enhanced Disk submenu (uses cached data from collector, Phase 6.2)
                    if self.show_disk and hasattr(self, "disk_menu"):
                        self._update_disk_menu()
                except Exception as e:
                    logger.error(f"Error updating metrics on main thread: {e}", exc_info=True)

            # Use rumps.Timer to execute on main thread (0 delay = immediate)
            rumps.Timer(update_on_main_thread, 0).start()

            # Check CPU usage and update high CPU warning (thread-safe)
            cpu_usage = self.cpu_usage_monitor.collect()
            if cpu_usage is not None:
                high_cpu_active = self.cpu_usage_monitor.is_warning_active()
                self.icon_manager.set_high_cpu(high_cpu_active)

                # Update display if high CPU state changed
                if high_cpu_active != self.icon_manager.is_high_cpu_active():
                    self._update_status_display()

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

    def _start_icon_animation(self) -> None:
        """Start background thread for icon animation (loading spinner)"""

        def animation_loop():
            while True:
                try:
                    # Advance loading animation frame if in loading state
                    if self.icon_manager.advance_loading_frame():
                        self._update_status_display()

                    time.sleep(0.2)  # 200ms per frame = 5 FPS

                except Exception as e:
                    logger.error(f"Error updating icon animation: {e}", exc_info=True)

        thread = threading.Thread(target=animation_loop, daemon=True, name="IconAnimator")
        thread.start()
        logger.info("Icon animation started")

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

        # Set icon to loading state (starts animation)
        self.icon_manager.set_state(IconState.LOADING)

        # Update display
        self._update_status_display()
        logger.info(f"Command started: {command}")

    def _handle_progress_update(self, message: Dict[str, Any]) -> None:
        """Handle progress_update message"""
        percentage = message.get("percentage")
        if percentage is not None and 0 <= percentage <= 100:
            self.status.progress = percentage

        # Update stage if provided
        stage = message.get("stage")
        if stage:
            self.status.current_stage = stage

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

        # Record to history (if enabled)
        if self.history_manager is not None and self.status.command:
            try:
                timestamp = self.status.start_time or time.time()
                logger.info(f"Adding command to history: {self.status.command} (success={success}, duration={duration:.2f}s)")
                self.history_manager.add_command(
                    command=self.status.command,
                    timestamp=timestamp,
                    success=success,
                    duration=duration,
                    error=error
                )
                logger.info(f"Command added to history, total entries: {len(self.history_manager)}")
                # Update history menu after adding new entry
                self._update_history_menu()
            except Exception as e:
                logger.error(f"Failed to record command to history: {e}", exc_info=True)

        # Flash success/failure icon and return to idle
        flash_state = IconState.SUCCESS if success else IconState.FAILURE
        self.icon_manager.flash(flash_state, duration=1.0)
        self.icon_manager.set_state(IconState.IDLE)

        # Update display
        self._update_status_display()
        logger.info(f"Command completed: {self.status.command} (success={success})")

        # Schedule status clear after 5 seconds
        self._status_clear_timer = threading.Timer(5.0, self._clear_status)
        self._status_clear_timer.start()

    def _update_status_display(self) -> None:
        """Update menu bar title with current status and icon"""
        try:
            # Get icon prefix from icon manager
            icon = self.icon_manager.get_icon_text()
            status_text = self.status.format_status()

            # Combine icon and status
            if icon and icon != "GS":
                # Use icon instead of "GS" prefix
                self.title = f"{icon} {status_text.replace('GS: ', '')}"
            else:
                self.title = status_text
        except Exception as e:
            logger.error(f"Error updating status display: {e}", exc_info=True)

    def _clear_status(self) -> None:
        """Clear status back to idle"""
        self.status.clear()
        self.icon_manager.reset()  # Reset icon to idle state
        self._update_status_display()
        logger.debug("Status cleared to idle")

    def _update_history_menu(self) -> None:
        """Update Recent Commands submenu with latest history"""
        if not self.history_manager or not hasattr(self, 'history_menu'):
            return

        try:
            # Clear existing items if menu is already built
            if self.history_menu._menu is not None:
                self.history_menu.clear()

            # Get recent commands
            history_display_count = self.config.get("history_display_count", 5)
            recent_entries = self.history_manager.get_recent(limit=history_display_count)

            if recent_entries:
                # Add history entries
                for entry in recent_entries:
                    icon = "✓" if entry.success else "✗"
                    title = f"{icon} {entry.command} ({entry.format_duration()})"
                    # Create menu item with command replay callback
                    item = rumps.MenuItem(title, callback=self._make_replay_callback(entry.command))
                    self.history_menu[title] = item

                # Add separator and clear history option
                self.history_menu["sep"] = rumps.separator
                clear_history_text = _i18n.get_message("menubar.menu.clear_history")
                self.history_menu["Clear History"] = rumps.MenuItem(
                    clear_history_text,
                    callback=self._clear_history
                )
            else:
                # Empty history - show placeholder
                empty_text = _i18n.get_message("menubar.menu.no_history")
                empty_item = rumps.MenuItem(empty_text, callback=None)
                self.history_menu["empty"] = empty_item

            logger.info(f"History menu updated with {len(recent_entries)} entries")

        except Exception as e:
            logger.error(f"Failed to update history menu: {e}", exc_info=True)

    def _make_replay_callback(self, command: str):
        """
        Create a callback function for replaying a command.

        Args:
            command: Command to replay (e.g., "android.build")

        Returns:
            Callback function for rumps MenuItem
        """
        def replay_command(_):
            """Replay command callback"""
            self._replay_command(command)
        return replay_command

    def _replay_command(self, command: str) -> None:
        """
        Replay a command from history.

        Args:
            command: Command to execute (e.g., "android.build")
        """
        try:
            import subprocess

            # Determine execution mode
            history_exec_mode = self.config.get("menubar", {}).get("history_execution_mode", "background")

            logger.info(f"Replaying command: {command} (mode: {history_exec_mode})")

            if history_exec_mode == "terminal":
                # Execute in Terminal.app (macOS)
                script = f'tell application "Terminal" to do script "gs {command}"'
                subprocess.Popen(
                    ["osascript", "-e", script],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True
                )
                logger.info(f"Opened Terminal for: {command}")
            else:
                # Execute in background
                subprocess.Popen(
                    ["gs", command],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True
                )
                logger.info(f"Executing in background: {command}")

        except Exception as e:
            logger.error(f"Failed to replay command '{command}': {e}", exc_info=True)
            # Optionally show error notification
            try:
                title = _i18n.get_message("menubar.errors.command_replay_failed")
                rumps.notification(
                    title=title,
                    subtitle=command,
                    message=str(e),
                    sound=False
                )
            except:
                pass

    def _clear_history(self, _) -> None:
        """Clear command history callback"""
        if not self.history_manager:
            return

        # Optional: show confirmation dialog
        confirm_clear = self.config.get("menubar", {}).get("confirm_clear_history", False)

        if confirm_clear:
            title = _i18n.get_message("menubar.errors.clear_history_confirm_title")
            message = _i18n.get_message("menubar.errors.clear_history_confirm_message")
            ok_text = _i18n.get_message("menubar.errors.clear_history_confirm_ok")
            cancel_text = _i18n.get_message("menubar.errors.clear_history_confirm_cancel")
            response = rumps.alert(
                title=title,
                message=message,
                ok=ok_text,
                cancel=cancel_text
            )
            if response != 1:  # User cancelled
                return

        # Clear history
        self.history_manager.clear()
        self._update_history_menu()
        logger.info("Command history cleared by user")

    def _update_shortcuts_menu(self) -> None:
        """Update shortcuts submenu with current shortcuts"""
        if not hasattr(self, "shortcuts_menu"):
            return

        try:
            # Clear existing items if menu is already built
            if self.shortcuts_menu._menu is not None:
                self.shortcuts_menu.clear()

            # Get shortcuts (sorted alphabetically)
            shortcuts_labels = self.shortcut_manager.get_sorted_labels()

            if shortcuts_labels:
                # Add shortcut menu items
                for label in shortcuts_labels:
                    item = rumps.MenuItem(label, callback=self._make_shortcut_callback(label))
                    self.shortcuts_menu[label] = item

                logger.info(f"Shortcuts menu updated with {len(shortcuts_labels)} shortcuts")
            else:
                # No shortcuts defined - show placeholder
                empty_text = _i18n.get_message("menubar.menu.no_shortcuts")
                empty_item = rumps.MenuItem(empty_text, callback=None)
                self.shortcuts_menu["empty"] = empty_item
                logger.info("No shortcuts configured, showing placeholder")

            # Add separator and Reload Config button at the end
            self.shortcuts_menu["sep_reload"] = rumps.separator
            reload_text = _i18n.get_message("menubar.menu.reload_config")
            reload_item = rumps.MenuItem(reload_text, callback=self._reload_config)
            self.shortcuts_menu["reload"] = reload_item

        except Exception as e:
            logger.error(f"Failed to update shortcuts menu: {e}", exc_info=True)

    def _update_cpu_menu(self) -> None:
        """
        Update CPU metrics submenu with enhanced monitoring data (Phase 5.5 + 6.1).

        Displays:
        - Overall CPU usage percentage
        - Per-core CPU usage breakdown
        - Current temperature with trend indicator
        - Average temperature (5 minutes)
        - Peak temperature (session)

        In on-demand mode, this is called only when menu is accessed.
        """
        if not hasattr(self, "cpu_menu"):
            return

        try:
            # Clear existing items
            if self.cpu_menu._menu is not None:
                self.cpu_menu.clear()

            # Collect metrics (uses caching internally)
            cpu_data = self.cpu_metrics_collector.collect()

            # Update main menu item title with summary (short format)
            if cpu_data["overall"] is not None and cpu_data["temp_current"] is not None:
                self.cpu_menu.title = f"CPU: {cpu_data['overall']:.0f}% {cpu_data['temp_current']:.0f}°C"
            elif cpu_data["overall"] is not None:
                self.cpu_menu.title = f"CPU: {cpu_data['overall']:.0f}%"
            elif cpu_data["temp_current"] is not None:
                self.cpu_menu.title = f"CPU: {cpu_data['temp_current']:.0f}°C"
            else:
                self.cpu_menu.title = "CPU: --"

            # Overall CPU usage
            if cpu_data["overall"] is not None:
                overall_text = _i18n.get_message("menubar.menu.cpu_overall", percent=f"{cpu_data['overall']:.1f}")
                overall_item = rumps.MenuItem(overall_text, callback=None)
                self.cpu_menu["overall"] = overall_item
            else:
                na_text = _i18n.get_message("menubar.menu.not_available")
                overall_item = rumps.MenuItem(f"Overall: {na_text}", callback=None)
                self.cpu_menu["overall"] = overall_item

            # Per-core CPU usage
            if cpu_data["per_core"]:
                for i, percent in enumerate(cpu_data["per_core"]):
                    core_text = _i18n.get_message("menubar.menu.cpu_core", core=i, percent=f"{percent:.1f}")
                    core_item = rumps.MenuItem(core_text, callback=None)
                    self.cpu_menu[f"core_{i}"] = core_item

            # Temperature section (with separator)
            if cpu_data["temp_current"] is not None:
                self.cpu_menu["sep1"] = rumps.separator

                # Current temperature with trend
                trend = cpu_data["temp_trend"]
                temp_text = _i18n.get_message("menubar.menu.cpu_temperature", temp=f"{cpu_data['temp_current']:.1f}", trend=trend)
                temp_item = rumps.MenuItem(temp_text, callback=None)
                self.cpu_menu["temp"] = temp_item

                # Average temperature
                if cpu_data["temp_avg"] is not None:
                    avg_text = _i18n.get_message("menubar.menu.cpu_temp_avg", temp=f"{cpu_data['temp_avg']:.1f}")
                    avg_item = rumps.MenuItem(avg_text, callback=None)
                    self.cpu_menu["temp_avg"] = avg_item

                # Peak temperature
                if cpu_data["temp_peak"] is not None:
                    peak_text = _i18n.get_message("menubar.menu.cpu_temp_peak", temp=f"{cpu_data['temp_peak']:.1f}")
                    peak_item = rumps.MenuItem(peak_text, callback=None)
                    self.cpu_menu["temp_peak"] = peak_item

                # Temperature alert status (Phase 6)
                if self.show_temp_alert:
                    self.cpu_menu["sep_alert"] = rumps.separator

                    # Get alert state
                    alert_state = self.cpu_monitor.get_alert_state()
                    temp_current = cpu_data["temp_current"]

                    # Display alert status with appropriate icon and message
                    if alert_state == "critical":
                        alert_text = _i18n.get_message("menubar.menu.cpu_temp_alert_critical",
                            temp=f"{temp_current:.1f}",
                            threshold=f"{self.temp_critical_threshold:.0f}")
                    elif alert_state == "warning":
                        alert_text = _i18n.get_message("menubar.menu.cpu_temp_alert_warning",
                            temp=f"{temp_current:.1f}",
                            threshold=f"{self.temp_warning_threshold:.0f}")
                    else:
                        alert_text = _i18n.get_message("menubar.menu.cpu_temp_alert_normal",
                            temp=f"{temp_current:.1f}")

                    alert_item = rumps.MenuItem(alert_text, callback=None)
                    self.cpu_menu["alert_status"] = alert_item

                    # Show thresholds
                    thresholds_text = _i18n.get_message("menubar.menu.cpu_temp_thresholds",
                        warning=f"{self.temp_warning_threshold:.0f}",
                        critical=f"{self.temp_critical_threshold:.0f}")
                    thresholds_item = rumps.MenuItem(thresholds_text, callback=None)
                    self.cpu_menu["thresholds"] = thresholds_item

            logger.debug("CPU menu updated")

        except Exception as e:
            logger.error(f"Failed to update CPU menu: {e}", exc_info=True)

    def _update_memory_menu(self) -> None:
        """
        Update Memory metrics submenu with enhanced monitoring data (Phase 5.6 + 6.1).

        Displays:
        - Total memory usage (used/total GB)
        - Memory breakdown (App, Wired, Compressed, Cached)
        - Swap usage
        - Memory pressure indicator
        - Top 3 memory-consuming processes (optional)

        In on-demand mode, this is called only when menu is accessed.
        """
        if not hasattr(self, "memory_menu"):
            return

        try:
            # Clear existing items
            if self.memory_menu._menu is not None:
                self.memory_menu.clear()

            # Collect metrics (include processes if configured, uses caching internally)
            mem_data = self.memory_metrics_collector.collect(
                include_processes=self.show_top_processes
            )

            # Update main menu item title with summary (short format)
            self.memory_menu.title = f"Memory: {mem_data['used']:.1f}/{mem_data['total']:.0f}GB"

            # Total memory usage
            total_text = _i18n.get_message("menubar.menu.memory_used",
                used=f"{mem_data['used']:.1f}",
                total=f"{mem_data['total']:.1f}",
                percent=f"{mem_data['percent']:.0f}")
            total_item = rumps.MenuItem(total_text, callback=None)
            self.memory_menu["total"] = total_item

            # Memory breakdown
            self.memory_menu["sep1"] = rumps.separator

            app_text = _i18n.get_message("menubar.menu.memory_app", size=f"{mem_data['app']:.1f}")
            app_item = rumps.MenuItem(app_text, callback=None)
            self.memory_menu["app"] = app_item

            wired_text = _i18n.get_message("menubar.menu.memory_wired", size=f"{mem_data['wired']:.1f}")
            wired_item = rumps.MenuItem(wired_text, callback=None)
            self.memory_menu["wired"] = wired_item

            if mem_data["compressed"] > 0:
                compressed_text = _i18n.get_message("menubar.menu.memory_compressed", size=f"{mem_data['compressed']:.1f}")
                compressed_item = rumps.MenuItem(compressed_text, callback=None)
                self.memory_menu["compressed"] = compressed_item

            if mem_data["cached"] > 0:
                cached_text = _i18n.get_message("menubar.menu.memory_cached", size=f"{mem_data['cached']:.1f}")
                cached_item = rumps.MenuItem(cached_text, callback=None)
                self.memory_menu["cached"] = cached_item

            # Swap and pressure
            self.memory_menu["sep2"] = rumps.separator

            if mem_data['swap'] > 0:
                swap_display = f"{mem_data['swap']:.1f} GB"
            else:
                swap_display = _i18n.get_message("menubar.menu.memory_swap_none")
            swap_text = _i18n.get_message("menubar.menu.memory_swap", size=swap_display)
            swap_item = rumps.MenuItem(swap_text, callback=None)
            self.memory_menu["swap"] = swap_item

            pressure_text = _i18n.get_message("menubar.menu.memory_pressure", level=mem_data['pressure'])
            pressure_item = rumps.MenuItem(pressure_text, callback=None)
            self.memory_menu["pressure"] = pressure_item

            # Top processes (if enabled and available)
            if "top_processes" in mem_data and mem_data["top_processes"]:
                self.memory_menu["sep3"] = rumps.separator

                header_text = _i18n.get_message("menubar.menu.top_processes")
                header_item = rumps.MenuItem(header_text, callback=None)
                self.memory_menu["processes_header"] = header_item

                for proc in mem_data["top_processes"]:
                    proc_item = rumps.MenuItem(
                        f"  {proc['name']}: {proc['memory']:.2f} GB",
                        callback=None
                    )
                    self.memory_menu[f"proc_{proc['pid']}"] = proc_item

            logger.debug("Memory menu updated")

        except Exception as e:
            logger.error(f"Failed to update memory menu: {e}", exc_info=True)

    def _update_disk_menu(self) -> None:
        """
        Update Disk metrics submenu with enhanced monitoring data (Phase 6.2).

        Displays:
        - Total disk usage (used/total GB with percentage)
        - Free disk space
        - I/O read/write rates (MB/s)
        - Disk pressure indicator

        In on-demand mode, this is called only when menu is accessed.
        """
        if not hasattr(self, "disk_menu"):
            return

        try:
            # Clear existing items
            if self.disk_menu._menu is not None:
                self.disk_menu.clear()

            # Collect metrics (uses caching internally)
            disk_data = self.disk_metrics_collector.collect()

            # Update main menu item title with summary (short format)
            self.disk_menu.title = f"Disk: {disk_data['used']:.0f}/{disk_data['total']:.0f}GB ({disk_data['percent']:.0f}%)"

            # Total disk usage
            used_text = _i18n.get_message("menubar.menu.disk_used",
                used=f"{disk_data['used']:.1f}",
                total=f"{disk_data['total']:.1f}",
                percent=f"{disk_data['percent']:.0f}")
            used_item = rumps.MenuItem(used_text, callback=None)
            self.disk_menu["used"] = used_item

            # Free space
            free_text = _i18n.get_message("menubar.menu.disk_free", free=f"{disk_data['free']:.1f}")
            free_item = rumps.MenuItem(free_text, callback=None)
            self.disk_menu["free"] = free_item

            # Pressure indicator
            pressure_text = _i18n.get_message("menubar.menu.disk_pressure", level=disk_data['pressure'])
            pressure_item = rumps.MenuItem(pressure_text, callback=None)
            self.disk_menu["pressure"] = pressure_item

            # I/O Activity section (with separator)
            if disk_data["io_read_rate"] > 0 or disk_data["io_write_rate"] > 0:
                self.disk_menu["sep1"] = rumps.separator

                # I/O Activity header
                io_header_text = _i18n.get_message("menubar.menu.disk_io_activity")
                io_header_item = rumps.MenuItem(io_header_text, callback=None)
                self.disk_menu["io_header"] = io_header_item

                # Read rate
                read_text = _i18n.get_message("menubar.menu.disk_read", rate=f"{disk_data['io_read_rate']:.1f}")
                read_item = rumps.MenuItem(read_text, callback=None)
                self.disk_menu["io_read"] = read_item

                # Write rate
                write_text = _i18n.get_message("menubar.menu.disk_write", rate=f"{disk_data['io_write_rate']:.1f}")
                write_item = rumps.MenuItem(write_text, callback=None)
                self.disk_menu["io_write"] = write_item

            logger.debug("Disk menu updated")

        except Exception as e:
            logger.error(f"Failed to update disk menu: {e}", exc_info=True)

    def _update_battery_menu(self) -> None:
        """
        Update Battery metrics submenu with enhanced monitoring data (Phase 3).

        Displays:
        - Battery charge level and status (charging/discharging)
        - Time remaining
        - Battery health percentage and status
        - Cycle count
        - Temperature
        - Power source

        In on-demand mode, this is called only when menu is accessed.
        Shows "N/A" for desktop Macs without battery.
        """
        if not hasattr(self, "battery_menu"):
            return

        try:
            # Clear existing items
            if self.battery_menu._menu is not None:
                self.battery_menu.clear()

            # Collect metrics (uses caching internally)
            battery_data = self.battery_metrics_collector.collect()

            # Check if device has battery
            if battery_data is None:
                # Desktop Mac without battery
                na_text = _i18n.get_message("menubar.menu.battery_not_available")
                self.battery_menu.title = na_text
                na_item = rumps.MenuItem(na_text, callback=None)
                self.battery_menu["na"] = na_item
                return

            # Update main menu item title with summary (short format)
            percent = battery_data["percent"]
            time_remaining = battery_data.get("time_remaining")
            time_str = self.battery_metrics_collector.format_time_remaining(time_remaining)

            if battery_data["is_charging"]:
                self.battery_menu.title = f"Battery: {percent:.0f}% (Charging)"
            else:
                self.battery_menu.title = f"Battery: {percent:.0f}% ({time_str})"

            # Charge level and status
            status = _i18n.get_message("menubar.menu.battery_charging") if battery_data["is_charging"] else _i18n.get_message("menubar.menu.battery_discharging")
            charge_text = _i18n.get_message("menubar.menu.battery_charge", percent=f"{percent:.0f}", status=status)
            charge_item = rumps.MenuItem(charge_text, callback=None)
            self.battery_menu["charge"] = charge_item

            # Time remaining
            time_text = _i18n.get_message("menubar.menu.battery_time_remaining", time=time_str)
            time_item = rumps.MenuItem(time_text, callback=None)
            self.battery_menu["time"] = time_item

            # Separator
            self.battery_menu["sep1"] = rumps.separator

            # Battery health
            health = battery_data.get("health")
            if health is not None:
                health_status = self.battery_metrics_collector.get_health_status(health)
                health_text = _i18n.get_message("menubar.menu.battery_health", percent=f"{health:.0f}", status=health_status)
                health_item = rumps.MenuItem(health_text, callback=None)
                self.battery_menu["health"] = health_item

            # Cycle count
            cycle_count = battery_data.get("cycle_count")
            if cycle_count is not None:
                # Most MacBooks have ~1000 cycle limit
                max_cycles = 1000
                cycle_text = _i18n.get_message("menubar.menu.battery_cycle_count", count=cycle_count, max=max_cycles)
                cycle_item = rumps.MenuItem(cycle_text, callback=None)
                self.battery_menu["cycles"] = cycle_item

            # Temperature
            temperature = battery_data.get("temperature")
            if temperature is not None:
                temp_text = _i18n.get_message("menubar.menu.battery_temperature", temp=f"{temperature:.1f}")
                temp_item = rumps.MenuItem(temp_text, callback=None)
                self.battery_menu["temp"] = temp_item

            # Separator
            self.battery_menu["sep2"] = rumps.separator

            # Power source
            power_source = battery_data.get("power_source", "Unknown")
            source_text = _i18n.get_message("menubar.menu.battery_power_source", source=power_source)
            source_item = rumps.MenuItem(source_text, callback=None)
            self.battery_menu["power"] = source_item

            logger.debug("Battery menu updated")

        except Exception as e:
            logger.error(f"Failed to update battery menu: {e}", exc_info=True)

    def _update_ports_menu(self) -> None:
        """
        Update Ports submenu with port occupation status (Phase 5).

        Displays:
        - Port number and status (in use / not in use)
        - Process name and PID for occupied ports
        - Kill process option for occupied ports

        In on-demand mode, this is called only when menu is accessed.
        """
        if not hasattr(self, "ports_menu"):
            return

        try:
            # Clear existing items
            if self.ports_menu._menu is not None:
                self.ports_menu.clear()

            # Check all monitored ports
            port_statuses = self.port_monitor.check_multiple_ports()

            # Count occupied ports for title
            occupied_count = sum(1 for status in port_statuses.values() if status["in_use"])
            ports_title = _i18n.get_message("menubar.menu.ports_title")
            self.ports_menu.title = f"{ports_title}: {occupied_count}/{len(port_statuses)}"

            # Build menu items for each port (sorted by port number)
            for port in sorted(port_statuses.keys()):
                status = port_statuses[port]

                if status["error"]:
                    # Error checking port
                    error_text = _i18n.get_message("menubar.menu.port_error",
                        port=port, error=status["error"])
                    error_item = rumps.MenuItem(error_text, callback=None)
                    self.ports_menu[f"port_{port}"] = error_item

                elif status["in_use"]:
                    # Port is occupied
                    port_text = _i18n.get_message("menubar.menu.port_in_use",
                        port=port,
                        process=status["process_name"] or "Unknown",
                        pid=status["pid"] or "?")
                    port_item = rumps.MenuItem(port_text, callback=None)
                    self.ports_menu[f"port_{port}"] = port_item

                    # Add kill process submenu if PID available
                    if status["pid"]:
                        kill_text = _i18n.get_message("menubar.menu.port_kill_process")
                        kill_item = rumps.MenuItem(
                            kill_text,
                            callback=self._make_kill_process_callback(status["pid"], status["process_name"])
                        )
                        port_item.add(kill_item)

                else:
                    # Port not in use
                    port_text = _i18n.get_message("menubar.menu.port_not_in_use", port=port)
                    port_item = rumps.MenuItem(port_text, callback=None)
                    self.ports_menu[f"port_{port}"] = port_item

            logger.debug("Ports menu updated")

        except Exception as e:
            logger.error(f"Failed to update ports menu: {e}", exc_info=True)

    def _make_kill_process_callback(self, pid: int, process_name: str):
        """
        Create a callback function for killing a process.

        Args:
            pid: Process ID to kill
            process_name: Process name for confirmation dialog

        Returns:
            Callback function for rumps MenuItem
        """
        def kill_process(_):
            """Kill process callback"""
            self._kill_process(pid, process_name)
        return kill_process

    def _kill_process(self, pid: int, process_name: str) -> None:
        """
        Kill a process by PID with confirmation dialog.

        Args:
            pid: Process ID to kill
            process_name: Process name for display
        """
        try:
            # Show confirmation dialog
            response = rumps.alert(
                title=f"Kill Process: {process_name}",
                message=f"Are you sure you want to kill process {process_name} (PID {pid})?",
                ok="Kill",
                cancel="Cancel"
            )

            if response == 1:  # User clicked "Kill"
                import signal
                import os

                try:
                    os.kill(pid, signal.SIGTERM)
                    logger.info(f"Killed process {process_name} (PID {pid})")

                    # Refresh ports menu after killing
                    self._update_ports_menu()

                    # Show success notification
                    rumps.notification(
                        title="Process Killed",
                        subtitle=f"{process_name} (PID {pid})",
                        message="Process terminated successfully",
                        sound=False
                    )

                except ProcessLookupError:
                    logger.warning(f"Process {pid} not found (already terminated?)")
                    rumps.notification(
                        title="Process Not Found",
                        subtitle=f"{process_name} (PID {pid})",
                        message="Process may have already terminated",
                        sound=False
                    )
                except PermissionError:
                    logger.error(f"Permission denied killing process {pid}")
                    rumps.notification(
                        title="Permission Denied",
                        subtitle=f"{process_name} (PID {pid})",
                        message="Insufficient permissions to kill this process",
                        sound=False
                    )

        except Exception as e:
            logger.error(f"Error killing process {pid}: {e}", exc_info=True)

    def _make_shortcut_callback(self, label: str):
        """
        Create a callback function for executing a shortcut.

        Args:
            label: Shortcut label

        Returns:
            Callback function for rumps MenuItem
        """
        def execute_shortcut(_):
            """Execute shortcut callback"""
            self._execute_shortcut(label)
        return execute_shortcut

    def _execute_shortcut(self, label: str) -> None:
        """
        Execute a shortcut by label.

        Args:
            label: Shortcut label to execute
        """
        try:
            success = self.shortcut_manager.execute_shortcut(label)
            if success:
                logger.info(f"Shortcut executed: {label}")
            else:
                logger.error(f"Failed to execute shortcut: {label}")
                # Show error notification
                try:
                    title = _i18n.get_message("menubar.errors.shortcut_execution_failed")
                    message = _i18n.get_message("menubar.errors.shortcut_failed_message")
                    rumps.notification(
                        title=title,
                        subtitle=label,
                        message=message,
                        sound=False
                    )
                except:
                    pass

        except Exception as e:
            logger.error(f"Error executing shortcut '{label}': {e}", exc_info=True)

    def _on_shortcut_background_start(self, label: str, command: str) -> None:
        """
        Callback when background shortcut starts.

        Args:
            label: Shortcut label
            command: Command being executed
        """
        # Update status to show shortcut execution
        self.status.command = label  # Use label as "command name"
        self.status.is_running = True
        self.status.start_time = time.time()
        self.status.progress = None
        self.status.current_stage = None
        self._update_status_display()

        logger.info(f"Background shortcut started: {label}")

    def _on_shortcut_background_complete(self, success: bool, duration: float, error: Optional[str]) -> None:
        """
        Callback when background shortcut completes.

        Args:
            success: Whether shortcut succeeded
            duration: Execution duration in seconds
            error: Error message if failed
        """
        # Update status to show completion
        self.status.is_running = False
        self.status.success = success
        self.status.end_time = self.status.start_time + duration if self.status.start_time else time.time()
        self.status.error = error
        self._update_status_display()

        # Schedule status clear after delay
        if self._status_clear_timer:
            self._status_clear_timer.cancel()
        self._status_clear_timer = threading.Timer(5.0, self._clear_status)
        self._status_clear_timer.start()

        logger.info(f"Background shortcut completed: success={success}, duration={duration:.1f}s")

    def _reload_config(self, _) -> None:
        """Reload configuration callback"""
        try:
            import json

            # Reload config file
            config_file = Path.home() / ".config" / "global-scripts" / "config" / "gs.json"
            if not config_file.exists():
                logger.warning("Config file not found, cannot reload")
                return

            new_config = json.loads(config_file.read_text())
            new_menubar_config = new_config.get("menubar", {})

            # Update config
            self.config = new_menubar_config

            # Reload shortcuts
            shortcuts_count = self.shortcut_manager.reload_config(new_menubar_config)
            if hasattr(self, "shortcuts_menu"):
                self._update_shortcuts_menu()

            logger.info(f"Config reloaded: {shortcuts_count} shortcuts loaded")

            # Show notification
            try:
                title = _i18n.get_message("menubar.errors.config_reload_success_title")
                message = _i18n.get_message("menubar.errors.config_reload_success_message")
                rumps.notification(
                    title=title,
                    subtitle=f"{shortcuts_count} shortcuts",
                    message=message,
                    sound=False
                )
            except:
                pass

        except Exception as e:
            logger.error(f"Failed to reload config: {e}", exc_info=True)
            # Show error notification
            try:
                title = _i18n.get_message("menubar.errors.config_reload_failed_title")
                rumps.notification(
                    title=title,
                    subtitle="",
                    message=str(e),
                    sound=False
                )
            except:
                pass

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
