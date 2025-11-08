"""
Menu Bar CLI Command Handler

Provides commands for manual control of the menu bar:
- gs menubar start: Start menu bar app
- gs menubar stop: Stop menu bar app
- gs menubar restart: Restart menu bar app
- gs menubar status: Show menu bar status
- gs menubar send <message>: Send custom message to display in status bar
"""

import sys
from pathlib import Path
from typing import List
from ...models import CommandResult
from ...menubar.utils import (
    is_menubar_running,
    start_menubar,
    stop_menubar,
    get_pid_file,
)
from ...menubar.ipc import IPCClient


class MenuBarCommand:
    """Handler for menubar CLI commands"""

    def __init__(self, chinese: bool = True):
        self.chinese = chinese

    def handle(self, args: List[str]) -> CommandResult:
        """
        Handle menubar command

        Args:
            args: Command arguments [subcommand, ...]

        Returns:
            CommandResult
        """
        # Check platform
        if sys.platform != "darwin":
            return CommandResult(
                success=False,
                error="Menu bar is only supported on macOS" if not self.chinese else "菜单栏仅支持 macOS",
                exit_code=1,
            )

        # Check rumps availability
        try:
            import rumps  # noqa: F401
        except ImportError:
            error_msg = (
                "rumps not installed. Install with: uv sync"
                if not self.chinese
                else "rumps 未安装。请运行: uv sync"
            )
            return CommandResult(success=False, error=error_msg, exit_code=1)

        if not args or args[0] in ["help", "-h", "--help"]:
            return self._show_help()

        subcommand = args[0]

        if subcommand == "start":
            return self._start()
        elif subcommand == "stop":
            return self._stop()
        elif subcommand == "restart":
            return self._restart()
        elif subcommand == "status":
            return self._status()
        elif subcommand == "send":
            return self._send(args[1:])
        else:
            error_msg = (
                f"Unknown subcommand: {subcommand}\nRun 'gs menubar help' for usage"
                if not self.chinese
                else f"未知子命令: {subcommand}\n运行 'gs menubar help' 查看用法"
            )
            return CommandResult(success=False, error=error_msg, exit_code=1)

    def _start(self) -> CommandResult:
        """Start menu bar app"""
        if is_menubar_running():
            msg = "Menu bar is already running" if not self.chinese else "菜单栏已在运行中"
            return CommandResult(success=True, output=msg, exit_code=0)

        if start_menubar():
            pid_file = get_pid_file()
            pid = int(pid_file.read_text().strip()) if pid_file.exists() else "unknown"
            msg = (
                f"Menu bar started (PID: {pid})"
                if not self.chinese
                else f"菜单栏已启动 (PID: {pid})"
            )
            return CommandResult(success=True, output=msg, exit_code=0)
        else:
            error_msg = "Failed to start menu bar" if not self.chinese else "启动菜单栏失败"
            return CommandResult(success=False, error=error_msg, exit_code=1)

    def _stop(self) -> CommandResult:
        """Stop menu bar app"""
        if not is_menubar_running():
            msg = "Menu bar is not running" if not self.chinese else "菜单栏未运行"
            return CommandResult(success=True, output=msg, exit_code=0)

        if stop_menubar():
            msg = "Menu bar stopped" if not self.chinese else "菜单栏已停止"
            return CommandResult(success=True, output=msg, exit_code=0)
        else:
            error_msg = "Failed to stop menu bar" if not self.chinese else "停止菜单栏失败"
            return CommandResult(success=False, error=error_msg, exit_code=1)

    def _restart(self) -> CommandResult:
        """Restart menu bar app"""
        # Stop if running
        if is_menubar_running():
            stop_result = self._stop()
            if not stop_result.success:
                return stop_result

            # Wait a moment for cleanup
            import time

            time.sleep(0.5)

        # Start
        return self._start()

    def _status(self) -> CommandResult:
        """Show menu bar status"""
        if is_menubar_running():
            pid_file = get_pid_file()
            pid = int(pid_file.read_text().strip()) if pid_file.exists() else "unknown"
            socket_path = Path.home() / ".config" / "global-scripts" / "menubar.sock"
            socket_status = "exists" if socket_path.exists() else "missing"

            if self.chinese:
                output = f"""菜单栏状态: 运行中
PID: {pid}
Socket: {socket_path} ({socket_status})
配置: ~/.config/global-scripts/config/gs.json
日志: ~/.config/global-scripts/logs/menubar.log"""
            else:
                output = f"""Menu Bar Status: Running
PID: {pid}
Socket: {socket_path} ({socket_status})
Config: ~/.config/global-scripts/config/gs.json
Logs: ~/.config/global-scripts/logs/menubar.log"""

            return CommandResult(success=True, output=output, exit_code=0)
        else:
            msg = "Menu bar is not running" if not self.chinese else "菜单栏未运行"
            return CommandResult(success=True, output=msg, exit_code=0)

    def _send(self, args: List[str]) -> CommandResult:
        """Send custom message to menu bar"""
        if not args:
            error_msg = (
                "Usage: gs menubar send <message>"
                if not self.chinese
                else "用法: gs menubar send <消息>"
            )
            return CommandResult(success=False, error=error_msg, exit_code=1)

        if not is_menubar_running():
            error_msg = (
                "Menu bar is not running. Start it with: gs menubar start"
                if not self.chinese
                else "菜单栏未运行。使用以下命令启动: gs menubar start"
            )
            return CommandResult(success=False, error=error_msg, exit_code=1)

        message = " ".join(args)

        # Send custom message via IPC
        try:
            client = IPCClient()
            success = client.send_message({"type": "custom_message", "text": message})

            if success:
                msg = (
                    f"Message sent to menu bar: {message}"
                    if not self.chinese
                    else f"消息已发送至菜单栏: {message}"
                )
                return CommandResult(success=True, output=msg, exit_code=0)
            else:
                error_msg = (
                    "Failed to send message (menu bar may not be responding)"
                    if not self.chinese
                    else "发送消息失败（菜单栏可能未响应）"
                )
                return CommandResult(success=False, error=error_msg, exit_code=1)

        except Exception as e:
            error_msg = f"Failed to send message: {e}"
            return CommandResult(success=False, error=error_msg, exit_code=1)

    def _show_help(self) -> CommandResult:
        """Show help message"""
        if self.chinese:
            help_text = """Global Scripts 菜单栏管理

用法: gs menubar <子命令> [参数]

子命令:
  start              启动菜单栏应用
  stop               停止菜单栏应用
  restart            重启菜单栏应用
  status             显示菜单栏状态
  send <消息>        向菜单栏发送自定义消息

示例:
  gs menubar start                    # 启动菜单栏
  gs menubar status                   # 查看状态
  gs menubar send "构建中..."         # 显示自定义消息
  gs menubar send "Build: 45%"        # 显示进度消息
  gs menubar stop                     # 停止菜单栏

配置:
  编辑 ~/.config/global-scripts/config/gs.json:
  {
    "menubar": {
      "enabled": true,           # 启用自动启动
      "refresh_interval": 5,     # 指标刷新间隔（秒）
      "show_cpu_temp": true,     # 显示CPU温度
      "show_memory": true        # 显示内存使用率
    }
  }

日志:
  ~/.config/global-scripts/logs/menubar.log
"""
        else:
            help_text = """Global Scripts Menu Bar Manager

Usage: gs menubar <subcommand> [args]

Subcommands:
  start              Start the menu bar app
  stop               Stop the menu bar app
  restart            Restart the menu bar app
  status             Show menu bar status
  send <message>     Send custom message to menu bar

Examples:
  gs menubar start                    # Start menu bar
  gs menubar status                   # Check status
  gs menubar send "Building..."       # Show custom message
  gs menubar send "Build: 45%"        # Show progress message
  gs menubar stop                     # Stop menu bar

Configuration:
  Edit ~/.config/global-scripts/config/gs.json:
  {
    "menubar": {
      "enabled": true,           # Enable auto-start
      "refresh_interval": 5,     # Metric refresh interval (seconds)
      "show_cpu_temp": true,     # Show CPU temperature
      "show_memory": true        # Show memory usage
    }
  }

Logs:
  ~/.config/global-scripts/logs/menubar.log
"""

        return CommandResult(success=True, output=help_text.strip(), exit_code=0)
