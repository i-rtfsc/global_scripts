#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Menu Bar Plugin

Provides commands to control the macOS menu bar status indicator.
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).resolve().parents[2]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from gscripts.plugins.base import BasePlugin
from gscripts.plugins.decorators import plugin_function
from gscripts.models import CommandResult


class MenuBar(BasePlugin):
    """Menu bar management plugin"""

    def __init__(self):
        self.name = "menubar"

    @plugin_function(
        name="start",
        description={
            "zh": "启动菜单栏应用",
            "en": "Start the menu bar app"
        },
        usage="gs menubar start",
        examples=["gs menubar start"]
    )
    async def start(self, args=None) -> CommandResult:
        """Start menu bar app"""
        # Check platform
        if sys.platform != "darwin":
            return CommandResult(
                success=False,
                error="菜单栏仅支持 macOS",
                exit_code=1
            )

        try:
            from gscripts.menubar.utils import is_menubar_running, start_menubar, get_pid_file

            if is_menubar_running():
                return CommandResult(
                    success=True,
                    output="菜单栏已在运行中",
                    exit_code=0
                )

            if start_menubar():
                pid_file = get_pid_file()
                pid = int(pid_file.read_text().strip()) if pid_file.exists() else "unknown"
                return CommandResult(
                    success=True,
                    output=f"菜单栏已启动 (PID: {pid})",
                    exit_code=0
                )
            else:
                return CommandResult(
                    success=False,
                    error="启动菜单栏失败",
                    exit_code=1
                )

        except ImportError as e:
            return CommandResult(
                success=False,
                error=f"rumps 未安装。请运行: uv sync\n详情: {e}",
                exit_code=1
            )
        except Exception as e:
            return CommandResult(
                success=False,
                error=f"启动失败: {e}",
                exit_code=1
            )

    @plugin_function(
        name="stop",
        description={
            "zh": "停止菜单栏应用",
            "en": "Stop the menu bar app"
        },
        usage="gs menubar stop",
        examples=["gs menubar stop"]
    )
    async def stop(self, args=None) -> CommandResult:
        """Stop menu bar app"""
        if sys.platform != "darwin":
            return CommandResult(success=False, error="菜单栏仅支持 macOS", exit_code=1)

        try:
            from gscripts.menubar.utils import is_menubar_running, stop_menubar

            if not is_menubar_running():
                return CommandResult(success=True, output="菜单栏未运行", exit_code=0)

            if stop_menubar():
                return CommandResult(success=True, output="菜单栏已停止", exit_code=0)
            else:
                return CommandResult(success=False, error="停止菜单栏失败", exit_code=1)

        except Exception as e:
            return CommandResult(success=False, error=f"停止失败: {e}", exit_code=1)

    @plugin_function(
        name="restart",
        description={
            "zh": "重启菜单栏应用",
            "en": "Restart the menu bar app"
        },
        usage="gs menubar restart",
        examples=["gs menubar restart"]
    )
    async def restart(self, args=None) -> CommandResult:
        """Restart menu bar app"""
        # Stop first
        stop_result = await self.stop()
        if not stop_result.success and "未运行" not in stop_result.output:
            return stop_result

        # Wait a moment
        import time
        time.sleep(0.5)

        # Start
        return await self.start()

    @plugin_function(
        name="status",
        description={
            "zh": "显示菜单栏状态",
            "en": "Show menu bar status"
        },
        usage="gs menubar status",
        examples=["gs menubar status"]
    )
    async def status(self, args=None) -> CommandResult:
        """Show menu bar status"""
        if sys.platform != "darwin":
            return CommandResult(success=False, error="菜单栏仅支持 macOS", exit_code=1)

        try:
            from gscripts.menubar.utils import is_menubar_running, get_pid_file

            if is_menubar_running():
                pid_file = get_pid_file()
                pid = int(pid_file.read_text().strip()) if pid_file.exists() else "unknown"
                socket_path = Path.home() / ".config" / "global-scripts" / "menubar.sock"
                socket_status = "存在" if socket_path.exists() else "缺失"

                output = f"""菜单栏状态: 运行中
PID: {pid}
Socket: {socket_path} ({socket_status})
配置: ~/.config/global-scripts/config/gs.json
日志: ~/.config/global-scripts/logs/menubar.log"""

                return CommandResult(success=True, output=output, exit_code=0)
            else:
                return CommandResult(success=True, output="菜单栏未运行", exit_code=0)

        except Exception as e:
            return CommandResult(success=False, error=f"获取状态失败: {e}", exit_code=1)

    @plugin_function(
        name="send",
        description={
            "zh": "向菜单栏发送自定义消息",
            "en": "Send custom message to menu bar"
        },
        usage="gs menubar send <message>",
        examples=[
            "gs menubar send '构建中...'",
            "gs menubar send 'Build: 45%'",
            "gs menubar send '测试通过 ✓'"
        ]
    )
    async def send(self, args=None) -> CommandResult:
        """Send custom message to menu bar"""
        if sys.platform != "darwin":
            return CommandResult(success=False, error="菜单栏仅支持 macOS", exit_code=1)

        if not args:
            return CommandResult(
                success=False,
                error="用法: gs menubar send <消息>",
                exit_code=1
            )

        try:
            from gscripts.menubar.utils import is_menubar_running
            from gscripts.menubar.ipc import IPCClient

            if not is_menubar_running():
                return CommandResult(
                    success=False,
                    error="菜单栏未运行。使用以下命令启动: gs menubar start",
                    exit_code=1
                )

            message = " ".join(args)
            client = IPCClient()
            success = client.send_message({"type": "custom_message", "text": message})

            if success:
                return CommandResult(
                    success=True,
                    output=f"消息已发送至菜单栏: {message}",
                    exit_code=0
                )
            else:
                return CommandResult(
                    success=False,
                    error="发送消息失败（菜单栏可能未响应）",
                    exit_code=1
                )

        except Exception as e:
            return CommandResult(success=False, error=f"发送失败: {e}", exit_code=1)
