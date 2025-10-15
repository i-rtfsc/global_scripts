"""
Android App Subplugin
- Application management utilities
- List, version info, package management functions
"""

import sys
import asyncio
from pathlib import Path
from typing import List, Optional

project_root = Path(__file__).resolve().parents[3]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from gscripts.plugins.decorators import plugin_function, subplugin
from gscripts.plugins.base import BasePlugin
from gscripts.core.config_manager import CommandResult
from plugins.android.common import get_selected_device as _get_dev


@subplugin("app")
class AndroidAppSubplugin(BasePlugin):
    def __init__(self):
        self.name = "app"
        self.parent_plugin = "android"

    async def _active_device(self) -> Optional[str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                "adb", "devices",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            out, _ = await proc.communicate()
            lines = out.decode(errors="ignore").strip().splitlines()[1:]
            devices = [l.split()[0] for l in lines if l.strip() and 'device' in l]
            if not devices:
                return None
            sel = _get_dev()
            return sel if sel in devices else devices[0]
        except Exception:
            return None

    async def _run(self, args: List[str]) -> CommandResult:
        serial = await self._active_device()
        cmd = ["adb"] + (["-s", serial] if serial else []) + args
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await proc.communicate()
            ok = proc.returncode == 0
            return CommandResult(ok, output=out.decode(errors="ignore"), error=err.decode(errors="ignore"), exit_code=proc.returncode or 0)
        except Exception as e:
            return CommandResult(False, error=str(e))

    @plugin_function(
        name="list-3rd",
        description={"zh": "列出第三方应用", "en": "List third-party applications"},
        usage="gs android app list-3rd",
        examples=["gs android app list-3rd"]
    )
    async def list_3rd(self, args: List[str] = None) -> CommandResult:
        """List third-party applications"""
        return await self._run(["shell", "pm", "list", "packages", "-f", "-3"])

    @plugin_function(
        name="list-system",
        description={"zh": "列出系统应用", "en": "List system applications"},
        usage="gs android app list-system",
        examples=["gs android app list-system"]
    )
    async def list_system(self, args: List[str] = None) -> CommandResult:
        """List system applications"""
        return await self._run(["shell", "pm", "list", "packages", "-f", "-s"])

    @plugin_function(
        name="version",
        description={"zh": "获取应用版本信息", "en": "Get application version info"},
        usage="gs android app version <package_name>",
        examples=[
            "gs android app version com.android.settings",
            "gs android app version com.example.app"
        ]
    )
    async def version(self, args: List[str] = None) -> CommandResult:
        """Get application version info"""
        if not args or len(args) == 0:
            return CommandResult(False, error="Package name is required")
        
        package_name = args[0]
        result = await self._run(["shell", "dumpsys", "package", package_name])
        
        if result.success:
            # Filter for version-related lines
            lines = result.output.splitlines()
            version_lines = [line for line in lines if 'version' in line.lower()]
            version_output = '\n'.join(version_lines) if version_lines else result.output
            return CommandResult(True, output=version_output)
        else:
            return result

    @plugin_function(
        name="kill",
        description={"zh": "终止应用进程", "en": "Kill application process"},
        usage="gs android app kill <package_name>",
        examples=[
            "gs android app kill com.example.app",
            "gs android app kill com.android.settings"
        ]
    )
    async def kill(self, args: List[str] = None) -> CommandResult:
        """Kill application process"""
        if not args or len(args) == 0:
            return CommandResult(False, error="Package name is required")
        
        package_name = args[0]
        result = await self._run(["shell", "killall", package_name])
        
        if result.success:
            return CommandResult(True, output=f"✅ Killed {package_name}")
        else:
            return result

    @plugin_function(
        name="clear",
        description={"zh": "清除应用数据", "en": "Clear application data"},
        usage="gs android app clear <package_name>",
        examples=[
            "gs android app clear com.example.app",
            "gs android app clear com.android.settings"
        ]
    )
    async def clear(self, args: List[str] = None) -> CommandResult:
        """Clear application data"""
        if not args or len(args) == 0:
            return CommandResult(False, error="Package name is required")
        
        package_name = args[0]
        result = await self._run(["shell", "pm", "clear", package_name])
        
        if result.success:
            return CommandResult(True, output=f"✅ Cleared data for {package_name}")
        else:
            return result

    @plugin_function(
        name="log",
        description={"zh": "显示应用日志", "en": "Show application logs"},
        usage="gs android app log <package_name>",
        examples=[
            "gs android app log com.example.app",
            "gs android app log com.android.settings"
        ]
    )
    async def log(self, args: List[str] = None) -> CommandResult:
        """Show application logs"""
        if not args or len(args) == 0:
            return CommandResult(False, error="Package name is required")
        
        package_name = args[0]
        
        # First get the PID
        pid_result = await self._run(["shell", "pidof", package_name])
        if not pid_result.success or not pid_result.output.strip():
            return CommandResult(False, error=f"Process not found for {package_name}")
        
        pid = pid_result.output.strip()
        return await self._run(["logcat", f"--pid={pid}"])

    @plugin_function(
        name="version-settings",
        description={"zh": "获取设置应用版本", "en": "Get Settings app version"},
        usage="gs android app version-settings",
        examples=["gs android app version-settings"]
    )
    async def version_settings(self, args: List[str] = None) -> CommandResult:
        """Get Settings app version"""
        return await self.version(["com.android.settings"])