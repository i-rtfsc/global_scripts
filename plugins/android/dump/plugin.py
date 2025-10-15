"""
Android Dump Subplugin
- dump battery info, system/build props
"""

import sys
from pathlib import Path
from typing import List, Optional
import asyncio

project_root = Path(__file__).resolve().parents[3]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from gscripts.plugins.decorators import plugin_function, subplugin
from gscripts.plugins.base import BasePlugin
from gscripts.core.config_manager import CommandResult
from plugins.android.common import get_selected_device as _get_dev


@subplugin("dump")
class AndroidDumpSubplugin(BasePlugin):
    def __init__(self):
        self.name = "dump"
        self.parent_plugin = "android"
    # no ConfigManager needed

    def _get_selected_device(self) -> Optional[str]:
        return _get_dev()

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
            sel = self._get_selected_device()
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
        name="battery",
        description={"zh": "电池信息", "en": "Battery info"},
        usage="gs android dump battery",
        examples=["gs android dump battery"],
    )
    async def battery(self, args: List[str] = None) -> CommandResult:
        return await self._run(["shell", "dumpsys", "battery"])

    @plugin_function(
        name="build",
        description={"zh": "系统属性", "en": "System build properties"},
        usage="gs android dump build",
        examples=["gs android dump build"],
    )
    async def build(self, args: List[str] = None) -> CommandResult:
        return await self._run(["shell", "getprop"])

    @plugin_function(
        name="top",
        description={"zh": "进程CPU占用快照", "en": "Top processes snapshot"},
        usage="gs android dump top [n]",
        examples=["gs android dump top", "gs android dump top 10"],
    )
    async def top(self, args: List[str] = None) -> CommandResult:
        lines = args[0] if args else "20"
        # Use busybox top -bn1 if available else dumpsys cpuinfo
        r = await self._run(["shell", "sh", "-c", f"(busybox top -bn1 || top -bn1) 2>/dev/null | head -n {lines}"])
        if r.success and r.output.strip():
            return r
        return await self._run(["shell", "dumpsys", "cpuinfo"])

    @plugin_function(
        name="meminfo",
        description={"zh": "内存信息", "en": "Memory info"},
        usage="gs android dump meminfo [package]",
        examples=["gs android dump meminfo", "gs android dump meminfo com.example.app"],
    )
    async def meminfo(self, args: List[str] = None) -> CommandResult:
        if args and args[0]:
            return await self._run(["shell", "dumpsys", "meminfo", args[0]])
        return await self._run(["shell", "dumpsys", "meminfo"])

    @plugin_function(
        name="cpuinfo",
        description={"zh": "CPU信息", "en": "CPU info"},
        usage="gs android dump cpuinfo",
        examples=["gs android dump cpuinfo"],
    )
    async def cpuinfo(self, args: List[str] = None) -> CommandResult:
        return await self._run(["shell", "dumpsys", "cpuinfo"])

    @plugin_function(
        name="activity",
        description={"zh": "当前焦点Activity", "en": "Current focused activity"},
        usage="gs android dump activity",
        examples=["gs android dump activity"],
    )
    async def activity(self, args: List[str] = None) -> CommandResult:
        # Support both old and new dumpsys outputs
        return await self._run(["shell", "dumpsys", "activity", "top"])

    @plugin_function(
        name="packages",
        description={"zh": "列出已安装包", "en": "List installed packages"},
        usage="gs android dump packages [keyword]",
        examples=["gs android dump packages", "gs android dump packages google"],
    )
    async def packages(self, args: List[str] = None) -> CommandResult:
        if args and args[0]:
            return await self._run(["shell", "pm", "list", "packages", "-f", "|", "grep", args[0]])
        return await self._run(["shell", "pm", "list", "packages", "-f"])

    @plugin_function(
        name="appops",
        description={"zh": "应用操作权限", "en": "App ops"},
        usage="gs android dump appops <package>",
        examples=["gs android dump appops com.example.app"],
    )
    async def appops(self, args: List[str] = None) -> CommandResult:
        args = args or []
        if not args:
            return CommandResult(False, error="Usage: gs android dump appops <package>")
        return await self._run(["shell", "appops", "get", args[0]])
