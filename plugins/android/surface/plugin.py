"""
Android Surface Subplugin
- SurfaceFlinger refresh rate helpers
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
from gscripts.models.result import CommandResult
from plugins.android.common import get_selected_device as _get_dev


@subplugin("surface")
class AndroidSurfaceSubplugin(BasePlugin):
    def __init__(self):
        self.name = "surface"
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
        name="show_refresh_rate",
        description={"zh": "显示刷新率开关", "en": "Show refresh rate toggle"},
        usage="gs android surface show_refresh_rate <0|1>",
        examples=[
            "gs android surface show_refresh_rate 1",
            "gs android surface show_refresh_rate 0"
        ]
    )
    async def show_refresh_rate(self, args: List[str] = None) -> CommandResult:
        args = args or []
        if not args:
            return CommandResult(False, error="Usage: gs android surface show_refresh_rate <0|1>")
        return await self._run(["shell", "service", "call", "SurfaceFlinger", "1034", "i32", args[0]])

    @plugin_function(
        name="set_refresh_rate",
        description={"zh": "设置刷新率", "en": "Set refresh rate"},
        usage="gs android surface set_refresh_rate <rate>",
        examples=[
            "gs android surface set_refresh_rate 60",
            "gs android surface set_refresh_rate 120"
        ]
    )
    async def set_refresh_rate(self, args: List[str] = None) -> CommandResult:
        args = args or []
        if not args:
            return CommandResult(False, error="Usage: gs android surface set_refresh_rate <rate>")
        return await self._run(["shell", "service", "call", "SurfaceFlinger", "1035", "i32", args[0]])

    @plugin_function(
        name="dump_refresh_rate",
        description={"zh": "Dump刷新率信息", "en": "Dump refresh info"},
        usage="gs android surface dump_refresh_rate",
        examples=[
            "gs android surface dump_refresh_rate"
        ]
    )
    async def dump_refresh_rate(self, args: List[str] = None) -> CommandResult:
        return await self._run(["shell", "dumpsys", "SurfaceFlinger"]) 
