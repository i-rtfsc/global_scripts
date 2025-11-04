"""
Android Logcat Subplugin
- clear, tail, filter
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


@subplugin("logcat")
class AndroidLogcatSubplugin(BasePlugin):
    def __init__(self):
        self.name = "logcat"
        self.parent_plugin = "android"
    # no ConfigManager needed

    def _get_selected_device(self) -> Optional[str]:
        return _get_dev()

    async def _active_device(self) -> Optional[str]:
        # simple resolution
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
        name="clear",
        description={"zh": "清除logcat缓冲区", "en": "Clear logcat buffer"},
        usage="gs android logcat clear",
        examples=["gs android logcat clear"],
    )
    async def clear(self, args: List[str] = None) -> CommandResult:
        return await self._run(["logcat", "-c"])

    @plugin_function(
        name="tail",
        description={"zh": "跟随输出logcat", "en": "Tail logcat"},
        usage="gs android logcat tail [level]",
        examples=["gs android logcat tail", "gs android logcat tail *:W"],
    )
    async def tail(self, args: List[str] = None) -> CommandResult:
        level = args[0] if args else "*:I"
        serial = await self._active_device()
        cmd = ["adb"] + (["-s", serial] if serial else []) + ["logcat", "-v", "time", level]
        try:
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            # Stream a few lines to avoid blocking indefinitely
            collected = []
            for _ in range(100):
                line = await proc.stdout.readline()
                if not line:
                    break
                collected.append(line.decode(errors="ignore"))
            try:
                proc.kill()
            except Exception:
                pass
            return CommandResult(True, output=''.join(collected))
        except Exception as e:
            return CommandResult(False, error=str(e))

    @plugin_function(
        name="filter",
        description={"zh": "按包含关键字过滤输出(非阻塞采样)", "en": "Filter logcat by keyword (sample)"},
        usage="gs android logcat filter <keyword>",
        examples=["gs android logcat filter ActivityManager"],
    )
    async def filter(self, args: List[str] = None) -> CommandResult:
        args = args or []
        if not args:
            return CommandResult(False, error="Usage: gs android logcat filter <keyword>")
        keyword = args[0]
        serial = await self._active_device()
        cmd = ["adb"] + (["-s", serial] if serial else []) + ["logcat", "-v", "time", "*:I"]
        try:
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            collected = []
            for _ in range(200):
                line = await proc.stdout.readline()
                if not line:
                    break
                decoded = line.decode(errors="ignore")
                if keyword in decoded:
                    collected.append(decoded)
            try:
                proc.kill()
            except Exception:
                pass
            return CommandResult(True, output=''.join(collected) or f"No lines matched: {keyword}")
        except Exception as e:
            return CommandResult(False, error=str(e))
