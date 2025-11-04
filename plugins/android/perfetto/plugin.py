"""
Android Perfetto Subplugin
- Trace with a config file (pbtx/txt) piped to perfetto
- Default quick trace of common categories
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


@subplugin("perfetto")
class AndroidPerfettoSubplugin(BasePlugin):
    def __init__(self):
        self.name = "perfetto"
        self.parent_plugin = "android"
        self._default_config = Path(__file__).resolve().parent / "config.pbtx"

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
        name="trace",
        description={"zh": "使用配置文件采集并拉取trace", "en": "Collect trace with config file and pull"},
        usage="gs android perfetto trace [-f <config.pbtx|txt>] [out_file]",
        examples=[
            "gs android perfetto trace -f config.pbtx trace.perfetto-trace",
            "gs android perfetto trace trace.perfetto-trace"
        ]
    )
    async def trace(self, args: List[str] = None) -> CommandResult:
        args = args or []
        # simple arg parse: support -f <config>, last arg optionally output filename
        config_path: Optional[Path] = None
        out_file = "trace.perfetto-trace"
        i = 0
        while i < len(args):
            if args[i] == "-f" and i + 1 < len(args):
                config_path = Path(args[i+1]).expanduser()
                i += 2
            else:
                out_file = args[i]
                i += 1
        if config_path is None:
            config_path = self._default_config
        
        # Priority file search: 1. Current working directory, 2. Plugin directory
        if not config_path.is_absolute():
            # 1. First try current working directory
            cwd_candidate = Path.cwd() / config_path.name
            if cwd_candidate.exists():
                config_path = cwd_candidate
            # 2. Then try plugin directory  
            elif not config_path.exists():
                plugin_candidate = self._default_config.parent / config_path.name
                if plugin_candidate.exists():
                    config_path = plugin_candidate
        
        if not config_path.exists():
            return CommandResult(False, error=f"Config file not found: {config_path}\nSearched: {Path.cwd() / config_path.name} and {self._default_config.parent / config_path.name}")

        # root + remount (best effort)
        await self._run(["root"])  # ignore result
        await self._run(["remount"])  # ignore result

        # pipe config to perfetto and pull result
        try:
            # Use shell to cat file and pipe via adb shell perfetto -c -
            # We'll read file content and pass via stdin using create_subprocess_exec
            serial = await self._active_device()
            cmd = ["adb"] + (["-s", serial] if serial else []) + [
                "shell", "perfetto", "-c", "-", "--txt", "-o", "/data/misc/perfetto-traces/trace.perfetto-trace"
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            content = config_path.read_bytes()
            out, err = await proc.communicate(input=content)
            if proc.returncode != 0:
                return CommandResult(False, error=err.decode(errors="ignore") or out.decode(errors="ignore"))
        except Exception as e:
            return CommandResult(False, error=str(e))

        # pull to local
        pull = await self._run(["pull", "/data/misc/perfetto-traces/trace.perfetto-trace", out_file])
        if not pull.success:
            return pull
        return CommandResult(True, output=f"Saved: {out_file}")

    @plugin_function(
        name="default",
        description={"zh": "快速采集常用事件10s", "en": "Quick 10s trace of common categories"},
        usage="gs android perfetto default [out_file]",
        examples=[
            "gs android perfetto default",
            "gs android perfetto default quick.perfetto-trace"
        ]
    )
    async def default(self, args: List[str] = None) -> CommandResult:
        args = args or []
        out_file = args[0] if args else "trace.perfetto-trace"
        await self._run(["root"])  # best effort
        await self._run(["remount"])  # best effort
        cmd = [
            "shell", "perfetto",
            "-o", "/data/misc/perfetto-traces/trace.perfetto-trace",
            "-t", "20s",
            "sched", "freq", "idle", "am", "wm", "gfx", "view", "binder_driver", "hal", "dalvik", "camera", "input", "res", "memory"
        ]
        r = await self._run(cmd)
        if not r.success:
            return r
        pull = await self._run(["pull", "/data/misc/perfetto-traces/trace.perfetto-trace", out_file])
        if not pull.success:
            return pull
        return CommandResult(True, output=f"Saved: {out_file}")
