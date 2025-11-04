"""
Android Proc Subplugin
- Process-level operations: ps_grep, kill_grep, Activity Manager monitoring
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


@subplugin("proc")
class AndroidProcSubplugin(BasePlugin):
    def __init__(self):
        self.name = "proc"
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
        name="ps_grep",
        description={"zh": "进程名查找", "en": "ps grep"},
        usage="gs android proc ps_grep <keyword>",
        examples=[
            "gs android proc ps_grep zygote",
            "gs android proc ps_grep com.android.systemui"
        ]
    )
    async def ps_grep(self, args: List[str] = None) -> CommandResult:
        args = args or []
        if not args:
            return CommandResult(False, error="Usage: gs android proc ps_grep <keyword>")
        # emulate: adb shell ps | grep -v "$1:" | grep "$1"
        sh = f"ps | grep -v '{args[0]}:' | grep '{args[0]}'"
        return await self._run(["shell", "sh", "-c", sh])

    @plugin_function(
        name="kill_grep",
        description={"zh": "按关键字杀进程", "en": "kill by grep"},
        usage="gs android proc kill_grep <keyword>",
        examples=[
            "gs android proc kill_grep zygote",
            "gs android proc kill_grep com.example.app"
        ]
    )
    async def kill_grep(self, args: List[str] = None) -> CommandResult:
        args = args or []
        if not args:
            return CommandResult(False, error="Usage: gs android proc kill_grep <keyword>")
        # emulate: kill $(ps | grep $1 | awk '{print $2}')
        sh = f"kill $(ps | grep {args[0]} | awk '{{print $2}}')"
        return await self._run(["shell", "sh", "-c", sh])

    @plugin_function(
        name="am-proc-start",
        description={"zh": "监控进程启动事件", "en": "Monitor process start events"},
        usage="gs android proc am-proc-start <package>",
        examples=["gs android proc am-proc-start com.example.app"]
    )
    async def am_proc_start(self, args: List[str] = None) -> CommandResult:
        """Monitor Activity Manager process start events"""
        if not args or len(args) == 0:
            return CommandResult(False, error="Package name is required")
        
        package = args[0]
        # Create regex pattern: package name with escaped dots
        escaped_package = package.replace(".", r"\.")
        regex = f"am_proc_start.*{escaped_package}|{escaped_package}.*am_proc_start"
        
        # Search in current directory for log files
        shell_cmd = f"cat * 2>/dev/null | grep -E '{regex}'"
        return await self._run(["shell", f"cd /data/local/tmp && {shell_cmd}"])

    @plugin_function(
        name="am-proc-died",
        description={"zh": "监控进程死亡事件", "en": "Monitor process died events"},
        usage="gs android proc am-proc-died <package>",
        examples=["gs android proc am-proc-died com.example.app"]
    )
    async def am_proc_died(self, args: List[str] = None) -> CommandResult:
        """Monitor Activity Manager process died events"""
        if not args or len(args) == 0:
            return CommandResult(False, error="Package name is required")
        
        package = args[0]
        escaped_package = package.replace(".", r"\.")
        regex = f"am_proc_died.*{escaped_package}|{escaped_package}.*am_proc_died"
        
        shell_cmd = f"cat * 2>/dev/null | grep -E '{regex}'"
        return await self._run(["shell", f"cd /data/local/tmp && {shell_cmd}"])

    @plugin_function(
        name="am-kill",
        description={"zh": "监控进程被杀事件", "en": "Monitor process kill events"},
        usage="gs android proc am-kill <package>",
        examples=["gs android proc am-kill com.example.app"]
    )
    async def am_kill(self, args: List[str] = None) -> CommandResult:
        """Monitor Activity Manager kill events"""
        if not args or len(args) == 0:
            return CommandResult(False, error="Package name is required")
        
        package = args[0]
        escaped_package = package.replace(".", r"\.")
        regex = f"am_kill.*{escaped_package}|{escaped_package}.*am_kill"
        
        shell_cmd = f"cat * 2>/dev/null | grep -E '{regex}'"
        return await self._run(["shell", f"cd /data/local/tmp && {shell_cmd}"])

    @plugin_function(
        name="am-anr",
        description={"zh": "监控ANR事件", "en": "Monitor ANR events"},
        usage="gs android proc am-anr <package>",
        examples=["gs android proc am-anr com.example.app"]
    )
    async def am_anr(self, args: List[str] = None) -> CommandResult:
        """Monitor Activity Manager ANR events"""
        if not args or len(args) == 0:
            return CommandResult(False, error="Package name is required")
        
        package = args[0]
        escaped_package = package.replace(".", r"\.")
        regex = f"am_anr.*{escaped_package}|{escaped_package}.*am_anr"
        
        shell_cmd = f"cat * 2>/dev/null | grep -E '{regex}'"
        return await self._run(["shell", f"cd /data/local/tmp && {shell_cmd}"])
