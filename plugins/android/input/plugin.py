"""
Android Input Subplugin
- keyevent, tap
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


@subplugin("input")
class AndroidInputSubplugin(BasePlugin):
    def __init__(self):
        self.name = "input"
        self.parent_plugin = "android"

    async def _active_device(self) -> Optional[str]:
        # choose saved or first online
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
        name="keyevent",
        description={"zh": "发送按键事件", "en": "Send keyevent"},
        usage="gs android input keyevent <KEYCODE>",
        examples=["gs android input keyevent 26"],
    )
    async def keyevent(self, args: List[str] = None) -> CommandResult:
        args = args or []
        if not args:
            return CommandResult(False, error="Usage: gs android input keyevent <KEYCODE>")
        return await self._run(["shell", "input", "keyevent", args[0]])

    @plugin_function(
        name="tap",
        description={"zh": "点击坐标", "en": "Tap at coordinates"},
        usage="gs android input tap <x> <y>",
        examples=["gs android input tap 100 200"],
    )
    async def tap(self, args: List[str] = None) -> CommandResult:
        args = args or []
        if len(args) < 2:
            return CommandResult(False, error="Usage: gs android input tap <x> <y>")
        return await self._run(["shell", "input", "tap", args[0], args[1]])

    @plugin_function(
        name="text",
        description={"zh": "输入文本", "en": "Type text"},
        usage="gs android input text <TEXT>",
        examples=["gs android input text hello", "gs android input text 'hello world'"]
    )
    async def text(self, args: List[str] = None) -> CommandResult:
        args = args or []
        if not args:
            return CommandResult(False, error="Usage: gs android input text <TEXT>")
        # Join tokens and apply simple encoding: space -> %s
        raw = " ".join(args)
        # Android input expects spaces as %s; keep basic ASCII safe
        encoded = raw.replace(" ", "%s")
        return await self._run(["shell", "input", "text", encoded])

    @plugin_function(
        name="swipe",
        description={"zh": "滑动手势", "en": "Swipe gesture"},
        usage="gs android input swipe <x1> <y1> <x2> <y2> [duration_ms]",
        examples=["gs android input swipe 100 100 300 300", "gs android input swipe 100 100 300 300 500"],
    )
    async def swipe(self, args: List[str] = None) -> CommandResult:
        args = args or []
        if len(args) < 4:
            return CommandResult(False, error="Usage: gs android input swipe <x1> <y1> <x2> <y2> [duration_ms]")
        cmd = ["shell", "input", "swipe", args[0], args[1], args[2], args[3]]
        if len(args) >= 5:
            cmd.append(args[4])
        return await self._run(cmd)

    @plugin_function(
        name="longpress",
        description={"zh": "长按", "en": "Long press"},
        usage="gs android input longpress <x> <y> [duration_ms]",
        examples=["gs android input longpress 200 400", "gs android input longpress 200 400 800"],
    )
    async def longpress(self, args: List[str] = None) -> CommandResult:
        args = args or []
        if len(args) < 2:
            return CommandResult(False, error="Usage: gs android input longpress <x> <y> [duration_ms]")
        duration = args[2] if len(args) >= 3 else "700"
        return await self._run(["shell", "input", "swipe", args[0], args[1], args[0], args[1], duration])

    # Convenience key commands
    async def _key(self, code: str) -> CommandResult:
        return await self._run(["shell", "input", "keyevent", code])

    @plugin_function(name="back", description={"zh": "返回键", "en": "Back"}, usage="gs android input back")
    async def back(self, args: List[str] = None) -> CommandResult:
        return await self._key("4")  # KEYCODE_BACK

    @plugin_function(name="home", description={"zh": "主页键", "en": "Home"}, usage="gs android input home")
    async def home(self, args: List[str] = None) -> CommandResult:
        return await self._key("3")  # KEYCODE_HOME

    @plugin_function(name="recent", description={"zh": "多任务键", "en": "Recents"}, usage="gs android input recent")
    async def recent(self, args: List[str] = None) -> CommandResult:
        return await self._key("187")  # KEYCODE_APP_SWITCH

    @plugin_function(name="power", description={"zh": "电源键", "en": "Power"}, usage="gs android input power")
    async def power(self, args: List[str] = None) -> CommandResult:
        return await self._key("26")  # KEYCODE_POWER

    @plugin_function(name="volume_up", description={"zh": "音量+", "en": "Volume Up"}, usage="gs android input volume_up")
    async def volume_up(self, args: List[str] = None) -> CommandResult:
        return await self._key("24")  # KEYCODE_VOLUME_UP

    @plugin_function(name="volume_down", description={"zh": "音量-", "en": "Volume Down"}, usage="gs android input volume_down")
    async def volume_down(self, args: List[str] = None) -> CommandResult:
        return await self._key("25")  # KEYCODE_VOLUME_DOWN

    @plugin_function(name="enter", description={"zh": "回车", "en": "Enter"}, usage="gs android input enter")
    async def enter(self, args: List[str] = None) -> CommandResult:
        return await self._key("66")  # KEYCODE_ENTER

    @plugin_function(name="del", description={"zh": "删除", "en": "Delete"}, usage="gs android input del")
    async def delete(self, args: List[str] = None) -> CommandResult:
        return await self._key("67")  # KEYCODE_DEL

    @plugin_function(name="space", description={"zh": "空格", "en": "Space"}, usage="gs android input space")
    async def space(self, args: List[str] = None) -> CommandResult:
        return await self._key("62")  # KEYCODE_SPACE

    @plugin_function(name="menu", description={"zh": "菜单键", "en": "Menu"}, usage="gs android input menu")
    async def menu(self, args: List[str] = None) -> CommandResult:
        return await self._key("82")  # KEYCODE_MENU

    @plugin_function(
        name="disable",
        description={"zh": "禁用触摸输入", "en": "Disable touch input"},
        usage="gs android input disable",
        examples=["gs android input disable"]
    )
    async def disable(self, args: List[str] = None) -> CommandResult:
        """Disable touch input"""
        results = []
        
        result1 = await self._run(["shell", "settings", "put", "system", "touch_event", "0"])
        results.append(result1.success)
        
        result2 = await self._run(["shell", "setprop", "sys.inputlog.enabled", "false"])
        results.append(result2.success)
        
        result3 = await self._run(["shell", "setprop", "sys.input.TouchFilterEnable", "false"])
        results.append(result3.success)
        
        result4 = await self._run(["shell", "dumpsys", "input"])
        
        if all(results):
            return CommandResult(True, output="✅ Touch input disabled\n" + result4.output)
        else:
            return CommandResult(False, error="Failed to disable touch input")

    @plugin_function(
        name="enable",
        description={"zh": "启用触摸输入", "en": "Enable touch input"},
        usage="gs android input enable",
        examples=["gs android input enable"]
    )
    async def enable(self, args: List[str] = None) -> CommandResult:
        """Enable touch input"""
        results = []
        
        result1 = await self._run(["shell", "settings", "put", "system", "touch_event", "1"])
        results.append(result1.success)
        
        result2 = await self._run(["shell", "setprop", "sys.inputlog.enabled", "true"])
        results.append(result2.success)
        
        result3 = await self._run(["shell", "setprop", "sys.input.TouchFilterEnable", "false"])
        results.append(result3.success)
        
        result4 = await self._run(["shell", "dumpsys", "input"])
        
        if all(results):
            return CommandResult(True, output="✅ Touch input enabled\n" + result4.output)
        else:
            return CommandResult(False, error="Failed to enable touch input")

    @plugin_function(
        name="screenrecord",
        description={"zh": "屏幕录制", "en": "Record screen"},
        usage="gs android input screenrecord <filename>",
        examples=["gs android input screenrecord recording", "gs android input screenrecord test_video"]
    )
    async def screenrecord(self, args: List[str] = None) -> CommandResult:
        """Record screen (note: this is a blocking operation)"""
        if not args or len(args) == 0:
            return CommandResult(False, error="Filename is required")
        
        filename = args[0]
        device_path = f"/sdcard/{filename}.mp4"
        
        print(f"🎥 Recording screen to {device_path}")
        print("⚠️ This is a blocking operation. Press Ctrl+C to stop recording.")
        
        # Record screen on device (blocking)
        result1 = await self._run(["shell", "screenrecord", device_path])
        if not result1.success:
            return result1
        
        # Pull to local
        result2 = await self._run(["pull", device_path])
        if result2.success:
            return CommandResult(True, output=f"✅ Screen recording saved as {filename}.mp4")
        else:
            return result2
