"""
Android Device Subplugin
- choose/current/clear selected device persisted via ConfigManager
"""

import sys
from pathlib import Path
from typing import List, Optional
import asyncio

# Ensure project root on sys.path
project_root = Path(__file__).resolve().parents[3]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from gscripts.plugins.decorators import plugin_function, subplugin
from gscripts.plugins.base import BasePlugin
from gscripts.models.result import CommandResult
from plugins.android.common import get_selected_device as _get_dev, set_selected_device as _set_dev


@subplugin("device")
class AndroidDeviceSubplugin(BasePlugin):
    def __init__(self):
        self.name = "device"
        self.parent_plugin = "android"
    # no global ConfigManager needed; persistence handled in plugins.android.common

    def _get_selected_device(self) -> Optional[str]:
        return _get_dev()

    def _set_selected_device(self, serial: Optional[str]):
        _set_dev(serial)

    async def _list_devices(self) -> List[str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                "adb", "devices",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, _ = await proc.communicate()
            if proc.returncode != 0:
                return []
            lines = out.decode(errors="ignore").strip().splitlines()
            devices = []
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "device":
                    devices.append(parts[0])
            return devices
        except Exception:
            return []

    async def _get_active_device(self) -> Optional[str]:
        selected = self._get_selected_device()
        devices = await self._list_devices()
        if not devices:
            return None
        if selected in devices:
            return selected
        self._set_selected_device(devices[0])
        return devices[0]

    @plugin_function(
        name="devices",
        description={"zh": "列出所有连接的设备", "en": "List connected devices"},
        usage="gs android device devices",
        examples=["gs android device devices"],
    )
    async def devices(self, args: List[str] = None) -> CommandResult:
        devices = await self._list_devices()
        if not devices:
            return CommandResult(False, error="No devices found by 'adb devices'")
        return CommandResult(True, output="\n".join(devices))

    async def _run(self, extra: List[str]) -> CommandResult:
        serial = await self._get_active_device()
        base = ["adb"] + (["-s", serial] if serial else [])
        try:
            proc = await asyncio.create_subprocess_exec(*base, *extra, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            out, err = await proc.communicate()
            ok = proc.returncode == 0
            return CommandResult(ok, output=out.decode(errors="ignore"), error=err.decode(errors="ignore"), exit_code=proc.returncode or 0)
        except Exception as e:
            return CommandResult(False, error=str(e))

    @plugin_function(
        name="connect",
        description={"zh": "通过IP连接设备", "en": "Connect to device over IP"},
        usage="gs android device connect <ip[:port]>",
        examples=["gs android device connect 192.168.1.10", "gs android device connect 192.168.1.10:5555"],
    )
    async def connect(self, args: List[str] = None) -> CommandResult:
        args = args or []
        if not args:
            return CommandResult(False, error="Usage: gs android device connect <ip[:port]>")
        try:
            proc = await asyncio.create_subprocess_exec("adb", "connect", args[0], stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            out, err = await proc.communicate()
            ok = proc.returncode == 0
            return CommandResult(ok, output=out.decode(errors="ignore"), error=err.decode(errors="ignore"), exit_code=proc.returncode or 0)
        except Exception as e:
            return CommandResult(False, error=str(e))

    @plugin_function(
        name="disconnect",
        description={"zh": "断开IP连接", "en": "Disconnect from IP device"},
        usage="gs android device disconnect [ip[:port]]",
        examples=["gs android device disconnect", "gs android device disconnect 192.168.1.10:5555"],
    )
    async def disconnect(self, args: List[str] = None) -> CommandResult:
        target = args[0] if args else None
        cmd = ["adb", "disconnect"] + ([target] if target else [])
        try:
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            out, err = await proc.communicate()
            ok = proc.returncode == 0
            return CommandResult(ok, output=out.decode(errors="ignore"), error=err.decode(errors="ignore"), exit_code=proc.returncode or 0)
        except Exception as e:
            return CommandResult(False, error=str(e))

    @plugin_function(
        name="size",
        description={"zh": "获取屏幕尺寸", "en": "Get screen size"},
        usage="gs android device size",
        examples=["gs android device size"],
    )
    async def size(self, args: List[str] = None) -> CommandResult:
        return await self._run(["shell", "wm", "size"])

    @plugin_function(
        name="screencap",
        description={"zh": "截取屏幕到本地", "en": "Capture screenshot to local"},
        usage="gs android device screencap [outfile.png]",
        examples=["gs android device screencap", "gs android device screencap screen.png"],
    )
    async def screencap(self, args: List[str] = None) -> CommandResult:
        import tempfile, os
        out = args[0] if args else "screencap.png"
        # Use adb exec-out if available (faster), fallback to pull
        serial = await self._get_active_device()
        cmd = ["adb"] + (["-s", serial] if serial else []) + ["exec-out", "screencap", "-p"]
        try:
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            data, err = await proc.communicate()
            if proc.returncode != 0 or not data:
                # fallback path
                tmp = "/sdcard/__gs_screencap.png"
                r1 = await self._run(["shell", "screencap", "-p", tmp])
                if not r1.success:
                    return r1
                proc2 = await asyncio.create_subprocess_exec("adb", *( ["-s", serial] if serial else [] ), "pull", tmp, out, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                _, err2 = await proc2.communicate()
                ok = proc2.returncode == 0
                # best-effort cleanup
                await self._run(["shell", "rm", "-f", tmp])
                return CommandResult(ok, output=(f"Saved to {out}" if ok else "pull failed"), error=err2.decode(errors="ignore"), exit_code=proc2.returncode or 0)
            with open(out, "wb") as f:
                f.write(data)
            return CommandResult(True, output=f"Saved to {out}")
        except Exception as e:
            return CommandResult(False, error=str(e))

    @plugin_function(
        name="wait",
        description={"zh": "等待设备就绪", "en": "Wait for device"},
        usage="gs android device wait",
        examples=["gs android device wait"],
    )
    async def wait(self, args: List[str] = None) -> CommandResult:
        try:
            proc = await asyncio.create_subprocess_exec("adb", "wait-for-device", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            out, err = await proc.communicate()
            ok = proc.returncode == 0
            return CommandResult(ok, output=out.decode(errors="ignore") or "device is ready", error=err.decode(errors="ignore"), exit_code=proc.returncode or 0)
        except Exception as e:
            return CommandResult(False, error=str(e))

    @plugin_function(
        name="choose",
        description={"zh": "交互选择设备并保存", "en": "Select device interactively and persist"},
        usage="gs android device choose",
        examples=["gs android device choose"],
    )
    async def choose(self, args: List[str] = None) -> CommandResult:
        devices = await self._list_devices()
        if not devices:
            return CommandResult(False, error="No devices found by 'adb devices'")
        print("🔌 Devices:")
        for i, d in enumerate(devices, 1):
            print(f"  {i}. {d}")
        print("Enter number to select (default=1): ", end="", flush=True)
        try:
            loop = asyncio.get_event_loop()
            sel = await loop.run_in_executor(None, sys.stdin.readline)
            sel = sel.strip()
            idx = int(sel) if sel else 1
            idx = max(1, min(idx, len(devices)))
            chosen = devices[idx - 1]
            self._set_selected_device(chosen)
            return CommandResult(True, output=f"Selected device: {chosen}")
        except Exception:
            chosen = devices[0]
            self._set_selected_device(chosen)
            return CommandResult(True, output=f"Selected device: {chosen}")

    @plugin_function(
        name="current",
        description={"zh": "查看当前默认设备", "en": "Show current default device"},
        usage="gs android device current",
        examples=["gs android device current"],
    )
    async def current(self, args: List[str] = None) -> CommandResult:
        serial = await self._get_active_device()
        if not serial:
            return CommandResult(False, error="No active device. Run: gs android device choose")
        return CommandResult(True, output=f"Current device: {serial}")

    @plugin_function(
        name="clear",
        description={"zh": "清除已选设备", "en": "Clear selected device"},
        usage="gs android device clear",
        examples=["gs android device clear"],
    )
    async def clear(self, args: List[str] = None) -> CommandResult:
        self._set_selected_device(None)
        return CommandResult(True, output="Cleared selected device")
