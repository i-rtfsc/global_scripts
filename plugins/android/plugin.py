"""
Android 主插件（共享状态与ADB工具）
- 提供共享工具方法：获取/设置默认设备、列出设备、运行adb
- 设备选择由子插件 device 暴露命令；此处不直接注册命令避免重复
- 设备选择持久化到 Shell 配置 ~/.config/global-scripts/config/gs.conf 的顶层键：android_selected_device
"""

import sys
from pathlib import Path
from typing import List, Optional
import asyncio

# 确保可以导入 gs_system
project_root = Path(__file__).resolve().parents[2]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from gscripts.plugins.base import BasePlugin
from gscripts.models.result import CommandResult
from plugins.android.common import get_selected_device as _get_dev, set_selected_device as _set_dev


class AndroidBase(BasePlugin):
    def __init__(self):
        self.name = "android"
    # no ConfigManager required here; persistence handled by plugins.android.common

    # 工具：读取与写入选中设备
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
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "device":
                    devices.append(parts[0])
            return devices
        except Exception:
            return []

    # 对外：获取当前默认设备（失效则回退到列表第一个）
    async def get_active_device(self) -> Optional[str]:
        selected = self._get_selected_device()
        devices = await self._list_devices()
        if not devices:
            return None
        if selected in devices:
            return selected
        # 选择已失效，回退到第一个并更新
        self._set_selected_device(devices[0])
        return devices[0]

    # 让其他子插件统一调用的 ADB 执行器
    async def run_adb(self, args: List[str]) -> CommandResult:
        serial = await self.get_active_device()
        base_cmd = ["adb"]
        if serial:
            base_cmd += ["-s", serial]
        base_cmd += args
        try:
            proc = await asyncio.create_subprocess_exec(
                *base_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await proc.communicate()
            ok = proc.returncode == 0
            return CommandResult(
                success=ok,
                output=out.decode(errors="ignore"),
                error=err.decode(errors="ignore"),
                exit_code=proc.returncode or 0,
            )
        except Exception as e:
            return CommandResult(False, error=str(e))

