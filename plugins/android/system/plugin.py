"""
Android System Subplugin
- System management and configuration utilities
- SELinux, hidden API, settings, optimization functions
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
from gscripts.models.result import CommandResult
from plugins.android.common import get_selected_device as _get_dev


@subplugin("system")
class AndroidSystemSubplugin(BasePlugin):
    def __init__(self):
        self.name = "system"
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
        name="selinux-disable",
        description={"zh": "禁用SELinux安全策略", "en": "Disable SELinux security policy"},
        usage="gs android system selinux-disable",
        examples=["gs android system selinux-disable"]
    )
    async def selinux_disable(self, args: List[str] = None) -> CommandResult:
        """Disable SELinux security policy"""
        result1 = await self._run(["shell", "setenforce", "0"])
        if not result1.success:
            return result1
        
        result2 = await self._run(["shell", "stop && start"])
        if result2.success:
            return CommandResult(True, output="✅ SELinux disabled and system restarted")
        else:
            return result2

    @plugin_function(
        name="hidden-api-enable",
        description={"zh": "启用Hidden API访问", "en": "Enable Hidden API access"},
        usage="gs android system hidden-api-enable",
        examples=["gs android system hidden-api-enable"]
    )
    async def hidden_api_enable(self, args: List[str] = None) -> CommandResult:
        """Enable Hidden API access"""
        result1 = await self._run(["shell", "settings", "put", "global", "hidden_api_policy_pre_p_apps", "1"])
        if not result1.success:
            return result1
        
        result2 = await self._run(["shell", "settings", "put", "global", "hidden_api_policy_p_apps", "1"])
        if result2.success:
            return CommandResult(True, output="✅ Hidden API access enabled")
        else:
            return result2

    @plugin_function(
        name="hidden-api-disable",
        description={"zh": "禁用Hidden API访问", "en": "Disable Hidden API access"},
        usage="gs android system hidden-api-disable",
        examples=["gs android system hidden-api-disable"]
    )
    async def hidden_api_disable(self, args: List[str] = None) -> CommandResult:
        """Disable Hidden API access"""
        result1 = await self._run(["shell", "settings", "delete", "global", "hidden_api_policy_pre_p_apps"])
        if not result1.success:
            return result1
        
        result2 = await self._run(["shell", "settings", "delete", "global", "hidden_api_policy_p_apps"])
        if result2.success:
            return CommandResult(True, output="✅ Hidden API access disabled")
        else:
            return result2

    @plugin_function(
        name="settings-dump",
        description={"zh": "查看SettingsProvider所有配置", "en": "Dump all SettingsProvider configurations"},
        usage="gs android system settings-dump",
        examples=["gs android system settings-dump"]
    )
    async def settings_dump(self, args: List[str] = None) -> CommandResult:
        """Dump all SettingsProvider configurations"""
        return await self._run(["shell", "dumpsys", "settings"])

    @plugin_function(
        name="remove-dex2oat",
        description={"zh": "删除dex2oat缓存并重启", "en": "Remove dex2oat cache and reboot"},
        usage="gs android system remove-dex2oat",
        examples=["gs android system remove-dex2oat"]
    )
    async def remove_dex2oat(self, args: List[str] = None) -> CommandResult:
        """Remove dex2oat cache and reboot"""
        await self._run(["root"])
        await self._run(["remount"])
        
        result1 = await self._run(["shell", "rm", "-rf", "system/framework/oat"])
        result2 = await self._run(["shell", "rm", "-rf", "system/framework/arm"])
        result3 = await self._run(["shell", "rm", "-rf", "system/framework/arm64"])
        
        if result1.success and result2.success and result3.success:
            await self._run(["reboot"])
            return CommandResult(True, output="✅ dex2oat cache removed, device rebooting")
        else:
            return CommandResult(False, error="Failed to remove dex2oat cache")

    @plugin_function(
        name="abx2xml",
        description={"zh": "转换ABX格式到XML", "en": "Convert ABX format to XML"},
        usage="gs android system abx2xml <file_path>",
        examples=["gs android system abx2xml /data/system/packages.xml"]
    )
    async def abx2xml(self, args: List[str] = None) -> CommandResult:
        """Convert ABX format to XML"""
        if not args or len(args) == 0:
            return CommandResult(False, error="File path is required")
        
        file_path = args[0]
        return await self._run(["shell", f"cat {file_path} | abx2xml - -"])

    @plugin_function(
        name="imei",
        description={"zh": "获取设备IMEI", "en": "Get device IMEI"},
        usage="gs android system imei",
        examples=["gs android system imei"]
    )
    async def imei(self, args: List[str] = None) -> CommandResult:
        """Get device IMEI"""
        return await self._run(["shell", "service call iphonesubinfo 1 | cut -c 52-66 | tr -d '.[:space:]'"])