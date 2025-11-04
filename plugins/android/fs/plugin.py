"""
Android FS Subplugin
- push, pull, and shortcuts for common Android modules/files.
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


COMMON_PATHS = {
    # Framework / boot jars
    "framework": ["/system/framework/framework.jar"],
    "framework_ext": ["/system/framework/framework-ext.jar"],
    "services": ["/system/framework/services.jar"],
    # System binaries and tools
    "toybox": ["/system/bin/toybox"],
    "surfaceflinger": ["/system/bin/surfaceflinger"],
    # Common native libs (multiple arch locations)
    "libandroid_runtime.so": [
        "/system/lib64/libandroid_runtime.so",
        "/system/lib/libandroid_runtime.so",
    ],
    # Frequently used libs (both 64/32-bit locations)
    "libgui": [
        "/system/lib64/libgui.so",
        "/system/lib/libgui.so",
    ],
    "libgpuservice": [
        "/system/lib64/libgpuservice.so",
        "/system/lib/libgpuservice.so",
    ],
    "libinputflinger": [
        "/system/lib64/libinputflinger.so",
        "/system/lib/libinputflinger.so",
    ],
    "libui": [
        "/system/lib64/libui.so",
        "/system/lib/libui.so",
    ],
    "libbinder": [
        "/system/lib64/libbinder.so",
        "/system/lib/libbinder.so",
    ],
    # Common APK/JAR assets
    "framework_res": ["/system/framework/framework-res.apk"],
    "systemui_apk": [
        "/system/priv-app/SystemUI/SystemUI.apk",
        "/product/priv-app/SystemUI/SystemUI.apk",
        "/system_ext/priv-app/SystemUI/SystemUI.apk",
    ],
    "settings_apk": [
        "/system/priv-app/Settings/Settings.apk",
        "/product/priv-app/Settings/Settings.apk",
        "/system_ext/priv-app/Settings/Settings.apk",
    ],
    "bootanimation": [
        "/system/media/bootanimation.zip",
        "/product/media/bootanimation.zip",
    ],
}


@subplugin("fs")
class AndroidFsSubplugin(BasePlugin):
    def __init__(self):
        self.name = "fs"
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

    async def _exists(self, path: str) -> bool:
        # Use POSIX test to avoid noisy ls errors
        try:
            serial = await self._active_device()
            base = ["adb"] + (["-s", serial] if serial else [])
            proc = await asyncio.create_subprocess_exec(*base, "shell", "sh", "-c", f"test -e '{path}'")
            rc = await proc.wait()
            return rc == 0
        except Exception:
            return False

    async def _resolve_alias(self, name: str) -> Optional[str]:
        entry = COMMON_PATHS.get(name)
        if not entry:
            return None
        candidates = entry if isinstance(entry, list) else [entry]
        for p in candidates:
            if await self._exists(p):
                return p
        # None exist; return first as fallback (for push target)
        return candidates[0] if candidates else None

    @plugin_function(
        name="push",
        description={"zh": "推送文件到设备", "en": "Push file to device"},
        usage="gs android fs push <local> <remote|alias>",
        examples=[
            "gs android fs push app.apk /sdcard/app.apk",
            "gs android fs push ./framework.jar framework",
        ],
    )
    async def push(self, args: List[str] = None) -> CommandResult:
        args = args or []
        if len(args) < 2:
            return CommandResult(False, error="Usage: gs android fs push <local> <remote|alias>")
        local, remote_spec = args[0], args[1]
        # Allow alias as remote target
        if remote_spec in COMMON_PATHS:
            remote = await self._resolve_alias(remote_spec)
            if not remote:
                return CommandResult(False, error=f"Unknown or unresolved alias: {remote_spec}")
        else:
            remote = remote_spec
        return await self._run(["push", local, remote])

    @plugin_function(
        name="pull",
        description={"zh": "从设备拉取文件", "en": "Pull file from device"},
        usage="gs android fs pull <remote|alias> <local>",
        examples=[
            "gs android fs pull /sdcard/log.txt ./log.txt",
            "gs android fs pull libgpuservice ./libgpuservice.so",
        ],
    )
    async def pull(self, args: List[str] = None) -> CommandResult:
        args = args or []
        if len(args) < 2:
            return CommandResult(False, error="Usage: gs android fs pull <remote|alias> <local>")
        remote_spec, local = args[0], args[1]
        # Allow alias as remote source
        if remote_spec in COMMON_PATHS:
            remote = await self._resolve_alias(remote_spec)
            if not remote:
                return CommandResult(False, error=f"Unknown or unresolved alias: {remote_spec}")
        else:
            remote = remote_spec
        return await self._run(["pull", remote, local])

    @plugin_function(
        name="common",
        description={"zh": "展示常见路径映射", "en": "Show common paths"},
        usage="gs android fs common",
        examples=["gs android fs common"],
    )
    async def common(self, args: List[str] = None) -> CommandResult:
        def fmt(v):
            return ", ".join(v) if isinstance(v, list) else v
        lines = [f"{k}: {fmt(v)}" for k, v in COMMON_PATHS.items()]
        return CommandResult(True, output="\n".join(lines))

    @plugin_function(
        name="resolve",
        description={"zh": "解析别名对应的实际路径（设备上存在的）", "en": "Resolve alias to existing device path"},
        usage="gs android fs resolve <name>",
        examples=["gs android fs resolve input"],
    )
    async def resolve(self, args: List[str] = None) -> CommandResult:
        args = args or []
        if not args:
            return CommandResult(False, error="Usage: gs android fs resolve <name>")
        path = await self._resolve_alias(args[0])
        if not path:
            return CommandResult(False, error=f"Unknown or unresolved alias: {args[0]}")
        return CommandResult(True, output=path)

    @plugin_function(
        name="verify",
        description={"zh": "校验常见路径在设备是否存在", "en": "Verify common paths on device"},
        usage="gs android fs verify",
        examples=["gs android fs verify"],
    )
    async def verify(self, args: List[str] = None) -> CommandResult:
        lines = []
        for k in sorted(COMMON_PATHS.keys()):
            resolved = await self._resolve_alias(k)
            if resolved and await self._exists(resolved):
                lines.append(f"[OK] {k}: {resolved}")
            else:
                lines.append(f"[--] {k}: not found")
        return CommandResult(True, output="\n".join(lines))

    @plugin_function(
        name="exists",
        description={"zh": "检查设备路径是否存在", "en": "Check if device path exists"},
        usage="gs android fs exists <path>",
        examples=["gs android fs exists /system/bin/sh"],
    )
    async def exists(self, args: List[str] = None) -> CommandResult:
        args = args or []
        if not args:
            return CommandResult(False, error="Usage: gs android fs exists <path>")
        ok = await self._exists(args[0])
        return CommandResult(ok, output=("exists" if ok else "not found"))

    @plugin_function(
        name="push_common",
        description={"zh": "推送文件到常见路径", "en": "Push file to common path"},
        usage="gs android fs push_common <local> <name>",
        examples=["gs android fs push_common ./framework.jar framework"],
    )
    async def push_common(self, args: List[str] = None) -> CommandResult:
        args = args or []
        if len(args) < 2:
            return CommandResult(False, error="Usage: gs android fs push_common <local> <name>")
        local, name = args[0], args[1]
        remote = await self._resolve_alias(name)
        if not remote:
            return CommandResult(False, error=f"Unknown common name: {name}")
        return await self._run(["push", local, remote])

    @plugin_function(
        name="pull_common",
        description={"zh": "从常见路径拉取文件", "en": "Pull file from common path"},
        usage="gs android fs pull_common <name> <local>",
        examples=["gs android fs pull_common framework ./framework.jar"],
    )
    async def pull_common(self, args: List[str] = None) -> CommandResult:
        args = args or []
        if len(args) < 2:
            return CommandResult(False, error="Usage: gs android fs pull_common <name> <local>")
        name, local = args[0], args[1]
        remote = await self._resolve_alias(name)
        if not remote:
            return CommandResult(False, error=f"Unknown common name: {name}")
        return await self._run(["pull", remote, local])

    @plugin_function(
        name="find_apk",
        description={"zh": "查找包名对应的APK路径", "en": "Find APK path(s) for package"},
        usage="gs android fs find_apk <package>",
        examples=["gs android fs find_apk com.android.settings"],
    )
    async def find_apk(self, args: List[str] = None) -> CommandResult:
        args = args or []
        if not args:
            return CommandResult(False, error="Usage: gs android fs find_apk <package>")
        pkg = args[0]
        r = await self._run(["shell", "pm", "path", pkg])
        if not r.success:
            return r
        # Output lines like: package:/data/app/.../base.apk
        paths = [line.split(":", 1)[1].strip() for line in r.output.splitlines() if ":" in line]
        return CommandResult(True, output="\n".join(paths) if paths else "")

    @plugin_function(
        name="locate_so",
        description={"zh": "定位.so库（常见目录扫描）", "en": "Locate .so library in common dirs"},
        usage="gs android fs locate_so <libname.so>",
        examples=["gs android fs locate_so libandroid_runtime.so"],
    )
    async def locate_so(self, args: List[str] = None) -> CommandResult:
        args = args or []
        if not args:
            return CommandResult(False, error="Usage: gs android fs locate_so <libname.so>")
        lib = args[0]
        search_dirs = [
            "/system/lib64", "/system/lib",
            "/vendor/lib64", "/vendor/lib",
            "/product/lib64", "/product/lib",
            "/system_ext/lib64", "/system_ext/lib",
            "/apex/com.android.runtime/lib64", "/apex/com.android.runtime/lib",
        ]
        # Use sh -c to iterate and echo matches
        query = " ; ".join([f"if [ -e '{d}/{lib}' ]; then echo '{d}/{lib}'; fi" for d in search_dirs])
        r = await self._run(["shell", "sh", "-c", query])
        return r

    @plugin_function(
        name="ls",
        description={"zh": "列出设备目录或文件", "en": "List device directory or file"},
        usage="gs android fs ls <path>",
        examples=["gs android fs ls /system/bin", "gs android fs ls /system/bin/input"],
    )
    async def ls(self, args: List[str] = None) -> CommandResult:
        args = args or []
        if not args:
            return CommandResult(False, error="Usage: gs android fs ls <path>")
        path = args[0]
        return await self._run(["shell", "ls", "-l", path])
