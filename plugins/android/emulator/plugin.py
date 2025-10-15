"""
Android Emulator Subplugin
- list/start/stop/restart Android emulators without Android Studio
"""

import sys
from pathlib import Path
from typing import List, Optional
import asyncio
import os

# Ensure project root on sys.path
project_root = Path(__file__).resolve().parents[3]
if str(project_root / 'src') not in sys.path:
    sys.path.insert(0, str(project_root / 'src'))

from gscripts.plugins.decorators import plugin_function, subplugin
from gscripts.plugins.base import BasePlugin
from gscripts.core.config_manager import CommandResult


@subplugin("emulator")
class AndroidEmulatorSubplugin(BasePlugin):
    def __init__(self):
        self.name = "emulator"
        self.parent_plugin = "android"
        self._emulator_path = self._find_emulator()

    def _find_emulator(self) -> Optional[str]:
        """查找 Android SDK emulator 路径"""
        # 尝试常见路径
        possible_paths = [
            Path.home() / "Library/Android/sdk/emulator/emulator",  # macOS
            Path.home() / "Android/Sdk/emulator/emulator",  # Linux
            Path(os.environ.get("ANDROID_HOME", "")) / "emulator/emulator" if os.environ.get("ANDROID_HOME") else None,
        ]

        for path in possible_paths:
            if path and path.exists():
                return str(path)

        # 尝试从 PATH 查找
        import shutil
        emulator = shutil.which("emulator")
        if emulator:
            return emulator

        return None

    async def _list_avds(self) -> List[str]:
        """列出所有可用的 AVD"""
        if not self._emulator_path:
            return []

        try:
            proc = await asyncio.create_subprocess_exec(
                self._emulator_path, "-list-avds",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, _ = await proc.communicate()
            if proc.returncode != 0:
                return []

            avds = [line.strip() for line in out.decode(errors="ignore").strip().splitlines() if line.strip()]
            return avds
        except Exception:
            return []

    async def _is_emulator_running(self, avd_name: str) -> bool:
        """检查指定的模拟器是否正在运行"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "adb", "devices",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, _ = await proc.communicate()
            if proc.returncode != 0:
                return False

            # 检查是否有模拟器在运行（emulator-xxxx）
            lines = out.decode(errors="ignore").strip().splitlines()
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "device" and "emulator-" in parts[0]:
                    return True
            return False
        except Exception:
            return False

    async def _get_running_emulators(self) -> List[str]:
        """获取所有正在运行的模拟器序列号"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "adb", "devices",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, _ = await proc.communicate()
            if proc.returncode != 0:
                return []

            emulators = []
            lines = out.decode(errors="ignore").strip().splitlines()
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "device" and "emulator-" in parts[0]:
                    emulators.append(parts[0])
            return emulators
        except Exception:
            return []

    @plugin_function(
        name="list",
        description={"zh": "列出所有可用的模拟器", "en": "List all available emulators"},
        usage="gs android emulator list",
        examples=["gs android emulator list"],
    )
    async def list_emulators(self, args: List[str] = None) -> CommandResult:
        """列出所有可用的 AVD"""
        if not self._emulator_path:
            return CommandResult(
                False,
                error="Emulator not found. Please install Android SDK and set ANDROID_HOME."
            )

        avds = await self._list_avds()
        if not avds:
            return CommandResult(False, error="No AVDs found. Create one in Android Studio first.")

        # 检查哪些正在运行
        running = await self._get_running_emulators()

        output_lines = ["📱 Available Android Emulators:"]
        for avd in avds:
            status = "🟢 Running" if running else "⚪ Stopped"
            output_lines.append(f"  • {avd} {status}")

        if running:
            output_lines.append(f"\n✅ Running emulators: {', '.join(running)}")

        return CommandResult(True, output="\n".join(output_lines))

    @plugin_function(
        name="start",
        description={"zh": "启动模拟器", "en": "Start an emulator"},
        usage="gs android emulator start [avd_name]",
        examples=[
            "gs android emulator start",
            "gs android emulator start Pixel_6_Pro_API_34"
        ],
    )
    async def start(self, args: List[str] = None) -> CommandResult:
        """启动模拟器"""
        if not self._emulator_path:
            return CommandResult(
                False,
                error="Emulator not found. Please install Android SDK and set ANDROID_HOME."
            )

        avds = await self._list_avds()
        if not avds:
            return CommandResult(False, error="No AVDs found. Create one in Android Studio first.")

        # 如果没有指定 AVD，使用第一个
        avd_name = args[0] if args else avds[0]

        if avd_name not in avds:
            return CommandResult(
                False,
                error=f"AVD '{avd_name}' not found. Available: {', '.join(avds)}"
            )

        # 检查是否已经在运行
        if await self._is_emulator_running(avd_name):
            return CommandResult(True, output=f"✅ Emulator '{avd_name}' is already running")

        try:
            # 在后台启动模拟器
            proc = await asyncio.create_subprocess_exec(
                self._emulator_path, "-avd", avd_name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )

            # 等待一小段时间确认启动
            await asyncio.sleep(1)

            return CommandResult(
                True,
                output=f"🚀 Starting emulator '{avd_name}' in background...\n"
                       f"   Use 'gs android emulator status' to check status"
            )
        except Exception as e:
            return CommandResult(False, error=f"Failed to start emulator: {str(e)}")

    @plugin_function(
        name="stop",
        description={"zh": "停止模拟器", "en": "Stop running emulator(s)"},
        usage="gs android emulator stop [serial]",
        examples=[
            "gs android emulator stop",
            "gs android emulator stop emulator-5554"
        ],
    )
    async def stop(self, args: List[str] = None) -> CommandResult:
        """停止模拟器"""
        running = await self._get_running_emulators()

        if not running:
            return CommandResult(False, error="No running emulators found")

        # 如果指定了序列号，只停止指定的
        if args:
            target = args[0]
            if target not in running:
                return CommandResult(
                    False,
                    error=f"Emulator '{target}' not found. Running: {', '.join(running)}"
                )
            targets = [target]
        else:
            targets = running

        # 停止模拟器
        results = []
        for serial in targets:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "adb", "-s", serial, "emu", "kill",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                out, err = await proc.communicate()
                if proc.returncode == 0:
                    results.append(f"✅ Stopped {serial}")
                else:
                    results.append(f"❌ Failed to stop {serial}: {err.decode(errors='ignore')}")
            except Exception as e:
                results.append(f"❌ Failed to stop {serial}: {str(e)}")

        return CommandResult(True, output="\n".join(results))

    @plugin_function(
        name="restart",
        description={"zh": "重启模拟器", "en": "Restart emulator"},
        usage="gs android emulator restart [avd_name]",
        examples=[
            "gs android emulator restart",
            "gs android emulator restart Pixel_6_Pro_API_34"
        ],
    )
    async def restart(self, args: List[str] = None) -> CommandResult:
        """重启模拟器"""
        # 先停止
        stop_result = await self.stop([])
        if not stop_result.success and "No running emulators" not in stop_result.error:
            return stop_result

        # 等待停止完成
        await asyncio.sleep(2)

        # 再启动
        return await self.start(args)

    @plugin_function(
        name="status",
        description={"zh": "查看模拟器状态", "en": "Check emulator status"},
        usage="gs android emulator status",
        examples=["gs android emulator status"],
    )
    async def status(self, args: List[str] = None) -> CommandResult:
        """查看模拟器状态"""
        if not self._emulator_path:
            return CommandResult(
                False,
                error="Emulator not found. Please install Android SDK and set ANDROID_HOME."
            )

        avds = await self._list_avds()
        running = await self._get_running_emulators()

        output_lines = [
            f"📱 Emulator Status:",
            f"   Emulator Path: {self._emulator_path}",
            f"   Total AVDs: {len(avds)}",
            f"   Running: {len(running)}",
        ]

        if avds:
            output_lines.append("\n📋 Available AVDs:")
            for avd in avds:
                output_lines.append(f"   • {avd}")

        if running:
            output_lines.append("\n🟢 Running Emulators:")
            for serial in running:
                output_lines.append(f"   • {serial}")
        else:
            output_lines.append("\n⚪ No running emulators")

        return CommandResult(True, output="\n".join(output_lines))

    @plugin_function(
        name="path",
        description={"zh": "显示模拟器路径", "en": "Show emulator path"},
        usage="gs android emulator path",
        examples=["gs android emulator path"],
    )
    async def path(self, args: List[str] = None) -> CommandResult:
        """显示模拟器路径"""
        if not self._emulator_path:
            return CommandResult(
                False,
                error="Emulator not found. Please install Android SDK and set ANDROID_HOME."
            )

        return CommandResult(True, output=f"Emulator: {self._emulator_path}")
