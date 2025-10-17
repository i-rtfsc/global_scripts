"""
Tmux Configuration Subplugin
- 管理 Tmux 配置文件
- 继承主插件的通用功能
"""

import sys
import shutil
from pathlib import Path
from typing import List

# Ensure project root on sys.path
project_root = Path(__file__).resolve().parents[3]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from gscripts.plugins.decorators import plugin_function, subplugin
from gscripts.core.config_manager import CommandResult
from plugins.dotfiles.plugin import DotfilesPlugin


@subplugin("tmux")
class TmuxConfigSubplugin(DotfilesPlugin):
    def __init__(self):
        super().__init__()
        self.name = "tmux"
        self.parent_plugin = "dotfiles"
        self.subplugin_dir = Path(__file__).parent

        # Tmux 配置路径映射
        self.main_config = {
            "source": self.subplugin_dir / ".tmux.conf",
            "target": Path.home() / ".tmux.conf",
        }

        # 备份目录
        self.backup_dir = self.get_backup_dir(self.name)

    @plugin_function(
        name="install",
        description={"zh": "安装 Tmux 配置", "en": "Install Tmux configuration"},
        usage="gs dotfiles tmux install [--force]",
        examples=["gs dotfiles tmux install", "gs dotfiles tmux install --force"]
    )
    async def install(self, args: List[str] = None) -> CommandResult:
        """安装 Tmux 配置"""
        force = "--force" in (args or []) or "-f" in (args or [])

        try:
            source = self.main_config["source"]
            target = self.main_config["target"]

            if not source.exists():
                return CommandResult(success=False, error=f"源配置文件不存在: {source}")

            # 备份现有配置
            if target.exists() and not force:
                await self._backup_file(target, self.backup_dir, self.name)

            # 确保目标目录存在
            target.parent.mkdir(parents=True, exist_ok=True)

            # 复制配置文件（添加头部信息）
            await self._copy_with_header(source, target, self.name, add_timestamp=True, comment_prefix="#")

            return CommandResult(success=True, output=f"Tmux 配置安装成功")
        except Exception as e:
            return CommandResult(success=False, error=f"安装配置失败: {str(e)}")

    @plugin_function(
        name="uninstall",
        description={"zh": "卸载 Tmux 配置", "en": "Uninstall Tmux configuration"},
        usage="gs dotfiles tmux uninstall",
        examples=["gs dotfiles tmux uninstall"]
    )
    async def uninstall(self, args: List[str] = None) -> CommandResult:
        """卸载 Tmux 配置"""
        try:
            target = self.main_config["target"]

            if not target.exists():
                return CommandResult(success=False, error="Tmux 配置未安装")

            # 备份后删除
            await self._backup_file(target, self.backup_dir, self.name)
            target.unlink()

            return CommandResult(success=True, output="Tmux 配置已卸载（已备份）")
        except Exception as e:
            return CommandResult(success=False, error=f"卸载配置失败: {str(e)}")

    @plugin_function(
        name="backup",
        description={"zh": "备份 Tmux 配置", "en": "Backup Tmux configuration"},
        usage="gs dotfiles tmux backup",
        examples=["gs dotfiles tmux backup"]
    )
    async def backup(self, args: List[str] = None) -> CommandResult:
        """备份 Tmux 配置"""
        try:
            target = self.main_config["target"]

            if not target.exists():
                return CommandResult(success=False, error="Tmux 配置未安装，无需备份")

            await self._backup_file(target, self.backup_dir, self.name)

            return CommandResult(success=True, output="Tmux 配置已备份")
        except Exception as e:
            return CommandResult(success=False, error=f"备份配置失败: {str(e)}")

    @plugin_function(
        name="restore",
        description={"zh": "恢复 Tmux 配置", "en": "Restore Tmux configuration"},
        usage="gs dotfiles tmux restore",
        examples=["gs dotfiles tmux restore"]
    )
    async def restore(self, args: List[str] = None) -> CommandResult:
        """恢复 Tmux 配置"""
        try:
            # 列出可用备份
            backups = await self._list_backups(self.backup_dir)

            if not backups:
                return CommandResult(success=False, error="没有可用的备份")

            # 显示备份列表
            print("可用备份:")
            for i, backup in enumerate(backups, 1):
                print(f"  {i}. {backup['name']} ({backup['modified']})")

            print("\n输入备份编号 (默认=1): ", end="", flush=True)

            # 读取用户输入
            import asyncio
            loop = asyncio.get_event_loop()
            sel = await loop.run_in_executor(None, sys.stdin.readline)
            sel = sel.strip()
            idx = int(sel) if sel else 1
            idx = max(1, min(idx, len(backups)))

            # 选中的备份
            chosen_backup = backups[idx - 1]
            backup_path = Path(chosen_backup["path"])

            # 查找备份文件
            backup_file = backup_path / ".tmux.conf"
            if not backup_file.exists():
                return CommandResult(success=False, error=f"备份文件不存在: {backup_file}")

            # 恢复配置
            target = self.main_config["target"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(backup_file, target)

            return CommandResult(success=True, output=f"Tmux 配置已恢复: {chosen_backup['name']}")
        except Exception as e:
            return CommandResult(success=False, error=f"恢复配置失败: {str(e)}")

    @plugin_function(
        name="status",
        description={"zh": "查看 Tmux 配置状态", "en": "Show Tmux configuration status"},
        usage="gs dotfiles tmux status",
        examples=["gs dotfiles tmux status"]
    )
    async def status(self, args: List[str] = None) -> CommandResult:
        """查看 Tmux 配置状态"""
        try:
            source = self.main_config["source"]
            target = self.main_config["target"]

            output = "Tmux 配置状态:\n"
            output += f"  源文件: {source} {'✓' if source.exists() else '✗'}\n"
            output += f"  目标文件: {target} {'✓ 已安装' if target.exists() else '✗ 未安装'}\n"

            # 备份信息
            backups = await self._list_backups(self.backup_dir)
            output += f"  备份数量: {len(backups)}\n"

            if backups:
                output += "\n最近备份:\n"
                for backup in backups[:3]:
                    output += f"    • {backup['name']} ({backup['modified']})\n"

            return CommandResult(success=True, output=output.strip())
        except Exception as e:
            return CommandResult(success=False, error=f"查询状态失败: {str(e)}")
