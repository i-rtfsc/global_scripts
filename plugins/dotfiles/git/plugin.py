"""
Git Configuration Subplugin
- 管理 Git 配置文件
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
from gscripts.models.result import CommandResult
from plugins.dotfiles.plugin import DotfilesPlugin


@subplugin("git")
class GitConfigSubplugin(DotfilesPlugin):
    def __init__(self):
        super().__init__()
        self.name = "git"
        self.parent_plugin = "dotfiles"
        self.subplugin_dir = Path(__file__).parent

        # Git 配置路径映射
        self.main_config = {
            "source": self.subplugin_dir / ".gitconfig",
            "target": Path.home() / ".gitconfig",
        }

        # 备份目录
        self.backup_dir = self.get_backup_dir(self.name)

    @plugin_function(
        name="install",
        description={"zh": "安装 Git 配置", "en": "Install Git configuration"},
        usage="gs dotfiles git install [--force]",
        examples=["gs dotfiles git install", "gs dotfiles git install --force"]
    )
    async def install(self, args: List[str] = None) -> CommandResult:
        """安装 Git 配置"""
        force = "--force" in (args or []) or "-f" in (args or [])

        try:
            source = self.main_config["source"]
            target = self.main_config["target"]

            if not source.exists():
                return CommandResult(success=False, error=f"源配置文件不存在: {source}")

            # 备份现有配置
            if target.exists() and not force:
                await self._backup_git_config()

            # 确保目标目录存在
            target.parent.mkdir(parents=True, exist_ok=True)

            # 复制主配置文件（添加头部信息）
            await self._copy_with_header(source, target, self.name, add_timestamp=True, comment_prefix="#")
            print(f"[DOTFILES] 安装配置: .gitconfig -> {target}")

            return CommandResult(success=True, output=f"Git 配置安装成功: {target}")
        except Exception as e:
            return CommandResult(success=False, error=f"安装配置失败: {str(e)}")

    @plugin_function(
        name="uninstall",
        description={"zh": "卸载 Git 配置", "en": "Uninstall Git configuration"},
        usage="gs dotfiles git uninstall",
        examples=["gs dotfiles git uninstall"]
    )
    async def uninstall(self, args: List[str] = None) -> CommandResult:
        """卸载 Git 配置"""
        try:
            target = self.main_config["target"]

            if not target.exists():
                return CommandResult(success=False, error="Git 配置未安装")

            # 备份后删除
            await self._backup_git_config()
            target.unlink()

            return CommandResult(success=True, output="Git 配置已卸载（已备份）")
        except Exception as e:
            return CommandResult(success=False, error=f"卸载配置失败: {str(e)}")

    @plugin_function(
        name="backup",
        description={"zh": "备份 Git 配置", "en": "Backup Git configuration"},
        usage="gs dotfiles git backup",
        examples=["gs dotfiles git backup"]
    )
    async def backup(self, args: List[str] = None) -> CommandResult:
        """备份 Git 配置"""
        try:
            target = self.main_config["target"]

            if not target.exists():
                return CommandResult(success=False, error="Git 配置未安装，无需备份")

            backup_path = await self._backup_git_config()

            return CommandResult(success=True, output=f"Git 配置已备份到: {backup_path}")
        except Exception as e:
            return CommandResult(success=False, error=f"备份配置失败: {str(e)}")

    @plugin_function(
        name="restore",
        description={"zh": "恢复 Git 配置", "en": "Restore Git configuration"},
        usage="gs dotfiles git restore",
        examples=["gs dotfiles git restore"]
    )
    async def restore(self, args: List[str] = None) -> CommandResult:
        """恢复 Git 配置"""
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

            # 恢复主配置
            backup_file = backup_path / ".gitconfig"
            if not backup_file.exists():
                return CommandResult(success=False, error=f"备份文件不存在: {backup_file}")

            target = self.main_config["target"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(backup_file, target)
            print(f"[DOTFILES] 恢复配置: .gitconfig")

            return CommandResult(success=True, output=f"Git 配置已恢复: {chosen_backup['name']}")
        except Exception as e:
            return CommandResult(success=False, error=f"恢复配置失败: {str(e)}")

    @plugin_function(
        name="status",
        description={"zh": "查看 Git 配置状态", "en": "Show Git configuration status"},
        usage="gs dotfiles git status",
        examples=["gs dotfiles git status"]
    )
    async def status(self, args: List[str] = None) -> CommandResult:
        """查看 Git 配置状态"""
        try:
            source = self.main_config["source"]
            target = self.main_config["target"]

            output = "Git 配置状态:\n"
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

    async def _backup_git_config(self) -> Path:
        """备份 Git 配置文件"""
        from datetime import datetime

        try:
            # 创建时间戳目录
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_subdir = self.backup_dir / timestamp
            backup_subdir.mkdir(parents=True, exist_ok=True)

            # 备份主配置文件
            target_config = self.main_config["target"]
            if target_config.exists():
                shutil.copy2(target_config, backup_subdir / ".gitconfig")
                print(f"[DOTFILES] 备份文件: {target_config} -> {backup_subdir / '.gitconfig'}")

            # 清理旧备份，只保留最新3份
            await self._cleanup_old_backups(self.backup_dir)

            return backup_subdir

        except Exception as e:
            print(f"[DOTFILES] 备份失败: {str(e)}")
            raise
