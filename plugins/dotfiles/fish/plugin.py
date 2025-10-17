"""
Fish Shell Configuration Subplugin
- 管理 Fish Shell 配置文件
- 继承主插件的通用功能
- 支持备份整个配置目录
"""

import sys
import shutil
from pathlib import Path
from typing import List
from datetime import datetime

# Ensure project root on sys.path
project_root = Path(__file__).resolve().parents[3]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from gscripts.plugins.decorators import plugin_function, subplugin
from gscripts.core.config_manager import CommandResult
from plugins.dotfiles.plugin import DotfilesPlugin


@subplugin("fish")
class FishConfigSubplugin(DotfilesPlugin):
    def __init__(self):
        super().__init__()
        self.name = "fish"
        self.parent_plugin = "dotfiles"
        self.subplugin_dir = Path(__file__).parent

        # Fish 配置路径映射
        self.main_config = {
            "source": self.subplugin_dir / "config.fish",
            "target": Path.home() / ".config" / "fish" / "config.fish",
        }

        # Functions 目录（改名为 gs-config，避免与 fish 自带 functions/ 冲突）
        self.functions_dir = {
            "source": self.subplugin_dir / "gs-config",
            "target": Path.home() / ".config" / "fish" / "gs-config"
        }

        # 额外的文件
        self.extra_files = [
            (self.subplugin_dir / "apply-tide-config.fish", Path.home() / ".config" / "fish" / "apply-tide-config.fish"),
            (self.subplugin_dir / "README.md", Path.home() / ".config" / "fish" / "README.md"),
            (self.subplugin_dir / "setup-plugins.fish", Path.home() / ".config" / "fish" / "setup-plugins.fish")
        ]

        # 备份目录
        self.backup_dir = self.get_backup_dir(self.name)

    async def _backup_config_dir(self):
        """备份整个配置目录（包括主配置和 gs-config 目录）"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_subdir = self.backup_dir / timestamp
        backup_subdir.mkdir(parents=True, exist_ok=True)

        # 备份主配置文件
        target_config = self.main_config["target"]
        if target_config.exists():
            shutil.copy2(target_config, backup_subdir / "config.fish")
            print(f"[DOTFILES] 备份主配置: config.fish")

        # 备份 gs-config 目录（只备份 gs- 开头的文件）
        target_functions = self.functions_dir["target"]
        if target_functions.exists():
            backup_functions = backup_subdir / "gs-config"
            backup_functions.mkdir(parents=True, exist_ok=True)

            for fish_file in target_functions.glob("*-gs-*.fish"):
                shutil.copy2(fish_file, backup_functions / fish_file.name)
                print(f"[DOTFILES] 备份函数文件: {fish_file.name}")

        # 备份额外文件
        for src_file, target_file in self.extra_files:
            if target_file.exists():
                shutil.copy2(target_file, backup_subdir / target_file.name)
                print(f"[DOTFILES] 备份文件: {target_file.name}")

        # 清理旧备份，只保留最新3份
        await self._cleanup_old_backups(self.backup_dir)

        return backup_subdir

    @plugin_function(
        name="install",
        description={"zh": "安装 Fish 配置", "en": "Install Fish configuration"},
        usage="gs dotfiles fish install [--force]",
        examples=["gs dotfiles fish install", "gs dotfiles fish install --force"]
    )
    async def install(self, args: List[str] = None) -> CommandResult:
        """安装 Fish 配置"""
        force = "--force" in (args or []) or "-f" in (args or [])

        try:
            source = self.main_config["source"]
            target = self.main_config["target"]

            if not source.exists():
                return CommandResult(success=False, error=f"源配置文件不存在: {source}")

            # 备份现有配置（包括整个配置目录）
            if target.exists() and not force:
                await self._backup_config_dir()

            # 确保目标目录存在
            target.parent.mkdir(parents=True, exist_ok=True)

            # 复制主配置文件（带时间戳头部）
            await self._copy_with_header(source, target, self.name, add_timestamp=True, comment_prefix="#")

            # 复制 gs-config 目录
            src_functions = self.functions_dir["source"]
            dst_functions = self.functions_dir["target"]
            if src_functions.exists():
                dst_functions.mkdir(parents=True, exist_ok=True)
                for fish_file in src_functions.glob("*.fish"):
                    dst_file = dst_functions / fish_file.name
                    shutil.copy2(fish_file, dst_file)
                    # 设置可执行权限
                    dst_file.chmod(0o755)
                    print(f"[DOTFILES] 复制函数文件: {fish_file.name}")

            # 复制额外的文件
            for src_file, dst_file in self.extra_files:
                if src_file.exists():
                    dst_file.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src_file, dst_file)
                    # 如果是 .fish 文件，设置可执行权限
                    if dst_file.suffix == '.fish':
                        dst_file.chmod(0o755)
                    print(f"[DOTFILES] 复制文件: {src_file.name} -> {dst_file}")

            return CommandResult(success=True, output=f"Fish 配置安装成功\n请运行 'source ~/.config/fish/config.fish' 或重启终端")
        except Exception as e:
            return CommandResult(success=False, error=f"安装配置失败: {str(e)}")

    @plugin_function(
        name="uninstall",
        description={"zh": "卸载 Fish 配置", "en": "Uninstall Fish configuration"},
        usage="gs dotfiles fish uninstall",
        examples=["gs dotfiles fish uninstall"]
    )
    async def uninstall(self, args: List[str] = None) -> CommandResult:
        """卸载 Fish 配置"""
        try:
            target = self.main_config["target"]

            if not target.exists():
                return CommandResult(success=False, error="Fish 配置未安装")

            # 备份整个配置目录后删除
            await self._backup_config_dir()

            # 删除主配置文件
            target.unlink()

            # 删除 gs-config 目录中的 gs- 文件
            target_functions = self.functions_dir["target"]
            if target_functions.exists():
                for fish_file in target_functions.glob("*-gs-*.fish"):
                    fish_file.unlink()
                    print(f"[DOTFILES] 删除函数文件: {fish_file.name}")

            return CommandResult(success=True, output="Fish 配置已卸载（已备份）")
        except Exception as e:
            return CommandResult(success=False, error=f"卸载配置失败: {str(e)}")

    @plugin_function(
        name="backup",
        description={"zh": "备份 Fish 配置", "en": "Backup Fish configuration"},
        usage="gs dotfiles fish backup",
        examples=["gs dotfiles fish backup"]
    )
    async def backup(self, args: List[str] = None) -> CommandResult:
        """备份 Fish 配置"""
        try:
            target = self.main_config["target"]

            if not target.exists():
                return CommandResult(success=False, error="Fish 配置未安装，无需备份")

            backup_path = await self._backup_config_dir()

            return CommandResult(success=True, output=f"Fish 配置已备份到: {backup_path}")
        except Exception as e:
            return CommandResult(success=False, error=f"备份配置失败: {str(e)}")

    @plugin_function(
        name="restore",
        description={"zh": "恢复 Fish 配置", "en": "Restore Fish configuration"},
        usage="gs dotfiles fish restore",
        examples=["gs dotfiles fish restore"]
    )
    async def restore(self, args: List[str] = None) -> CommandResult:
        """恢复 Fish 配置"""
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

            # 恢复主配置文件
            backup_config = backup_path / "config.fish"
            if backup_config.exists():
                target = self.main_config["target"]
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(backup_config, target)
                print(f"[DOTFILES] 恢复主配置: config.fish")

            # 恢复 gs-config 目录
            backup_functions = backup_path / "gs-config"
            if backup_functions.exists():
                target_functions = self.functions_dir["target"]
                target_functions.mkdir(parents=True, exist_ok=True)
                for fish_file in backup_functions.glob("*.fish"):
                    dst_file = target_functions / fish_file.name
                    shutil.copy2(fish_file, dst_file)
                    dst_file.chmod(0o755)
                    print(f"[DOTFILES] 恢复函数文件: {fish_file.name}")

            # 恢复额外文件
            for _, target_file in self.extra_files:
                backup_file = backup_path / target_file.name
                if backup_file.exists():
                    target_file.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(backup_file, target_file)
                    if target_file.suffix == '.fish':
                        target_file.chmod(0o755)
                    print(f"[DOTFILES] 恢复文件: {target_file.name}")

            return CommandResult(success=True, output=f"Fish 配置已恢复: {chosen_backup['name']}")
        except Exception as e:
            return CommandResult(success=False, error=f"恢复配置失败: {str(e)}")

    @plugin_function(
        name="status",
        description={"zh": "查看 Fish 配置状态", "en": "Show Fish configuration status"},
        usage="gs dotfiles fish status",
        examples=["gs dotfiles fish status"]
    )
    async def status(self, args: List[str] = None) -> CommandResult:
        """查看 Fish 配置状态"""
        try:
            source = self.main_config["source"]
            target = self.main_config["target"]

            output = "Fish 配置状态:\n"
            output += f"  主配置: {target} {'✓ 已安装' if target.exists() else '✗ 未安装'}\n"

            # 检查 gs-config 目录
            target_functions = self.functions_dir["target"]
            if target_functions.exists():
                gs_files = list(target_functions.glob("*-gs-*.fish"))
                output += f"  gs-config: {len(gs_files)} 个配置文件\n"
            else:
                output += f"  gs-config: ✗ 未安装\n"

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
