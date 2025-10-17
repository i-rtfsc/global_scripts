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
from gscripts.core.config_manager import CommandResult
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

        # Git hooks 路径映射
        self.hooks_config = {
            "source": self.subplugin_dir / "hooks",
            "target": Path.home() / ".config" / "global-scripts" / "git" / "hooks",
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

            # 备份现有配置（包括 hooks）
            if target.exists() and not force:
                await self._backup_git_config()

            # 确保目标目录存在
            target.parent.mkdir(parents=True, exist_ok=True)

            # 复制主配置文件（添加头部信息）
            await self._copy_with_header(source, target, self.name, add_timestamp=True, comment_prefix="#")
            print(f"[DOTFILES] 安装配置: .gitconfig -> {target}")

            # 安装 hooks
            hooks_result = await self._install_hooks()
            if not hooks_result:
                print("[DOTFILES] 警告: Hooks 安装失败，但主配置已安装")

            return CommandResult(success=True, output=f"Git 配置安装成功: {target}\n" +
                                                      ("Git hooks 已安装到全局目录" if hooks_result else ""))
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

            # 备份后删除（包括 hooks）
            await self._backup_git_config()
            target.unlink()

            # 卸载 hooks
            await self._uninstall_hooks()

            return CommandResult(success=True, output="Git 配置已卸载（已备份）\nGit hooks 已移除")
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

            # 恢复 hooks（如果存在）
            backup_hooks = backup_path / "hooks"
            if backup_hooks.exists():
                target_hooks = self.hooks_config["target"]
                target_hooks.parent.mkdir(parents=True, exist_ok=True)

                # 删除现有 hooks
                if target_hooks.exists():
                    shutil.rmtree(target_hooks)

                # 复制备份的 hooks
                shutil.copytree(backup_hooks, target_hooks)
                # 确保所有 hook 文件可执行
                for hook_file in target_hooks.glob("*"):
                    if hook_file.is_file():
                        hook_file.chmod(0o755)
                print(f"[DOTFILES] 恢复 hooks: {len(list(target_hooks.glob('*')))} 个")

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
            target_hooks = self.hooks_config["target"]

            output = "Git 配置状态:\n"
            output += f"  源文件: {source} {'✓' if source.exists() else '✗'}\n"
            output += f"  目标文件: {target} {'✓ 已安装' if target.exists() else '✗ 未安装'}\n"

            # Hooks 状态
            if target_hooks.exists():
                hooks = list(target_hooks.glob("*"))
                output += f"  Git Hooks: ✓ 已安装 ({len(hooks)} 个)\n"
                for hook in hooks:
                    if hook.is_file():
                        output += f"    • {hook.name}\n"
            else:
                output += f"  Git Hooks: ✗ 未安装\n"

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

    async def _install_hooks(self) -> bool:
        """安装 Git hooks 到全局目录"""
        try:
            source_hooks = self.hooks_config["source"]
            target_hooks = self.hooks_config["target"]

            if not source_hooks.exists():
                print(f"[DOTFILES] 警告: Hooks 源目录不存在: {source_hooks}")
                return False

            # 创建目标目录
            target_hooks.mkdir(parents=True, exist_ok=True)

            # 复制所有 hook 文件
            installed_count = 0
            for hook_file in source_hooks.glob("*"):
                if hook_file.is_file():
                    target_file = target_hooks / hook_file.name
                    shutil.copy2(hook_file, target_file)
                    # 确保可执行
                    target_file.chmod(0o755)
                    print(f"[DOTFILES] 安装 hook: {hook_file.name}")
                    installed_count += 1

            if installed_count > 0:
                print(f"[DOTFILES] 成功安装 {installed_count} 个 Git hooks")
                print(f"[DOTFILES] Hooks 路径: {target_hooks}")
                return True
            else:
                print("[DOTFILES] 警告: 没有找到可安装的 hooks")
                return False

        except Exception as e:
            print(f"[DOTFILES] 安装 hooks 失败: {str(e)}")
            return False

    async def _uninstall_hooks(self) -> bool:
        """卸载 Git hooks"""
        try:
            target_hooks = self.hooks_config["target"]

            if not target_hooks.exists():
                print("[DOTFILES] Hooks 目录不存在，无需卸载")
                return True

            # 删除 hooks 目录
            shutil.rmtree(target_hooks)
            print(f"[DOTFILES] 已删除 hooks 目录: {target_hooks}")
            return True

        except Exception as e:
            print(f"[DOTFILES] 卸载 hooks 失败: {str(e)}")
            return False

    async def _backup_git_config(self) -> Path:
        """备份完整的 Git 配置（包括主配置和 hooks）"""
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

            # 备份 hooks 目录
            target_hooks = self.hooks_config["target"]
            if target_hooks.exists():
                backup_hooks = backup_subdir / "hooks"
                shutil.copytree(target_hooks, backup_hooks)
                hooks_count = len(list(backup_hooks.glob("*")))
                print(f"[DOTFILES] 备份 hooks: {hooks_count} 个文件 -> {backup_hooks}")

            # 清理旧备份，只保留最新3份
            await self._cleanup_old_backups(self.backup_dir)

            return backup_subdir

        except Exception as e:
            print(f"[DOTFILES] 备份失败: {str(e)}")
            raise
