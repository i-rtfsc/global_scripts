"""
System Config Subplugin
- 配置管理系统
- 支持多种shell和编辑器的配置管理
"""

import sys
import os
import shutil
import asyncio
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

# Ensure project root on sys.path
project_root = Path(__file__).resolve().parents[3]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from gscripts.plugins.decorators import plugin_function, subplugin
from gscripts.plugins.base import BasePlugin
from gscripts.core.config_manager import CommandResult


@subplugin("config")
class SystemConfigSubplugin(BasePlugin):
    def __init__(self):
        self.name = "config"
        self.parent_plugin = "system"
        self.plugin_dir = Path(__file__).parent
        self.config_dir = self.plugin_dir / "configs"

        # 统一备份目录到 ~/.config/global-scripts/backups/
        self.backup_root = Path.home() / ".config" / "global-scripts" / "backups"
        self.backup_dir = self.backup_root / "config"

        # 私有配置使用全局private目录
        self.private_dir = Path(__file__).parents[3] / "custom" / "private"

        # 只确保必要目录存在
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        # 不再创建 custom_dir，按需创建 private_dir

        # 配置映射 - 定义配置文件的源和目标路径
        self.config_mappings = {
            "zsh": {
                "source": self.config_dir / "zsh" / ".zshrc",
                "target": Path.home() / ".zshrc",
                "description": "Zsh shell configuration",
                "category": "shell",
                "add_timestamp": True
            },
            "fish": {
                "source": self.config_dir / "fish" / "config.fish",
                "target": Path.home() / ".config" / "fish" / "config.fish",
                "description": "Fish shell configuration",
                "category": "shell",
                "add_timestamp": True,
                "extra_dirs": [
                    (self.config_dir / "fish" / "conf.d", Path.home() / ".config" / "fish" / "conf.d")
                ],
                "extra_files": [
                    (self.config_dir / "fish" / "apply-tide-config.fish", Path.home() / ".config" / "fish" / "apply-tide-config.fish"),
                    (self.config_dir / "fish" / "README.md", Path.home() / ".config" / "fish" / "README.md")
                ]
            },
            "vim": {
                "source": self.config_dir / "vim" / ".vimrc",
                "target": Path.home() / ".vimrc",
                "description": "Vim editor configuration",
                "category": "editor",
                "backup_dirs": [
                    (self.config_dir / "vim" / "vim_runtime", Path.home() / ".vim_runtime")
                ]
            },
            "nvim": {
                "source": self.config_dir / "nvim" / "init.vim",
                "target": Path.home() / ".config" / "nvim" / "init.vim",
                "description": "Neovim editor configuration",
                "category": "editor",
                "backup_dirs": [
                    (self.config_dir / "nvim" / "nvim_runtime", Path.home() / ".config" / "nvim")
                ]
            },
            "tmux": {
                "source": self.config_dir / "tmux" / ".tmux.conf",
                "target": Path.home() / ".tmux.conf",
                "description": "Tmux terminal multiplexer configuration",
                "category": "tool"
            },
            "git": {
                "source": self.config_dir / "git" / ".gitconfig",
                "target": Path.home() / ".gitconfig",
                "description": "Git configuration",
                "category": "tool",
                "private_sources": [
                    (self.private_dir / "git" / ".gitconfig-user", "用户信息配置"),
                    (self.private_dir / "git" / ".gitconfig-work", "工作配置")
                ]
            },
            "ssh": {
                "source": self.config_dir / "ssh" / "config",
                "target": Path.home() / ".ssh" / "config",
                "description": "SSH configuration",
                "category": "tool",
                "private_sources": [
                    (self.private_dir / "ssh" / "config-private", "私有主机配置"),
                    (self.private_dir / "ssh" / "keys", "SSH密钥目录")
                ]
            }
        }

    def get_available_configs(self) -> List[str]:
        """获取可用的配置名称列表 - 用于补全"""
        return sorted(self.config_mappings.keys())

    @plugin_function(
        name="install",
        description={"zh": "安装指定配置", "en": "Install specific configuration"},
        usage="gs system config install <config_name> [force]",
        examples=[
            "gs system config install zsh",
            "gs system config install vim force"
        ],
        args=[
            {
                "name": "config_name",
                "type": "choice",
                "required": True,
                "description": "配置名称",
                "choices": ["zsh", "fish", "vim", "nvim", "tmux", "git", "ssh"]
            },
            {
                "name": "force",
                "type": "flag",
                "required": False,
                "description": "强制安装,覆盖现有配置",
                "choices": ["force", "--force", "-f"]
            }
        ]
    )
    async def install(self, args: List[str] = None) -> CommandResult:
        """安装配置"""
        if not args:
            return CommandResult(success=False, error="请指定要安装的配置名称")

        config_name = args[0]
        force = "--force" in args or "-f" in args or "force" in args

        if config_name not in self.config_mappings:
            return CommandResult(success=False, error=f"配置 '{config_name}' 不存在")

        try:
            mapping = self.config_mappings[config_name]
            source = mapping["source"]
            target = mapping["target"]

            if not source.exists():
                return CommandResult(success=False, error=f"源配置文件不存在: {source}")

            # 备份现有配置
            if target.exists() and not force:
                backup_name = f"{config_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                await self._backup_file(target, backup_name)

            # 确保目标目录存在
            target.parent.mkdir(parents=True, exist_ok=True)

            # 复制主配置文件（带时间戳）
            if mapping.get("add_timestamp", False):
                await self._copy_with_timestamp(source, target, config_name)
            else:
                shutil.copy2(source, target)

            # 处理私有配置源文件 - 仅提示用户手动配置
            if "private_sources" in mapping:
                for private_source, description in mapping["private_sources"]:
                    if not private_source.exists():
                        # 创建私有配置目录
                        if private_source.name == "keys":
                            private_source.mkdir(parents=True, exist_ok=True)
                            private_source.chmod(0o700)
                            print(f"[CONFIG] 创建私有密钥目录: {private_source}")
                        else:
                            # 仅提示用户需要配置私有文件
                            print(f"[CONFIG] 提示: 需要配置私有文件 {private_source} ({description})")
                            print(f"[CONFIG] 请手动创建并编辑该文件")


            # 处理额外的目录复制（新增支持 extra_dirs）
            if "extra_dirs" in mapping:
                for src_dir, dst_dir in mapping["extra_dirs"]:
                    if src_dir.exists():
                        # 确保目标目录存在
                        dst_dir.mkdir(parents=True, exist_ok=True)
                        # 递归复制目录内容
                        shutil.copytree(src_dir, dst_dir, dirs_exist_ok=True)
                        print(f"[CONFIG] 复制目录: {src_dir.name}/ -> {dst_dir}")

            # 处理额外的文件复制（新增支持 extra_files）
            if "extra_files" in mapping:
                for src_file, dst_file in mapping["extra_files"]:
                    if src_file.exists():
                        # 确保目标目录存在
                        dst_file.parent.mkdir(parents=True, exist_ok=True)
                        # 复制文件
                        shutil.copy2(src_file, dst_file)
                        # 如果是 .fish 文件，设置可执行权限
                        if dst_file.suffix == '.fish' and dst_file.name != 'config.fish':
                            dst_file.chmod(0o755)
                        print(f"[CONFIG] 复制文件: {src_file.name} -> {dst_file}")

            # 处理额外的目录复制（旧的 backup_dirs）
            if "backup_dirs" in mapping:
                for src_dir, dst_dir in mapping["backup_dirs"]:
                    if src_dir.exists():
                        if dst_dir.exists() and not force:
                            # 备份现有目录
                            backup_dir = self.backup_dir / f"{config_name}_dirs_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                            backup_dir.mkdir(parents=True, exist_ok=True)
                            shutil.copytree(dst_dir, backup_dir / dst_dir.name)
                            shutil.rmtree(dst_dir)

                        dst_dir.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copytree(src_dir, dst_dir, dirs_exist_ok=True)

            # 处理SSH配置的特殊权限
            if config_name == "ssh":
                target.chmod(0o600)
                target.parent.chmod(0o700)

            return CommandResult(success=True, output=f"配置 '{config_name}' 安装成功")
        except Exception as e:
            return CommandResult(success=False, error=f"安装配置失败: {str(e)}")

    @plugin_function(
        name="backup",
        description={"zh": "备份配置", "en": "Backup configuration"},
        usage="gs system config backup [config_name]",
        examples=[
            "gs system config backup",
            "gs system config backup zsh"
        ],
        args=[
            {
                "name": "config_name",
                "type": "choice",
                "required": False,
                "description": "配置名称(可选,不指定则备份所有)",
                "choices": ["zsh", "fish", "vim", "nvim", "tmux", "git", "ssh"]
            }
        ]
    )
    async def backup(self, args: List[str] = None) -> CommandResult:
        """备份配置"""
        config_name = args[0] if args else None

        try:
            if config_name:
                # 备份指定配置
                if config_name not in self.config_mappings:
                    return CommandResult(success=False, error=f"配置 '{config_name}' 不存在")

                mapping = self.config_mappings[config_name]
                target = mapping["target"]

                if not target.exists():
                    return CommandResult(success=False, error=f"配置文件不存在: {target}")

                backup_name = f"{config_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                await self._backup_file(target, backup_name)

                return CommandResult(success=True, output=f"配置 '{config_name}' 备份完成")
            else:
                # 备份所有配置
                backed_up = []
                for name, mapping in self.config_mappings.items():
                    target = mapping["target"]
                    if target.exists():
                        backup_name = f"{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                        await self._backup_file(target, backup_name)
                        backed_up.append(name)

                return CommandResult(success=True, output=f"备份完成: {', '.join(backed_up)}")
        except Exception as e:
            return CommandResult(success=False, error=f"备份失败: {str(e)}")

    @plugin_function(
        name="restore",
        description={"zh": "恢复配置", "en": "Restore configuration"},
        usage="gs system config restore <backup_name>",
        examples=["gs system config restore zsh_20250918_112934"],
    )
    async def restore(self, args: List[str] = None) -> CommandResult:
        """恢复配置"""
        if not args:
            return CommandResult(success=False, error="请指定备份文件名")

        backup_name = args[0]
        backup_file = self.backup_dir / backup_name

        if not backup_file.exists():
            return CommandResult(success=False, error=f"备份文件不存在: {backup_name}")

        try:
            # 从备份文件名推断配置类型
            config_name = backup_name.split('_')[0]
            if config_name not in self.config_mappings:
                return CommandResult(success=False, error=f"无法识别配置类型: {config_name}")

            mapping = self.config_mappings[config_name]
            target = mapping["target"]

            # 确保目标目录存在
            target.parent.mkdir(parents=True, exist_ok=True)

            # 恢复配置文件
            shutil.copy2(backup_file, target)

            # 处理私有配置的特殊权限
            if mapping.get("private", False):
                target.chmod(0o600)

            return CommandResult(success=True, output=f"配置 '{config_name}' 恢复成功")
        except Exception as e:
            return CommandResult(success=False, error=f"恢复配置失败: {str(e)}")

    @plugin_function(
        name="list",
        description={"zh": "列出可用配置或备份", "en": "List available configurations or backups"},
        usage="gs system config list [backups]",
        examples=[
            "gs system config list",
            "gs system config list backups"
        ],
        args=[
            {
                "name": "mode",
                "type": "choice",
                "required": False,
                "description": "显示模式: backups=显示备份列表, 不指定=显示可用配置",
                "choices": ["backups", "--backups"]
            }
        ]
    )
    async def list(self, args: List[str] = None) -> CommandResult:
        """列出可用配置"""
        show_backups = "backups" in (args or []) or "--backups" in (args or [])

        if show_backups:
            # 列出备份文件
            backups = []
            for backup_file in self.backup_dir.glob("*"):
                if backup_file.is_file():
                    stat = backup_file.stat()
                    backups.append({
                        "name": backup_file.name,
                        "size": f"{stat.st_size} bytes",
                        "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                    })

            if not backups:
                return CommandResult(success=True, output="没有找到备份文件")

            output = "备份文件:\n"
            for backup in backups:
                output += f"  {backup['name']:<30} {backup['size']:<10} {backup['modified']}\n"

            return CommandResult(success=True, output=output.strip())
        else:
            # 列出可用配置
            output = "可用配置:\n"
            for name, mapping in self.config_mappings.items():
                source_exists = mapping["source"].exists()
                target_exists = mapping["target"].exists()

                # 检查是否有私有配置源
                has_private_sources = "private_sources" in mapping
                private_mark = " [私有]" if has_private_sources else ""

                status = "✓" if source_exists else "✗"
                installed = "已安装" if target_exists else "未安装"

                output += f"  {status} {name:<8} - {mapping['description']} ({installed}){private_mark}\n"

            return CommandResult(success=True, output=output.strip())

    async def _backup_file(self, source_file: Path, backup_name: str):
        """备份文件，只保留最新2份"""
        backup_file = self.backup_dir / backup_name
        shutil.copy2(source_file, backup_file)
        print(f"[CONFIG] 备份文件: {source_file} -> {backup_file}")

        # 清理旧备份，只保留最新2份
        await self._cleanup_old_backups(backup_name)

    async def _copy_with_timestamp(self, source: Path, target: Path, config_name: str):
        """复制配置文件并添加时间戳注释"""
        # 读取源文件内容
        with open(source, 'r', encoding='utf-8') as f:
            content = f.read()

        # 根据文件类型确定注释符号
        comment_prefix = "#"  # Fish 和 Zsh 都使用 #

        # 生成时间戳
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 检测 shebang 行
        lines = content.split('\n')
        has_shebang = lines and lines[0].startswith('#!')

        # 获取项目根目录（动态获取）
        project_root = Path(__file__).resolve().parents[3]

        # 构建带时间戳的头部
        if config_name == "fish":
            header = f"""#!/usr/bin/env fish
# Global Scripts - Fish Shell Configuration
# Generated automatically by: gs system config install fish
# Generated at: {timestamp}
# Source: plugins/system/config/configs/fish/
#
# ============================================
"""
            # Fish 配置末尾添加 env.fish source
            env_fish_path = project_root / "env.fish"
            if env_fish_path.exists():
                footer = f"""
# ============================================
# Global Scripts Environment
# ============================================
source {env_fish_path}
"""
            else:
                footer = ""
        elif config_name == "zsh":
            header = f"""#!/usr/bin/env zsh
# Global Scripts - Zsh Shell Configuration
# Generated automatically by: gs system config install zsh
# Generated at: {timestamp}
# Source: plugins/system/config/configs/zsh/
#
# ============================================
"""
            # Zsh 配置末尾添加 env.sh source
            env_sh_path = project_root / "env.sh"
            if env_sh_path.exists():
                footer = f"""
# ============================================
# Global Scripts Environment
# ============================================
source {env_sh_path}
"""
            else:
                footer = ""
        else:
            header = f"""{comment_prefix} Global Scripts - {config_name.upper()} Configuration
{comment_prefix} Generated automatically by: gs system config install {config_name}
{comment_prefix} Generated at: {timestamp}
{comment_prefix}
"""
            footer = ""

        # 如果源文件有 shebang，去掉它（我们会添加自己的）
        if has_shebang:
            content = '\n'.join(lines[1:])

        # 组合最终内容（头部 + 内容 + 尾部）
        final_content = header + content + footer

        # 写入目标文件
        with open(target, 'w', encoding='utf-8') as f:
            f.write(final_content)

        print(f"[CONFIG] 安装配置: {config_name} (时间戳: {timestamp})")
        if footer:
            print(f"[CONFIG] 添加环境变量: {project_root}/env.{'fish' if config_name == 'fish' else 'sh'}")

    async def _cleanup_old_backups(self, current_backup: str):
        """清理旧备份，只保留最新2份"""
        try:
            # 从备份文件名提取配置名称（例如: zsh_20250101_120000 -> zsh）
            config_name = current_backup.split('_')[0]

            # 获取该配置的所有备份文件
            pattern = f"{config_name}_*"
            backups = sorted(
                self.backup_dir.glob(pattern),
                key=lambda p: p.stat().st_mtime,
                reverse=True  # 最新的在前
            )

            # 只保留最新2份，删除其余的
            if len(backups) > 2:
                for old_backup in backups[2:]:
                    try:
                        if old_backup.is_file():
                            # 确保文件有写权限
                            old_backup.chmod(0o644)
                            old_backup.unlink()
                            print(f"[CONFIG] 删除旧备份: {old_backup.name}")
                        elif old_backup.is_dir():
                            # 如果是目录，递归删除
                            shutil.rmtree(old_backup)
                            print(f"[CONFIG] 删除旧备份目录: {old_backup.name}")
                    except PermissionError as e:
                        print(f"[CONFIG] 警告: 无法删除旧备份 {old_backup.name}: 权限不足")
                    except Exception as e:
                        print(f"[CONFIG] 警告: 无法删除旧备份 {old_backup.name}: {str(e)}")
        except Exception as e:
            print(f"[CONFIG] 警告: 清理旧备份时出错: {str(e)}")