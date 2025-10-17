"""
Dotfiles Management Plugin
- 配置文件管理基类
- 提供通用的安装、卸载、备份、恢复功能
- 子插件继承此类并配置自己的路径映射
"""

import sys
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

# Ensure project root on sys.path
project_root = Path(__file__).resolve().parents[2]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from gscripts.plugins.base import BasePlugin
from gscripts.plugins.decorators import plugin_function
from gscripts.core.config_manager import CommandResult


class DotfilesPlugin(BasePlugin):
    """Dotfiles 管理插件基类"""

    def __init__(self):
        self.name = "dotfiles"
        self.plugin_dir = Path(__file__).parent

        # 备份根目录
        self.backup_root = Path.home() / ".config" / "global-scripts" / "backups" / "dotfiles"
        self.backup_root.mkdir(parents=True, exist_ok=True)

        # 项目根目录
        self.project_root = Path(__file__).resolve().parents[2]

        # 配置映射 - 子插件需要覆盖此属性
        self.config_mappings: Dict[str, Any] = {}

    def get_backup_dir(self, subplugin_name: str) -> Path:
        """获取子插件的备份目录"""
        backup_dir = self.backup_root / subplugin_name
        backup_dir.mkdir(parents=True, exist_ok=True)
        return backup_dir

    def _generate_header(self, config_name: str, comment_prefix: str = "#") -> str:
        """生成配置文件头部"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 检测 shebang
        if config_name == "fish":
            shebang = "#!/usr/bin/env fish\n"
        elif config_name == "zsh":
            shebang = "#!/usr/bin/env zsh\n"
        elif config_name == "bash":
            shebang = "#!/usr/bin/env bash\n"
        else:
            shebang = ""

        header = f"""{shebang}{comment_prefix} Global Scripts Configuration
{comment_prefix} Generated automatically - do not edit manually
{comment_prefix} Generated at: {timestamp}
{comment_prefix} Configuration source: {self.project_root}

"""
        return header

    def _generate_footer(self, config_name: str, comment_prefix: str = "#") -> str:
        """生成配置文件尾部（添加环境变量）"""
        # Fish 使用 env.fish，其他 shell 使用 env.sh
        if config_name == "fish":
            env_file = self.project_root / "env.fish"
            if env_file.exists():
                return f"""
{comment_prefix} ============================================
{comment_prefix} Global Scripts Environment
{comment_prefix} ============================================
source {env_file}
"""
        elif config_name in ["zsh", "bash"]:
            env_file = self.project_root / "env.sh"
            if env_file.exists():
                return f"""
{comment_prefix} ============================================
{comment_prefix} Global Scripts Environment
{comment_prefix} ============================================
source {env_file}
"""

        return ""

    async def _copy_with_header(
        self,
        source: Path,
        target: Path,
        config_name: str,
        add_timestamp: bool = True,
        comment_prefix: str = "#"
    ):
        """复制配置文件并添加头部和尾部"""
        # 读取源文件内容
        with open(source, 'r', encoding='utf-8') as f:
            content = f.read()

        # 如果需要添加时间戳
        if add_timestamp:
            # 去除源文件中的 shebang（我们会添加自己的）
            lines = content.split('\n')
            if lines and lines[0].startswith('#!'):
                content = '\n'.join(lines[1:])

            # 生成头部和尾部
            header = self._generate_header(config_name, comment_prefix)
            footer = self._generate_footer(config_name, comment_prefix)

            # 组合最终内容
            final_content = header + content + footer
        else:
            final_content = content

        # 写入目标文件
        with open(target, 'w', encoding='utf-8') as f:
            f.write(final_content)

        print(f"[DOTFILES] 安装配置: {config_name} -> {target}")

    async def _backup_file(self, source_file: Path, backup_dir: Path, config_name: str):
        """备份文件，只保留最新3份"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_subdir = backup_dir / timestamp
        backup_subdir.mkdir(parents=True, exist_ok=True)

        # 备份文件
        backup_file = backup_subdir / source_file.name
        shutil.copy2(source_file, backup_file)
        print(f"[DOTFILES] 备份文件: {source_file} -> {backup_file}")

        # 清理旧备份，只保留最新3份
        await self._cleanup_old_backups(backup_dir)

    async def _cleanup_old_backups(self, backup_dir: Path):
        """清理旧备份，只保留最新3份"""
        try:
            # 获取所有备份目录
            backups = sorted(
                [d for d in backup_dir.iterdir() if d.is_dir()],
                key=lambda p: p.stat().st_mtime,
                reverse=True  # 最新的在前
            )

            # 只保留最新3份，删除其余的
            if len(backups) > 3:
                for old_backup in backups[3:]:
                    try:
                        shutil.rmtree(old_backup)
                        print(f"[DOTFILES] 删除旧备份: {old_backup.name}")
                    except Exception as e:
                        print(f"[DOTFILES] 警告: 无法删除旧备份 {old_backup.name}: {str(e)}")
        except Exception as e:
            print(f"[DOTFILES] 警告: 清理旧备份时出错: {str(e)}")

    async def _list_backups(self, backup_dir: Path) -> List[Dict[str, str]]:
        """列出可用的备份"""
        backups = []
        if not backup_dir.exists():
            return backups

        for backup_subdir in sorted(backup_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if backup_subdir.is_dir():
                stat = backup_subdir.stat()
                backups.append({
                    "name": backup_subdir.name,
                    "path": str(backup_subdir),
                    "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                })

        return backups

    @plugin_function(
        name="list",
        description={"zh": "列出所有可用的配置工具", "en": "List all available configuration tools"},
        usage="gs dotfiles list",
        examples=["gs dotfiles list"]
    )
    async def list_configs(self, args: List[str] = None) -> CommandResult:
        """列出所有可用的配置工具"""
        subplugins = ["fish", "nvim", "tmux", "zsh", "git", "ssh", "vim"]

        output = "可用配置:\n"
        for name in subplugins:
            output += f"  • {name:<8} - 使用 'gs dotfiles {name}' 查看详情\n"

        return CommandResult(success=True, output=output.strip())

    @plugin_function(
        name="help",
        description={"zh": "显示帮助信息", "en": "Show help information"},
        usage="gs dotfiles help",
        examples=["gs dotfiles help"]
    )
    async def help(self, args: List[str] = None) -> CommandResult:
        """显示帮助信息"""
        help_text = """Dotfiles Management Plugin

用法:
  gs dotfiles <tool> [command] [options]

可用工具:
  fish    - Fish Shell 配置
  nvim    - Neovim 配置
  tmux    - Tmux 配置
  zsh     - Zsh Shell 配置
  git     - Git 配置
  ssh     - SSH 配置
  vim     - Vim 配置

可用命令:
  install   - 安装配置 (gs dotfiles <tool> install)
  uninstall - 卸载配置 (gs dotfiles <tool> uninstall)
  backup    - 备份配置 (gs dotfiles <tool> backup)
  restore   - 恢复配置 (gs dotfiles <tool> restore)
  status    - 查看状态 (gs dotfiles <tool> status)

示例:
  gs dotfiles fish install    # 安装 fish 配置
  gs dotfiles fish backup     # 备份 fish 配置
  gs dotfiles fish restore    # 恢复 fish 配置（会列出可用备份）
  gs dotfiles fish uninstall  # 卸载 fish 配置
"""
        return CommandResult(success=True, output=help_text)
