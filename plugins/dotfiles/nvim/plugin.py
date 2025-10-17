"""
Neovim Configuration Subplugin
- 管理 Neovim 配置文件
- 继承主插件的通用功能
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


@subplugin("nvim")
class NvimConfigSubplugin(DotfilesPlugin):
    def __init__(self):
        super().__init__()
        self.name = "nvim"
        self.parent_plugin = "dotfiles"
        self.subplugin_dir = Path(__file__).parent

        # Neovim 配置路径映射
        self.main_config = {
            "source": self.subplugin_dir / "init.vim",
            "target": Path.home() / ".config" / "nvim" / "init.vim",
        }

        # 额外的目录
        self.extra_dirs = [
            (self.subplugin_dir / "gs-runtime", Path.home() / ".config" / "nvim" / "gs-runtime")
        ]

        # 备份目录
        self.backup_dir = self.get_backup_dir(self.name)

    async def _backup_config_dir(self):
        """备份整个配置目录（包括主配置和 gs-runtime 目录）"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_subdir = self.backup_dir / timestamp
        backup_subdir.mkdir(parents=True, exist_ok=True)

        # 备份主配置文件
        target_config = self.main_config["target"]
        if target_config.exists():
            shutil.copy2(target_config, backup_subdir / "init.vim")
            print(f"[DOTFILES] 备份主配置: init.vim")

        # 备份 gs-runtime 目录
        for src_dir, dst_dir in self.extra_dirs:
            if dst_dir.exists():
                backup_runtime = backup_subdir / dst_dir.name
                shutil.copytree(dst_dir, backup_runtime)
                print(f"[DOTFILES] 备份目录: {dst_dir.name}/")

        # 清理旧备份，只保留最新3份
        await self._cleanup_old_backups(self.backup_dir)

        return backup_subdir

    @plugin_function(
        name="install",
        description={"zh": "安装 Neovim 配置", "en": "Install Neovim configuration"},
        usage="gs dotfiles nvim install [--force]",
        examples=["gs dotfiles nvim install", "gs dotfiles nvim install --force"]
    )
    async def install(self, args: List[str] = None) -> CommandResult:
        """安装 Neovim 配置"""
        force = "--force" in (args or []) or "-f" in (args or [])

        try:
            # 检查 lazy.nvim 是否已安装
            lazy_path = Path.home() / ".local" / "share" / "nvim" / "lazy" / "lazy.nvim"
            if not lazy_path.exists():
                warning_msg = (
                    "\n⚠️  警告: lazy.nvim 插件管理器未安装！\n\n"
                    "Neovim 配置依赖 lazy.nvim 插件管理器。\n\n"
                    "请选择操作:\n"
                    "  1. 现在安装 lazy.nvim 并继续 (推荐)\n"
                    "  2. 跳过 lazy.nvim，只安装配置\n"
                    "  3. 取消安装\n\n"
                    "请输入选项 [1/2/3] (默认=1): "
                )
                print(warning_msg, end="", flush=True)

                # 读取用户输入
                import asyncio
                loop = asyncio.get_event_loop()
                response = await loop.run_in_executor(None, sys.stdin.readline)
                response = response.strip() or "1"

                if response == "1":
                    # 安装 lazy.nvim
                    print("\n正在安装 lazy.nvim...")
                    lazy_path.parent.mkdir(parents=True, exist_ok=True)

                    import subprocess
                    clone_cmd = [
                        "git", "clone", "--filter=blob:none",
                        "https://github.com/folke/lazy.nvim.git",
                        "--branch=stable",
                        str(lazy_path)
                    ]

                    try:
                        result = subprocess.run(clone_cmd, capture_output=True, text=True)
                        if result.returncode == 0:
                            print("✓ lazy.nvim 安装成功！\n")
                        else:
                            print(f"✗ lazy.nvim 安装失败: {result.stderr}")
                            print("\n请手动安装后重试:")
                            print("  git clone --filter=blob:none \\")
                            print("    https://github.com/folke/lazy.nvim.git \\")
                            print("    --branch=stable \\")
                            print("    ~/.local/share/nvim/lazy/lazy.nvim\n")

                            print("是否继续安装配置? [y/N]: ", end="", flush=True)
                            cont = await loop.run_in_executor(None, sys.stdin.readline)
                            if cont.strip().lower() not in ['y', 'yes']:
                                return CommandResult(success=False, error="安装已取消")
                    except Exception as e:
                        print(f"✗ 安装 lazy.nvim 时出错: {str(e)}")
                        print("\n是否继续安装配置? [y/N]: ", end="", flush=True)
                        cont = await loop.run_in_executor(None, sys.stdin.readline)
                        if cont.strip().lower() not in ['y', 'yes']:
                            return CommandResult(success=False, error="安装已取消")

                elif response == "2":
                    print("\n跳过 lazy.nvim 安装，继续安装配置...\n")

                elif response == "3":
                    return CommandResult(
                        success=False,
                        error="用户取消安装。"
                    )
                else:
                    return CommandResult(
                        success=False,
                        error="无效的选项。请重新运行并选择 1、2 或 3。"
                    )

            source = self.main_config["source"]
            target = self.main_config["target"]

            if not source.exists():
                return CommandResult(success=False, error=f"源配置文件不存在: {source}")

            # 备份现有配置（使用统一的备份方法）
            if (target.exists() or any(dst_dir.exists() for _, dst_dir in self.extra_dirs)) and not force:
                await self._backup_config_dir()

            # 确保目标目录存在
            target.parent.mkdir(parents=True, exist_ok=True)

            # 复制主配置文件（添加头部信息，vim 配置使用 " 作为注释）
            await self._copy_with_header(source, target, self.name, add_timestamp=True, comment_prefix="\"")
            print(f"[DOTFILES] 安装主配置: init.vim -> {target}")

            # 复制额外的目录，并为 lua 文件添加头部
            for src_dir, dst_dir in self.extra_dirs:
                if src_dir.exists():
                    dst_dir.parent.mkdir(parents=True, exist_ok=True)

                    # 先删除目标目录（如果存在）
                    if dst_dir.exists():
                        shutil.rmtree(dst_dir)

                    # 复制目录结构
                    shutil.copytree(src_dir, dst_dir)
                    print(f"[DOTFILES] 复制目录: {src_dir.name}/ -> {dst_dir}")

                    # 为所有 lua 文件添加头部
                    for lua_file in dst_dir.rglob("*.lua"):
                        await self._add_header_to_lua(lua_file)

            # 复制文档到用户配置目录
            # 复制主 README
            readme_main = self.subplugin_dir / "README.md"
            if readme_main.exists():
                shutil.copy2(readme_main, target.parent / "README.md")
                print(f"[DOTFILES] 复制文档: README.md -> {target.parent / 'README.md'}")

            # 复制 docs 目录
            docs_src = self.subplugin_dir / "docs"
            if docs_src.exists():
                docs_dst = target.parent / "docs"
                docs_dst.mkdir(parents=True, exist_ok=True)

                for doc_file in docs_src.glob("*.md"):
                    shutil.copy2(doc_file, docs_dst / doc_file.name)
                    print(f"[DOTFILES] 复制文档: docs/{doc_file.name} -> {docs_dst / doc_file.name}")

            success_msg = "\n✅ Neovim 配置安装成功！"
            if lazy_path.exists():
                success_msg += "\n✓ lazy.nvim 已安装"
                success_msg += "\n\n下一步:"
                success_msg += "\n  1. 启动 nvim"
                success_msg += "\n  2. lazy.nvim 会自动安装所有插件"
                success_msg += "\n  3. 安装完成后重启 nvim 即可使用"
                success_msg += "\n\n📚 文档导航:"
                success_msg += "\n  主文档: ~/.config/nvim/README.md"
                success_msg += "\n  新手教程: ~/.config/nvim/docs/nvim-tutorial.md"
                success_msg += "\n  日常操作: ~/.config/nvim/docs/nvim-operations.md"
                success_msg += "\n\n  或在 nvim 中执行: :e ~/.config/nvim/README.md"
            else:
                success_msg += "\n⚠️  提示: lazy.nvim 未安装"
                success_msg += "\n\n请手动安装 lazy.nvim:"
                success_msg += "\n  git clone --filter=blob:none \\"
                success_msg += "\n    https://github.com/folke/lazy.nvim.git \\"
                success_msg += "\n    --branch=stable \\"
                success_msg += "\n    ~/.local/share/nvim/lazy/lazy.nvim"
                success_msg += "\n\n📚 文档导航:"
                success_msg += "\n  主文档: ~/.config/nvim/README.md"
                success_msg += "\n  新手教程: ~/.config/nvim/docs/nvim-tutorial.md"
                success_msg += "\n  日常操作: ~/.config/nvim/docs/nvim-operations.md"

            return CommandResult(success=True, output=success_msg)
        except Exception as e:
            return CommandResult(success=False, error=f"安装配置失败: {str(e)}")

    async def _add_header_to_lua(self, lua_file: Path):
        """为已存在的 lua 文件添加头部"""
        try:
            # 读取原文件内容
            content = lua_file.read_text()

            # 生成头部（lua 使用 -- 注释）
            header = self._generate_header(self.name, comment_prefix="--")

            # 写入带头部的内容
            lua_file.write_text(header + content)
            print(f"[DOTFILES]   添加头部: {lua_file.relative_to(lua_file.parents[2])}")
        except Exception as e:
            print(f"[DOTFILES]   警告: 无法为 {lua_file.name} 添加头部: {e}")

    @plugin_function(
        name="uninstall",
        description={"zh": "卸载 Neovim 配置", "en": "Uninstall Neovim configuration"},
        usage="gs dotfiles nvim uninstall",
        examples=["gs dotfiles nvim uninstall"]
    )
    async def uninstall(self, args: List[str] = None) -> CommandResult:
        """卸载 Neovim 配置"""
        try:
            target = self.main_config["target"]

            if not target.exists():
                return CommandResult(success=False, error="Neovim 配置未安装")

            # 备份整个配置目录后删除
            await self._backup_config_dir()

            # 删除主配置文件
            target.unlink()

            # 删除 gs-runtime 目录
            for _, dst_dir in self.extra_dirs:
                if dst_dir.exists():
                    shutil.rmtree(dst_dir)
                    print(f"[DOTFILES] 删除目录: {dst_dir.name}/")

            return CommandResult(success=True, output="Neovim 配置已卸载（已备份）")
        except Exception as e:
            return CommandResult(success=False, error=f"卸载配置失败: {str(e)}")

    @plugin_function(
        name="backup",
        description={"zh": "备份 Neovim 配置", "en": "Backup Neovim configuration"},
        usage="gs dotfiles nvim backup",
        examples=["gs dotfiles nvim backup"]
    )
    async def backup(self, args: List[str] = None) -> CommandResult:
        """备份 Neovim 配置"""
        try:
            target = self.main_config["target"]

            if not target.exists():
                return CommandResult(success=False, error="Neovim 配置未安装，无需备份")

            backup_path = await self._backup_config_dir()

            return CommandResult(success=True, output=f"Neovim 配置已备份到: {backup_path}")
        except Exception as e:
            return CommandResult(success=False, error=f"备份配置失败: {str(e)}")

    @plugin_function(
        name="restore",
        description={"zh": "恢复 Neovim 配置", "en": "Restore Neovim configuration"},
        usage="gs dotfiles nvim restore",
        examples=["gs dotfiles nvim restore"]
    )
    async def restore(self, args: List[str] = None) -> CommandResult:
        """恢复 Neovim 配置"""
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
            backup_file = backup_path / "init.vim"
            if backup_file.exists():
                target = self.main_config["target"]
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(backup_file, target)
                print(f"[DOTFILES] 恢复主配置: init.vim")

            # 恢复 gs-runtime 目录
            for _, dst_dir in self.extra_dirs:
                backup_runtime = backup_path / dst_dir.name
                if backup_runtime.exists():
                    # 删除现有目录
                    if dst_dir.exists():
                        shutil.rmtree(dst_dir)

                    # 恢复目录
                    dst_dir.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copytree(backup_runtime, dst_dir)
                    print(f"[DOTFILES] 恢复目录: {dst_dir.name}/")

            return CommandResult(success=True, output=f"Neovim 配置已恢复: {chosen_backup['name']}")
        except Exception as e:
            return CommandResult(success=False, error=f"恢复配置失败: {str(e)}")

    @plugin_function(
        name="status",
        description={"zh": "查看 Neovim 配置状态", "en": "Show Neovim configuration status"},
        usage="gs dotfiles nvim status",
        examples=["gs dotfiles nvim status"]
    )
    async def status(self, args: List[str] = None) -> CommandResult:
        """查看 Neovim 配置状态"""
        try:
            source = self.main_config["source"]
            target = self.main_config["target"]

            output = "Neovim 配置状态:\n"
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
