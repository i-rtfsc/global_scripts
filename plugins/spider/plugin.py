"""
Spider Plugin - Main Plugin
网络爬虫插件主模块
"""

import sys
from pathlib import Path

# 添加项目根目录到sys.path以支持导入
project_root = Path(__file__).resolve().parents[2]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from gscripts.plugins.decorators import plugin_function
from gscripts.plugins.base import CommandResult, BasePlugin
from typing import List
import subprocess


class SpiderPlugin(BasePlugin):
    """网络爬虫插件主类"""

    def __init__(self):
        self.name = "spider"

    @plugin_function(
        name="info",
        description={
            "zh": "显示爬虫插件信息",
            "en": "Show spider plugin information"
        },
        usage="gs spider info",
        examples=["gs spider info"]
    )
    async def info(self, args: List[str] = None) -> CommandResult:
        """显示主插件信息"""
        message = "🕷️ Spider Plugin | 支持平台: 简书、博客园、CSDN | 子插件: jianshu, cnblogs, csdn | 功能: 文章批量下载、Markdown转换"
        return CommandResult(success=True, output=message)

    @plugin_function(
        name="install_deps",
        description={
            "zh": "安装爬虫插件所需的Python依赖",
            "en": "Install Python dependencies for spider plugin"
        },
        usage="gs spider install_deps",
        examples=["gs spider install_deps"]
    )
    async def install_deps(self, args: List[str] = None) -> CommandResult:
        """安装爬虫插件所需的Python依赖"""
        dependencies = [
            "requests>=2.25.0",
            "beautifulsoup4>=4.9.0",
            "markdownify>=0.9.0",
            "selenium>=4.0.0",
            "parsel>=1.6.0"
        ]

        output_lines = ["🕷️ 正在安装爬虫插件依赖..."]

        for dep in dependencies:
            try:
                output_lines.append(f"📦 安装 {dep}...")
                # 首先尝试用 --user 安装
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", dep],
                                        capture_output=True, text=True)
                    output_lines.append(f"✅ {dep} 安装成功 (用户模式)")
                except subprocess.CalledProcessError:
                    # 如果失败，尝试使用 --break-system-packages
                    try:
                        subprocess.check_call([sys.executable, "-m", "pip", "install", "--break-system-packages", dep],
                                            capture_output=True, text=True)
                        output_lines.append(f"✅ {dep} 安装成功 (系统包模式)")
                    except subprocess.CalledProcessError:
                        output_lines.append(f"❌ {dep} 安装失败")
                        output_lines.append("💡 建议:")
                        output_lines.append(f"   1. 手动安装: pip install --user {dep}")
                        output_lines.append(f"   2. 或使用虚拟环境")
                        return CommandResult(success=False, output="\n".join(output_lines))
            except Exception as e:
                output_lines.append(f"❌ {dep} 安装失败: {e}")
                return CommandResult(success=False, output="\n".join(output_lines))

        output_lines.append("🎉 所有依赖安装完成！")
        return CommandResult(success=True, output="\n".join(output_lines))

    @plugin_function(
        name="check_deps",
        description={
            "zh": "检查爬虫插件依赖是否已安装",
            "en": "Check if spider plugin dependencies are installed"
        },
        usage="gs spider check_deps",
        examples=["gs spider check_deps"]
    )
    async def check_deps(self, args: List[str] = None) -> CommandResult:
        """检查依赖是否已安装"""
        missing_deps = []
        output_lines = ["🔍 检查爬虫插件依赖..."]

        deps_to_check = {
            "requests": "requests",
            "beautifulsoup4": "bs4",
            "markdownify": "markdownify",
            "selenium": "selenium",
            "parsel": "parsel"
        }

        for dep_name, import_name in deps_to_check.items():
            try:
                __import__(import_name)
                output_lines.append(f"✅ {dep_name} - 已安装")
            except ImportError:
                output_lines.append(f"❌ {dep_name} - 未安装")
                missing_deps.append(dep_name)

        if missing_deps:
            output_lines.append("\n💡 缺少依赖，请运行: gs spider install_deps")
            return CommandResult(success=False, output="\n".join(output_lines))
        else:
            output_lines.append("\n🎉 所有依赖已安装！")
            return CommandResult(success=True, output="\n".join(output_lines))

    @plugin_function(
        name="list_subplugins",
        description={
            "zh": "列出所有爬虫子插件",
            "en": "List all spider subplugins"
        },
        usage="gs spider list_subplugins",
        examples=["gs spider list_subplugins"]
    )
    async def list_subplugins(self, args: List[str] = None) -> CommandResult:
        """列出子插件"""
        message = ("📂 Spider 子插件:\n"
                  "1. jianshu - 简书文章爬虫\n"
                  "2. cnblogs - 博客园文章爬虫\n"
                  "3. csdn - CSDN文章爬虫")
        return CommandResult(success=True, output=message)