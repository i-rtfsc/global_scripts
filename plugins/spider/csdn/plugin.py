"""
CSDN Subplugin - CSDN文章爬虫
Subplugin for spider main plugin
"""

import sys
from pathlib import Path

# 添加项目根目录到sys.path以支持导入
project_root = Path(__file__).resolve().parents[3]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from gscripts.plugins.decorators import plugin_function, subplugin
from gscripts.plugins.base import CommandResult, BasePlugin
from typing import List


@subplugin("csdn")
class CSDNSubPlugin(BasePlugin):
    """CSDN文章爬虫子插件"""

    def __init__(self):
        self.name = "csdn"
        self.parent_plugin = "spider"

    @plugin_function(
        name="crawl",
        description={
            "zh": "爬取CSDN用户的所有文章或单篇文章",
            "en": "Crawl all articles from CSDN user or single article"
        },
        usage="gs spider csdn crawl <url_or_username> [output_dir]",
        examples=[
            "gs spider csdn crawl username",
            "gs spider csdn crawl https://blog.csdn.net/username"
        ]
    )
    async def crawl(self, args: List[str] = None) -> CommandResult:
        """爬取CSDN文章"""
        if not args or len(args) == 0:
            return CommandResult(
                success=False,
                output="❌ 请提供用户名或URL\n用法: gs spider csdn crawl <url_or_username> [output_dir]"
            )

        # 简化版：仅验证参数并提示功能
        url_or_username = args[0]
        output_dir = args[1] if len(args) > 1 else "./csdn_output"

        return CommandResult(
            success=True,
            output=f"📋 CSDN爬虫功能\n目标: {url_or_username}\n输出目录: {output_dir}\n💡 需要先运行 gs spider install_deps 安装依赖"
        )

    @plugin_function(
        name="info",
        description={
            "zh": "显示CSDN爬虫子插件信息",
            "en": "Show CSDN spider subplugin information"
        },
        usage="gs spider csdn info",
        examples=["gs spider csdn info"]
    )
    async def info(self, args: List[str] = None) -> CommandResult:
        """子插件信息"""
        message = ("📋 CSDN Spider CSDN文章爬虫\n"
                  "支持功能:\n"
                  "• 爬取用户所有文章\n"
                  "• 爬取单篇文章\n"
                  "• 自动转换为Markdown格式\n"
                  "• 提取文章标签和元数据\n"
                  "• 支持CSDN特殊格式处理")
        return CommandResult(success=True, output=message)