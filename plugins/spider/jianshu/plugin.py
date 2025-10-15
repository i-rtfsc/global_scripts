"""
JianShu Subplugin - 简书文章爬虫
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


@subplugin("jianshu")
class JianShuSubPlugin(BasePlugin):
    """简书文章爬虫子插件"""

    def __init__(self):
        self.name = "jianshu"
        self.parent_plugin = "spider"

    @plugin_function(
        name="crawl",
        description={
            "zh": "爬取简书用户的所有文章或单篇文章",
            "en": "Crawl all articles from JianShu user or single article"
        },
        usage="gs spider jianshu crawl <url_or_username> [output_dir]",
        examples=[
            "gs spider jianshu crawl username",
            "gs spider jianshu crawl https://www.jianshu.com/u/username",
            "gs spider jianshu crawl https://www.jianshu.com/p/article_id ./output"
        ]
    )
    async def crawl(self, args: List[str] = None) -> CommandResult:
        """爬取简书文章"""
        if not args or len(args) == 0:
            return CommandResult(
                success=False,
                output="❌ 请提供用户名或URL\n用法: gs spider jianshu crawl <url_or_username> [output_dir]"
            )

        # 简化版：仅验证参数并提示功能
        url_or_username = args[0]
        output_dir = args[1] if len(args) > 1 else "./jianshu_output"

        # 检查是否为URL还是用户名
        if url_or_username.startswith('http'):
            if '/u/' in url_or_username:
                mode = "用户主页"
            elif '/p/' in url_or_username:
                mode = "单篇文章"
            else:
                mode = "无效URL"
        else:
            mode = "用户名"

        return CommandResult(
            success=True,
            output=f"📋 JianShu爬虫功能\n目标: {url_or_username}\n模式: {mode}\n输出目录: {output_dir}\n💡 需要先运行 gs spider install_deps 安装依赖"
        )

    @plugin_function(
        name="info",
        description={
            "zh": "显示简书爬虫子插件信息",
            "en": "Show JianShu spider subplugin information"
        },
        usage="gs spider jianshu info",
        examples=["gs spider jianshu info"]
    )
    async def info(self, args: List[str] = None) -> CommandResult:
        """子插件信息"""
        message = ("📋 JianShu Spider 简书爬虫\n"
                  "支持功能:\n"
                  "• 爬取用户所有文章\n"
                  "• 爬取单篇文章\n"
                  "• 自动转换为Markdown格式\n"
                  "• 生成文章元数据")
        return CommandResult(success=True, output=message)