"""
Python Plugin with Subplugins - Main Plugin
Demonstrates Python main plugin with subplugin structure
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


class PythonWithSubpluginsPlugin(BasePlugin):
    """带子插件的Python插件主类"""
    
    def __init__(self):
        self.name = "python-with-subplugins"
    
    @plugin_function(
        name="info",
        description={
            "zh": "显示Python主插件信息",
            "en": "Show Python main plugin information"
        },
        usage="gs python-with-subplugins info",
        examples=["gs python-with-subplugins info"]
    )
    async def info(self, args: List[str] = None) -> CommandResult:
        """显示主插件信息"""
        message = "📋 python-with-subplugins Main Info | Type: Python with Subplugins | Subplugins: analysis, processing | Total Commands: 7"
        return CommandResult(success=True, output=message)
    
    @plugin_function(
        name="list_subplugins",
        description={
            "zh": "列出所有Python子插件",
            "en": "List all Python subplugins"
        },
        usage="gs python-with-subplugins list_subplugins",
        examples=["gs python-with-subplugins list_subplugins"]
    )
    async def list_subplugins(self, args: List[str] = None) -> CommandResult:
        """列出子插件"""
        message = "📂 python-with-subplugins Subplugins: | 1. analysis (数据分析) | 2. processing (数据处理)"
        return CommandResult(success=True, output=message)
