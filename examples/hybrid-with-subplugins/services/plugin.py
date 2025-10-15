"""
Services Subplugin - Python Implementation  
Subplugin for hybrid-with-subplugins main plugin
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
import time


@subplugin("services")
class ServicesSubPlugin(BasePlugin):
    """服务子插件"""
    
    def __init__(self):
        self.name = "services"
        self.parent_plugin = "hybrid-with-subplugins"
    
    @plugin_function(
        name="status",
        description={
            "zh": "检查服务状态",
            "en": "Check service status"
        },
        usage="gs hybrid-with-subplugins services status",
        examples=["gs hybrid-with-subplugins services status"]
    )
    async def status(self, args: List[str] = None) -> CommandResult:
        """服务状态"""
        message = "✅ hybrid-with-subplugins services status | Subplugin: services | Status: Running | Parent: Full hybrid"
        return CommandResult(success=True, output=message)
    
    @plugin_function(
        name="info",
        description={
            "zh": "显示服务子插件信息",
            "en": "Show services subplugin information"
        },
        usage="gs hybrid-with-subplugins services info",
        examples=["gs hybrid-with-subplugins services info"]
    )
    async def info(self, args: List[str] = None) -> CommandResult:
        """服务信息"""
        message = "📋 hybrid-with-subplugins services info | Subplugin: services | Parent: hybrid-with-subplugins | Commands: 2"
        return CommandResult(success=True, output=message)
