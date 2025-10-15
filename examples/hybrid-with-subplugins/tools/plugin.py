"""
Tools Subplugin - Python Implementation
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


@subplugin("tools")
class ToolsSubPlugin(BasePlugin):
    """工具子插件"""
    
    def __init__(self):
        self.name = "tools"
        self.parent_plugin = "hybrid-with-subplugins"
    
    @plugin_function(
        name="python_tool",
        description={
            "zh": "Python工具功能",
            "en": "Python tool functionality"
        },
        usage="gs hybrid-with-subplugins tools python_tool",
        examples=["gs hybrid-with-subplugins tools python_tool"]
    )
    async def python_tool(self, args: List[str] = None) -> CommandResult:
        """Python工具"""
        message = "🐍 hybrid-with-subplugins tools python_tool | Subplugin: tools | Implementation: Python | Parent: Full hybrid"
        return CommandResult(success=True, output=message)
