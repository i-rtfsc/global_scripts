"""
Hybrid Plugin with Subplugins - Python Part
Demonstrates full hybrid implementation with subplugin support
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


class HybridWithSubpluginsPlugin(BasePlugin):
    """带子插件的混合插件主类"""
    
    def __init__(self):
        self.name = "hybrid-with-subplugins"
    
    @plugin_function(
        name="python_info",
        description={
            "zh": "Python函数信息（混合主插件中的Python部分）",
            "en": "Python function info (Python part in hybrid main plugin)"
        },
        usage="gs hybrid-with-subplugins python_info",
        examples=["gs hybrid-with-subplugins python_info"]
    )
    async def python_info(self, args: List[str] = None) -> CommandResult:
        """显示Python部分信息"""
        message = "🐍 hybrid-with-subplugins Python Info | Main Plugin: Python function | Subplugins: tools, services | Implementation: Full hybrid"
        return CommandResult(success=True, output=message)
