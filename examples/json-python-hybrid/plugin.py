"""
JSON-Python Hybrid Plugin - Mixed Implementation
Demonstrates combining JSON commands with Python functions
"""

import sys
import os
from pathlib import Path

# 添加项目根目录到sys.path以支持导入
project_root = Path(__file__).resolve().parents[2]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from gscripts.plugins.decorators import plugin_function
from gscripts.plugins.base import CommandResult, BasePlugin
from typing import List


class JsonPythonHybridPlugin(BasePlugin):
    """JSON+Python混合插件示例类"""
    
    def __init__(self):
        self.name = "json-python-hybrid"
    
    @plugin_function(
        name="python_demo",
        description={
            "zh": "Python函数演示（混合插件中的Python部分）",
            "en": "Python function demo (Python part in hybrid plugin)"
        },
        usage="gs json-python-hybrid python_demo",
        examples=["gs json-python-hybrid python_demo"]
    )
    async def python_demo(self, args: List[str] = None) -> CommandResult:
        """Python函数演示"""
        message = f"🐍 json-python-hybrid Python Demo | Source: plugin.py | Combined with JSON commands | Process PID: {os.getpid()}"
        return CommandResult(success=True, output=message)
    
    @plugin_function(
        name="hybrid_stats",
        description={
            "zh": "显示混合插件统计信息",
            "en": "Show hybrid plugin statistics"
        },
        usage="gs json-python-hybrid hybrid_stats",
        examples=["gs json-python-hybrid hybrid_stats"]
    )
    async def hybrid_stats(self, args: List[str] = None) -> CommandResult:
        """显示混合插件统计"""
        message = "📊 json-python-hybrid Stats | JSON Commands: Available | Python Functions: Active | Hybrid Mode: Enabled"
        return CommandResult(success=True, output=message)
