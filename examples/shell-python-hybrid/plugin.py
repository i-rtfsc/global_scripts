"""
Shell-Python Hybrid Plugin - Mixed Implementation  
Demonstrates combining shell and Python functions
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
import platform


class ShellPythonHybridPlugin(BasePlugin):
    """Shell+Python混合插件示例类"""
    
    def __init__(self):
        self.name = "shell-python-hybrid"
    
    @plugin_function(
        name="python_info",
        description={
            "zh": "Python函数信息（混合插件中的Python部分）", 
            "en": "Python function info (Python part in hybrid plugin)"
        },
        usage="gs shell-python-hybrid python_info",
        examples=["gs shell-python-hybrid python_info"]
    )
    async def python_info(self, args: List[str] = None) -> CommandResult:
        """Python函数信息"""
        python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        message = f"🐍 shell-python-hybrid Python Info | Source: plugin.py | Works with Shell functions | Python: {python_version}"
        return CommandResult(success=True, output=message)
