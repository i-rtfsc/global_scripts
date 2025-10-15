"""
Processing Subplugin - Data Processing Features
Subplugin for python-with-subplugins main plugin
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


@subplugin("processing")
class ProcessingSubPlugin(BasePlugin):
    """数据处理子插件"""
    
    def __init__(self):
        self.name = "processing"
        self.parent_plugin = "python-with-subplugins"
    
    @plugin_function(
        name="transform",
        description={
            "zh": "执行数据转换处理",
            "en": "Execute data transformation processing"
        },
        usage="gs python-with-subplugins processing transform [type]",
        examples=[
            "gs python-with-subplugins processing transform",
            "gs python-with-subplugins processing transform json"
        ]
    )
    async def transform(self, args: List[str] = None) -> CommandResult:
        """数据转换"""
        transform_type = args[0] if args and len(args) > 0 else "default"
        message = f"🔄 python-with-subplugins processing transform | Subplugin: processing | Type: {transform_type} | Status: Completed"
        return CommandResult(success=True, output=message)
    
    @plugin_function(
        name="batch",
        description={
            "zh": "执行批量处理任务",
            "en": "Execute batch processing task"
        },
        usage="gs python-with-subplugins processing batch",
        examples=["gs python-with-subplugins processing batch"]
    )
    async def batch(self, args: List[str] = None) -> CommandResult:
        """批量处理"""
        start_time = time.time()
        # 模拟处理时间
        processing_time = round((time.time() - start_time) * 1000, 2)
        message = f"⚡ python-with-subplugins processing batch | Subplugin: processing | Items: 100 | Time: {processing_time}ms"
        return CommandResult(success=True, output=message)
    
    @plugin_function(
        name="info",
        description={
            "zh": "显示处理子插件信息",
            "en": "Show processing subplugin information"
        },
        usage="gs python-with-subplugins processing info",
        examples=["gs python-with-subplugins processing info"]
    )
    async def info(self, args: List[str] = None) -> CommandResult:
        """子插件信息"""
        message = "📋 python-with-subplugins processing info | Subplugin: processing | Parent: python-with-subplugins | Commands: 3"
        return CommandResult(success=True, output=message)
