"""
Analysis Subplugin - Data Analysis Features
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
import random


@subplugin("analysis")
class AnalysisSubPlugin(BasePlugin):
    """数据分析子插件"""
    
    def __init__(self):
        self.name = "analysis"
        self.parent_plugin = "python-with-subplugins"
    
    @plugin_function(
        name="stats",
        description={
            "zh": "生成统计数据分析",
            "en": "Generate statistical data analysis"
        },
        usage="gs python-with-subplugins analysis stats",
        examples=["gs python-with-subplugins analysis stats"]
    )
    async def stats(self, args: List[str] = None) -> CommandResult:
        """统计分析"""
        sample_data = [random.randint(1, 100) for _ in range(5)]
        avg = sum(sample_data) / len(sample_data)
        message = f"📊 python-with-subplugins analysis stats | Subplugin: analysis | Sample: {sample_data} | Average: {avg:.2f}"
        return CommandResult(success=True, output=message)
    
    @plugin_function(
        name="report",
        description={
            "zh": "生成分析报告",
            "en": "Generate analysis report"
        },
        usage="gs python-with-subplugins analysis report",
        examples=["gs python-with-subplugins analysis report"]
    )
    async def report(self, args: List[str] = None) -> CommandResult:
        """生成报告"""
        message = "📄 python-with-subplugins analysis report | Subplugin: analysis | Status: Generated | Format: Text"
        return CommandResult(success=True, output=message)
