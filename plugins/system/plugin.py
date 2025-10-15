"""
System 主插件
- 提供系统管理工具的基础功能
- 不直接注册命令，由各子插件实现具体功能
"""

import sys
from pathlib import Path

# 确保可以导入 gs_system
project_root = Path(__file__).resolve().parents[2]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from gscripts.plugins.base import BasePlugin


class SystemBase(BasePlugin):
    def __init__(self):
        self.name = "system"