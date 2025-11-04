"""
插件相关数据结构
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Dict, Optional, Union


class PluginType(Enum):
    """插件类型枚举"""

    PYTHON = "python"
    SHELL = "shell"
    CONFIG = "config"
    HYBRID = "hybrid"
    UNKNOWN = "unknown"


class FunctionType(Enum):
    """函数类型枚举"""

    PYTHON = "python"
    PYTHON_DECORATED = "python_decorated"
    SHELL = "shell"
    SHELL_ANNOTATED = "shell_annotated"
    CONFIG = "config"


@dataclass
class PluginPaths:
    """插件路径信息缓存

    避免重复的路径解析和exists检查
    """

    plugin_dir: Path
    python_file: Optional[Path] = None
    config_file: Optional[Path] = None
    script_files: List[Path] = field(default_factory=list)

    def __post_init__(self):
        """自动解析为绝对路径"""
        self.plugin_dir = self.plugin_dir.resolve()
        if self.python_file:
            self.python_file = self.python_file.resolve()
        if self.config_file:
            self.config_file = self.config_file.resolve()
        self.script_files = [f.resolve() for f in self.script_files]


@dataclass
class PluginMetadata:
    """插件元数据

    标准化的插件元信息结构,从plugin.json加载
    """

    name: str
    version: str = "1.0.0"
    author: str = "Unknown"
    description: Union[str, Dict[str, str]] = ""
    homepage: str = ""
    license: str = ""
    enabled: bool = True
    priority: int = 50
    category: str = ""
    keywords: List[str] = field(default_factory=list)
    requirements: Dict[str, List[str]] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    subplugins: List[str] = field(default_factory=list)
    type: PluginType = PluginType.UNKNOWN

    def get_description(self, language: str = "zh") -> str:
        """获取指定语言的描述"""
        if isinstance(self.description, dict):
            return (
                self.description.get(language)
                or self.description.get("zh")
                or self.description.get("en")
                or ""
            )
        return str(self.description)
