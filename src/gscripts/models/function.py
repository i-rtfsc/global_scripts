"""
函数信息相关数据结构
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union, Dict, List
from .plugin import FunctionType


@dataclass
class FunctionInfo:
    """插件函数信息

    统一的函数元数据结构,支持所有类型的插件函数
    """
    name: str
    description: Union[str, Dict[str, str]]
    type: FunctionType
    subplugin: str = ""

    # 执行相关
    command: Optional[str] = None
    python_file: Optional[Path] = None
    script_file: Optional[Path] = None
    config_file: Optional[Path] = None
    method: Optional[str] = None

    # 文档相关
    usage: str = ""
    examples: List[str] = field(default_factory=list)

    # 执行配置
    timeout: int = 30
    working_dir: Optional[Path] = None
    env_vars: Dict[str, str] = field(default_factory=dict)

    def get_description(self, language: str = 'zh') -> str:
        """获取指定语言的描述"""
        if isinstance(self.description, dict):
            return self.description.get(language) or self.description.get('zh') or self.description.get('en') or ''
        return str(self.description)

    @property
    def full_name(self) -> str:
        """完整函数名(包含子插件)"""
        if self.subplugin and self.subplugin != "":
            return f"{self.subplugin}-{self.name}"
        return self.name

    @property
    def is_python(self) -> bool:
        """是否为Python函数"""
        return self.type in (FunctionType.PYTHON, FunctionType.PYTHON_DECORATED)

    @property
    def is_shell(self) -> bool:
        """是否为Shell函数"""
        return self.type in (FunctionType.SHELL, FunctionType.SHELL_ANNOTATED)

    @property
    def is_config(self) -> bool:
        """是否为配置函数"""
        return self.type == FunctionType.CONFIG
