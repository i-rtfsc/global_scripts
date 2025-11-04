"""
配置相关数据结构
"""

from dataclasses import dataclass, field
from typing import Dict


@dataclass
class ConfigSchema:
    """配置文件架构

    明确定义config/gs.json的数据结构
    """

    # 插件启用状态映射
    system_plugins: Dict[str, bool] = field(default_factory=dict)
    custom_plugins: Dict[str, bool] = field(default_factory=dict)

    # 日志配置
    logging_level: str = "INFO"  # E/W/I/D/V/NANO 或完整名称

    # 界面配置
    language: str = "zh"
    prompt_theme: str = "minimalist"
    show_examples: bool = False

    # 系统配置
    max_concurrent_commands: int = 10
    default_timeout: int = 30

    def to_dict(self) -> Dict:
        """转换为字典"""
        return {
            "system_plugins": self.system_plugins,
            "custom_plugins": self.custom_plugins,
            "logging_level": self.logging_level,
            "language": self.language,
            "prompt_theme": self.prompt_theme,
            "show_examples": self.show_examples,
            "max_concurrent_commands": self.max_concurrent_commands,
            "default_timeout": self.default_timeout,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "ConfigSchema":
        """从字典创建"""
        return cls(
            system_plugins=data.get("system_plugins", {}),
            custom_plugins=data.get("custom_plugins", {}),
            logging_level=data.get("logging_level", "INFO"),
            language=data.get("language", "zh"),
            prompt_theme=data.get("prompt_theme", "minimalist"),
            show_examples=data.get("show_examples", False),
            max_concurrent_commands=data.get("max_concurrent_commands", 10),
            default_timeout=data.get("default_timeout", 30),
        )
