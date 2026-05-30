"""
插件相关数据结构
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, List, Dict, Optional, Union


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


@dataclass(eq=False)
class SubPlugin:
    """子插件元数据（统一模型）

    插件下的子插件历史上以三种形态出现：纯字符串名、plugin.json 中的完整
    字典、以及运行期对象。``SubPlugin`` 统一这三者：

    - :meth:`from_raw` 接受 str / dict / SubPlugin，始终返回 SubPlugin（幂等）；
    - :meth:`to_index_dict` 序列化为 router.json 与 shell 补全约定的
      ``{"name", "description": {"zh", "en"}}`` 形状；
    - :meth:`to_dict` 序列化回 plugin.json 的完整形状（省略默认值，可无损往返）。

    为兼容历史的 ``"name" in metadata.subplugins`` 写法，相等性按名称比较，
    并允许直接与字符串比较。
    """

    name: str
    type: PluginType = PluginType.UNKNOWN
    entry: str = ""
    version: str = "1.0.0"
    description: Union[str, Dict[str, str]] = ""

    # plugin.json 中 type 的别名 → 规范类型，与 PluginRepository 的映射保持一致
    _TYPE_ALIASES = {"json": "config", "script": "shell", "sh": "shell"}

    @classmethod
    def from_raw(cls, raw: Any) -> "SubPlugin":
        """从 str / dict / SubPlugin 构造 SubPlugin，幂等。"""
        if isinstance(raw, SubPlugin):
            return raw
        if isinstance(raw, str):
            return cls(name=raw)
        if isinstance(raw, dict):
            type_str = str(raw.get("type", "unknown")).lower()
            type_str = cls._TYPE_ALIASES.get(type_str, type_str)
            try:
                plugin_type = PluginType(type_str)
            except ValueError:
                plugin_type = PluginType.UNKNOWN
            return cls(
                name=raw.get("name", ""),
                type=plugin_type,
                entry=raw.get("entry", ""),
                version=raw.get("version", "1.0.0"),
                description=raw.get("description", ""),
            )
        # 未知形态：尽力而为，避免在加载期抛错
        return cls(name=str(raw))

    def get_description(self, language: str = "zh") -> str:
        """获取指定语言的描述（回退顺序 language → zh → en）。"""
        if isinstance(self.description, dict):
            return (
                self.description.get(language)
                or self.description.get("zh")
                or self.description.get("en")
                or ""
            )
        return str(self.description)

    def _description_dict(self) -> Dict[str, str]:
        """归一化描述为 {"zh", "en"} 字典(等价于 router 的 _normalize_description)。"""
        if isinstance(self.description, dict):
            return self.description
        if isinstance(self.description, str):
            return {"zh": self.description, "en": self.description}
        return {"zh": "", "en": ""}

    def to_index_dict(self) -> Dict[str, Any]:
        """序列化为 router.json / shell 补全约定的形状。"""
        return {"name": self.name, "description": self._description_dict()}

    def to_dict(self) -> Dict[str, Any]:
        """序列化为 plugin.json 完整形状,省略默认值以保证无损往返。"""
        data: Dict[str, Any] = {"name": self.name}
        if self.type is not PluginType.UNKNOWN:
            data["type"] = self.type.value
        if self.entry:
            data["entry"] = self.entry
        if self.version and self.version != "1.0.0":
            data["version"] = self.version
        if self.description:
            data["description"] = self.description
        return data

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, SubPlugin):
            return self.name == other.name
        if isinstance(other, str):
            return self.name == other
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.name)


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
    subplugins: List["SubPlugin"] = field(default_factory=list)
    type: PluginType = PluginType.UNKNOWN

    def __setattr__(self, name: str, value: Any) -> None:
        """统一子插件模型:任何对 subplugins 的赋值都归一化为 List[SubPlugin]。

        覆盖 __setattr__(而非仅 __post_init__)以同时拦截 dataclass 构造、
        测试工厂的 setattr 覆盖,以及后续的重新赋值,使该字段始终是
        SubPlugin 列表这一不变量在所有赋值路径上都成立。
        """
        if name == "subplugins":
            value = [SubPlugin.from_raw(item) for item in (value or [])]
        super().__setattr__(name, value)

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
