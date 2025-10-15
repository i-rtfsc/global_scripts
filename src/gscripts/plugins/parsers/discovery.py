"""
解析器自动发现机制
支持从 Entry Points、目录和配置文件自动发现解析器
"""

from pathlib import Path
from typing import List, Dict, Any, Tuple, Type, Optional
import importlib.metadata
import importlib.util
import sys

from . import FunctionParser, ParserMetadata
from ...core.logger import get_logger

logger = get_logger(tag="PARSER.DISCOVERY", name=__name__)


class ParserDiscovery:
    """
    解析器自动发现类

    职责:
    - 从 Python Entry Points 发现第三方解析器
    - 从指定目录加载自定义解析器
    - 从配置文件加载解析器设置
    - 支持懒加载和缓存机制
    """

    ENTRY_POINT_GROUP = "gscripts.parsers"

    def __init__(self):
        """初始化发现机制"""
        self._cache: Dict[str, Tuple[Type[FunctionParser], Optional[ParserMetadata]]] = {}
        self._cache_valid = False

    def discover_from_entry_points(self) -> List[Tuple[Type[FunctionParser], Optional[ParserMetadata]]]:
        """
        从 Python Entry Points 自动发现解析器

        Returns:
            解析器类和元数据的列表
        """
        if self._cache_valid and self._cache:
            return list(self._cache.values())

        discovered = []

        try:
            # Python 3.10+ 使用 entry_points().select()
            # Python 3.9 使用 entry_points().get()
            entry_points = importlib.metadata.entry_points()

            if hasattr(entry_points, 'select'):
                # Python 3.10+
                parsers = entry_points.select(group=self.ENTRY_POINT_GROUP)
            else:
                # Python 3.9
                parsers = entry_points.get(self.ENTRY_POINT_GROUP, [])

            for ep in parsers:
                try:
                    # 加载解析器类
                    parser_class = ep.load()

                    # 验证是 FunctionParser 子类
                    if not issubclass(parser_class, FunctionParser):
                        logger.warning(f"Entry point {ep.name} is not a FunctionParser subclass, skipping")
                        continue

                    # 提取元数据
                    metadata = getattr(parser_class, '_metadata', None)

                    # 缓存
                    self._cache[ep.name] = (parser_class, metadata)
                    discovered.append((parser_class, metadata))

                    logger.info(f"Discovered parser from entry point: {ep.name}")

                except Exception as e:
                    logger.warning(f"Failed to load parser from entry point {ep.name}: {e}")

        except Exception as e:
            logger.error(f"Failed to discover parsers from entry points: {e}")

        self._cache_valid = True
        return discovered

    def discover_from_directory(self, directory: Path) -> List[Tuple[Type[FunctionParser], Optional[ParserMetadata]]]:
        """
        从指定目录加载自定义解析器

        Args:
            directory: 解析器目录路径

        Returns:
            解析器类和元数据的列表
        """
        if not directory.exists() or not directory.is_dir():
            logger.warning(f"Parser directory does not exist: {directory}")
            return []

        discovered = []

        # 查找所有 Python 文件
        for py_file in directory.glob("**/*_parser.py"):
            try:
                # 动态导入模块
                module_name = f"custom_parsers.{py_file.stem}"
                spec = importlib.util.spec_from_file_location(module_name, py_file)

                if spec is None or spec.loader is None:
                    logger.warning(f"Cannot load module spec for {py_file}")
                    continue

                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)

                # 查找 FunctionParser 子类
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)

                    # 检查是否是类，并且是 FunctionParser 的子类（但不是 FunctionParser 本身）
                    if (isinstance(attr, type) and
                        issubclass(attr, FunctionParser) and
                        attr is not FunctionParser):

                        metadata = getattr(attr, '_metadata', None)
                        discovered.append((attr, metadata))

                        logger.info(f"Discovered parser from directory: {attr.__name__} in {py_file.name}")

            except Exception as e:
                logger.warning(f"Failed to load parser from {py_file}: {e}")

        return discovered

    def discover_from_config(self, config: Dict[str, Any]) -> List[str]:
        """
        从配置文件加载解析器设置

        Args:
            config: 配置字典（通常来自 gs.json 的 parsers 节）

        Returns:
            启用的解析器名称列表
        """
        if not config:
            return []

        enabled = config.get('enabled', [])
        disabled = config.get('disabled', [])

        # 计算最终启用的解析器列表
        if isinstance(enabled, list):
            # 移除被禁用的
            return [name for name in enabled if name not in disabled]

        return []

    def get_custom_paths(self, config: Dict[str, Any]) -> List[Path]:
        """
        从配置文件获取自定义解析器路径

        Args:
            config: 配置字典

        Returns:
            自定义解析器目录列表
        """
        custom_paths = config.get('custom_paths', [])

        paths = []
        for path_str in custom_paths:
            path = Path(path_str).expanduser()
            if path.exists():
                paths.append(path)
            else:
                logger.warning(f"Custom parser path does not exist: {path_str}")

        return paths

    def get_priority_overrides(self, config: Dict[str, Any]) -> Dict[str, int]:
        """
        从配置文件获取优先级覆盖设置

        Args:
            config: 配置字典

        Returns:
            解析器名称到优先级的映射
        """
        return config.get('priority_overrides', {})

    def clear_cache(self) -> None:
        """清除缓存"""
        self._cache.clear()
        self._cache_valid = False
