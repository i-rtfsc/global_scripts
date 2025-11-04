"""
重构的插件加载器（Phase 2 + Phase 4）
使用协调者模式，符合单一职责原则
实现 IPluginLoader 接口
"""

import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Union

from ..core.logger import get_logger
from .discovery import PluginDiscovery, PluginScanResult
from .validators import PluginValidator
from .parsers import FunctionParserRegistry, ParserDiscovery
from .parsers.python_parser import PythonFunctionParser
from .parsers.shell_parser import ShellFunctionParser
from .parsers.config_parser import ConfigFunctionParser

logger = get_logger(tag="PLUGINS.LOADER", name=__name__)


class RefactoredPluginLoader:
    """
    重构的插件加载器（协调者）
    实现 IPluginLoader 接口

    职责：
    - 协调各个组件完成插件加载
    - 不直接实现具体逻辑
    - 提供类型安全的插件加载
    """

    def __init__(
        self, plugins_root: Union[str, Path], parser_config: Optional[Dict] = None
    ):
        """
        初始化插件加载器

        Args:
            plugins_root: 插件根目录
            parser_config: 解析器配置（来自 gs.json 的 parsers 节）
        """
        self.plugins_root = Path(plugins_root)
        self.parser_config = parser_config or {}

        # 组件初始化
        self.discovery = PluginDiscovery(self.plugins_root)
        self.validator = PluginValidator()
        self.parser_registry = FunctionParserRegistry()

        # 注册解析器
        self._register_parsers()

        # 存储
        self.loaded_plugins: Dict[str, dict] = {}
        self.failed_plugins: Dict[str, str] = {}

    def _register_parsers(self):
        """
        注册所有解析器（内置 + 自动发现 + 配置）
        """
        # 1. 注册内置解析器（高优先级）
        self.parser_registry.register(PythonFunctionParser(), priority=10)
        self.parser_registry.register(ShellFunctionParser(), priority=20)
        self.parser_registry.register(ConfigFunctionParser(), priority=30)

        # 2. 自动发现并注册第三方解析器
        discovery = ParserDiscovery()

        try:
            # 从 Entry Points 发现
            external_parsers = discovery.discover_from_entry_points()

            for parser_class, metadata in external_parsers:
                try:
                    # 实例化解析器
                    parser = parser_class()

                    # 获取解析器名称
                    parser_name = metadata.name if metadata else parser_class.__name__

                    # 检查配置中的启用/禁用状态
                    enabled_parsers = self.parser_config.get("enabled", [])
                    disabled_parsers = self.parser_config.get("disabled", [])

                    # 如果在禁用列表中，跳过
                    if parser_name in disabled_parsers:
                        logger.info(
                            f"Parser {parser_name} is disabled in config, skipping"
                        )
                        continue

                    # 获取优先级（配置覆盖 > 元数据）
                    priority_overrides = self.parser_config.get(
                        "priority_overrides", {}
                    )
                    priority = priority_overrides.get(parser_name)

                    # 注册（会自动使用元数据中的优先级或配置覆盖）
                    self.parser_registry.register(parser, priority=priority)

                    logger.info(f"Registered external parser: {parser_name}")

                except Exception as e:
                    logger.warning(
                        f"Failed to register parser {parser_class.__name__}: {e}"
                    )

            # 从自定义路径发现
            custom_paths = discovery.get_custom_paths(self.parser_config)
            for custom_path in custom_paths:
                custom_parsers = discovery.discover_from_directory(custom_path)

                for parser_class, metadata in custom_parsers:
                    try:
                        parser = parser_class()
                        parser_name = (
                            metadata.name if metadata else parser_class.__name__
                        )

                        # 检查启用/禁用
                        disabled_parsers = self.parser_config.get("disabled", [])
                        if parser_name in disabled_parsers:
                            continue

                        # 获取优先级
                        priority_overrides = self.parser_config.get(
                            "priority_overrides", {}
                        )
                        priority = priority_overrides.get(parser_name)

                        self.parser_registry.register(parser, priority=priority)

                        logger.info(
                            f"Registered custom parser from {custom_path}: {parser_name}"
                        )

                    except Exception as e:
                        logger.warning(
                            f"Failed to register custom parser {parser_class.__name__}: {e}"
                        )

        except Exception as e:
            logger.warning(f"Parser auto-discovery failed: {e}")

    async def load_all_plugins(self, include_examples: bool = False) -> Dict[str, dict]:
        """
        加载所有插件

        Args:
            include_examples: 是否包含示例插件

        Returns:
            Dict[str, dict]: 已加载的插件字典
        """
        # 1. 发现所有插件
        plugin_dirs = self.discovery.discover_all_plugins(include_examples)

        # 2. 并行加载插件
        tasks = []
        for plugin_dir in plugin_dirs:
            tasks.append(self.load_plugin(plugin_dir))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 3. 收集结果
        for plugin_dir, result in zip(plugin_dirs, results):
            if isinstance(result, Exception):
                self.failed_plugins[plugin_dir.name] = str(result)
            elif result:
                self.loaded_plugins[result["name"]] = result

        return self.loaded_plugins

    async def load_plugin(self, plugin_dir: Path) -> Optional[dict]:
        """
        加载单个插件

        Args:
            plugin_dir: 插件目录

        Returns:
            Optional[dict]: 插件信息，失败返回 None
        """
        # 1. 验证插件目录
        validation = self.validator.validate_plugin_directory(plugin_dir)
        if not validation.is_valid:
            logger.error(f"Plugin validation failed: {validation.error_message}")
            return None

        # 2. 扫描插件
        scan_result = self.discovery.scan_plugin_directory(plugin_dir)

        # 3. 加载元数据
        metadata = await self._load_metadata(plugin_dir, scan_result)

        # 4. 发现函数
        functions = await self._discover_functions(scan_result, metadata["name"])

        # 5. 构建插件信息
        plugin_info = {
            "name": metadata["name"],
            "version": metadata.get("version", "1.0.0"),
            "author": metadata.get("author", "Unknown"),
            "description": metadata.get("description", {}),
            "type": scan_result.plugin_type.value,
            "enabled": metadata.get("enabled", True),
            "priority": metadata.get("priority", 50),
            "functions": {f.command: self._function_to_dict(f) for f in functions},
            "dir": str(plugin_dir),
        }

        return plugin_info

    async def _load_metadata(
        self, plugin_dir: Path, scan_result: PluginScanResult
    ) -> dict:
        """
        加载插件元数据

        Args:
            plugin_dir: 插件目录
            scan_result: 扫描结果

        Returns:
            dict: 元数据
        """
        import json

        metadata = {
            "name": plugin_dir.name,
            "version": "1.0.0",
            "author": "Unknown",
            "description": {"en": f"{plugin_dir.name} plugin"},
        }

        # 从 plugin.json 加载
        plugin_json = plugin_dir / "plugin.json"
        if plugin_json.exists():
            try:
                with open(plugin_json, "r", encoding="utf-8") as f:
                    config = json.load(f)
                    metadata.update(config)
            except Exception as e:
                logger.warning(f"Failed to load metadata from {plugin_json}: {e}")

        return metadata

    async def _discover_functions(
        self, scan_result: PluginScanResult, plugin_name: str
    ) -> List:
        """
        发现插件中的函数

        Args:
            scan_result: 扫描结果
            plugin_name: 插件名称

        Returns:
            List: 函数信息列表
        """
        files_to_parse = []

        # 收集需要解析的文件
        if scan_result.python_file:
            files_to_parse.append(scan_result.python_file)

        files_to_parse.extend(scan_result.config_files)
        files_to_parse.extend(scan_result.script_files)

        # 使用解析器注册表解析
        functions = []
        for file in files_to_parse:
            try:
                parser = self.parser_registry.get_parser(file)
                file_functions = await parser.parse(file, plugin_name)
                functions.extend(file_functions)
            except ValueError as e:
                logger.warning(f"No parser for file {file}: {e}")
            except Exception as e:
                logger.error(f"Failed to parse {file}: {e}")

        return functions

    def _function_to_dict(self, func_info) -> dict:
        """
        将 FunctionInfo 转换为字典

        Args:
            func_info: FunctionInfo 对象

        Returns:
            dict: 函数信息字典
        """
        return {
            "name": func_info.name,
            "description": func_info.description,
            "command": func_info.command,
            "type": func_info.type,
            "args": func_info.args,
            "options": func_info.options,
            "examples": func_info.examples,
        }

    def get_plugin(self, plugin_name: str) -> Optional[dict]:
        """
        获取插件信息

        Args:
            plugin_name: 插件名称

        Returns:
            Optional[dict]: 插件信息
        """
        return self.loaded_plugins.get(plugin_name)

    def get_all_plugins(self) -> Dict[str, dict]:
        """
        获取所有插件

        Returns:
            Dict[str, dict]: 所有插件
        """
        return self.loaded_plugins
