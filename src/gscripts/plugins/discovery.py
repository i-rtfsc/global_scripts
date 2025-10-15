"""
插件发现模块
负责扫描和发现插件目录
符合单一职责原则
"""

from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass
from enum import Enum


class PluginType(Enum):
    """插件类型枚举"""
    PYTHON = "python"
    CONFIG = "config"
    SCRIPT = "script"
    HYBRID = "hybrid"


@dataclass
class PluginScanResult:
    """插件扫描结果"""
    plugin_dir: Path
    plugin_type: PluginType
    has_python: bool = False
    has_config: bool = False
    has_scripts: bool = False
    python_file: Optional[Path] = None
    config_files: List[Path] = None
    script_files: List[Path] = None
    metadata_files: List[Path] = None

    def __post_init__(self):
        if self.config_files is None:
            self.config_files = []
        if self.script_files is None:
            self.script_files = []
        if self.metadata_files is None:
            self.metadata_files = []


class PluginDiscovery:
    """
    插件发现类

    职责：
    - 扫描插件目录
    - 识别插件类型
    - 查找插件文件
    """

    def __init__(self, plugins_root: Path):
        """
        初始化插件发现器

        Args:
            plugins_root: 插件根目录
        """
        self.plugins_root = plugins_root
        self._normalize_plugins_root()

    def _normalize_plugins_root(self):
        """规范化插件根目录路径"""
        import os

        if not self.plugins_root.exists():
            # 尝试从环境变量获取
            gs_root = os.environ.get('GS_ROOT')
            if gs_root:
                candidate = Path(gs_root) / 'plugins'
                if candidate.exists():
                    self.plugins_root = candidate

        # 如果指向项目根目录，切换到 plugins 子目录
        if (self.plugins_root.exists() and
            (self.plugins_root / 'plugins').exists() and
            self.plugins_root.name != 'plugins'):
            potential = self.plugins_root / 'plugins'
            if potential.is_dir():
                self.plugins_root = potential

    def discover_all_plugins(self, include_examples: bool = False) -> List[Path]:
        """
        发现所有插件目录

        Args:
            include_examples: 是否包含示例插件

        Returns:
            List[Path]: 插件目录列表
        """
        if not self.plugins_root.exists():
            return []

        plugin_dirs = [p for p in self.plugins_root.iterdir() if p.is_dir()]

        if include_examples:
            examples_root = self.plugins_root.parent / 'examples'
            if examples_root.exists():
                example_dirs = [p for p in examples_root.iterdir() if p.is_dir()]
                plugin_dirs.extend(example_dirs)

        return plugin_dirs

    def scan_plugin_directory(self, plugin_dir: Path) -> PluginScanResult:
        """
        扫描单个插件目录，识别插件类型和文件

        Args:
            plugin_dir: 插件目录路径

        Returns:
            PluginScanResult: 扫描结果
        """
        result = PluginScanResult(
            plugin_dir=plugin_dir,
            plugin_type=PluginType.CONFIG  # 默认类型
        )

        # 扫描文件
        for file in plugin_dir.iterdir():
            if not file.is_file():
                continue

            filename = file.name.lower()

            # Python 文件
            if filename == 'plugin.py':
                result.has_python = True
                result.python_file = file

            # 配置文件
            elif filename == 'plugin.json':
                result.has_config = True
                result.config_files.append(file)
                result.metadata_files.append(file)

            # Shell 脚本
            elif filename.endswith('.sh'):
                result.has_scripts = True
                result.script_files.append(file)

        # 确定插件类型
        result.plugin_type = self._determine_plugin_type(result)

        return result

    def _determine_plugin_type(self, scan_result: PluginScanResult) -> PluginType:
        """
        根据扫描结果确定插件类型

        Args:
            scan_result: 扫描结果

        Returns:
            PluginType: 插件类型
        """
        has_python = scan_result.has_python
        has_config = scan_result.has_config
        has_scripts = scan_result.has_scripts

        # Hybrid: 包含多种类型
        if sum([has_python, has_config, has_scripts]) > 1:
            return PluginType.HYBRID

        # Python 插件
        if has_python:
            return PluginType.PYTHON

        # 脚本插件
        if has_scripts:
            return PluginType.SCRIPT

        # 配置插件（默认）
        return PluginType.CONFIG

    def discover_custom_plugins(self, custom_root: Path) -> List[Path]:
        """
        递归发现自定义插件

        Args:
            custom_root: 自定义插件根目录

        Returns:
            List[Path]: 插件目录列表
        """
        return self._discover_recursive(custom_root)

    def _discover_recursive(self, root: Path, parent_path: str = "") -> List[Path]:
        """
        递归发现插件目录

        Args:
            root: 根目录
            parent_path: 父路径（用于构建插件名称）

        Returns:
            List[Path]: 插件目录列表
        """
        plugin_dirs = []

        if not root.exists() or not root.is_dir():
            return plugin_dirs

        for item in root.iterdir():
            if not item.is_dir():
                continue

            # 检查是否为插件目录（包含 plugin.json 或 plugin.py）
            has_plugin_json = (item / 'plugin.json').exists()
            has_plugin_py = (item / 'plugin.py').exists()

            if has_plugin_json or has_plugin_py:
                plugin_dirs.append(item)
            else:
                # 递归查找子目录
                sub_plugins = self._discover_recursive(
                    item,
                    f"{parent_path}/{item.name}" if parent_path else item.name
                )
                plugin_dirs.extend(sub_plugins)

        return plugin_dirs

    def find_subplugins(self, plugin_dir: Path) -> List[Path]:
        """
        查找子插件目录

        Args:
            plugin_dir: 插件目录

        Returns:
            List[Path]: 子插件路径列表
        """
        subplugins = []

        for item in plugin_dir.iterdir():
            if not item.is_dir():
                continue

            # 子插件也应该有 plugin.py 或配置文件
            if (item / 'plugin.py').exists() or (item / 'plugin.json').exists():
                subplugins.append(item)

        return subplugins
