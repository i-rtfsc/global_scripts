"""
插件验证模块
负责验证插件的有效性和合法性
符合单一职责原则
"""

from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass


@dataclass
class ValidationResult:
    """验证结果"""
    is_valid: bool
    error_message: Optional[str] = None
    warnings: list = None

    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []


class PluginValidator:
    """
    插件验证类

    职责：
    - 验证插件目录结构
    - 验证插件元数据
    - 验证依赖关系
    """

    def __init__(self):
        """初始化插件验证器"""
        pass

    def validate_plugin_directory(self, plugin_dir: Path) -> ValidationResult:
        """
        验证插件目录

        Args:
            plugin_dir: 插件目录路径

        Returns:
            ValidationResult: 验证结果
        """
        # 检查目录存在性
        if not plugin_dir.exists():
            return ValidationResult(
                is_valid=False,
                error_message=f"Plugin directory does not exist: {plugin_dir}"
            )

        if not plugin_dir.is_dir():
            return ValidationResult(
                is_valid=False,
                error_message=f"Not a directory: {plugin_dir}"
            )

        # 检查是否有必要的文件（plugin.json 或 plugin.py）
        has_json = (plugin_dir / 'plugin.json').exists()
        has_py = (plugin_dir / 'plugin.py').exists()

        if not (has_json or has_py):
            return ValidationResult(
                is_valid=False,
                error_message="Plugin must have either plugin.json or plugin.py"
            )

        return ValidationResult(is_valid=True)

    def validate_plugin_metadata(
        self,
        metadata: Dict[str, Any],
        plugin_name: str
    ) -> ValidationResult:
        """
        验证插件元数据

        Args:
            metadata: 插件元数据（来自 plugin.json）
            plugin_name: 插件名称

        Returns:
            ValidationResult: 验证结果
        """
        result = ValidationResult(is_valid=True)

        # 检查必需字段
        required_fields = ['name', 'version']
        for field in required_fields:
            if field not in metadata:
                result.warnings.append(f"Missing required field: {field}")

        # 验证名称一致性
        if 'name' in metadata and metadata['name'] != plugin_name:
            result.warnings.append(
                f"Plugin name mismatch: directory='{plugin_name}', "
                f"metadata='{metadata['name']}'"
            )

        # 验证版本格式
        if 'version' in metadata:
            version = metadata['version']
            if not isinstance(version, str):
                result.warnings.append(f"Invalid version type: {type(version)}")

        # 验证描述
        if 'description' in metadata:
            desc = metadata['description']
            if isinstance(desc, dict):
                # 多语言描述
                if 'zh' not in desc and 'en' not in desc:
                    result.warnings.append("Description should have 'zh' or 'en' key")
            elif not isinstance(desc, str):
                result.warnings.append(f"Invalid description type: {type(desc)}")

        # 验证优先级
        if 'priority' in metadata:
            priority = metadata['priority']
            if not isinstance(priority, (int, float)):
                result.warnings.append(f"Invalid priority type: {type(priority)}")
            elif not (1 <= priority <= 100):
                result.warnings.append(f"Priority should be 1-100, got: {priority}")

        return result

    def validate_dependencies(
        self,
        requirements: Dict[str, list],
        plugin_name: str
    ) -> ValidationResult:
        """
        验证插件依赖

        Args:
            requirements: 依赖配置
            plugin_name: 插件名称

        Returns:
            ValidationResult: 验证结果
        """
        result = ValidationResult(is_valid=True)

        if not isinstance(requirements, dict):
            return ValidationResult(
                is_valid=False,
                error_message="Requirements must be a dictionary"
            )

        # 验证系统依赖
        if 'system' in requirements:
            system_deps = requirements['system']
            if not isinstance(system_deps, list):
                result.warnings.append("System dependencies should be a list")
            else:
                # 检查每个系统依赖是否为字符串
                for dep in system_deps:
                    if not isinstance(dep, str):
                        result.warnings.append(f"Invalid system dependency: {dep}")

        # 验证 Python 依赖
        if 'python' in requirements:
            python_deps = requirements['python']
            if not isinstance(python_deps, list):
                result.warnings.append("Python dependencies should be a list")
            else:
                for dep in python_deps:
                    if not isinstance(dep, str):
                        result.warnings.append(f"Invalid Python dependency: {dep}")

        return result

    def validate_plugin_config(
        self,
        plugin_json_path: Path
    ) -> ValidationResult:
        """
        验证 plugin.json 配置文件

        Args:
            plugin_json_path: plugin.json 文件路径

        Returns:
            ValidationResult: 验证结果
        """
        import json

        # 检查文件存在
        if not plugin_json_path.exists():
            return ValidationResult(
                is_valid=False,
                error_message=f"Config file not found: {plugin_json_path}"
            )

        # 检查 JSON 格式
        try:
            with open(plugin_json_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
        except json.JSONDecodeError as e:
            return ValidationResult(
                is_valid=False,
                error_message=f"Invalid JSON format: {e}"
            )
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                error_message=f"Failed to read config: {e}"
            )

        # 验证配置内容
        if not isinstance(config, dict):
            return ValidationResult(
                is_valid=False,
                error_message="Plugin config must be a JSON object"
            )

        plugin_name = plugin_json_path.parent.name
        return self.validate_plugin_metadata(config, plugin_name)

    def validate_python_plugin(self, python_file: Path) -> ValidationResult:
        """
        验证 Python 插件文件

        Args:
            python_file: plugin.py 文件路径

        Returns:
            ValidationResult: 验证结果
        """
        result = ValidationResult(is_valid=True)

        # 检查文件存在
        if not python_file.exists():
            return ValidationResult(
                is_valid=False,
                error_message=f"Python file not found: {python_file}"
            )

        # 检查文件大小（避免加载过大文件）
        file_size = python_file.stat().st_size
        max_size = 10 * 1024 * 1024  # 10MB
        if file_size > max_size:
            result.warnings.append(
                f"Large Python file ({file_size} bytes), may slow down loading"
            )

        # 简单的语法检查（不导入模块）
        try:
            with open(python_file, 'r', encoding='utf-8') as f:
                content = f.read()

            # 使用 compile 检查语法
            compile(content, str(python_file), 'exec')
        except SyntaxError as e:
            return ValidationResult(
                is_valid=False,
                error_message=f"Python syntax error: {e}"
            )
        except Exception as e:
            result.warnings.append(f"Failed to validate Python file: {e}")

        return result

    def validate_shell_script(self, script_file: Path) -> ValidationResult:
        """
        验证 Shell 脚本文件

        Args:
            script_file: Shell 脚本路径

        Returns:
            ValidationResult: 验证结果
        """
        result = ValidationResult(is_valid=True)

        # 检查文件存在
        if not script_file.exists():
            return ValidationResult(
                is_valid=False,
                error_message=f"Script file not found: {script_file}"
            )

        # 检查文件扩展名
        if not script_file.name.endswith('.sh'):
            result.warnings.append(
                f"Script file should have .sh extension: {script_file.name}"
            )

        # 检查 shebang
        try:
            with open(script_file, 'r', encoding='utf-8') as f:
                first_line = f.readline().strip()

            if not first_line.startswith('#!'):
                result.warnings.append("Missing shebang line (#!/bin/bash)")
        except Exception as e:
            result.warnings.append(f"Failed to read script: {e}")

        return result
