"""
插件基类系统
支持多种插件类型和执行方式
"""

import asyncio
import shlex
import json
from abc import ABC
from pathlib import Path
from typing import Dict, List, Optional, Any, Union


from ..core.logger import get_logger

# Module-level logger
logger = get_logger(tag="PLUGINS.BASE", name=__name__)

# Import CommandResult from the standard location to avoid duplication
from gscripts.models.result import CommandResult


class BasePlugin(ABC):
    """子插件基类"""

    def __init__(self, name: str):
        self.name = name
        self.functions = {}
        self._discover_functions()

    def _discover_functions(self):
        """自动发现插件函数"""
        for attr_name in dir(self):
            attr = getattr(self, attr_name)
            if hasattr(attr, "_is_plugin_function"):
                func_name = attr._plugin_metadata.name
                self.functions[func_name] = attr._plugin_metadata

    async def execute_function(
        self, func_name: str, args: List[str] = None
    ) -> CommandResult:
        """执行子插件的特定函数"""
        if func_name not in self.functions:
            from gscripts.utils.i18n import I18nManager

            i18n = I18nManager()
            return CommandResult(
                False,
                error=i18n.get_message(
                    "errors.function_not_found", function=func_name, subplugin=self.name
                ),
            )

        # 获取实际的函数对象
        method = getattr(self, func_name.replace("-", "_"))
        if not method:
            # 尝试查找带下划线的函数名
            for attr_name in dir(self):
                attr = getattr(self, attr_name)
                if (
                    hasattr(attr, "_plugin_metadata")
                    and attr._plugin_metadata.name == func_name
                ):
                    method = attr
                    break

        if not method:
            from gscripts.utils.i18n import I18nManager

            i18n = I18nManager()
            return CommandResult(
                False,
                error=i18n.get_message(
                    "errors.function_not_found", function=func_name, subplugin=self.name
                ),
            )

        # 执行函数
        try:
            if asyncio.iscoroutinefunction(method):
                return await method(args or [])
            else:
                return method(args or [])
        except Exception as e:
            from gscripts.utils.i18n import I18nManager

            i18n = I18nManager()
            return CommandResult(
                False, error=i18n.get_message("errors.execution_failed", error=str(e))
            )

    async def run_shell_command(
        self, command: Union[str, List[str]], timeout: int = 30
    ) -> CommandResult:
        """执行shell命令 - 使用统一的ProcessExecutor"""
        from ..utils.process_executor import get_process_executor

        try:
            executor = get_process_executor()

            if isinstance(command, list):
                # 列表形式的命令
                result = await executor.execute(command, timeout=timeout)
            else:
                # 字符串命令
                result = await executor.execute_shell(command, timeout=timeout)

            # 确保向后兼容
            result.stdout = result.output
            result.stderr = result.error
            return result

        except Exception as e:
            return CommandResult(False, error=str(e))

    def list_functions(self) -> Dict[str, str]:
        """列出所有可用函数"""
        return {name: info.description for name, info in self.functions.items()}


class ConfigFileSubPlugin(BasePlugin):
    """基于配置文件的子插件"""

    def __init__(self, name: str, config_path: Path):
        self.config_path = config_path
        self.config = self._load_config()
        super().__init__(name)

    def _load_config(self) -> Dict[str, Any]:
        """加载配置文件"""
        if not self.config_path.exists():
            return {}

        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                if self.config_path.suffix.lower() == ".json":
                    return json.load(f)
                else:
                    return {}
        except Exception as e:
            logger.warning(f"加载配置文件失败 {self.config_path}: {e}")
            return {}

    def _discover_functions(self):
        """从配置文件发现函数"""
        functions_config = self.config.get("functions", {})

        for func_name, func_config in functions_config.items():
            if isinstance(func_config, str):
                # 简单字符串配置
                command_template = func_config
                description = f"执行命令: {command_template}"
            elif isinstance(func_config, dict):
                # 详细配置
                command_template = func_config.get("command", "")
                description = func_config.get(
                    "description", f"执行命令: {command_template}"
                )
            else:
                continue

            # 创建动态函数
            async def dynamic_function(
                args: List[str] = None, template=command_template
            ):
                command = self._build_command(template, args or [])
                return await self.run_shell_command(command)

            # 添加到函数字典
            from .decorators import FunctionMetadata

            metadata = FunctionMetadata(
                name=func_name,
                description=description,
                usage=f"gs-{{plugin}}-{self.name}-{func_name}",
                async_func=True,
            )

            dynamic_function._plugin_metadata = metadata
            dynamic_function._is_plugin_function = True

            setattr(self, func_name.replace("-", "_"), dynamic_function)
            self.functions[func_name] = metadata

    def _build_command(self, template: str, args: List[str]) -> str:
        """构建命令，支持参数替换"""
        if "{args}" in template:
            args_str = " ".join(shlex.quote(arg) for arg in args)
            return template.replace("{args}", args_str)
        elif args:
            return f"{template} {' '.join(shlex.quote(arg) for arg in args)}"
        else:
            return template


class ShellScriptSubPlugin(BasePlugin):
    """基于Shell脚本的子插件"""

    def __init__(self, name: str, script_dir: Path):
        self.script_dir = script_dir
        super().__init__(name)

    def _discover_functions(self):
        """发现Shell脚本函数"""
        if not self.script_dir.exists():
            return

        for script_file in self.script_dir.glob("*.sh"):
            func_name = script_file.stem

            # 创建执行脚本的函数
            async def script_function(args: List[str] = None, script_path=script_file):
                command = ["bash", str(script_path)] + (args or [])
                return await self.run_shell_command(command)

            from .decorators import FunctionMetadata

            metadata = FunctionMetadata(
                name=func_name,
                description=f"执行脚本: {script_file.name}",
                usage=f"gs-{{plugin}}-{self.name}-{func_name}",
                async_func=True,
            )

            script_function._plugin_metadata = metadata
            script_function._is_plugin_function = True

            setattr(self, func_name.replace("-", "_"), script_function)
            self.functions[func_name] = metadata


class Plugin:
    """主插件类"""

    def __init__(self, name: str, version: str = "1.0.0", author: str = ""):
        self.name = name
        self.version = version
        self.author = author
        self.sub_plugins: Dict[str, BasePlugin] = {}
        self.enabled = True
        self.priority = 10

    def register_sub_plugin(self, sub_plugin: BasePlugin):
        """注册子插件"""
        self.sub_plugins[sub_plugin.name] = sub_plugin

    def get_sub_plugin(self, name: str) -> Optional[BasePlugin]:
        """获取子插件"""
        return self.sub_plugins.get(name)

    def list_sub_plugins(self) -> List[str]:
        """列出子插件名称"""
        return list(self.sub_plugins.keys())

    async def execute(
        self, sub_plugin_name: str, func_name: str, args: List[str] = None
    ) -> CommandResult:
        """执行插件下的子插件函数"""
        sub_plugin = self.get_sub_plugin(sub_plugin_name)
        if not sub_plugin:
            return CommandResult(
                False, error=f"子插件 '{sub_plugin_name}' 不存在于 {self.name}"
            )

        return await sub_plugin.execute_function(func_name, args)

    def get_plugin_info(self) -> Dict[str, Any]:
        """获取插件信息"""
        total_functions = sum(len(sp.functions) for sp in self.sub_plugins.values())

        return {
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "enabled": self.enabled,
            "priority": self.priority,
            "sub_plugins": len(self.sub_plugins),
            "total_functions": total_functions,
            "sub_plugin_list": list(self.sub_plugins.keys()),
        }
