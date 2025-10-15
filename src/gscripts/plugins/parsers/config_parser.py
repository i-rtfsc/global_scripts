"""
配置文件解析器
解析 plugin.json 中定义的命令
"""

import json
from pathlib import Path
from typing import List

from ...core.logger import get_logger
from . import FunctionParser, FunctionInfo

logger = get_logger(tag="PLUGINS.PARSER.CONFIG", name=__name__)


class ConfigFunctionParser(FunctionParser):
    """
    配置函数解析器

    职责：
    - 解析 plugin.json 文件
    - 提取 commands 定义的函数
    """

    def can_parse(self, file: Path) -> bool:
        """检查是否为 JSON 配置文件"""
        return file.suffix == '.json' and file.name == 'plugin.json'

    async def parse(self, file: Path, plugin_name: str, subplugin_name: str = "") -> List[FunctionInfo]:
        """
        解析配置文件中的函数

        Args:
            file: plugin.json 文件路径
            plugin_name: 插件名称
            subplugin_name: 子插件名称

        Returns:
            List[FunctionInfo]: 函数信息列表
        """
        functions = []

        try:
            with open(file, 'r', encoding='utf-8') as f:
                config = json.load(f)

            # 提取 commands 定义
            commands = config.get('commands', {})

            for cmd_key, cmd_info in commands.items():
                if not isinstance(cmd_info, dict):
                    continue

                # 提取命令信息
                func_info = self._parse_command_config(
                    cmd_key,
                    cmd_info,
                    plugin_name,
                    subplugin_name
                )

                if func_info:
                    functions.append(func_info)

        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON in {file}: {e}")
        except Exception as e:
            logger.warning(f"Failed to parse config file {file}: {e}")

        return functions

    def _parse_command_config(
        self,
        cmd_key: str,
        cmd_info: dict,
        plugin_name: str,
        subplugin_name: str
    ) -> FunctionInfo:
        """
        解析单个命令配置

        Args:
            cmd_key: 命令键名
            cmd_info: 命令信息字典
            plugin_name: 插件名称
            subplugin_name: 子插件名称

        Returns:
            FunctionInfo: 函数信息
        """
        # 提取描述
        description = cmd_info.get('description', '')
        if isinstance(description, dict):
            # 多语言描述
            description = description.get('zh', description.get('en', ''))

        # 提取命令
        command = cmd_info.get('command', cmd_key)

        # 提取类型
        cmd_type = cmd_info.get('kind', 'config')

        return FunctionInfo(
            name=cmd_key,
            description=description,
            command=command,
            type=cmd_type,
            args=cmd_info.get('args', []),
            options=cmd_info.get('options', {}),
            examples=cmd_info.get('examples', []),
            plugin_name=plugin_name,
            subplugin_name=subplugin_name
        )
