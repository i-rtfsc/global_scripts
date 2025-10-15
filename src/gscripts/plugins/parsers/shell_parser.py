"""
Shell 脚本解析器
解析 Shell 脚本中的函数和注释
"""

import re
from pathlib import Path
from typing import List

from ...core.logger import get_logger
from . import FunctionParser, FunctionInfo

logger = get_logger(tag="PLUGINS.PARSER.SHELL", name=__name__)


class ShellFunctionParser(FunctionParser):
    """
    Shell 函数解析器

    职责：
    - 解析 Shell 脚本
    - 提取函数定义和注释
    """

    def can_parse(self, file: Path) -> bool:
        """检查是否为 Shell 脚本"""
        return file.suffix == '.sh'

    async def parse(self, file: Path, plugin_name: str, subplugin_name: str = "") -> List[FunctionInfo]:
        """
        解析 Shell 脚本中的函数

        Args:
            file: Shell 脚本路径
            plugin_name: 插件名称
            subplugin_name: 子插件名称

        Returns:
            List[FunctionInfo]: 函数信息列表
        """
        functions = []

        try:
            with open(file, 'r', encoding='utf-8') as f:
                content = f.read()

            # 解析函数注释（特殊格式）
            annotated_functions = self._parse_annotated_functions(
                content,
                plugin_name,
                subplugin_name
            )
            functions.extend(annotated_functions)

            # 如果没有注释，尝试解析普通函数定义
            if not annotated_functions:
                simple_functions = self._parse_simple_functions(
                    content,
                    plugin_name,
                    subplugin_name
                )
                functions.extend(simple_functions)

        except Exception as e:
            logger.warning(f"Failed to parse Shell script {file}: {e}")

        return functions

    def _parse_annotated_functions(
        self,
        content: str,
        plugin_name: str,
        subplugin_name: str
    ) -> List[FunctionInfo]:
        """
        解析带注释的函数

        注释格式:
        # @gs-function: function_name
        # @gs-description: description text
        # @gs-command: command
        """
        functions = []

        # 查找注释块
        pattern = r'# @gs-function:\s*(\w+)\s*\n((?:# @gs-\w+:.*\n)*)'
        matches = re.finditer(pattern, content)

        for match in matches:
            func_name = match.group(1)
            annotations = match.group(2)

            # 提取描述
            desc_match = re.search(r'# @gs-description:\s*(.+)', annotations)
            description = desc_match.group(1) if desc_match else ''

            # 提取命令
            cmd_match = re.search(r'# @gs-command:\s*(.+)', annotations)
            command = cmd_match.group(1) if cmd_match else func_name

            functions.append(FunctionInfo(
                name=func_name,
                description=description.strip(),
                command=command.strip(),
                type='shell',
                plugin_name=plugin_name,
                subplugin_name=subplugin_name
            ))

        return functions

    def _parse_simple_functions(
        self,
        content: str,
        plugin_name: str,
        subplugin_name: str
    ) -> List[FunctionInfo]:
        """
        解析简单的函数定义

        格式: function_name() {
        """
        functions = []

        # 查找函数定义
        pattern = r'^(?:function\s+)?(\w+)\s*\(\)\s*\{'
        matches = re.finditer(pattern, content, re.MULTILINE)

        for match in matches:
            func_name = match.group(1)

            # 跳过内部函数（以 _ 开头）
            if func_name.startswith('_'):
                continue

            functions.append(FunctionInfo(
                name=func_name,
                description=f"Shell function: {func_name}",
                command=func_name,
                type='shell',
                plugin_name=plugin_name,
                subplugin_name=subplugin_name
            ))

        return functions
