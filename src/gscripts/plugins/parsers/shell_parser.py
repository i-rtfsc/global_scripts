"""
Shell 脚本解析器
解析 Shell 脚本中的函数和注释
"""

import re
from pathlib import Path
from typing import List

from ...core.logger import get_logger
from ...models.function import FunctionInfo
from ...models.plugin import FunctionType
from . import FunctionParser

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
        return file.suffix == ".sh"

    async def parse(
        self, file: Path, plugin_name: str, subplugin_name: str = ""
    ) -> List[FunctionInfo]:
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
            with open(file, "r", encoding="utf-8") as f:
                content = f.read()

            # 解析函数注释（特殊格式）
            annotated_functions = self._parse_annotated_functions(
                content, plugin_name, subplugin_name, file
            )

            if annotated_functions:
                # 如果有带注释的函数，只返回这些函数
                functions.extend(annotated_functions)
            else:
                # 如果没有注释，将整个脚本作为一个命令
                # 命令名从文件路径派生：<parent_dir>-<filename_without_ext>
                parent_dir = file.parent.name
                file_stem = file.stem

                # For scripts in subdirectories (e.g., alias/common/aliases.sh)
                # Command name should be "common-aliases"
                if parent_dir and parent_dir != plugin_name:
                    command_name = f"{parent_dir}-{file_stem}"
                else:
                    command_name = file_stem

                functions.append(
                    FunctionInfo(
                        name=command_name,
                        description=f"Execute script: {file.name}",
                        command="",
                        type=FunctionType.SHELL,
                        subplugin=subplugin_name,
                        script_file=file,
                        usage="",
                    )
                )

        except Exception as e:
            logger.warning(f"Failed to parse Shell script {file}: {e}")

        return functions

    def _parse_annotated_functions(
        self, content: str, plugin_name: str, subplugin_name: str, file: Path = None
    ) -> List[FunctionInfo]:
        """
        解析带注释的函数

        注释格式:
        # @plugin_function
        # name: function_name
        # description:
        #   zh: 中文描述
        #   en: English description
        # usage: gs plugin subplugin function
        """
        functions = []

        # 查找 @plugin_function 注释块
        pattern = r"# @plugin_function\s*\n((?:#.*\n)*?)(\w+)\(\)"
        matches = re.finditer(pattern, content, re.MULTILINE)

        for match in matches:
            annotations = match.group(1)
            raw_func_name = match.group(2)

            # 提取 name
            name_match = re.search(r"# name:\s*(.+)", annotations)
            func_name = name_match.group(1).strip() if name_match else None

            # 提取多语言描述
            description = {}
            desc_section = re.search(
                r"# description:\s*\n((?:#\s+\w+:.*\n)*)", annotations
            )
            if desc_section:
                desc_lines = desc_section.group(1)
                zh_match = re.search(r"#\s+zh:\s*(.+)", desc_lines)
                en_match = re.search(r"#\s+en:\s*(.+)", desc_lines)
                if zh_match:
                    description["zh"] = zh_match.group(1).strip()
                if en_match:
                    description["en"] = en_match.group(1).strip()

            # 提取 usage
            usage_match = re.search(r"# usage:\s*(.+)", annotations)
            usage = usage_match.group(1).strip() if usage_match else ""

            # 从 raw_func_name 解析 subplugin
            # 格式: gs_{plugin}_{subplugin}_{function} 或 gs_{plugin}_{function}
            parts = raw_func_name.split("_")
            detected_subplugin = ""

            if len(parts) >= 4 and parts[0] == "gs":
                # Format: gs_plugin_subplugin_function
                detected_plugin = parts[1]
                if detected_plugin == plugin_name:
                    # Extract subplugin from parts[2]
                    detected_subplugin = parts[2]
                    # If func_name not explicitly set, use the last part
                    if not func_name:
                        func_name = "_".join(parts[3:])
            elif len(parts) >= 3 and parts[0] == "gs":
                # Format: gs_plugin_function (no subplugin)
                if not func_name:
                    func_name = "_".join(parts[2:])

            # Override with passed subplugin_name if available
            if subplugin_name:
                detected_subplugin = subplugin_name

            # If func_name still not set, use raw_func_name
            if not func_name:
                func_name = raw_func_name

            functions.append(
                FunctionInfo(
                    name=func_name,
                    description=description if description else "",
                    command="",
                    type=FunctionType.SHELL,
                    subplugin=detected_subplugin,
                    script_file=file,
                    usage=usage,
                )
            )

        return functions

    def _parse_simple_functions(
        self, content: str, plugin_name: str, subplugin_name: str, file: Path = None
    ) -> List[FunctionInfo]:
        """
        解析简单的函数定义

        格式: function_name() {
        """
        functions = []

        # 查找函数定义
        pattern = r"^(?:function\s+)?(\w+)\s*\(\)\s*\{"
        matches = re.finditer(pattern, content, re.MULTILINE)

        for match in matches:
            func_name = match.group(1)

            # 跳过内部函数（以 _ 开头）
            if func_name.startswith("_"):
                continue

            functions.append(
                FunctionInfo(
                    name=func_name,
                    description=f"Shell function: {func_name}",
                    command=func_name,
                    type=FunctionType.SHELL,
                    subplugin=subplugin_name,
                    script_file=file,
                )
            )

        return functions
