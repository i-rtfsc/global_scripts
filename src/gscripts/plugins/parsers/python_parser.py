"""
Python 函数解析器
解析 Python 文件中带有装饰器的函数
"""

import re
import ast
from pathlib import Path
from typing import List

from ...core.logger import get_logger
from ...models.plugin import FunctionType
from ...models.function import FunctionInfo
from . import FunctionParser

logger = get_logger(tag="PLUGINS.PARSER.PYTHON", name=__name__)


class PythonFunctionParser(FunctionParser):
    """
    Python 函数解析器

    职责：
    - 解析 Python 文件
    - 提取带有 @plugin_function 装饰器的函数
    """

    def can_parse(self, file: Path) -> bool:
        """检查是否为 Python 文件"""
        return file.suffix == ".py"

    async def parse(
        self, file: Path, plugin_name: str, subplugin_name: str = ""
    ) -> List[FunctionInfo]:
        """
        解析 Python 文件中的函数

        Args:
            file: Python 文件路径
            plugin_name: 插件名称
            subplugin_name: 子插件名称

        Returns:
            List[FunctionInfo]: 函数信息列表
        """
        functions = []

        try:
            with open(file, "r", encoding="utf-8") as f:
                content = f.read()

            # 使用正则表达式查找装饰器
            pattern = r"@plugin_function\((.*?)\)\s*(?:async\s+)?def\s+(\w+)"
            matches = re.finditer(pattern, content, re.DOTALL)

            for match in matches:
                decorator_content = match.group(1)
                func_name = match.group(2)

                # 解析装饰器参数
                func_info = self._parse_decorator(
                    decorator_content,
                    func_name,
                    plugin_name,
                    subplugin_name,
                    file,  # Pass file path
                )

                if func_info:
                    functions.append(func_info)

        except Exception as e:
            logger.warning(f"Failed to parse Python file {file}: {e}")

        return functions

    def _parse_decorator(
        self,
        decorator_content: str,
        func_name: str,
        plugin_name: str,
        subplugin_name: str,
        file: Path,
    ) -> FunctionInfo:
        """
        解析装饰器参数

        Args:
            decorator_content: 装饰器内容
            func_name: 函数名称
            plugin_name: 插件名称
            subplugin_name: 子插件名称
            file: Python file path

        Returns:
            FunctionInfo: 函数信息
        """
        # 尝试使用 AST 解析
        try:
            # 构造一个完整的函数调用表达式
            expr = f"f({decorator_content})"
            tree = ast.parse(expr, mode="eval")

            # 提取关键字参数
            call = tree.body
            kwargs = {}

            for keyword in call.keywords:
                key = keyword.arg
                value = ast.literal_eval(keyword.value)
                kwargs[key] = value

            # 构建 FunctionInfo
            description = kwargs.get("description", {})
            if isinstance(description, str):
                description = {"en": description}

            return FunctionInfo(
                name=kwargs.get("name", func_name),
                description=description.get("zh", description.get("en", "")),
                command=kwargs.get("command", func_name),
                type=FunctionType.PYTHON,
                subplugin=subplugin_name,
                examples=kwargs.get("examples", []),
                python_file=file,
                method=func_name,  # Set the actual Python method name
            )

        except Exception:
            # 如果 AST 解析失败，使用简单的正则提取
            return self._parse_decorator_simple(
                decorator_content,
                func_name,
                plugin_name,
                subplugin_name,
                file,  # Pass file to simple parser
            )

    def _parse_decorator_simple(
        self,
        decorator_content: str,
        func_name: str,
        plugin_name: str,
        subplugin_name: str,
        file: Path,
    ) -> FunctionInfo:
        """
        简单的装饰器解析（正则表达式）

        Args:
            decorator_content: 装饰器内容
            func_name: 函数名称
            plugin_name: 插件名称
            subplugin_name: 子插件名称
            file: Python file path

        Returns:
            FunctionInfo: 函数信息
        """
        # 提取 name
        name_match = re.search(r'name\s*=\s*["\'](.+?)["\']', decorator_content)
        name = name_match.group(1) if name_match else func_name

        # 提取 description
        desc_match = re.search(r'description\s*=\s*["\'](.+?)["\']', decorator_content)
        description = desc_match.group(1) if desc_match else ""

        # 提取 command
        cmd_match = re.search(r'command\s*=\s*["\'](.+?)["\']', decorator_content)
        command = cmd_match.group(1) if cmd_match else func_name

        return FunctionInfo(
            name=name,
            description=description,
            command=command,
            type=FunctionType.PYTHON,
            subplugin=subplugin_name,
            python_file=file,  # Set python_file
            method=func_name,  # Set the actual Python method name
        )
