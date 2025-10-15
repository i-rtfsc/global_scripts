"""
YAML Parser Example for Global Scripts
演示如何创建第三方解析器扩展

This is a complete example showing how to:
1. Create a custom parser for YAML-based plugin definitions
2. Use the @parser_metadata decorator
3. Implement the FunctionParser interface
4. Package as a separate installable extension
"""

from pathlib import Path
from typing import List
import yaml

from gscripts.plugins.parsers import (
    FunctionParser,
    FunctionInfo,
    parser_metadata
)


@parser_metadata(
    name="yaml",
    version="1.0.0",
    supported_extensions=[".yaml", ".yml"],
    priority=100,
    description="YAML configuration parser for plugin definitions"
)
class YAMLFunctionParser(FunctionParser):
    """
    YAML 解析器 - 解析 YAML 格式的插件定义

    支持的 YAML 格式:
    ```yaml
    functions:
      - name: hello
        description: Say hello
        command: echo "Hello, World!"
        type: shell
        args:
          - name
        options:
          greeting:
            description: Custom greeting
            default: Hello
        examples:
          - hello world
          - hello --greeting=Hi world

      - name: goodbye
        description: Say goodbye
        command: echo "Goodbye!"
        type: shell
    ```
    """

    def can_parse(self, file: Path) -> bool:
        """
        检查是否能解析该文件

        Args:
            file: 文件路径

        Returns:
            bool: 如果文件扩展名是 .yaml 或 .yml 返回 True
        """
        return file.suffix.lower() in ['.yaml', '.yml']

    async def parse(
        self,
        file: Path,
        plugin_name: str,
        subplugin_name: str = ""
    ) -> List[FunctionInfo]:
        """
        解析 YAML 文件中的函数定义

        Args:
            file: YAML 文件路径
            plugin_name: 插件名称
            subplugin_name: 子插件名称

        Returns:
            List[FunctionInfo]: 函数信息列表
        """
        functions = []

        try:
            # 读取 YAML 文件
            with open(file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            if not data or 'functions' not in data:
                return functions

            # 解析每个函数定义
            for func_data in data['functions']:
                if not isinstance(func_data, dict):
                    continue

                # 必需字段
                name = func_data.get('name')
                description = func_data.get('description', '')
                command = func_data.get('command', '')
                func_type = func_data.get('type', 'shell')

                if not name:
                    continue

                # 可选字段
                args = func_data.get('args', [])
                options = func_data.get('options', {})
                examples = func_data.get('examples', [])

                # 创建 FunctionInfo
                function_info = FunctionInfo(
                    name=name,
                    description=description,
                    command=command,
                    type=func_type,
                    args=args if isinstance(args, list) else [],
                    options=options if isinstance(options, dict) else {},
                    examples=examples if isinstance(examples, list) else [],
                    plugin_name=plugin_name,
                    subplugin_name=subplugin_name
                )

                functions.append(function_info)

        except yaml.YAMLError as e:
            # YAML 解析错误
            print(f"Error parsing YAML file {file}: {e}")
        except Exception as e:
            # 其他错误
            print(f"Error processing {file}: {e}")

        return functions


# 使用示例
if __name__ == "__main__":
    import asyncio

    async def test_parser():
        parser = YAMLFunctionParser()

        # 测试文件
        test_file = Path(__file__).parent / "example_plugin.yaml"

        if test_file.exists():
            functions = await parser.parse(test_file, "example_plugin")

            print(f"Found {len(functions)} functions:")
            for func in functions:
                print(f"  - {func.name}: {func.description}")
        else:
            print(f"Test file not found: {test_file}")

    asyncio.run(test_parser())
