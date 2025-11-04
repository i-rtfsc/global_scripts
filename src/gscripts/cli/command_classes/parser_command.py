"""
ParserCommand - 解析器管理命令
管理插件函数解析器的注册、启用、禁用等操作
"""

from typing import List
from pathlib import Path
import json

from ...core.logger import get_logger
from .base import Command
from gscripts.models.result import CommandResult
from ...plugins.loader import RefactoredPluginLoader

logger = get_logger(tag="CLI.PARSER", name=__name__)


class ParserCommand(Command):
    """解析器管理命令"""

    @property
    def name(self) -> str:
        return "parser"

    @property
    def aliases(self) -> List[str]:
        return []

    @property
    def help_text(self) -> str:
        return "Manage plugin parsers (list, info, enable, disable, test)"

    async def execute(self, args: List[str]) -> CommandResult:
        """执行解析器管理命令"""
        if not args:
            return self._show_usage()

        subcommand = args[0]
        remaining_args = args[1:]

        if subcommand == "list":
            return await self._list_parsers(remaining_args)
        elif subcommand == "info":
            return await self._parser_info(remaining_args)
        elif subcommand == "enable":
            return await self._enable_parser(remaining_args)
        elif subcommand == "disable":
            return await self._disable_parser(remaining_args)
        elif subcommand == "test":
            return await self._test_parser(remaining_args)
        else:
            return self._show_usage()

    def _show_usage(self) -> CommandResult:
        """显示使用帮助"""
        usage = """
Parser Management Commands:

  gs parser list              List all registered parsers
  gs parser info <name>       Show detailed parser information
  gs parser enable <name>     Enable a parser
  gs parser disable <name>    Disable a parser
  gs parser test <file>       Test which parser can handle a file

Examples:
  gs parser list
  gs parser info yaml
  gs parser enable yaml
  gs parser disable python
  gs parser test plugin.yaml
"""
        return CommandResult(success=True, output=usage)

    async def _list_parsers(self, args: List[str]) -> CommandResult:
        """列出所有已注册的解析器"""
        try:
            # 创建临时 loader 来访问 parser registry
            project_root = Path(__file__).resolve().parents[4]
            plugins_root = project_root / "plugins"

            # 加载配置
            config = self._load_parser_config()

            loader = RefactoredPluginLoader(plugins_root, parser_config=config)
            parsers = loader.parser_registry.list_parsers()

            if not parsers:
                return CommandResult(success=True, output="No parsers registered.")

            # 格式化输出使用 formatter
            headers = ["Name", "Priority", "Enabled", "Extensions", "Description"]
            rows = []

            for parser in parsers:
                name = parser["name"]
                priority = str(parser["priority"])
                enabled = "✓" if parser["enabled"] else "✗"
                extensions = ", ".join(parser.get("supported_extensions", [])) or "-"
                description = parser.get("description", "-")

                rows.append([name, priority, enabled, extensions, description])

            # 使用 formatter 格式化表格
            from ...cli.formatters import ChineseFormatter

            table = ChineseFormatter.format_table(headers, rows)
            output = f"Registered Parsers:\n\n{table}"

            return CommandResult(success=True, output=output)

        except Exception as e:
            logger.error(f"Failed to list parsers: {e}")
            return CommandResult(
                success=False,
                error=f"Failed to list parsers: {e}",
                exit_code=self.constants.exit_execution_error,
            )

    async def _parser_info(self, args: List[str]) -> CommandResult:
        """显示解析器详细信息"""
        if not args:
            return CommandResult(
                success=False,
                error="Usage: gs parser info <parser_name>",
                exit_code=self.constants.exit_invalid_arguments,
            )

        parser_name = args[0]

        try:
            # 创建临时 loader
            project_root = Path(__file__).resolve().parents[4]
            plugins_root = project_root / "plugins"
            config = self._load_parser_config()

            loader = RefactoredPluginLoader(plugins_root, parser_config=config)
            info = loader.parser_registry.get_parser_info(parser_name)

            if not info:
                return CommandResult(
                    success=False,
                    error=f"Parser '{parser_name}' not found.",
                    exit_code=self.constants.exit_execution_error,
                )

            # 使用 formatter 格式化信息表格
            from ...cli.formatters import ChineseFormatter

            # 准备数据字典
            data = {
                "Name": info["name"],
                "Class": info["class"],
                "Priority": str(info["priority"]),
                "Enabled": "Yes" if info["enabled"] else "No",
            }

            if "version" in info and info["version"]:
                data["Version"] = info["version"]

            if "supported_extensions" in info and info["supported_extensions"]:
                data["Extensions"] = ", ".join(info["supported_extensions"])

            if "description" in info and info["description"]:
                data["Description"] = info["description"]

            # 使用 format_info_table 格式化
            table = ChineseFormatter.format_info_table(data)
            output = f"Parser Information\n\n{table}"

            return CommandResult(success=True, output=output)

        except Exception as e:
            logger.error(f"Failed to get parser info: {e}")
            return CommandResult(
                success=False,
                error=f"Failed to get parser info: {e}",
                exit_code=self.constants.exit_execution_error,
            )

    async def _enable_parser(self, args: List[str]) -> CommandResult:
        """启用解析器"""
        if not args:
            return CommandResult(
                success=False,
                error="Usage: gs parser enable <parser_name>",
                exit_code=self.constants.exit_invalid_arguments,
            )

        parser_name = args[0]

        try:
            # 更新配置文件
            config_path = self._get_config_path()
            config = self._load_config(config_path)

            if "parsers" not in config:
                config["parsers"] = {}

            # 从禁用列表移除
            disabled = config["parsers"].get("disabled", [])
            if parser_name in disabled:
                disabled.remove(parser_name)
                config["parsers"]["disabled"] = disabled

            # 添加到启用列表（如果不存在）
            enabled = config["parsers"].get("enabled", [])
            if parser_name not in enabled:
                enabled.append(parser_name)
                config["parsers"]["enabled"] = enabled

            # 保存配置
            self._save_config(config_path, config)

            return CommandResult(
                success=True,
                output=f"Parser '{parser_name}' has been enabled.\nRun 'gs refresh' to apply changes.",
            )

        except Exception as e:
            logger.error(f"Failed to enable parser: {e}")
            return CommandResult(
                success=False,
                error=f"Failed to enable parser: {e}",
                exit_code=self.constants.exit_execution_error,
            )

    async def _disable_parser(self, args: List[str]) -> CommandResult:
        """禁用解析器"""
        if not args:
            return CommandResult(
                success=False,
                error="Usage: gs parser disable <parser_name>",
                exit_code=self.constants.exit_invalid_arguments,
            )

        parser_name = args[0]

        try:
            # 更新配置文件
            config_path = self._get_config_path()
            config = self._load_config(config_path)

            if "parsers" not in config:
                config["parsers"] = {}

            # 添加到禁用列表
            disabled = config["parsers"].get("disabled", [])
            if parser_name not in disabled:
                disabled.append(parser_name)
                config["parsers"]["disabled"] = disabled

            # 从启用列表移除
            enabled = config["parsers"].get("enabled", [])
            if parser_name in enabled:
                enabled.remove(parser_name)
                config["parsers"]["enabled"] = enabled

            # 保存配置
            self._save_config(config_path, config)

            return CommandResult(
                success=True,
                output=f"Parser '{parser_name}' has been disabled.\nRun 'gs refresh' to apply changes.",
            )

        except Exception as e:
            logger.error(f"Failed to disable parser: {e}")
            return CommandResult(
                success=False,
                error=f"Failed to disable parser: {e}",
                exit_code=self.constants.exit_execution_error,
            )

    async def _test_parser(self, args: List[str]) -> CommandResult:
        """测试哪个解析器可以处理指定文件"""
        if not args:
            return CommandResult(
                success=False,
                error="Usage: gs parser test <file_path>",
                exit_code=self.constants.exit_invalid_arguments,
            )

        file_path = Path(args[0])

        if not file_path.exists():
            return CommandResult(
                success=False,
                error=f"File not found: {file_path}",
                exit_code=self.constants.exit_execution_error,
            )

        try:
            # 创建临时 loader
            project_root = Path(__file__).resolve().parents[4]
            plugins_root = project_root / "plugins"
            config = self._load_parser_config()

            loader = RefactoredPluginLoader(plugins_root, parser_config=config)

            # 尝试获取解析器
            try:
                parser = loader.parser_registry.get_parser(file_path)
                parser_name = parser.__class__.__name__
                metadata = parser.metadata

                output_lines = [f"File: {file_path}", ""]
                output_lines.append(f"✓ Can be parsed by: {parser_name}")

                if metadata:
                    output_lines.append(f"  Parser:      {metadata.name}")
                    output_lines.append(f"  Priority:    {metadata.priority}")
                    output_lines.append(
                        f"  Extensions:  {', '.join(metadata.supported_extensions)}"
                    )
                    output_lines.append(f"  Description: {metadata.description}")

                return CommandResult(success=True, output="\n".join(output_lines))

            except ValueError as e:
                return CommandResult(
                    success=False,
                    error=f"No parser found for file: {file_path}\n{e}",
                    exit_code=self.constants.exit_execution_error,
                )

        except Exception as e:
            logger.error(f"Failed to test parser: {e}")
            return CommandResult(
                success=False,
                error=f"Failed to test parser: {e}",
                exit_code=self.constants.exit_execution_error,
            )

    def _get_config_path(self) -> Path:
        """获取配置文件路径"""
        project_root = Path(__file__).resolve().parents[4]
        return project_root / "config" / "gs.json"

    def _load_config(self, config_path: Path) -> dict:
        """加载配置文件"""
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save_config(self, config_path: Path, config: dict) -> None:
        """保存配置文件"""
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4, ensure_ascii=False)

    def _load_parser_config(self) -> dict:
        """加载解析器配置"""
        try:
            config_path = self._get_config_path()
            config = self._load_config(config_path)
            return config.get("parsers", {})
        except Exception:
            return {}
