#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Global Scripts - 输出格式化器
支持中文显示和表格格式化输出
"""
import sys
import os
from typing import List, Dict, Any, Optional, Union
from datetime import datetime
import textwrap

from ..utils.rich_table import RichTableFormatter
from ..utils.color_helpers import get_color_helper
from rich.console import Console, Group
from rich.text import Text
from rich.rule import Rule
from rich.panel import Panel
from rich.table import Table
from rich import box
from ..utils.i18n import get_i18n_manager, t
from ..core.constants import GlobalConstants



from ..core.logger import get_logger
from ..utils.logging_utils import (
    redact, redact_kv, redact_command, ctx, correlation_id, 
    duration, trunc, sanitize_path, format_size, safe_repr,
    log_context, format_exception, measure_time
)

# Module-level logger
logger = get_logger(tag="CLI.FORMATTERS", name=__name__)

class ChineseFormatter:
    """中文友好的格式化器"""

    def __init__(self):
        self.constants = GlobalConstants()
        self.rich_formatter = RichTableFormatter(style='rounded')
    
    # 表格样式
    TABLE_STYLES = {
        'unicode': {
            'top_left': '┌',
            'top_right': '┐', 
            'bottom_left': '└',
            'bottom_right': '┘',
            'horizontal': '─',
            'vertical': '│',
            'cross': '┼',
            'top_cross': '┬',
            'bottom_cross': '┴',
            'left_cross': '├',
            'right_cross': '┤'
        },
        'simple': {
            'top_left': '+',
            'top_right': '+',
            'bottom_left': '+', 
            'bottom_right': '+',
            'horizontal': '-',
            'vertical': '|',
            'cross': '+',
            'top_cross': '+',
            'bottom_cross': '+',
            'left_cross': '+',
            'right_cross': '+'
        }
    }
    
    @staticmethod
    def get_display_width(text: str) -> int:
        """计算包含中文字符的显示宽度"""
        width = 0
        for char in text:
            if ord(char) > 127:  # 非ASCII字符
                width += 2
            else:
                width += 1
        return width
    
    @staticmethod
    def pad_text(text: str, width: int, align: str = 'left') -> str:
        """按显示宽度填充文本"""
        display_width = ChineseFormatter.get_display_width(text)
        padding = width - display_width
        
        if padding <= 0:
            return text
            
        if align == 'center':
            left_pad = padding // 2
            right_pad = padding - left_pad
            return ' ' * left_pad + text + ' ' * right_pad
        elif align == 'right':
            return ' ' * padding + text
        else:  # left
            return text + ' ' * padding
    
    @staticmethod
    def format_table(headers: List[str], rows: List[List[str]],
                    style: str = 'unicode', align: List[str] = None) -> str:
        """格式化表格，支持中文，使用 rich table"""
        if not headers or not rows:
            return ""

        # 使用 rich table
        formatter = RichTableFormatter(style='rounded')
        return formatter.draw_table(headers, rows)
    
    @staticmethod
    def format_title(title: str, icon: str = "🚀", width: int = 80) -> str:
        """格式化标题"""
        title_line = f"{icon} {title}"
        separator = "=" * width
        return f"{title_line}\n{separator}"
    
    @staticmethod
    def format_section(title: str, icon: str = "📋", content: str = "") -> str:
        """格式化章节"""
        section_line = f"{icon} {title}:"
        if content:
            return f"{section_line}\n{content}"
        return section_line
    
    @staticmethod
    def format_status(status: str, is_enabled: bool = True) -> str:
        """格式化状态"""
        if is_enabled:
            return f"✅ {status}"
        else:
            return f"❌ {status}"
    
    @staticmethod
    def format_info_table(data: Dict[str, Any], title: Optional[str] = None) -> str:
        """格式化信息表格"""
        if not data:
            return ""

        # Use i18n for headers with fallback
        from ..utils.i18n import get_i18n_manager
        i18n = get_i18n_manager()
        lang = i18n.current_language or os.getenv('GS_LANGUAGE', 'zh')
        prop = i18n.get_message('cli.property')
        val = i18n.get_message('cli.value')
        if prop == 'cli.property':
            prop = 'Property' if lang == 'en' else '属性'
        if val == 'cli.value':
            val = 'Value' if lang == 'en' else '值'
        headers = [prop, val]
        rows = []

        for key, value in data.items():
            rows.append([str(key), str(value)])

        from rich.console import Console
        from io import StringIO
        import shutil

        formatter = RichTableFormatter(style='rounded')

        # 使用统一的方法创建表格（有 title 时自动用 Panel 包装）
        table_or_panel = formatter.create_table_with_panel(
            headers, rows,
            title=title,
            column_styles=["bold bright_cyan", "yellow"],
            column_justifies=["left", "left"]
        )

        # 转换为字符串
        string_io = StringIO()
        terminal_width = shutil.get_terminal_size().columns
        temp_console = Console(file=string_io, force_terminal=True, width=terminal_width)
        temp_console.print(table_or_panel)
        return string_io.getvalue().rstrip()
    
    @staticmethod
    def format_help_usage() -> str:
        """格式化帮助用法"""
        from ..utils.i18n import get_i18n_manager
        i18n = get_i18n_manager()
        lang = i18n.current_language or os.getenv('GS_LANGUAGE', 'zh')
        title = ChineseFormatter.format_title(
            f"Global Scripts {i18n.get_message('commands.help')}"
        )
        
        # Headers with fallback (两列：命令、描述)
        h1 = i18n.get_message('cli.command');     h1 = h1 if h1 != 'cli.command' else ('命令' if lang == 'zh' else 'Command')
        h2 = i18n.get_message('cli.description'); h2 = h2 if h2 != 'cli.description' else ('描述' if lang == 'zh' else 'Description')
        headers = [h1, h2]

        # Rows using i18n (第一列展示命令字符串，第二列展示描述)
        basic = i18n.get_message('cli.basic_info'); basic = basic if basic != 'cli.basic_info' else ('基本用法' if lang == 'zh' else 'Basics')
        usage_word = i18n.get_message('cli.usage'); usage_word = usage_word if usage_word != 'cli.usage' else ('用法' if lang == 'zh' else 'Usage')
        name_word = i18n.get_message('cli.name'); name_word = name_word if name_word != 'cli.name' else ('名称' if lang == 'zh' else 'Name')
        cmd_word = i18n.get_message('cli.command'); cmd_word = cmd_word if cmd_word != 'cli.command' else ('命令' if lang == 'zh' else 'Command')
        rows = [
            [f"gs <{name_word}> <{cmd_word}> [{usage_word}]", basic],
            ["gs help", i18n.get_message('commands.help')],
            ["gs version", i18n.get_message('commands.version')], 
            ["gs status", i18n.get_message('commands.system_status')],
            ["gs refresh", i18n.get_message('commands.refresh')],
            ["gs plugin list", i18n.get_message('commands.list_plugins')],
        ]

        # 使用 rich table
        formatter = RichTableFormatter(style='rounded')
        table = formatter.draw_table(headers, rows)
        return f"{title}\n\n{table}"


class OutputFormatter:
    """输出格式化主类"""

    def __init__(self, chinese: bool = True):
        self.chinese = chinese
        self.formatter = ChineseFormatter()
        self.constants = GlobalConstants()
        self.i18n = get_i18n_manager()

        # 初始化 rich formatter 和 console
        self.rich_formatter = RichTableFormatter(style='rounded')
        self.console = Console()
        self.color_helper = get_color_helper()

        # 设置语言
        language = "zh" if chinese else "en"
        self.i18n.set_language(language)

    def _m(self, key: str, zh_fallback: str, en_fallback: str) -> str:
        """Fetch i18n message with robust fallback to provided zh/en strings when key is missing."""
        msg = self.i18n.get_message(key)
        # When key missing, get_message returns the key string itself
        if msg == key:
            return zh_fallback if self.chinese else en_fallback
        return msg
    
    def _get_language_texts(self, language: str) -> Dict[str, str]:
        """获取语言文本 - 使用i18n系统"""
        i18n = get_i18n_manager()
        i18n.set_language(language)

        return {
            'plugin_details': i18n.get_message('cli.plugin_details'),
            'basic_info': i18n.get_message('cli.basic_info'),
            'name': i18n.get_message('cli.name'),
            'version': i18n.get_message('cli.version'),
            'author': i18n.get_message('cli.author'),
            'description': i18n.get_message('cli.description'),
            'status': i18n.get_message('cli.status'),
            'enabled': i18n.get_message('cli.enabled'),
            'disabled': i18n.get_message('cli.disabled'),
            'type': i18n.get_message('cli.type'),
            'subplugin': ('Subplugin' if language == 'en' else '子插件'),
            'priority': i18n.get_message('cli.priority'),
            'directory': i18n.get_message('cli.directory'),
            'property': 'Property' if language == 'en' else '属性',
            'value': 'Value' if language == 'en' else '值',
            'available_commands': i18n.get_message('cli.available_commands'),
            'commands_count': 'commands' if language == 'en' else '个',
            'command': i18n.get_message('cli.command'),
            'shell_function': i18n.get_message('cli.shell_function'),
            'usage': i18n.get_message('cli.usage')
        }

    def _create_stats_table(
        self,
        total_plugins: int,
        enabled_count: int,
        disabled_count: int,
        total_commands: int,
        enabled_commands: int,
        disabled_commands: int
    ):
        """创建统计信息表格（返回 Table with title，不用 Panel 包装）"""
        from ..utils.i18n import get_i18n_manager
        i18n = get_i18n_manager()

        # 单位
        unit = "个" if i18n.current_language == 'zh' else ""

        # 表格数据
        headers = ["📊 统计项", "总数", "✅ 已启用", "❌ 已禁用"]
        rows = [
            [
                "📦 插件",
                f"{total_plugins}{unit}",
                f"{enabled_count}{unit}",
                f"{disabled_count}{unit}"
            ],
            [
                "📜 命令",
                f"{total_commands + disabled_commands}{unit}",
                f"{enabled_commands}{unit}",
                f"{disabled_commands}{unit}"
            ]
        ]

        # 列样式
        column_styles = ["bold cyan", "bold bright_white", "green", "red"]
        column_justifies = ["left", "center", "center", "center"]

        # 创建表格（使用 Table 的 title，不用 Panel 包装）
        from ..utils.rich_table import RichTableFormatter
        formatter = RichTableFormatter(style='rounded')

        return formatter.create_table(
            headers, rows,
            title=f"📊 {i18n.get_message('plugin_list.statistics')}",
            column_styles=column_styles,
            column_justifies=column_justifies
        )
    
    def format_help_usage(self) -> str:
        """格式化帮助用法"""
        # 使用i18n获取表格头部（两列：命令、描述）
        headers = [self.i18n.get_message('cli.command'), self.i18n.get_message('cli.description')]

        # 构建帮助行（第一列：命令字符串；第二列：描述）
        rows = [
            [f"gs <{self.i18n.get_message('cli.name')}> <{self.i18n.get_message('cli.command')}> [{self.i18n.get_message('cli.usage')}]",
             self.i18n.get_message('cli.basic_info')],
            ["gs help", self.i18n.get_message('commands.help')],
            ["gs version", self.i18n.get_message('commands.version')],
            ["gs status", self.i18n.get_message('commands.system_status')],
            ["gs doctor", self.i18n.get_message('commands.doctor')],
            ["gs refresh", self.i18n.get_message('commands.refresh')],
            ["gs plugin list", self.i18n.get_message('commands.list_plugins')]
        ]

        from rich.console import Console
        from rich.panel import Panel
        from io import StringIO
        import shutil

        # 创建表格
        table = self.rich_formatter.create_table(
            headers, rows,
            title=None  # 不使用表格 title
        )

        # 用 Panel 包装，title 在边框上
        panel_title = f"🚀 {self.constants.project_name} - {self.i18n.get_message('commands.help')}"
        panel = Panel(
            table,
            title=panel_title,
            title_align="left",
            border_style="dim cyan",  # 统一使用淡色
            expand=True,
            padding=(1, 2)
        )

        # 转换为字符串
        string_io = StringIO()
        terminal_width = shutil.get_terminal_size().columns
        temp_console = Console(file=string_io, force_terminal=True, width=terminal_width)
        temp_console.print(panel)
        return string_io.getvalue().rstrip()
    
    def format_info_table(self, data: Dict[str, Any], title: Optional[str] = None) -> str:
        """格式化信息表格"""
        return self.formatter.format_info_table(data, title=title)
    
    def format_title(self, title: str, icon: str = "🚀") -> str:
        """格式化标题"""
        return self.formatter.format_title(title, icon)
    
    def format_table(self, data: List[Dict[str, Any]], title: Optional[str] = None) -> str:
        """格式化表格数据"""
        if not data:
            return ""

        # 获取所有键作为表头
        all_keys = set()
        for item in data:
            all_keys.update(item.keys())
        headers = list(all_keys)

        # 生成行数据
        rows = []
        for item in data:
            row = [str(item.get(key, '')) for key in headers]
            rows.append(row)

        from rich.console import Console
        from io import StringIO
        import shutil

        # 使用统一的方法创建表格（有 title 时自动用 Panel 包装）
        table_or_panel = self.rich_formatter.create_table_with_panel(
            headers, rows,
            title=title
        )

        # 转换为字符串
        string_io = StringIO()
        terminal_width = shutil.get_terminal_size().columns
        temp_console = Console(file=string_io, force_terminal=True, width=terminal_width)
        temp_console.print(table_or_panel)
        return string_io.getvalue().rstrip()
    
    def format_command_result(self, result) -> str:
        """格式化命令结果"""
        lang = 'zh' if self.chinese else 'en'
        status_ok = self._m('cli.success', '成功', 'Success')
        status_fail = self._m('cli.failed', '失败', 'Failed')
        status = ("✅ " + status_ok) if result.success else ("❌ " + status_fail)

        # Keys localized when possible
        key_status = self._m('cli.status', '状态', 'Status')
        key_output = self._m('cli.output', '输出', 'Output')
        key_exec_time = self._m('cli.execution_time', '执行时间', 'Execution Time')
        key_error = self._m('cli.error', '错误', 'Error')

        info = {
            key_status: status,
            key_output: (result.output or getattr(result, 'stdout', '') or ''),
            key_exec_time: f"{getattr(result, 'execution_time', 0.0):.2f}s",
        }

        if (getattr(result, 'error', None) or getattr(result, 'stderr', None)) and not result.success:
            info[key_error] = (result.error or getattr(result, 'stderr', ''))

        return self.format_info_table(info)
    
    def print_help(self):
        """打印帮助信息"""
        # Use i18n-aware help builder
        help_text = self.format_help_usage()
        print(help_text)
    
    def print_version(self, version: str = None):
        """打印版本信息"""
        if version is None:
            # Read from VERSION file
            from pathlib import Path
            version_file = Path(__file__).parent.parent.parent.parent / "VERSION"
            version = version_file.read_text().strip() if version_file.exists() else "unknown"
        print(f"{self.constants.project_name} v{version}")
    
    def print_plugin_list(self, enabled_plugins: List[Dict], disabled_plugins: List[Dict] = None):
        """打印插件列表"""
        # 使用i18n管理器获取文本
        from ..utils.i18n import get_i18n_manager
        i18n = get_i18n_manager()

        renderables = []

        # 已启用插件表格
        if enabled_plugins:
            headers = [
                i18n.get_message('plugin_list.table_headers.plugin_name'),
                i18n.get_message('plugin_list.table_headers.status'),
                i18n.get_message('plugin_list.table_headers.type'),
                i18n.get_message('plugin_list.table_headers.priority'),
                i18n.get_message('plugin_list.table_headers.version'),
                i18n.get_message('plugin_list.table_headers.commands'),
                i18n.get_message('plugin_list.table_headers.description')
            ]

            rows = []
            for plugin in enabled_plugins:
                plugin_status = i18n.get_message('plugin_list.status_values.active')
                plugin_type_text = plugin.get('type', i18n.get_message('plugin_types.system'))

                plugin_name = f"[bold white]{plugin.get('name', '')}[/bold white]"
                status = self.color_helper.colorize_status(plugin_status)
                ptype = self.color_helper.colorize_type(plugin_type_text)
                priority = self.color_helper.colorize_number(str(plugin.get('priority', '')), "bright_blue")
                version = f"[dim]{plugin.get('version', '')}[/dim]"
                cmd_count = self.color_helper.colorize_number(str(plugin.get('command_count', 0)), "bright_green")
                desc = f"[dim]{plugin.get('description', '')}[/dim]"

                rows.append([plugin_name, status, ptype, priority, version, cmd_count, desc])

            total_commands = sum(plugin.get('command_count', 0) for plugin in enabled_plugins)
            table_title = f"✅ {i18n.get_message('plugin_list.enabled_plugins')} ({len(enabled_plugins)}{'个' if i18n.current_language == 'zh' else ''})"

            column_styles = ["", "", "", "", "", "", ""]
            column_justifies = ["left", "center", "center", "center", "center", "right", "left"]

            # 创建表格（使用 Table 的 title，不用 Panel 包装）
            enabled_table = self.rich_formatter.create_table(
                headers, rows,
                title=table_title,
                show_footer=False,
                column_styles=column_styles,
                column_justifies=column_justifies,
            )
            renderables.append(enabled_table)
            renderables.append("")  # 添加空行

        # 已禁用插件表格
        if disabled_plugins:
            headers = [
                i18n.get_message('plugin_list.table_headers.plugin_name'),
                i18n.get_message('plugin_list.table_headers.status'),
                i18n.get_message('plugin_list.table_headers.type'),
                i18n.get_message('plugin_list.table_headers.priority'),
                i18n.get_message('plugin_list.table_headers.version'),
                i18n.get_message('plugin_list.table_headers.commands'),
                i18n.get_message('plugin_list.table_headers.description')
            ]

            rows = []
            for plugin in disabled_plugins:
                plugin_type_text = plugin.get('type', i18n.get_message('plugin_types.third_party'))
                rows.append([
                    plugin.get('name', ''),
                    i18n.get_message('plugin_list.status_values.disabled'),
                    plugin_type_text,
                    str(plugin.get('priority', '')),
                    plugin.get('version', ''),
                    str(plugin.get('command_count', 0)),
                    plugin.get('description', '')
                ])

            total_commands = sum(plugin.get('command_count', 0) for plugin in disabled_plugins)
            table_title = f"❌ {i18n.get_message('plugin_list.disabled_plugins')} ({len(disabled_plugins)}{'个' if i18n.current_language == 'zh' else ''})"

            column_styles = ["cyan", "red", "yellow", "blue", "magenta", "green", "white"]
            column_justifies = ["left", "center", "center", "center", "center", "right", "left"]

            # 创建表格（使用 Table 的 title，不用 Panel 包装）
            disabled_table = self.rich_formatter.create_table(
                headers, rows,
                title=table_title,
                show_footer=False,
                column_styles=column_styles,
                column_justifies=column_justifies,
            )
            renderables.append(disabled_table)
            renderables.append("")  # 添加空行

        # 统计信息表格
        total_plugins = len(enabled_plugins or []) + len(disabled_plugins or [])
        enabled_count = len(enabled_plugins or [])
        disabled_count = len(disabled_plugins or [])
        total_commands = sum(p.get('command_count', 0) for p in (enabled_plugins or []))
        enabled_commands = total_commands
        disabled_commands = sum(p.get('command_count', 0) for p in (disabled_plugins or []))

        stats_table = self._create_stats_table(
            total_plugins, enabled_count, disabled_count,
            total_commands, enabled_commands, disabled_commands
        )
        renderables.append(stats_table)

        # 用 Panel 包围所有内容，标题在 Panel 的上边框（居左）
        panel_title = f"🚀 {i18n.get_message('plugin_list.title')}"
        panel = Panel(
            Group(*renderables),
            title=panel_title,
            title_align="left",
            border_style="dim cyan",  # 外层用淡色，突出内层表格
            expand=True,
            padding=(1, 2)
        )
        self.console.print(panel)
    
    def print_plugin_info(self, plugin_info: Dict):
        """打印插件详细信息"""
        plugin_name = plugin_info.get('name', 'Unknown')

        # 检查语言设置
        language = os.getenv('GS_LANGUAGE', 'zh')

        # 获取语言文本
        texts = self._get_language_texts(language)

        basic_info = {
            texts['name']: plugin_info.get('name', ''),
            texts['version']: plugin_info.get('version', ''),
            texts['author']: plugin_info.get('author', ''),
            texts['description']: plugin_info.get('description', ''),
            texts['status']: texts['enabled'] if plugin_info.get('enabled', True) else texts['disabled'],
            texts['type']: plugin_info.get('type', ''),
            texts['priority']: str(plugin_info.get('priority', '')),
            texts['directory']: plugin_info.get('directory', '')
        }

        # 使用新的表格库显示信息表格
        headers = [texts['property'], texts['value']]
        rows = [[key, value] for key, value in basic_info.items()]

        renderables = []

        # 基本信息表格（使用 Table 的 title，不用 Panel 包装）
        info_table_title = f"📋 {texts['basic_info']}"
        column_styles = ["bold bright_cyan", "yellow"]
        column_justifies = ["left", "left"]

        info_table = self.rich_formatter.create_table(
            headers, rows,
            title=info_table_title,
            column_styles=column_styles,
            column_justifies=column_justifies,
        )
        renderables.append(info_table)
        renderables.append("")  # 添加空行

        # 可用命令表格
        commands = plugin_info.get('commands', [])
        if commands:
            cmd_headers = [texts['command'], texts['subplugin'], texts['shell_function'], texts['type'], texts['usage'], texts['description']]
            cmd_rows = []

            for cmd in commands:
                command = f"[bold white]{cmd.get('command', '')}[/bold white]"
                subplugin = self.color_helper.colorize_subplugin(cmd.get('subplugin', ''))
                shell_func = f"[dim]{cmd.get('shell_function', '')}[/dim]"
                plugin_type = self.color_helper.colorize_type(cmd.get('plugin_type', ''))
                usage = self.color_helper.colorize_usage(cmd.get('usage', ''))
                description = f"[dim]{cmd.get('description', '')}[/dim]"
                cmd_rows.append([command, subplugin, shell_func, plugin_type, usage, description])

            count_text = f"({len(commands)} {texts['commands_count']})" if language == 'zh' else f"({len(commands)} {texts['commands_count']})"
            commands_table_title = f"📜 {texts['available_commands']} {count_text}"

            cmd_column_styles = ["", "", "", "", "", ""]
            cmd_column_justifies = ["left", "center", "center", "center", "left", "left"]

            commands_table = self.rich_formatter.create_table(
                cmd_headers, cmd_rows,
                title=commands_table_title,
                show_footer=False,
                column_styles=cmd_column_styles,
                column_justifies=cmd_column_justifies,
            )
            renderables.append(commands_table)

        # 用 Panel 包围所有内容，标题在 Panel 的上边框（居左）
        panel_title = f"🔌 {texts['plugin_details']}: {plugin_name}"
        panel = Panel(
            Group(*renderables),
            title=panel_title,
            title_align="left",
            border_style="dim cyan",  # 外层用淡色，突出内层表格
            expand=True,
            padding=(1, 2)
        )
        self.console.print(panel)

    def print_table(
        self,
        headers: List[str],
        rows: List[List[str]],
        title: Optional[str] = None
    ) -> None:
        """
        直接打印表格（便捷方法）

        Args:
            headers: 表头列表
            rows: 数据行列表
            title: 表格标题
        """
        self.rich_formatter.print_table(headers, rows, title=title)
