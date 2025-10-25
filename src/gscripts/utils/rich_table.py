#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Global Scripts - Rich 表格格式化器
支持流式输出和更美观的表格显示
"""

from typing import List, Optional, Any, Dict
from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
import time

from ..core.logger import get_logger

# Module-level logger
logger = get_logger(tag="UTILS.RICH_TABLE", name=__name__)


class RichTableFormatter:
    """Rich 表格格式化器，提供美观的表格显示"""

    # 预定义的表格样式
    BOX_STYLES = {
        'rounded': box.ROUNDED,           # 圆角边框（默认，推荐）
        'heavy': box.HEAVY,               # 粗线边框
        'simple_heavy': box.SIMPLE_HEAVY, # 简单粗线
        'double': box.DOUBLE,             # 双线边框
        'simple': box.SIMPLE,             # 简单边框
        'minimal': box.MINIMAL,           # 最小边框
        'minimal_heavy_head': box.MINIMAL_HEAVY_HEAD,  # 最小粗表头
    }

    def __init__(self, console: Optional[Console] = None, style: str = 'rounded'):
        """
        初始化 Rich 表格格式化器

        Args:
            console: Rich Console 实例，如果为 None 则创建新实例
            style: 表格样式 ('rounded', 'heavy', 'simple_heavy', 'double', 'simple', 'minimal')
        """
        self.console = console or Console()
        self.box_style = self.BOX_STYLES.get(style, box.ROUNDED)

    def create_table_with_panel(
        self,
        headers: List[str],
        rows: List[List[str]],
        title: Optional[str] = None,
        caption: Optional[str] = None,
        show_footer: bool = False,
        column_styles: Optional[List[str]] = None,
        column_justifies: Optional[List[str]] = None,
        footer_values: Optional[List[str]] = None,
    ):
        """
        创建表格，如果有 title 则用 Panel 包装（title 显示在边框线上）

        Args:
            headers: 表头列表
            rows: 数据行列表
            title: 表格标题（如果提供，会用 Panel 包装，title 显示在边框线上）
            caption: 表格底部说明
            show_footer: 是否显示表尾
            column_styles: 每列的样式列表
            column_justifies: 每列的对齐方式
            footer_values: 表尾统计值列表

        Returns:
            Table 或 Panel 对象
        """
        # 创建表格（不带 title）
        table = self.create_table(
            headers, rows,
            title=None,  # title 将显示在 Panel 上
            caption=caption,
            show_footer=show_footer,
            column_styles=column_styles,
            column_justifies=column_justifies,
            footer_values=footer_values,
        )

        # 如果有 title，用 Panel 包装
        if title:
            panel = Panel(
                table,
                title=title,
                title_align="left",
                border_style="dim cyan",  # 统一使用淡色，突出内层表格
                expand=True,
                padding=(0, 1)
            )
            return panel

        return table

    def create_table(
        self,
        headers: List[str],
        rows: List[List[str]],
        title: Optional[str] = None,
        caption: Optional[str] = None,
        show_header: bool = True,
        show_footer: bool = False,
        column_styles: Optional[List[str]] = None,
        column_justifies: Optional[List[str]] = None,
        footer_values: Optional[List[str]] = None,
    ) -> Table:
        """
        创建 Rich Table 对象（支持多彩列样式和统计）

        Args:
            headers: 表头列表
            rows: 数据行列表
            title: 表格标题
            caption: 表格底部说明
            show_header: 是否显示表头
            show_footer: 是否显示表尾（统计行）
            column_styles: 每列的样式列表（颜色）
            column_justifies: 每列的对齐方式
            footer_values: 表尾统计值列表

        Returns:
            Rich Table 对象
        """
        table = Table(
            title=title,
            caption=caption,
            box=self.box_style,
            show_header=show_header,
            show_footer=show_footer,
            expand=True,
            title_style="bold magenta",
            title_justify="left",  # 标题居左显示
            caption_style="dim italic",
            border_style="blue",
            header_style="bold bright_cyan",
        )

        # 默认列样式（彩色方案）
        if column_styles is None:
            column_styles = self._generate_column_styles(len(headers))

        # 默认对齐方式
        if column_justifies is None:
            column_justifies = ["left"] * len(headers)

        # 添加列（每列不同颜色）
        for i, header in enumerate(headers):
            style = column_styles[i] if i < len(column_styles) else ""
            justify = column_justifies[i] if i < len(column_justifies) else "left"
            footer = footer_values[i] if footer_values and i < len(footer_values) else ""

            table.add_column(
                header,
                style=style,
                justify=justify,
                footer=footer,
                footer_style="bold green",
                no_wrap=False
            )

        # 添加行
        for row in rows:
            table.add_row(*[str(cell) for cell in row])

        return table

    def _generate_column_styles(self, num_columns: int) -> List[str]:
        """
        生成默认的列样式（彩色方案）

        Args:
            num_columns: 列数

        Returns:
            样式列表
        """
        # 默认彩色方案
        colors = [
            "cyan",           # 第1列：青色
            "green",          # 第2列：绿色
            "yellow",         # 第3列：黄色
            "magenta",        # 第4列：洋红
            "blue",           # 第5列：蓝色
            "bright_cyan",    # 第6列：亮青色
            "bright_green",   # 第7列：亮绿色
            "bright_yellow",  # 第8列：亮黄色
        ]

        # 循环使用颜色
        return [colors[i % len(colors)] for i in range(num_columns)]

    def draw_table(
        self,
        headers: List[str],
        rows: List[List[str]],
        title: Optional[str] = None,
        **kwargs
    ) -> str:
        """
        绘制表格并返回字符串（兼容旧接口）

        Args:
            headers: 表头列表
            rows: 数据行列表
            title: 表格标题
            **kwargs: 其他参数传递给 create_table

        Returns:
            表格字符串
        """
        if not headers or not rows:
            return ""

        table = self.create_table(headers, rows, title=title, **kwargs)

        # 使用 Console 的 capture 功能获取字符串
        from io import StringIO
        string_io = StringIO()
        # 获取当前终端宽度，如果无法获取则使用默认值
        import shutil
        terminal_width = shutil.get_terminal_size().columns
        temp_console = Console(file=string_io, force_terminal=True, width=terminal_width)
        temp_console.print(table)
        return string_io.getvalue().rstrip()

    def print_table(
        self,
        headers: List[str],
        rows: List[List[str]],
        title: Optional[str] = None,
        caption: Optional[str] = None,
        show_footer: bool = False,
        column_styles: Optional[List[str]] = None,
        column_justifies: Optional[List[str]] = None,
        footer_values: Optional[List[str]] = None,
        **kwargs
    ) -> None:
        """
        直接打印表格到终端

        Args:
            headers: 表头列表
            rows: 数据行列表
            title: 表格标题
            caption: 表格底部说明
            show_footer: 是否显示表尾统计
            column_styles: 每列的样式列表
            column_justifies: 每列的对齐方式
            footer_values: 表尾统计值列表
            **kwargs: 其他参数传递给 create_table
        """
        if not headers or not rows:
            return

        table = self.create_table(
            headers, rows,
            title=title,
            caption=caption,
            show_footer=show_footer,
            column_styles=column_styles,
            column_justifies=column_justifies,
            footer_values=footer_values,
            **kwargs
        )
        self.console.print(table)

    def print_table_with_panel(
        self,
        headers: List[str],
        rows: List[List[str]],
        title: str = "Table",
        subtitle: Optional[str] = None,
        **kwargs
    ) -> None:
        """
        在 Panel 中打印表格

        Args:
            headers: 表头列表
            rows: 数据行列表
            title: Panel 标题
            subtitle: Panel 副标题
            **kwargs: 其他参数传递给 create_table
        """
        if not headers or not rows:
            return

        table = self.create_table(headers, rows, **kwargs)
        panel = Panel(
            table,
            title=title,
            subtitle=subtitle,
            border_style="blue",
            expand=True  # 自动扩展到终端宽度
        )
        self.console.print(panel)

    def create_info_table(self, data: Dict[str, Any], title: Optional[str] = None) -> Table:
        """
        创建信息表格（键值对格式）

        Args:
            data: 键值对字典
            title: 表格标题

        Returns:
            Rich Table 对象
        """
        headers = ["Property", "Value"]
        rows = [[str(key), str(value)] for key, value in data.items()]
        return self.create_table(headers, rows, title=title)

    def print_info_table(self, data: Dict[str, Any], title: Optional[str] = None) -> None:
        """
        打印信息表格

        Args:
            data: 键值对字典
            title: 表格标题
        """
        table = self.create_info_table(data, title=title)
        self.console.print(table)


# 便捷函数
def draw_rich_table(
    headers: List[str],
    rows: List[List[str]],
    title: Optional[str] = None,
    style: str = 'rounded',
    **kwargs
) -> str:
    """
    绘制 Rich 表格的便捷函数

    Args:
        headers: 表头列表
        rows: 数据行列表
        title: 表格标题
        style: 表格样式
        **kwargs: 其他参数

    Returns:
        表格字符串
    """
    formatter = RichTableFormatter(style=style)
    return formatter.draw_table(headers, rows, title=title, **kwargs)


def print_rich_table(
    headers: List[str],
    rows: List[List[str]],
    title: Optional[str] = None,
    style: str = 'rounded',
    **kwargs
) -> None:
    """
    打印 Rich 表格的便捷函数

    Args:
        headers: 表头列表
        rows: 数据行列表
        title: 表格标题
        style: 表格样式
        **kwargs: 其他参数
    """
    formatter = RichTableFormatter(style=style)
    formatter.print_table(headers, rows, title=title, **kwargs)
