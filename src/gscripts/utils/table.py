#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Global Scripts - 表格显示库
支持中文字符宽度计算和表格绘制，包含颜色美化功能
"""

import unicodedata
from typing import List, Tuple, Optional



from ..core.logger import get_logger
from ..utils.logging_utils import (
    redact, redact_kv, redact_command, ctx, correlation_id, 
    duration, trunc, sanitize_path, format_size, safe_repr,
    log_context, format_exception, measure_time
)

# Module-level logger
logger = get_logger(tag="UTILS.TABLE", name=__name__)

class TableFormatter:
    """表格格式化器，支持中文字符宽度计算和颜色美化"""
    
    def __init__(self, enable_colors=None):
        self.box_chars = {
            'top_left': '┌',
            'top_right': '┐',
            'bottom_left': '└',
            'bottom_right': '┘',
            'horizontal': '─',
            'vertical': '│',
            'cross': '┼',
            'top_tee': '┬',
            'bottom_tee': '┴',
            'left_tee': '├',
            'right_tee': '┤'
        }
        
        # 自动检测终端颜色支持
        if enable_colors is None:
            enable_colors = self._supports_color()
        
        # ANSI 颜色代码
        if enable_colors:
            self.colors = {
                'reset': '\033[0m',
                'bold': '\033[1m',
                'header_bg': '\033[46m',      # 青色背景（更柔和）
                'header_fg': '\033[1;30m',    # 黑色粗体前景（在青色背景上）
                'row_even_bg': '\033[48;5;235m',  # 深灰色背景（偶数行）
                'row_odd_bg': '\033[0m',       # 正常背景（奇数行）
                'text_bright': '\033[97m',     # 明亮白色文字
                'text_normal': '\033[37m'      # 浅灰色文字
            }
        else:
            # 禁用颜色时使用空字符串
            self.colors = {key: '' for key in [
                'reset', 'bold', 'header_bg', 'header_fg', 
                'row_even_bg', 'row_odd_bg', 'text_bright', 'text_normal'
            ]}
    
    def _supports_color(self):
        """检测终端是否支持颜色"""
        import os
        import sys
        
        # 检查环境变量
        if 'NO_COLOR' in os.environ:
            return False
        
        # 检查是否在终端中运行
        if not hasattr(sys.stdout, 'isatty') or not sys.stdout.isatty():
            return False
            
        # 检查TERM环境变量
        term = os.environ.get('TERM', '').lower()
        if 'color' in term or 'xterm' in term or 'screen' in term:
            return True
            
        return False
    
    def get_display_width(self, text: str) -> int:
        """
        计算字符串显示宽度（中文字符宽度为2）
        
        Args:
            text: 输入字符串
            
        Returns:
            显示宽度
        """
        width = 0
        for char in text:
            # 使用 unicodedata 更准确地判断字符宽度
            if unicodedata.east_asian_width(char) in ('F', 'W'):
                # Full-width 和 Wide 字符（如中文）宽度为 2
                width += 2
            else:
                # 其他字符宽度为 1
                width += 1
        return width
    
    def pad_string(self, text: str, target_width: int) -> str:
        """
        字符串填充，考虑中文字符宽度
        
        Args:
            text: 原始字符串
            target_width: 目标宽度
            
        Returns:
            填充后的字符串
        """
        actual_width = self.get_display_width(text)
        padding = target_width - actual_width
        
        if padding > 0:
            return text + ' ' * padding
        else:
            return text
    
    def draw_table(self, headers: List[str], rows: List[List[str]], min_widths: Optional[List[int]] = None) -> str:
        """
        绘制表格
        
        Args:
            headers: 表头列表
            rows: 数据行列表，每行为字符串列表
            min_widths: 各列最小宽度，默认为 [8, 6, 6, 8, 20]
            
        Returns:
            格式化的表格字符串
        """
        if not headers or not rows:
            return ""
        
        num_cols = len(headers)
        if min_widths is None:
            min_widths = [8, 6, 6, 8, 20]
        
        # 扩展 min_widths 到所需长度
        while len(min_widths) < num_cols:
            min_widths.append(8)
        
        # 计算每列的实际宽度
        col_widths = [self.get_display_width(header) for header in headers]
        
        # 确保满足最小宽度要求
        for i in range(num_cols):
            col_widths[i] = max(col_widths[i], min_widths[i])
        
        # 遍历数据行，更新列宽
        for row in rows:
            for i, cell in enumerate(row[:num_cols]):
                if i < len(col_widths):
                    cell_width = self.get_display_width(str(cell))
                    col_widths[i] = max(col_widths[i], cell_width)
        
        # 构建表格
        result = []
        
        # 顶部边框
        top_line = self.box_chars['top_left']
        for i, width in enumerate(col_widths):
            top_line += self.box_chars['horizontal'] * (width + 2)
            if i < len(col_widths) - 1:
                top_line += self.box_chars['top_tee']
        top_line += self.box_chars['top_right']
        result.append(top_line)
        
        # 表头（带颜色）
        header_line = self.box_chars['vertical']
        for i, (header, width) in enumerate(zip(headers, col_widths)):
            # 添加表头颜色
            colored_header = f"{self.colors['header_bg']}{self.colors['header_fg']} {self.pad_string(header, width)} {self.colors['reset']}"
            header_line += colored_header
            header_line += self.box_chars['vertical']
        result.append(header_line)
        
        # 表头分隔线
        sep_line = self.box_chars['left_tee']
        for i, width in enumerate(col_widths):
            sep_line += self.box_chars['horizontal'] * (width + 2)
            if i < len(col_widths) - 1:
                sep_line += self.box_chars['cross']
        sep_line += self.box_chars['right_tee']
        result.append(sep_line)
        
        # 数据行（带交替颜色）
        for row_index, row in enumerate(rows):
            # 选择行背景颜色（交替显示）
            if row_index % 2 == 0:
                row_bg_color = self.colors['row_even_bg']
                text_color = self.colors['text_bright']
            else:
                row_bg_color = self.colors['row_odd_bg']
                text_color = self.colors['text_normal']
            
            data_line = self.box_chars['vertical']
            for i, width in enumerate(col_widths):
                cell_value = str(row[i]) if i < len(row) else ""
                # 添加行背景色和文字颜色
                colored_cell = f"{row_bg_color}{text_color} {self.pad_string(cell_value, width)} {self.colors['reset']}"
                data_line += colored_cell
                data_line += self.box_chars['vertical']
            result.append(data_line)
        
        # 底部边框
        bottom_line = self.box_chars['bottom_left']
        for i, width in enumerate(col_widths):
            bottom_line += self.box_chars['horizontal'] * (width + 2)
            if i < len(col_widths) - 1:
                bottom_line += self.box_chars['bottom_tee']
        bottom_line += self.box_chars['bottom_right']
        result.append(bottom_line)
        
        return '\n'.join(result)
    
    def draw_simple_table(self, headers: List[str], rows: List[List[str]]) -> str:
        """
        绘制简单表格（无边框）
        
        Args:
            headers: 表头列表
            rows: 数据行列表
            
        Returns:
            格式化的表格字符串
        """
        if not headers or not rows:
            return ""
        
        num_cols = len(headers)
        
        # 计算每列的最大宽度
        col_widths = [self.get_display_width(header) for header in headers]
        
        for row in rows:
            for i, cell in enumerate(row[:num_cols]):
                if i < len(col_widths):
                    cell_width = self.get_display_width(str(cell))
                    col_widths[i] = max(col_widths[i], cell_width)
        
        # 构建表格
        result = []
        
        # 表头
        header_line = "  ".join(self.pad_string(header, width) 
                               for header, width in zip(headers, col_widths))
        result.append(header_line)
        
        # 分隔线
        sep_line = "  ".join("─" * width for width in col_widths)
        result.append(sep_line)
        
        # 数据行
        for row in rows:
            data_line = "  ".join(
                self.pad_string(str(row[i]) if i < len(row) else "", width)
                for i, width in enumerate(col_widths)
            )
            result.append(data_line)
        
        return '\n'.join(result)


# 便捷函数
def draw_table(headers: List[str], rows: List[List[str]], min_widths: Optional[List[int]] = None, enable_colors=None) -> str:
    """
    绘制表格的便捷函数
    
    Args:
        headers: 表头列表
        rows: 数据行列表
        min_widths: 各列最小宽度
        enable_colors: 是否启用颜色（None表示自动检测）
        
    Returns:
        格式化的表格字符串
    """
    formatter = TableFormatter(enable_colors=enable_colors)
    return formatter.draw_table(headers, rows, min_widths)


def draw_simple_table(headers: List[str], rows: List[List[str]], enable_colors=None) -> str:
    """
    绘制简单表格的便捷函数
    
    Args:
        headers: 表头列表
        rows: 数据行列表
        enable_colors: 是否启用颜色（None表示自动检测）
        
    Returns:
        格式化的表格字符串
    """
    formatter = TableFormatter(enable_colors=enable_colors)
    return formatter.draw_simple_table(headers, rows)