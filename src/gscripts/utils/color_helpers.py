#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
颜色辅助工具 - 为不同类型的文本添加颜色标记
"""

import re
from typing import Dict


class ColorHelper:
    """颜色辅助类 - 为不同内容添加 Rich 颜色标记"""

    # 插件类型颜色映射
    TYPE_COLORS: Dict[str, str] = {
        "Python插件": "bright_magenta",
        "Python": "bright_magenta",
        "Shell插件": "bright_green",
        "Shell": "bright_green",
        "混合插件": "bright_cyan",
        "Hybrid": "bright_cyan",
        "配置插件": "bright_yellow",
        "Config": "bright_yellow",
        "json": "bright_yellow",
        "shell": "bright_green",
        "python": "bright_magenta",
    }

    # 子插件颜色列表（循环使用）
    SUBPLUGIN_COLORS = [
        "cyan",
        "green",
        "yellow",
        "magenta",
        "blue",
        "bright_cyan",
        "bright_green",
        "bright_yellow",
        "bright_magenta",
        "bright_blue",
    ]

    # 状态颜色
    STATUS_COLORS = {
        "启用": "green",
        "禁用": "red",
        "正常": "green",
        "异常": "red",
        "运行中": "green",
        "已停止": "red",
        "空闲": "yellow",
    }

    def __init__(self):
        self._subplugin_color_map: Dict[str, str] = {}
        self._color_index = 0

    def colorize_type(self, plugin_type: str) -> str:
        """
        为插件类型添加颜色

        Args:
            plugin_type: 插件类型

        Returns:
            带颜色标记的文本
        """
        if not plugin_type or plugin_type == "":
            return ""

        color = self.TYPE_COLORS.get(plugin_type, "white")
        return f"[{color}]{plugin_type}[/{color}]"

    def colorize_subplugin(self, subplugin: str) -> str:
        """
        为子插件名称添加颜色（相同名字使用相同颜色）

        Args:
            subplugin: 子插件名称

        Returns:
            带颜色标记的文本
        """
        if not subplugin or subplugin == "":
            return ""

        # 如果已经有颜色映射，直接使用
        if subplugin in self._subplugin_color_map:
            color = self._subplugin_color_map[subplugin]
        else:
            # 分配新颜色
            color = self.SUBPLUGIN_COLORS[self._color_index % len(self.SUBPLUGIN_COLORS)]
            self._subplugin_color_map[subplugin] = color
            self._color_index += 1

        return f"[{color}]{subplugin}[/{color}]"

    def colorize_usage(self, usage: str) -> str:
        """
        为用法添加颜色（参数部分高亮）

        Args:
            usage: 用法字符串

        Returns:
            带颜色标记的文本
        """
        if not usage:
            return ""

        # 匹配 <参数> 或 [可选参数] 或 {选项}
        # 将参数部分标记为高亮颜色
        result = usage

        # <必需参数> - 用红色
        result = re.sub(r'(<[^>]+>)', r'[bright_red]\1[/bright_red]', result)

        # [可选参数] - 用黄色
        result = re.sub(r'(\[[^\]]+\])', r'[bright_yellow]\1[/bright_yellow]', result)

        # {选项} - 用青色
        result = re.sub(r'(\{[^}]+\})', r'[bright_cyan]\1[/bright_cyan]', result)

        return result

    def colorize_status(self, status: str) -> str:
        """
        为状态添加颜色

        Args:
            status: 状态文本

        Returns:
            带颜色标记的文本
        """
        if not status:
            return ""

        # 移除可能已有的 emoji
        clean_status = status.replace("✅", "").replace("❌", "").replace("⚠️", "").strip()

        color = self.STATUS_COLORS.get(clean_status, "white")

        # 添加 emoji
        if "启用" in clean_status or "正常" in clean_status or "运行" in clean_status:
            return f"[{color}]✓[/{color}]"
        elif "禁用" in clean_status or "异常" in clean_status or "停止" in clean_status:
            return f"[{color}]✗[/{color}]"
        else:
            return f"[{color}]{status}[/{color}]"

    def colorize_number(self, number: str, style: str = "bright_blue") -> str:
        """
        为数字添加颜色

        Args:
            number: 数字字符串
            style: 颜色样式

        Returns:
            带颜色标记的文本
        """
        if not number or number == "":
            return ""

        return f"[{style}]{number}[/{style}]"


# 全局实例
_color_helper = ColorHelper()


def get_color_helper() -> ColorHelper:
    """获取全局颜色辅助实例"""
    return _color_helper
