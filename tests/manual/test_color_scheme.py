#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""测试新的颜色方案和 Rich 美化"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).resolve().parent
if str(project_root / "src") not in sys.path:
    sys.path.insert(0, str(project_root / "src"))

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from gscripts.utils.color_helpers import get_color_helper

def test_color_helpers():
    """测试颜色辅助工具"""
    console = Console()
    color_helper = get_color_helper()

    console.print("\n" + "="*70, style="bold blue")
    console.print("        颜色辅助工具测试", style="bold magenta")
    console.print("="*70 + "\n", style="bold blue")

    # 测试插件类型颜色
    console.print("[bold cyan]1. 插件类型颜色测试:[/bold cyan]\n")
    types = ["Python插件", "Shell插件", "混合插件", "配置插件", "python", "shell"]
    for t in types:
        colored = color_helper.colorize_type(t)
        console.print(f"  {t:20s} → {colored}")

    console.print()

    # 测试子插件颜色
    console.print("[bold cyan]2. 子插件颜色测试（相同名字相同颜色）:[/bold cyan]\n")
    subplugins = ["device", "emulator", "logcat", "device", "emulator", "adb", "device"]
    for sub in subplugins:
        colored = color_helper.colorize_subplugin(sub)
        console.print(f"  {sub:20s} → {colored}")

    console.print()

    # 测试用法颜色
    console.print("[bold cyan]3. 用法颜色测试（参数高亮）:[/bold cyan]\n")
    usages = [
        "gs android device",
        "gs android device connect <ip[:port]>",
        "gs android device disconnect [ip[:port]]",
        "gs android install {apk_path}",
        "gs system monitor [duration]",
    ]
    for usage in usages:
        colored = color_helper.colorize_usage(usage)
        console.print(f"  {colored}")

    console.print()

    # 测试状态颜色
    console.print("[bold cyan]4. 状态颜色测试:[/bold cyan]\n")
    statuses = ["启用", "禁用", "正常", "异常", "运行中", "已停止", "空闲"]
    for status in statuses:
        colored = color_helper.colorize_status(status)
        console.print(f"  {status:20s} → {colored}")

    console.print()

    # 测试数字颜色
    console.print("[bold cyan]5. 数字颜色测试:[/bold cyan]\n")
    numbers = ["10", "100", "1000", "42"]
    for num in numbers:
        colored = color_helper.colorize_number(num, "bright_green")
        console.print(f"  数字: {colored}")

def test_rich_components():
    """测试 Rich 组件美化"""
    console = Console()

    console.print("\n" + "="*70, style="bold blue")
    console.print("        Rich 组件美化测试", style="bold magenta")
    console.print("="*70 + "\n", style="bold blue")

    # 测试 Panel
    console.print("[bold cyan]1. Panel 标题测试:[/bold cyan]\n")

    title_text = Text("Global Scripts - 插件管理", style="bold magenta")
    title_panel = Panel(
        title_text,
        border_style="bright_blue",
        padding=(0, 2),
    )
    console.print(title_panel)
    console.print()

    # 测试节标题
    console.print("[bold cyan]2. 节标题测试:[/bold cyan]\n")

    enabled_text = Text("✅ 已启用插件 ", style="bold green")
    count_text = Text("(12个)", style="dim")
    console.print(enabled_text + count_text)

    console.print()

    commands_text = Text("📜 可用命令 ", style="bold cyan")
    count = Text("(94 个)", style="dim")
    console.print(commands_text + count)

    console.print()

def test_table_with_colors():
    """测试带颜色的表格"""
    from gscripts.utils.rich_table import RichTableFormatter
    from gscripts.utils.color_helpers import get_color_helper

    console = Console()
    console.print("\n" + "="*70, style="bold blue")
    console.print("        彩色表格测试", style="bold magenta")
    console.print("="*70 + "\n", style="bold blue")

    formatter = RichTableFormatter(style='rounded')
    color_helper = get_color_helper()

    # 测试插件列表表格
    console.print("[bold cyan]1. 插件列表（类型颜色化）:[/bold cyan]\n")

    headers = ["插件名称", "状态", "类型", "优先级", "版本", "命令数", "描述"]

    plugins = [
        ("android", "正常", "混合插件", "20", "6.0.0", "94", "Android 开发与调试"),
        ("system", "正常", "混合插件", "50", "6.0.0", "19", "系统管理工具集"),
        ("grep", "正常", "Shell插件", "50", "1.0.0", "17", "代码搜索工具"),
        ("spider", "正常", "Python插件", "50", "1.0.0", "10", "网络爬虫插件"),
    ]

    rows = []
    for name, status, ptype, priority, version, cmd_count, desc in plugins:
        rows.append([
            f"[bold white]{name}[/bold white]",
            color_helper.colorize_status(status),
            color_helper.colorize_type(ptype),
            color_helper.colorize_number(priority, "bright_blue"),
            f"[dim]{version}[/dim]",
            color_helper.colorize_number(cmd_count, "bright_green"),
            f"[dim]{desc}[/dim]",
        ])

    formatter.print_table(
        headers, rows,
        title="插件列表",
        show_footer=True,
        column_justifies=["left", "center", "center", "center", "center", "right", "left"],
        footer_values=[f"[bold green]总计: {len(rows)}[/bold green]", "", "", "", "", f"[bold green]140[/bold green]", ""]
    )

    # 测试命令列表表格
    console.print("\n[bold cyan]2. 命令列表（子插件、类型、用法颜色化）:[/bold cyan]\n")

    headers2 = ["命令", "子插件", "函数", "类型", "用法", "描述"]

    commands = [
        ("gs android device devices", "device", "devices", "python", "gs android device devices", "列出所有连接的设备"),
        ("gs android device connect", "device", "connect", "python", "gs android device connect <ip[:port]>", "通过IP连接设备"),
        ("gs android emulator list", "emulator", "list", "python", "gs android emulator list", "列出所有可用模拟器"),
        ("gs android logcat clear", "logcat", "clear", "python", "gs android logcat clear [tag]", "清除日志"),
    ]

    rows2 = []
    for cmd, subplugin, func, ptype, usage, desc in commands:
        rows2.append([
            f"[bold white]{cmd}[/bold white]",
            color_helper.colorize_subplugin(subplugin),
            f"[dim]{func}[/dim]",
            color_helper.colorize_type(ptype),
            color_helper.colorize_usage(usage),
            f"[dim]{desc}[/dim]",
        ])

    formatter.print_table(
        headers2, rows2,
        title="命令列表",
        show_footer=True,
        column_justifies=["left", "center", "center", "center", "left", "left"],
        footer_values=[f"[bold green]共 {len(rows2)} 个命令[/bold green]", "", "", "", "", ""]
    )

if __name__ == "__main__":
    test_color_helpers()
    test_rich_components()
    test_table_with_colors()

    console = Console()
    console.print("\n" + "="*70, style="bold blue")
    console.print("        ✅ 所有测试完成！", style="bold green")
    console.print("="*70 + "\n", style="bold blue")
