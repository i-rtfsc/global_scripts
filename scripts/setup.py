#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Global Scripts Setup Script
使用模板引擎和已有模块，避免代码重复
"""

import os
import subprocess
import sys
import asyncio
from pathlib import Path
import platform
from typing import Dict

# Add src directory to Python path
_SCRIPT_DIR = Path(__file__).parent.absolute()
_PROJECT_ROOT = _SCRIPT_DIR.parent
sys.path.insert(0, str(_PROJECT_ROOT / 'src'))

# Import utilities
from gscripts.utils.shell_utils import detect_current_shell
from gscripts.core.config_manager import ConfigManager
from gscripts.core.plugin_loader import PluginLoader
from gscripts.core.template_engine import get_template_engine
from gscripts.shell_completion.generator import generate_completions_from_index
from gscripts.router.indexer import build_router_index, write_router_index

# Terminal colors
BOLD = '\033[1m'
BLUE = '\033[34m'
CYAN = '\033[36m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
RED = '\033[31m'
RESET = '\033[0m'

def get_version() -> str:
    """从 VERSION 文件读取版本号"""
    version_file = _PROJECT_ROOT / "VERSION"
    if version_file.exists():
        return version_file.read_text().strip()
    return "unknown"

GS_VERSION = get_version()

def _supports_color() -> bool:
    """判断当前终端是否支持ANSI颜色"""
    try:
        return sys.stdout.isatty() and os.environ.get('NO_COLOR') is None
    except Exception:
        return False

def show_banner():
    """显示ASCII banner"""
    art = r"""
  ____  _       _           _   ____            _       _
 / ___|(_) ___ | |__   __ _| | / ___|  ___ _ __(_)_ __ | |_ ___
| |  _ | |/ _ \| '_ \ / _` | | \___ \ / __| '__| | '_ \| __/ __|
| |_| || | (_) | |_) | (_| | |  ___) | (__| |  | | |_) | |_\__ \
 \____||_|\___/|_.__/ \__,_|_| |____/ \___|_|  |_| .__/ \__|___/
                                                 |_|
"""
    if _supports_color():
        print(BOLD + CYAN + art + RESET)
        print(BOLD + BLUE + "Global Scripts - Modern Plugin Framework" + RESET)
        print(CYAN + f"Version: {GS_VERSION}" + RESET)
    else:
        print(art)
        print("Global Scripts - Modern Plugin Framework")
        print(f"Version: {GS_VERSION}")

def select_language(auto_mode: bool = False) -> str:
    """选择语言设置"""
    if auto_mode:
        print(f"{GREEN}✅ English selected (auto mode){RESET}")
        return 'en'

    print(f"{BOLD}🌐 Language Selection / 语言选择{RESET}")
    print(f"""
1. {CYAN}中文{RESET} (Chinese)
2. {CYAN}English{RESET}
""")

    while True:
        try:
            choice = input(f"{YELLOW}Please select language / 请选择语言 (1/2, Enter=中文): {RESET}").strip()
            if choice == '' or choice == '1':
                print(f"{GREEN}✅ 已选择中文{RESET}")
                return 'zh'
            elif choice == '2':
                print(f"{GREEN}✅ English selected{RESET}")
                return 'en'
            else:
                print(f"{RED}❌ Invalid choice / 无效选择{RESET}")
        except KeyboardInterrupt:
            print(f"\n{YELLOW}⚠️  Installation cancelled / 安装已取消{RESET}")
            sys.exit(0)

def ask_show_examples(language: str = 'zh', auto_mode: bool = False) -> bool:
    """询问是否启用示例插件显示"""
    if auto_mode:
        print(f"{GREEN}✅ Example plugins enabled (auto mode){RESET}")
        return True

    if language == 'zh':
        print(f"\n{BOLD}📚 示例插件配置{RESET}")
        prompt = f"{YELLOW}是否在插件列表中显示示例插件？ (y/N): {RESET}"
    else:
        print(f"\n{BOLD}📚 Example Plugins Configuration{RESET}")
        prompt = f"{YELLOW}Show example plugins? (y/N): {RESET}"

    try:
        choice = input(prompt).strip().lower()
        result = choice in ['y', 'yes']
        if result:
            print(f"{GREEN}✅ {'示例插件已启用' if language == 'zh' else 'Example plugins enabled'}{RESET}")
        else:
            print(f"{YELLOW}⚠️  {'示例插件已禁用' if language == 'zh' else 'Example plugins disabled'}{RESET}")
        return result
    except KeyboardInterrupt:
        print(f"\n{YELLOW}⚠️  {'安装已取消' if language == 'zh' else 'Installation cancelled'}{RESET}")
        sys.exit(0)

async def main():
    """主安装函数"""
    import argparse

    # 解析命令行参数
    parser = argparse.ArgumentParser(description='Global Scripts Setup')
    parser.add_argument('--generate-completion', action='store_true',
                       help='Generate only completion scripts without interactive prompts')
    parser.add_argument('--auto', action='store_true',
                       help='Run in automatic mode (non-interactive)')
    parser.add_argument('--lang', choices=['en', 'zh'],
                       help='Language for generated scripts')
    parser.add_argument('--examples', choices=['true', 'false'],
                       help='Whether to show example plugins')
    parser.add_argument('--shell', choices=['bash', 'zsh', 'fish'],
                       help='Target shell (overrides auto-detection)')
    args = parser.parse_args()

    # 显示banner
    show_banner()

    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher required")
        sys.exit(1)

    # 路径配置
    source_dir = _PROJECT_ROOT
    cache_dir = Path.home() / ".config" / "global-scripts"
    cache_dir.mkdir(parents=True, exist_ok=True)

    # 配置管理器
    config_manager = ConfigManager()
    config = config_manager.get_config()

    # 语言设置优先级：命令行 > 配置文件 > 用户选择
    if args.lang:
        language = args.lang
    elif config.get('language'):
        language = config['language']
        if not args.auto:
            print(f"✅ 使用配置文件中的语言设置: {language}")
    else:
        language = select_language(auto_mode=args.auto)

    # 示例插件开关
    if args.examples is not None:
        show_examples = args.examples.lower() == 'true'
    elif 'show_examples' in config:
        show_examples = config['show_examples']
    else:
        show_examples = ask_show_examples(language=language, auto_mode=args.auto)

    # 插件扫描
    print(f"\n{'=' * 70}")
    print(f"{'[1/3] 插件扫描' if language == 'zh' else '[1/3] Plugin Scanning':^70}")
    print(f"{'-' * 70}")

    plugins_root = source_dir / "plugins"
    custom_root = source_dir / "custom"

    # 使用 PluginLoader 加载插件
    loader = PluginLoader(plugins_root)
    system_plugins = await loader.load_all_plugins()
    system_count = len(system_plugins)

    # 加载自定义插件
    custom_plugins = {}
    custom_count = 0
    if custom_root.exists():
        custom_loader = PluginLoader(custom_root)
        custom_plugins = await custom_loader.load_all_plugins()
        custom_count = len(custom_plugins)

    # 合并所有插件
    plugins = {**system_plugins, **custom_plugins}

    # 显示插件统计
    print(f"\n  {'插件统计' if language == 'zh' else 'Plugin Statistics'}:")
    print(f"  ├─ {'系统插件' if language == 'zh' else 'System plugins'}: {system_count}")
    if custom_count > 0:
        print(f"  ├─ {'自定义插件' if language == 'zh' else 'Custom plugins'}: {custom_count}")
    print(f"  └─ {'总计' if language == 'zh' else 'Total'}: {len(plugins)}")

    # 生成 Router Index
    print(f"\n{'[2/3] 命令路由索引' if language == 'zh' else '[2/3] Command Router Index':^70}")
    print(f"{'-' * 70}")

    router_index = build_router_index(plugins)
    router_path = write_router_index(router_index)
    print(f"  ✅ Router index: {router_path}")

    # 生成环境文件和补全脚本
    print(f"\n{'[3/3] 环境配置' if language == 'zh' else '[3/3] Environment Setup':^70}")
    print(f"{'-' * 70}")

    # 检测或使用指定的 Shell
    if args.shell:
        current_shell = args.shell
    else:
        current_shell = detect_current_shell()

    print(f"  🐚 Shell: {current_shell}")

    # 使用模板引擎生成环境文件
    template_engine = get_template_engine()

    # 转换插件格式为模板引擎需要的格式
    plugins_dict = {name: plugin.__dict__ if hasattr(plugin, '__dict__') else {} for name, plugin in plugins.items()}

    if current_shell == 'fish':
        env_content = template_engine.render_env_fish(
            source_dir, cache_dir, plugins_dict, language, show_examples
        )
        env_file = source_dir / 'env.fish'
    else:
        env_content = template_engine.render_env_sh(
            source_dir, cache_dir, plugins_dict, language, show_examples
        )
        env_file = source_dir / 'env.sh'

    # 写入环境文件
    if env_file.exists():
        try:
            env_file.chmod(0o644)
        except Exception:
            pass

    env_file.write_text(env_content, encoding='utf-8')
    env_file.chmod(0o755)
    print(f"  ✅ {'环境文件' if language == 'zh' else 'Environment file'}: {env_file.name}")

    # 生成补全脚本
    if not args.generate_completion:
        completions_dir = cache_dir / 'completions'
        completions_dir.mkdir(parents=True, exist_ok=True)

        bash_file, zsh_file, fish_file = generate_completions_from_index(
            router_path,
            completions_dir,
            language=language
        )

        print(f"  ✅ {'补全脚本' if language == 'zh' else 'Completions'}: bash, zsh, fish")

    # Shell 配置说明
    print(f"\n{'[4/5] Shell 配置说明' if language == 'zh' else '[4/5] Shell Configuration':^70}")
    print(f"{'-' * 70}")

    if current_shell == 'fish':
        config_file = Path.home() / ".config" / "fish" / "config.fish"
    elif current_shell == 'zsh':
        config_file = Path.home() / ".zshrc"
    else:
        config_file = Path.home() / ".bashrc"

    print(f"\n  {'配置信息' if language == 'zh' else 'Configuration Info'}:")
    print(f"  ├─ Shell: {current_shell}")
    print(f"  └─ {'配置文件' if language == 'zh' else 'Config file'}: {config_file}")

    # 检查配置文件是否已包含环境加载
    if config_file.exists():
        with open(config_file, 'r', encoding='utf-8') as f:
            content = f.read()

        if str(env_file) in content:
            print(f"\n  ✅ {'Shell 配置已存在' if language == 'zh' else 'Shell already configured'}")
        else:
            print(f"\n  ⚠️  {'需要手动配置 Shell' if language == 'zh' else 'Shell configuration needed'}")
            print(f"\n  {'请在配置文件中添加以下行' if language == 'zh' else 'Please add the following line to your config file'}:")
            print(f"  {CYAN}source {env_file}{RESET}")
    else:
        print(f"\n  ℹ️  {'配置文件不存在，请创建' if language == 'zh' else 'Config file does not exist, please create it'}: {config_file}")
        print(f"  {'并添加以下行' if language == 'zh' else 'And add the following line'}:")
        print(f"  {CYAN}source {env_file}{RESET}")

    # 插件统计信息
    print(f"\n{'[5/5] 插件统计' if language == 'zh' else '[5/5] Plugin Statistics':^70}")
    print(f"{'-' * 70}")

    # 计算启用/禁用的插件
    enabled_plugins = {}
    disabled_plugins = {}

    for name, plugin in plugins.items():
        enabled = config.get('system_plugins', {}).get(name, False) or \
                  config.get('custom_plugins', {}).get(name, False)
        if enabled:
            enabled_plugins[name] = plugin
        else:
            disabled_plugins[name] = plugin

    enabled_count = len(enabled_plugins)
    disabled_count = len(disabled_plugins)
    total_functions = sum(len(getattr(p, 'functions', {})) for p in enabled_plugins.values())

    print(f"\n  {'已启用插件' if language == 'zh' else 'Enabled plugins'}: {GREEN}{enabled_count}{RESET} / {len(plugins)}")
    if disabled_count > 0:
        print(f"  {'已禁用插件' if language == 'zh' else 'Disabled plugins'}: {YELLOW}{disabled_count}{RESET}")
    print(f"  {'可用命令数' if language == 'zh' else 'Available commands'}: {CYAN}{total_functions}{RESET}")

    # 显示启用的插件列表
    if enabled_plugins:
        print(f"\n  {'启用的插件' if language == 'zh' else 'Enabled Plugins'}:")

        # 区分系统插件和自定义插件
        system_enabled = {k: v for k, v in enabled_plugins.items() if k in system_plugins}
        custom_enabled = {k: v for k, v in enabled_plugins.items() if k in custom_plugins}

        if system_enabled:
            print(f"    {'系统插件' if language == 'zh' else 'System Plugins'}:")
            for plugin_name in sorted(system_enabled.keys()):
                plugin = system_enabled[plugin_name]
                functions_count = len(getattr(plugin, 'functions', {}))
                subplugins_count = len(getattr(plugin, 'subplugins', []))
                print(f"      {GREEN}✓{RESET} {plugin_name:15} ({functions_count} {'命令' if language == 'zh' else 'cmds'}, {subplugins_count} {'子插件' if language == 'zh' else 'subs'})")

        if custom_enabled:
            print(f"    {'自定义插件' if language == 'zh' else 'Custom Plugins'}:")
            for plugin_name in sorted(custom_enabled.keys()):
                plugin = custom_enabled[plugin_name]
                functions_count = len(getattr(plugin, 'functions', {}))
                subplugins_count = len(getattr(plugin, 'subplugins', []))
                print(f"      {GREEN}✓{RESET} {plugin_name:15} ({functions_count} {'命令' if language == 'zh' else 'cmds'}, {subplugins_count} {'子插件' if language == 'zh' else 'subs'})")

    # 安装完成
    print(f"\n{'=' * 70}")
    print(f"{'🎉 ' + ('安装完成！' if language == 'zh' else 'Installation Complete!'):^70}")
    print(f"{'=' * 70}\n")

    print(f"{'📋 ' + ('使用说明' if language == 'zh' else 'Usage')}:")
    print(f"  1. {'重新加载 Shell 配置' if language == 'zh' else 'Reload shell configuration'}:")
    print(f"     {CYAN}source {config_file}{RESET}")
    print(f"\n  2. {'使用命令' if language == 'zh' else 'Use commands'}:")
    print(f"     {CYAN}gs help{RESET}         # {'查看帮助' if language == 'zh' else 'Show help'}")
    print(f"     {CYAN}gs status{RESET}       # {'查看系统状态' if language == 'zh' else 'Show system status'}")
    print(f"     {CYAN}gs plugin list{RESET}  # {'查看插件列表' if language == 'zh' else 'List plugins'}")

    # 项目信息
    print(f"\n{'📚 ' + ('项目信息' if language == 'zh' else 'Project Info')}:")
    print(f"  {'版本' if language == 'zh' else 'Version'}:    {GS_VERSION}")
    print(f"  {'源码目录' if language == 'zh' else 'Source'}:    {source_dir}")
    print(f"  {'配置目录' if language == 'zh' else 'Config'}:    {cache_dir}")
    print(f"  {'日志文件' if language == 'zh' else 'Log file'}:  {cache_dir / 'logs' / 'gs.log'}")
    print(f"  {'文档' if language == 'zh' else 'Docs'}:      README.md\n")

    print(f"{'=' * 70}\n")

    return True

if __name__ == "__main__":
    try:
        success = asyncio.run(main())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⚠️  安装已取消")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ 安装失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
