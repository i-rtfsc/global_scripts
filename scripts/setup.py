#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Global Scripts Setup Script
使用模板引擎和已有模块，避免代码重复
"""

import os
import sys
import asyncio
from pathlib import Path

# Add src directory to Python path
_SCRIPT_DIR = Path(__file__).parent.absolute()
_PROJECT_ROOT = _SCRIPT_DIR.parent
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

# Import utilities (after sys.path modification)
# ruff: noqa: E402
from gscripts.utils.shell_utils import detect_current_shell
from gscripts.core.config_manager import ConfigManager
from gscripts.core.template_engine import get_template_engine
from gscripts.shell_completion.generator import generate_completions_from_index
from gscripts.router.indexer import build_router_index, write_router_index

# Import Clean Architecture components for setup
from gscripts.infrastructure.filesystem.file_operations import RealFileSystem
from gscripts.infrastructure.persistence.plugin_repository import PluginRepository
from gscripts.plugins.discovery import PluginDiscovery
from gscripts.plugins.parsers.python_parser import PythonFunctionParser
from gscripts.plugins.parsers.shell_parser import ShellFunctionParser
from gscripts.plugins.parsers.config_parser import ConfigFunctionParser

# Terminal colors
BOLD = "\033[1m"
BLUE = "\033[34m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
RESET = "\033[0m"


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
        return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
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
    if GS_VERSION.startswith("5."):
        print("Legacy setup: this installer configures GS 5.2. GS 6.0 uses rust/target/debug/gs and scripts/verify_gs6.sh.")


def select_language(auto_mode: bool = False) -> str:
    """选择语言设置"""
    if auto_mode:
        print(f"{GREEN}✅ English selected (auto mode){RESET}")
        return "en"

    print(f"{BOLD}🌐 Language Selection / 语言选择{RESET}")
    print(
        f"""
1. {CYAN}中文{RESET} (Chinese)
2. {CYAN}English{RESET}
"""
    )

    while True:
        try:
            choice = input(
                f"{YELLOW}Please select language / 请选择语言 (1/2, Enter=中文): {RESET}"
            ).strip()
            if choice == "" or choice == "1":
                print(f"{GREEN}✅ 已选择中文{RESET}")
                return "zh"
            elif choice == "2":
                print(f"{GREEN}✅ English selected{RESET}")
                return "en"
            else:
                print(f"{RED}❌ Invalid choice / 无效选择{RESET}")
        except KeyboardInterrupt:
            print(f"\n{YELLOW}⚠️  Installation cancelled / 安装已取消{RESET}")
            sys.exit(0)


def ask_show_examples(language: str = "zh", auto_mode: bool = False) -> bool:
    """询问是否启用示例插件显示"""
    if auto_mode:
        print(f"{GREEN}✅ Example plugins enabled (auto mode){RESET}")
        return True

    if language == "zh":
        print(f"\n{BOLD}📚 示例插件配置{RESET}")
        prompt = f"{YELLOW}是否在插件列表中显示示例插件？ (y/N): {RESET}"
    else:
        print(f"\n{BOLD}📚 Example Plugins Configuration{RESET}")
        prompt = f"{YELLOW}Show example plugins? (y/N): {RESET}"

    try:
        choice = input(prompt).strip().lower()
        result = choice in ["y", "yes"]
        if result:
            print(
                f"{GREEN}✅ {'示例插件已启用' if language == 'zh' else 'Example plugins enabled'}{RESET}"
            )
        else:
            print(
                f"{YELLOW}⚠️  {'示例插件已禁用' if language == 'zh' else 'Example plugins disabled'}{RESET}"
            )
        return result
    except KeyboardInterrupt:
        print(
            f"\n{YELLOW}⚠️  {'安装已取消' if language == 'zh' else 'Installation cancelled'}{RESET}"
        )
        sys.exit(0)


async def main():
    """主安装函数"""
    import argparse

    # 解析命令行参数
    parser = argparse.ArgumentParser(description="Global Scripts Setup")
    parser.add_argument(
        "--generate-completion",
        action="store_true",
        help="Generate only completion scripts without interactive prompts",
    )
    parser.add_argument(
        "--auto", action="store_true", help="Run in automatic mode (non-interactive)"
    )
    parser.add_argument(
        "--lang", choices=["en", "zh"], help="Language for generated scripts"
    )
    parser.add_argument(
        "--examples", choices=["true", "false"], help="Whether to show example plugins"
    )
    parser.add_argument(
        "--shell",
        choices=["bash", "zsh", "fish"],
        help="Target shell (overrides auto-detection)",
    )
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
    elif config.get("language"):
        language = config["language"]
        if not args.auto:
            print(f"✅ 使用配置文件中的语言设置: {language}")
    else:
        language = select_language(auto_mode=args.auto)

    # 示例插件开关
    if args.examples is not None:
        show_examples = args.examples.lower() == "true"
    elif "show_examples" in config:
        show_examples = config["show_examples"]
    else:
        show_examples = ask_show_examples(language=language, auto_mode=args.auto)

    # 插件扫描
    print(f"\n{'=' * 70}")
    print(f"{'[1/3] 插件扫描' if language == 'zh' else '[1/3] Plugin Scanning':^70}")
    print(f"{'-' * 70}")

    plugins_root = source_dir / "plugins"
    custom_root = source_dir / "custom"

    # 使用 PluginRepository 加载插件（创建 PluginMetadata 对象）
    filesystem = RealFileSystem()

    # 系统插件 - 直接扫描 plugins/ 目录
    system_repository = PluginRepository(
        filesystem=filesystem, plugins_dir=plugins_root, config_manager=config_manager
    )
    system_plugins_list = await system_repository.get_all()

    # 自定义插件 - 递归扫描 custom/ 目录下的所有插件
    custom_plugins_list = []
    if custom_root.exists():
        # 使用 PluginDiscovery 递归查找所有 plugin.json 文件
        # 递归发现所有插件目录
        def find_all_plugin_dirs(root_dir):
            """递归查找所有包含 plugin.json 的目录"""
            plugin_dirs = []
            if not root_dir.exists():
                return plugin_dirs

            for item in root_dir.iterdir():
                if not item.is_dir():
                    continue

                # 检查当前目录是否有 plugin.json
                if (item / "plugin.json").exists():
                    plugin_dirs.append(item)
                else:
                    # 递归查找子目录
                    plugin_dirs.extend(find_all_plugin_dirs(item))

            return plugin_dirs

        custom_plugin_dirs = find_all_plugin_dirs(custom_root)

        # 为每个找到的插件目录创建 PluginMetadata
        for plugin_dir in custom_plugin_dirs:
            try:
                # 读取 plugin.json
                plugin_json_path = plugin_dir / "plugin.json"
                if plugin_json_path.exists():
                    import json

                    with open(plugin_json_path, "r", encoding="utf-8") as f:
                        plugin_data = json.load(f)

                    # 使用 PluginRepository._parse_plugin_metadata 创建对象
                    from gscripts.models.plugin import PluginMetadata, PluginType

                    # Parse plugin type, default to PYTHON if invalid
                    plugin_type_str = plugin_data.get("type", "python").lower()

                    # Map alternate names to canonical types
                    type_mapping = {
                        "json": "config",
                        "script": "shell",
                        "sh": "shell",
                    }
                    plugin_type_str = type_mapping.get(plugin_type_str, plugin_type_str)

                    try:
                        plugin_type = PluginType(plugin_type_str)
                    except ValueError:
                        # Invalid type, default to PYTHON
                        plugin_type = PluginType.PYTHON

                    # 获取enabled状态 - 优先从配置文件读取
                    enabled = plugin_data.get("enabled", True)
                    # 从配置文件覆盖enabled状态（优先级：用户配置 > 项目配置 > plugin.json）
                    plugin_name = plugin_data.get("name", plugin_dir.name)
                    custom_config = config.get("custom_plugins", {})
                    if plugin_name in custom_config:
                        enabled = custom_config[plugin_name]

                    plugin_meta = PluginMetadata(
                        name=plugin_name,
                        version=plugin_data.get("version", "1.0.0"),
                        author=plugin_data.get("author", ""),
                        description=plugin_data.get("description", {}),
                        homepage=plugin_data.get("homepage", ""),
                        license=plugin_data.get("license", ""),
                        enabled=enabled,
                        priority=plugin_data.get("priority", 50),
                        category=plugin_data.get("category", ""),
                        keywords=plugin_data.get("keywords", []),
                        type=plugin_type,
                        subplugins=plugin_data.get("subplugins", []),
                    )
                    # Store plugin_dir separately for use in load_plugin_functions
                    plugin_meta._plugin_dir = plugin_dir
                    custom_plugins_list.append(plugin_meta)
            except Exception as e:
                print(f"  ⚠️  Failed to load custom plugin {plugin_dir.name}: {e}")

    # 为每个插件解析函数
    discovery = PluginDiscovery(plugins_root)

    async def load_plugin_functions(plugin_meta, plugin_dir):
        """加载插件函数（包括主插件和子插件）"""
        try:
            functions = []
            plugin_name = plugin_meta.name

            # 1. 扫描主插件目录
            scan_result = discovery.scan_plugin_directory(plugin_dir)

            if scan_result.has_python and scan_result.python_file:
                parser = PythonFunctionParser()
                functions.extend(
                    await parser.parse(scan_result.python_file, plugin_name)
                )

            if scan_result.has_config:
                parser = ConfigFunctionParser()
                for cfg_file in scan_result.config_files:
                    if cfg_file.name == "commands.json":
                        functions.extend(await parser.parse(cfg_file, plugin_name))

            for script_file in scan_result.script_files:
                parser = ShellFunctionParser()
                functions.extend(await parser.parse(script_file, plugin_name))

            # 2. 扫描子插件目录
            # 遍历所有子目录查找.sh, .py等文件
            for item in plugin_dir.iterdir():
                if (
                    not item.is_dir()
                    or item.name.startswith("_")
                    or item.name.startswith(".")
                ):
                    continue

                # 子插件名称就是子目录名
                subplugin_name = item.name

                # 扫描子目录
                sub_scan = discovery.scan_plugin_directory(item)

                if sub_scan.has_python and sub_scan.python_file:
                    parser = PythonFunctionParser()
                    functions.extend(
                        await parser.parse(sub_scan.python_file, plugin_name, subplugin_name)
                    )

                if sub_scan.has_config:
                    parser = ConfigFunctionParser()
                    for cfg_file in sub_scan.config_files:
                        if cfg_file.name == "commands.json":
                            functions.extend(await parser.parse(cfg_file, plugin_name))

                for script_file in sub_scan.script_files:
                    parser = ShellFunctionParser()
                    functions.extend(await parser.parse(script_file, plugin_name, subplugin_name))

            # 将函数附加到 PluginMetadata 对象
            # 使用唯一键：对于子插件函数使用 "subplugin name" 格式，否则使用函数名
            function_dict = {}
            for f in functions:
                if f.subplugin:
                    key = f"{f.subplugin} {f.name}"
                else:
                    key = f.name
                function_dict[key] = f
            plugin_meta.functions = function_dict
            plugin_meta.plugin_dir = str(plugin_dir)  # 添加plugin_dir属性

            return plugin_meta
        except Exception as e:
            print(f"  ⚠️  Failed to load plugin {plugin_dir.name}: {e}")
            return None

    # 加载系统插件函数
    system_tasks = [
        load_plugin_functions(p, plugins_root / p.name) for p in system_plugins_list
    ]
    system_results = await asyncio.gather(*system_tasks, return_exceptions=True)
    system_plugins = {
        p.name: p for p in system_results if p and not isinstance(p, Exception)
    }

    # 加载自定义插件函数
    custom_tasks = [
        load_plugin_functions(p, p._plugin_dir) for p in custom_plugins_list
    ]
    custom_results = await asyncio.gather(*custom_tasks, return_exceptions=True)
    custom_plugins = {
        p.name: p for p in custom_results if p and not isinstance(p, Exception)
    }

    system_count = len(system_plugins)
    custom_count = len(custom_plugins)

    # 合并所有插件
    plugins = {**system_plugins, **custom_plugins}

    # 显示插件统计
    print(f"\n  {'插件统计' if language == 'zh' else 'Plugin Statistics'}:")
    print(
        f"  ├─ {'系统插件' if language == 'zh' else 'System plugins'}: {system_count}"
    )
    if custom_count > 0:
        print(
            f"  ├─ {'自定义插件' if language == 'zh' else 'Custom plugins'}: {custom_count}"
        )
    print(f"  └─ {'总计' if language == 'zh' else 'Total'}: {len(plugins)}")

    # 生成 Router Index
    print(
        f"\n{'[2/3] 命令路由索引' if language == 'zh' else '[2/3] Command Router Index':^70}"
    )
    print(f"{'-' * 70}")

    router_index = build_router_index(plugins)
    router_path = write_router_index(router_index)
    print(f"  ✅ Router index: {router_path}")

    # 生成环境文件和补全脚本
    print(
        f"\n{'[3/3] 环境配置' if language == 'zh' else '[3/3] Environment Setup':^70}"
    )
    print(f"{'-' * 70}")

    # 检测或使用指定的 Shell
    if args.shell:
        current_shell = args.shell
    else:
        current_shell = detect_current_shell()

    print(f"  🐚 Shell: {current_shell}")

    # 使用模板引擎生成环境文件
    template_engine = get_template_engine()

    # 转换PluginMetadata对象为字典（template engine需要dict格式）
    # 从刚生成的router.json读取（包含完整的plugin metadata）
    import json

    router_path_for_template = cache_dir / "cache" / "router.json"
    with open(router_path_for_template, "r", encoding="utf-8") as f:
        router_data = json.load(f)
    plugins_dict = router_data.get("plugins", {})

    if current_shell == "fish":
        env_content = template_engine.render_env_fish(
            source_dir, cache_dir, plugins_dict, language, show_examples
        )
        env_file = source_dir / "env.fish"
    else:
        env_content = template_engine.render_env_sh(
            source_dir, cache_dir, plugins_dict, language, show_examples
        )
        env_file = source_dir / "env.sh"

    # 写入环境文件
    if env_file.exists():
        try:
            env_file.chmod(0o644)
        except Exception:
            pass

    env_file.write_text(env_content, encoding="utf-8")
    env_file.chmod(0o755)
    print(
        f"  ✅ {'环境文件' if language == 'zh' else 'Environment file'}: {env_file.name}"
    )

    # 生成补全脚本
    if not args.generate_completion:
        completions_dir = cache_dir / "completions"
        completions_dir.mkdir(parents=True, exist_ok=True)

        bash_file, zsh_file, fish_file = generate_completions_from_index(
            router_path, completions_dir, language=language
        )

        print(
            f"  ✅ {'补全脚本' if language == 'zh' else 'Completions'}: bash, zsh, fish"
        )

    # Shell 配置说明
    print(
        f"\n{'[4/5] Shell 配置说明' if language == 'zh' else '[4/5] Shell Configuration':^70}"
    )
    print(f"{'-' * 70}")

    if current_shell == "fish":
        config_file = Path.home() / ".config" / "fish" / "config.fish"
    elif current_shell == "zsh":
        config_file = Path.home() / ".zshrc"
    else:
        config_file = Path.home() / ".bashrc"

    print(f"\n  {'配置信息' if language == 'zh' else 'Configuration Info'}:")
    print(f"  ├─ Shell: {current_shell}")
    print(f"  └─ {'配置文件' if language == 'zh' else 'Config file'}: {config_file}")

    # 检查配置文件是否已包含环境加载
    if config_file.exists():
        with open(config_file, "r", encoding="utf-8") as f:
            content = f.read()

        if str(env_file) in content:
            print(
                f"\n  ✅ {'Shell 配置已存在' if language == 'zh' else 'Shell already configured'}"
            )
        else:
            print(
                f"\n  ⚠️  {'需要手动配置 Shell' if language == 'zh' else 'Shell configuration needed'}"
            )
            print(
                f"\n  {'请在配置文件中添加以下行' if language == 'zh' else 'Please add the following line to your config file'}:"
            )
            print(f"  {CYAN}source {env_file}{RESET}")
    else:
        print(
            f"\n  ℹ️  {'配置文件不存在，请创建' if language == 'zh' else 'Config file does not exist, please create it'}: {config_file}"
        )
        print(
            f"  {'并添加以下行' if language == 'zh' else 'And add the following line'}:"
        )
        print(f"  {CYAN}source {env_file}{RESET}")

    # 插件统计信息
    print(
        f"\n{'[5/5] 插件统计' if language == 'zh' else '[5/5] Plugin Statistics':^70}"
    )
    print(f"{'-' * 70}")

    # 计算启用/禁用的插件
    enabled_plugins = {}
    disabled_plugins = {}

    for name, plugin in plugins.items():
        # 优先从配置文件读取，如果配置文件没有则使用插件自身的enabled字段
        if name in system_plugins:
            # 系统插件：从 system_plugins 配置读取
            enabled = config.get("system_plugins", {}).get(name, plugin.enabled)
        elif name in custom_plugins:
            # 自定义插件：从 custom_plugins 配置读取
            enabled = config.get("custom_plugins", {}).get(name, plugin.enabled)
        else:
            # 未在配置中：使用插件自身的enabled字段（默认True）
            enabled = getattr(plugin, "enabled", True)

        if enabled:
            enabled_plugins[name] = plugin
        else:
            disabled_plugins[name] = plugin

    enabled_count = len(enabled_plugins)
    disabled_count = len(disabled_plugins)
    total_functions = sum(
        len(getattr(p, "functions", {})) for p in enabled_plugins.values()
    )

    print(
        f"\n  {'已启用插件' if language == 'zh' else 'Enabled plugins'}: {GREEN}{enabled_count}{RESET} / {len(plugins)}"
    )
    if disabled_count > 0:
        print(
            f"  {'已禁用插件' if language == 'zh' else 'Disabled plugins'}: {YELLOW}{disabled_count}{RESET}"
        )
    print(
        f"  {'可用命令数' if language == 'zh' else 'Available commands'}: {CYAN}{total_functions}{RESET}"
    )

    # 显示启用的插件列表
    if enabled_plugins:
        print(f"\n  {'启用的插件' if language == 'zh' else 'Enabled Plugins'}:")

        # 区分系统插件和自定义插件
        system_enabled = {
            k: v for k, v in enabled_plugins.items() if k in system_plugins
        }
        custom_enabled = {
            k: v for k, v in enabled_plugins.items() if k in custom_plugins
        }

        if system_enabled:
            print(f"    {'系统插件' if language == 'zh' else 'System Plugins'}:")
            for plugin_name in sorted(system_enabled.keys()):
                plugin = system_enabled[plugin_name]
                functions_count = len(getattr(plugin, "functions", {}))
                subplugins_count = len(getattr(plugin, "subplugins", []))
                print(
                    f"      {GREEN}✓{RESET} {plugin_name:15} ({functions_count} {'命令' if language == 'zh' else 'cmds'}, {subplugins_count} {'子插件' if language == 'zh' else 'subs'})"
                )

        if custom_enabled:
            print(f"    {'自定义插件' if language == 'zh' else 'Custom Plugins'}:")
            for plugin_name in sorted(custom_enabled.keys()):
                plugin = custom_enabled[plugin_name]
                functions_count = len(getattr(plugin, "functions", {}))
                subplugins_count = len(getattr(plugin, "subplugins", []))
                print(
                    f"      {GREEN}✓{RESET} {plugin_name:15} ({functions_count} {'命令' if language == 'zh' else 'cmds'}, {subplugins_count} {'子插件' if language == 'zh' else 'subs'})"
                )

    # 安装完成
    print(f"\n{'=' * 70}")
    print(
        f"{'🎉 ' + ('安装完成！' if language == 'zh' else 'Installation Complete!'):^70}"
    )
    print(f"{'=' * 70}\n")

    print(f"{'📋 ' + ('使用说明' if language == 'zh' else 'Usage')}:")
    print(
        f"  1. {'重新加载 Shell 配置' if language == 'zh' else 'Reload shell configuration'}:"
    )
    print(f"     {CYAN}source {config_file}{RESET}")
    print(f"\n  2. {'使用命令' if language == 'zh' else 'Use commands'}:")
    print(
        f"     {CYAN}gs help{RESET}         # {'查看帮助' if language == 'zh' else 'Show help'}"
    )
    print(
        f"     {CYAN}gs status{RESET}       # {'查看系统状态' if language == 'zh' else 'Show system status'}"
    )
    print(
        f"     {CYAN}gs plugin list{RESET}  # {'查看插件列表' if language == 'zh' else 'List plugins'}"
    )

    # 项目信息
    print(f"\n{'📚 ' + ('项目信息' if language == 'zh' else 'Project Info')}:")
    print(f"  {'版本' if language == 'zh' else 'Version'}:    {GS_VERSION}")
    print(f"  {'源码目录' if language == 'zh' else 'Source'}:    {source_dir}")
    print(f"  {'配置目录' if language == 'zh' else 'Config'}:    {cache_dir}")
    print(
        f"  {'日志文件' if language == 'zh' else 'Log file'}:  {cache_dir / 'logs' / 'gs.log'}"
    )
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
