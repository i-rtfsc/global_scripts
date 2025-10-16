#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Global Scripts v6 - 自动安装脚本
"""

import os
import subprocess
import sys
import asyncio
from pathlib import Path
import platform
from typing import Dict, List, Tuple

# Add src directory to Python path for new structure
_SCRIPT_DIR = Path(__file__).parent.absolute()
# setup.py 在 scripts/ 目录下，需要向上一级到项目根目录
_PROJECT_ROOT = _SCRIPT_DIR.parent
sys.path.insert(0, str(_PROJECT_ROOT / 'src'))

# Import shell utils
from gscripts.utils.shell_utils import detect_current_shell

# 终端颜色定义
BOLD = '\033[1m'
BLUE = '\033[34m'
CYAN = '\033[36m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
RED = '\033[31m'
RESET = '\033[0m'

# 版本信息
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
    """显示ASCII banner（更稳定的对齐和颜色）"""
    art = r"""
  ____  _       _           _   ____            _       _
 / ___|(_) ___ | |__   __ _| | / ___|  ___ _ __(_)_ __ | |_ ___
| |  _ | |/ _ \| '_ \ / _` | | \___ \ / __| '__| | '_ \| __/ __|
| |_| || | (_) | |_) | (_| | |  ___) | (__| |  | | |_) | |_\__ \
 \____||_|\___/|_.__/ \__,_|_| |____/ \___|_|  |_| .__/ \__|___/
                                                 |_|
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


def generate_env_fish(source_dir: Path, cache_dir: Path, plugins: Dict[str, Dict],
                     language: str = 'zh', show_examples: bool = True) -> str:
    """生成 env.fish 文件内容（不加载 prompt theme）"""
    import json, datetime

    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    gs_root_path = str(source_dir.resolve())
    cache_dir_path = str(cache_dir.resolve())

    # 收集并排序 alias 插件
    aliases_to_load = []
    for plugin_name, plugin_info in plugins.items():
        alias_info = plugin_info.get('alias')
        if alias_info and isinstance(alias_info, dict):
            # 检查是否支持 fish
            shells = alias_info.get('shells', [])
            if 'fish' not in shells:
                continue

            # 获取 fish 的 sources
            sources = alias_info.get('sources')
            if isinstance(sources, dict):
                fish_sources = sources.get('fish', [])
            elif isinstance(sources, list):
                # 兼容旧格式：尝试查找 .fish 文件
                fish_sources = [s.replace('.sh', '.fish') for s in sources if '.sh' in s]
            else:
                fish_sources = []

            if fish_sources:
                aliases_to_load.append({
                    'name': plugin_name,
                    'interactive_only': alias_info.get('interactive_only', True),
                    'priority': alias_info.get('priority', 100),
                    'sources': fish_sources
                })

    # 按 priority 升序排序
    aliases_to_load.sort(key=lambda x: (x['priority'], x['name']))

    # 读取配置
    raw_cfg = {}
    cfg_path = source_dir / 'config' / 'gs.json'
    if cfg_path.exists():
        try:
            with open(cfg_path, 'r', encoding='utf-8') as f:
                raw_cfg = json.load(f)
        except Exception:
            raw_cfg = {}

    # 生成导出变量
    export_lines: List[str] = []
    for k, v in raw_cfg.items():
        if k in ('system_plugins', 'custom_plugins') or isinstance(v, (dict, list)):
            continue
        env_key = f"GS_{k.upper()}"
        if isinstance(v, bool):
            export_lines.append(f'set -gx {env_key} "{str(v).lower()}"')
        else:
            export_lines.append(f'set -gx {env_key} "{v}"')

    # 拆分 prompt_theme
    prompt_line = 'set -gx GS_PROMPT_THEME "bitstream"'
    other_exports: List[str] = []
    for line in export_lines:
        if line.startswith('set -gx GS_PROMPT_THEME'):
            prompt_line = line
        else:
            other_exports.append(line)

    # 构建 env.fish 内容
    lines: List[str] = [
        '#!/usr/bin/env fish',
        '# Global Scripts V6 Environment Configuration (Fish Shell)',
        '# Generated automatically - do not edit manually',
        f'# Generated at: {timestamp}',
        f'# Configuration source: {source_dir}',
        '',
        '# Global Scripts root directory (absolute path)',
        f'set -gx GS_ROOT "{gs_root_path}"',
        '',
        '# Language setting - Controls UI language for all commands',
        f'set -gx GS_LANGUAGE "{language}"',
        '',
        '# V6 Configuration Variables (from gs.json)',
        *(other_exports if other_exports else ['# (no config exports found)']),
        f'set -gx GS_CONFIG_SHOW_EXAMPLES "{str(show_examples).lower()}"',
        prompt_line,
        '',
        '# Add Global Scripts to PATH',
        '# Prepend GS_ROOT to PATH if not present',
        'if not contains $GS_ROOT $PATH',
        '    set -gx PATH $GS_ROOT $PATH',
        'end',
        '',
        '# Global Scripts version',
        f'set -gx GS_VERSION "{GS_VERSION}"',
        '',
        '# Platform detection',
        f'set -gx GS_PLATFORM "{platform.system().lower()}"',
        '',
        '# Cache directory',
    # NOTE: For fish previously GS_CACHE_DIR pointed to parent dir, causing router.json lookup to fail.
    # Align with bash/zsh: always expose the /cache directory itself so path resolution is consistent.
    f'set -gx GS_CACHE_DIR "{cache_dir_path}/cache"',
        '',
        '# Load router script (if exists)',
        'if test -r "$GS_ROOT/src/gscripts/scripts/gs-router.fish"',
        '    source "$GS_ROOT/src/gscripts/scripts/gs-router.fish"',
        'end',
        '',
        '# Main gs() function with command routing',
        'function gs --description "Global Scripts main command"',
        '    set -l router_index "$GS_CACHE_DIR/router.json"',
        '',
        '    # If no router index or jq not available, fall back to Python',
        '    if not test -f "$router_index"; or not command -v jq >/dev/null 2>&1',
        '        uv run --directory "$GS_ROOT" python -m gscripts.cli.main $argv',
        '        return $status',
        '    end',
        '',
        '    # System commands always go to Python',
        '    if test (count $argv) -eq 0; or contains -- $argv[1] help version plugin status doctor refresh',
        '        uv run --directory "$GS_ROOT" python -m gscripts.cli.main $argv',
        '        return $status',
        '    end',
        '',
        '    # Query router index to determine command type',
        '    set -l plugin_name $argv[1]',
        '    set -l query ""',
        '',
        '',
        '    if test (count $argv) -eq 1',
        '        set query $plugin_name',
        '    else if test (count $argv) -eq 2',
        '        set query $argv[2]',
        '    else if test (count $argv) -ge 3',
        '        # Try two-token form first',
        '        set -l two_token "$argv[2] $argv[3]"',
        '        set -l has_two_token (jq -r --arg plugin "$plugin_name" --arg query "$two_token" \\',
        r'            ".plugins[\$plugin].commands[\$query] // empty" "$router_index" 2>/dev/null)',
        '',
        '',
        '        if test -n "$has_two_token"',
        '            set query "$two_token"',
        '        else',
        '            set query $argv[3]',
        '        end',
        '    end',
        '',
        '    # Get command metadata',
        '    set -l meta (jq -c --arg plugin "$plugin_name" --arg query "$query" \\',
        r'        ".plugins[\$plugin].commands[\$query] // empty" "$router_index" 2>/dev/null)',
        '',
        '',
        '    if test -z "$meta"; or test "$meta" = "null"',
        '        # Command not found in router, fall back to Python',
        '        uv run --directory "$GS_ROOT" python -m gscripts.cli.main $argv',
        '        return $status',
        '    end',
        '',
        '    # Check if plugin is enabled',
        '    set -l plugin_enabled (jq -r --arg plugin "$plugin_name" \\',
        '        \'.plugins[$plugin].enabled\' "$router_index" 2>/dev/null)',
        '',
        '    if test -z "$plugin_enabled"; or test "$plugin_enabled" = "null"',
        '        set plugin_enabled true',
        '    end',
        '',
        '    if test "$plugin_enabled" = "false"',
        '        echo "错误: 插件 \'$plugin_name\' 已被禁用" >&2',
        '        echo "提示: 使用 \'gs plugin enable $plugin_name\' 启用插件" >&2',
        '        return 1',
        '    end',
        '',
        '    set -l kind (echo "$meta" | jq -r \'.kind // "python"\')',
        '',
        '    # Route based on command type',
        '    switch $kind',
        '        case json',
        '            # JSON commands: execute in current shell',
        '            set -l command_tpl (echo "$meta" | jq -r \'.command // empty\')',
        '            if test -z "$command_tpl"',
        '                echo "Error: No command template defined for json type" >&2',
        '                return 1',
        '            end',
        '',
        '            # Execute command (ensure cd/export take effect in current shell)',
        '            if test (count $argv) -gt 2',
        '                eval "$command_tpl" $argv[3..-1]',
        '            else',
        '                eval "$command_tpl"',
        '            end',
        '        case shell',
        '            # Use shell router',
        '            gs-router $argv',
        '        case \'*\'',
        '            # Use Python CLI (default)',
        '            uv run --directory "$GS_ROOT" python -m gscripts.cli.main $argv',
        '    end',
        'end',
        '',
        '# Quick reload alias',
        'function gsreload --description "Reload Global Scripts environment"',
        '    gs refresh >/dev/null 2>&1',
        '    and source "$GS_ROOT/env.fish"',
        '    and echo "✅ Global Scripts 环境已重新加载！"',
        'end',
        '',
        '# Initialize conda if available',
        'if not command -v conda >/dev/null 2>&1',
        '    for conda_base in "$HOME/miniconda3" "$HOME/anaconda3" "$HOME/miniforge3" \\',
        '                      "/opt/miniconda3" "/opt/anaconda3" "/opt/miniforge3" \\',
        '                      "/usr/local/miniconda3" "/usr/local/anaconda3"',
        '        if test -f "$conda_base/etc/profile.d/conda.sh"',
        '            bass source "$conda_base/etc/profile.d/conda.sh" 2>/dev/null',
        '            break',
        '        end',
        '    end',
        'end',
        '',
        '# Load generated completion scripts',
        'if test -d "$GS_CACHE_DIR/completions"',
        '    for comp_file in $GS_CACHE_DIR/completions/*.fish',
        '        test -r "$comp_file"; and source "$comp_file"',
        '    end',
        'end',
        '',
        '# Alias loading section',
    ]

    # 生成 alias 加载段（混合方案）
    if aliases_to_load:
        lines.extend([
            '# BEGIN aliases',
            ''
        ])

        for alias_info in aliases_to_load:
            plugin_name = alias_info['name']
            interactive_only = alias_info['interactive_only']
            sources = alias_info['sources']
            priority = alias_info['priority']

            lines.append(f'# Plugin: {plugin_name}, Priority: {priority}')

            # 交互式检查
            if interactive_only:
                lines.append('if status is-interactive')
                indent = '    '
            else:
                indent = ''

            # 加载每个 source 文件（混合方案）
            for source_path in sources:
                full_path_fish = f'"$GS_ROOT/plugins/{plugin_name}/{source_path}"'
                full_path_sh = f'"$GS_ROOT/plugins/{plugin_name}/{source_path.replace(".fish", ".sh")}"'

                # 平台检测
                if 'darwin' in source_path.lower():
                    lines.append(f'{indent}# Load Darwin-specific aliases')
                    lines.append(f'{indent}if test (uname -s) = "Darwin"')
                    lines.append(f'{indent}    # Try .fish first, fallback to bass + .sh')
                    lines.append(f'{indent}    if test -f {full_path_fish}')
                    lines.append(f'{indent}        source {full_path_fish}')
                    lines.append(f'{indent}    else if type -q bass; and test -f {full_path_sh}')
                    lines.append(f'{indent}        bass source {full_path_sh}')
                    lines.append(f'{indent}    end')
                    lines.append(f'{indent}end')
                elif 'linux' in source_path.lower():
                    lines.append(f'{indent}# Load Linux-specific aliases')
                    lines.append(f'{indent}if test (uname -s) = "Linux"')
                    lines.append(f'{indent}    # Try .fish first, fallback to bass + .sh')
                    lines.append(f'{indent}    if test -f {full_path_fish}')
                    lines.append(f'{indent}        source {full_path_fish}')
                    lines.append(f'{indent}    else if type -q bass; and test -f {full_path_sh}')
                    lines.append(f'{indent}        bass source {full_path_sh}')
                    lines.append(f'{indent}    end')
                    lines.append(f'{indent}end')
                else:
                    # 通用文件
                    lines.append(f'{indent}# Load common aliases (hybrid: .fish or bass + .sh)')
                    lines.append(f'{indent}if test -f {full_path_fish}')
                    lines.append(f'{indent}    source {full_path_fish}')
                    lines.append(f'{indent}else if type -q bass; and test -f {full_path_sh}')
                    lines.append(f'{indent}    bass source {full_path_sh}')
                    lines.append(f'{indent}end')

            if interactive_only:
                lines.append('end')
            lines.append('')

        lines.extend([
            '# END aliases',
            ''
        ])

    lines.append('')

    return '\n'.join(lines) + '\n'


def generate_fish_completion(plugins: Dict[str, Dict]) -> str:
    """生成 fish 补全脚本 - 动态从 router index 读取"""
    import json

    # 过滤启用的插件
    enabled_plugins = {}
    language = 'zh'

    try:
        from gscripts.core.config_manager import ConfigManager

        # 使用 ConfigManager 获取合并后的配置
        config_manager = ConfigManager()
        cfg = config_manager.get_config() or {}

        system_map = cfg.get('system_plugins', {}) or {}
        custom_map = cfg.get('custom_plugins', {}) or {}
        language = cfg.get('language', 'zh')

        for name, pinfo in plugins.items():
            if system_map.get(name, False) or custom_map.get(name, False):
                enabled_plugins[name] = pinfo
    except Exception:
        enabled_plugins = plugins

    plugin_names = list(enabled_plugins.keys())
    router_index_path = str(Path.home() / ".config" / "global-scripts" / "cache" / "router.json")

    # Get system command descriptions from i18n
    try:
        from gscripts.utils.i18n import I18nManager
        i18n = I18nManager(chinese=(language == 'zh'))
        help_desc = i18n.get_message('commands.help')
        version_desc = i18n.get_message('commands.version')
        plugin_desc = i18n.get_message('commands.plugin_management')
        refresh_desc = i18n.get_message('commands.refresh')
        status_desc = i18n.get_message('commands.system_status')
        doctor_desc = i18n.get_message('commands.doctor')
        parser_desc = i18n.get_message('commands.parser_management')
    except Exception:
        # Fallback to hardcoded if i18n fails
        if language == 'zh':
            help_desc = '显示帮助信息'
            version_desc = '显示版本信息'
            plugin_desc = '插件管理'
            refresh_desc = '刷新系统'
            status_desc = '显示系统状态'
            doctor_desc = '系统诊断'
            parser_desc = '解析器管理'
        else:
            help_desc = 'Show help information'
            version_desc = 'Show version information'
            plugin_desc = 'Plugin management'
            refresh_desc = 'Refresh configuration'
            status_desc = 'Show system status'
            doctor_desc = 'Check system health'
            parser_desc = 'Parser management'

    # 生成动态补全脚本 - 完全动态化，从 router index 读取所有数据
    completion_script = f'''# Global Scripts v6 Fish Completion - Dynamic router index support
# Auto-generated - All data dynamically loaded from router index

# Router index path for dynamic lookup
set -g _GS_ROUTER_INDEX "{router_index_path}"
set -g _GS_LANGUAGE "{language}"

# System commands (static)
set -g _GS_SYSTEM_COMMANDS "help version plugin refresh status doctor parser"

# Helper function to get the plugin name (second argument)
function __fish_gs_plugin
    set -l cmd (commandline -opc)
    if test (count $cmd) -ge 2
        echo $cmd[2]
    end
end

# Helper function to get the subplugin name (third argument)
function __fish_gs_subplugin
    set -l cmd (commandline -opc)
    if test (count $cmd) -ge 3
        echo $cmd[3]
    end
end

# Helper function to check if we're at a specific position
function __fish_gs_needs_subplugin
    set -l cmd (commandline -opc)
    test (count $cmd) -eq 2
end

function __fish_gs_needs_function
    set -l cmd (commandline -opc)
    test (count $cmd) -eq 3
end

# Dynamic plugin completion - read from router index (Level 1)
function __fish_gs_plugins
    # Check if jq is available
    if not command -q jq
        return
    end

    # Get all plugin names
    set -l plugins (jq -r ".plugins | keys[]" "$_GS_ROUTER_INDEX" 2>/dev/null)

    for plugin in $plugins
        # Get description
        set -l desc (jq -r ".plugins[\\"$plugin\\"].description.$_GS_LANGUAGE // .plugins[\\"$plugin\\"].description.zh // .plugins[\\"$plugin\\"].description.en // \\"\\"" "$_GS_ROUTER_INDEX" 2>/dev/null)

        if test -n "$desc"; and test "$desc" != "null"
            echo -e "$plugin\\t$desc"
        else
            echo "$plugin"
        end
    end
end

# Dynamic subplugin completion - read from router index (Level 2)
function __fish_gs_subplugins
    set -l plugin (__fish_gs_plugin)
    if test -z "$plugin"
        return
    end

    # Check if jq is available
    if not command -q jq
        return
    end

    # Get subplugins count
    set -l count (jq -r ".plugins[\\"$plugin\\"].subplugins | length" "$_GS_ROUTER_INDEX" 2>/dev/null)

    if test -n "$count"; and test "$count" != "null"; and test "$count" != "0"
        # Plugin has subplugins, iterate and extract name and description
        for i in (seq 0 (math $count - 1))
            set -l name (jq -r ".plugins[\\"$plugin\\"].subplugins[$i].name" "$_GS_ROUTER_INDEX" 2>/dev/null)
            set -l desc (jq -r ".plugins[\\"$plugin\\"].subplugins[$i].description.$_GS_LANGUAGE // .plugins[\\"$plugin\\"].subplugins[$i].description.zh // .plugins[\\"$plugin\\"].subplugins[$i].description.en // \\"\\"" "$_GS_ROUTER_INDEX" 2>/dev/null)

            if test -n "$name"; and test "$name" != "null"
                if test -n "$desc"; and test "$desc" != "null"
                    echo -e "$name\\t$desc"
                else
                    echo "$name"
                end
            end
        end
    else
        # No subplugins, fallback to extracting first words from commands (like zsh version)
        set -l commands (jq -r ".plugins[\\"$plugin\\"].commands | keys[]" "$_GS_ROUTER_INDEX" 2>/dev/null)

        # Use associative array to track seen first words
        set -l seen_words
        for cmd in $commands
            # Extract first word
            set -l first_word (echo "$cmd" | awk '{{print $1}}')

            # Skip if already seen
            if contains -- "$first_word" $seen_words
                continue
            end
            set -a seen_words "$first_word"

            # Get description for this command
            set -l desc (jq -r ".plugins[\\"$plugin\\"].commands[\\"$cmd\\"].description.$_GS_LANGUAGE // .plugins[\\"$plugin\\"].commands[\\"$cmd\\"].description.zh // .plugins[\\"$plugin\\"].commands[\\"$cmd\\"].description.en // \\"\\"" "$_GS_ROUTER_INDEX" 2>/dev/null)

            if test -n "$desc"; and test "$desc" != "null"
                echo -e "$first_word\\t$desc"
            else
                echo "$first_word"
            end
        end
    end
end

# Dynamic function completion - read from router index (Level 3+)
function __fish_gs_functions
    set -l plugin (__fish_gs_plugin)
    set -l subplugin (__fish_gs_subplugin)

    if test -z "$plugin"
        return
    end

    # Check if jq is available
    if not command -q jq
        return
    end

    # Build command prefix
    set -l cmd_prefix ""
    if test -n "$subplugin"
        set cmd_prefix "$subplugin "
    end

    # Get all commands that start with the prefix
    set -l commands (jq -r ".plugins[\\"$plugin\\"].commands | keys[]" "$_GS_ROUTER_INDEX" 2>/dev/null | grep "^$cmd_prefix")

    for cmd in $commands
        # Extract the next word after prefix
        set -l remaining (echo "$cmd" | sed "s/^$cmd_prefix//")
        set -l next_word (echo "$remaining" | awk '{{print $1}}')

        if test -n "$next_word"
            # Get description
            set -l desc (jq -r ".plugins[\\"$plugin\\"].commands[\\"$cmd\\"].description.$_GS_LANGUAGE // .plugins[\\"$plugin\\"].commands[\\"$cmd\\"].description.zh // .plugins[\\"$plugin\\"].commands[\\"$cmd\\"].description.en // \\"\\"" "$_GS_ROUTER_INDEX" 2>/dev/null)

            if test -n "$desc"; and test "$desc" != "null"
                echo -e "$next_word\\t$desc"
            else
                echo "$next_word"
            end
        end
    end | sort -u
end

# Helper to check if we need plugin name completion (for plugin info/enable/disable)
function __fish_gs_needs_plugin_name
    set -l cmd (commandline -opc)
    if test (count $cmd) -eq 3
        if test "$cmd[2]" = "plugin"
            if contains -- "$cmd[3]" info enable disable
                return 0
            end
        end
    end
    return 1
end

# Helper to check if we need parameter completion (Level 4+)
function __fish_gs_needs_param
    set -l cmd (commandline -opc)
    test (count $cmd) -ge 4
end

# Helper to get the full command path for parameter lookup
function __fish_gs_get_command_path
    set -l cmd (commandline -opc)
    set -l count (count $cmd)

    if test $count -lt 4
        return
    end

    # Build command path from index 3 onwards (config install)
    # cmd layout: [1:gs, 2:system, 3:config, 4:install, ...]
    set -l path ""
    for i in (seq 3 $count)
        if test -n "$path"
            set path "$path $cmd[$i]"
        else
            set path "$cmd[$i]"
        end
    end

    echo "$path"
end

# Dynamic parameter completion - read completions from router index (Level 4+)
function __fish_gs_params
    set -l plugin (__fish_gs_plugin)
    set -l cmd_path (__fish_gs_get_command_path)

    if test -z "$plugin"; or test -z "$cmd_path"
        return
    end

    # Check if jq is available
    if not command -q jq
        return
    end

    # Get completions for this command from router index
    set -l completions (jq -r ".plugins[\\"$plugin\\"].commands[\\"$cmd_path\\"].completions[]?" "$_GS_ROUTER_INDEX" 2>/dev/null)

    if test -n "$completions"
        for item in $completions
            echo "$item"
        end
    end
end

# Main gs command completion
complete -c gs -f

# First level: system commands (static)
complete -c gs -n "__fish_use_subcommand" -a "help" -d "{help_desc}"
complete -c gs -n "__fish_use_subcommand" -a "version" -d "{version_desc}"
complete -c gs -n "__fish_use_subcommand" -a "plugin" -d "{plugin_desc}"
complete -c gs -n "__fish_use_subcommand" -a "refresh" -d "{refresh_desc}"
complete -c gs -n "__fish_use_subcommand" -a "status" -d "{status_desc}"
complete -c gs -n "__fish_use_subcommand" -a "doctor" -d "{doctor_desc}"
complete -c gs -n "__fish_use_subcommand" -a "parser" -d "{parser_desc}"

# First level: plugins (dynamic from router index)
complete -c gs -n "__fish_use_subcommand" -a "(__fish_gs_plugins)"

# Plugin subcommands (only show when no subcommand selected yet)
complete -c gs -n "__fish_seen_subcommand_from plugin; and not __fish_seen_subcommand_from list info enable disable create" -a "list info enable disable create" -d "Plugin commands"

# Parser subcommands
complete -c gs -n "__fish_seen_subcommand_from parser; and not __fish_seen_subcommand_from list info enable disable test" -a "list" -d "List all parsers"
complete -c gs -n "__fish_seen_subcommand_from parser; and not __fish_seen_subcommand_from list info enable disable test" -a "info" -d "Show parser information"
complete -c gs -n "__fish_seen_subcommand_from parser; and not __fish_seen_subcommand_from list info enable disable test" -a "enable" -d "Enable a parser"
complete -c gs -n "__fish_seen_subcommand_from parser; and not __fish_seen_subcommand_from list info enable disable test" -a "disable" -d "Disable a parser"
complete -c gs -n "__fish_seen_subcommand_from parser; and not __fish_seen_subcommand_from list info enable disable test" -a "test" -d "Test file parsing"

# Plugin name completion for info/enable/disable commands
complete -c gs -n "__fish_gs_needs_plugin_name" -a "(__fish_gs_plugins)"

# Dynamic subplugin completions (Level 2)
complete -c gs -n "__fish_gs_needs_subplugin" -a "(__fish_gs_subplugins)"

# Dynamic parameter completions (Level 4+) - Check this BEFORE Level 3!
complete -c gs -n "__fish_gs_needs_param" -a "(__fish_gs_params)"

# Dynamic function completions (Level 3)
complete -c gs -n "__fish_gs_needs_function" -a "(__fish_gs_functions)"
'''

    return completion_script


def load_config_from_json() -> tuple[str | None, bool | None]:
    """通过 ConfigManager 加载合并后的配置，提取 language / show_examples
    优先顺序：用户配置(~/.config/global-scripts/config/gs.json) 覆盖 项目配置(config/gs.json)
    若键缺失则返回 (None, None) 对应项。
    """
    try:
        # 延迟导入，避免在极简环境下阻塞
        from gscripts.core.config_manager import ConfigManager  # type: ignore
        cm = ConfigManager()
        cfg = cm.get_config() or {}
        return cfg.get('language'), cfg.get('show_examples')
    except Exception as e:
        # 回退到直接读取项目级 config/gs.json（保持兼容）
        try:
            import json
            cfg_path = Path.cwd() / 'config' / 'gs.json'
            if cfg_path.exists():
                with open(cfg_path, 'r', encoding='utf-8') as f:
                    cfg = json.load(f)
                return cfg.get('language'), cfg.get('show_examples')
        except Exception:
            pass
        print(f"Warning: failed to load config via ConfigManager: {e}")
    return None, None

def select_language(auto_mode: bool = False) -> str:
    """选择语言设置"""
    if auto_mode:
        # 自动模式：默认使用英文，用于脚本自动化
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
                # 默认中文
                print(f"{GREEN}✅ 已选择中文{RESET}")
                return 'zh'
            elif choice == '2':
                print(f"{GREEN}✅ English selected{RESET}")
                return 'en'
            else:
                print(f"{RED}❌ Invalid choice. Please enter 1 or 2 / 无效选择，请输入1或2{RESET}")
        except KeyboardInterrupt:
            print(f"\n{YELLOW}⚠️  Installation cancelled / 安装已取消{RESET}")
            sys.exit(0)
        except Exception:
            print(f"{RED}❌ Invalid input / 输入无效{RESET}")

def ask_show_examples(language: str = 'zh', auto_mode: bool = False) -> bool:
    """询问是否启用示例插件显示"""
    if auto_mode:
        # 自动模式：默认启用示例插件
        print(f"{GREEN}✅ Example plugins enabled (auto mode){RESET}")
        return True
    
    if language == 'zh':
        print(f"\n{BOLD}📚 示例插件配置{RESET}")
        print(f"""
{CYAN}Global Scripts 包含了完整的插件开发示例，包括：{RESET}
• JSON配置插件示例
• Shell脚本插件示例  
• Python装饰器插件示例
• 混合插件示例（JSON+Shell+Python）
• 带子插件的复杂示例

{YELLOW}是否在插件列表中显示这些示例插件？{RESET}
1. {GREEN}是{RESET} - 启用示例插件显示（推荐用于学习）
2. {RED}否{RESET} - 仅显示系统插件
""")
        prompt = f"{YELLOW}请选择 (1/2, 回车=否): {RESET}"
        yes_choice = '1'
        no_choice = '2'
    else:  # English
        print(f"\n{BOLD}📚 Example Plugins Configuration{RESET}")
        print(f"""
{CYAN}Global Scripts includes comprehensive plugin development examples:{RESET}
• JSON configuration plugin examples
• Shell script plugin examples
• Python decorator plugin examples  
• Hybrid plugin examples (JSON+Shell+Python)
• Complex examples with subplugins

{YELLOW}Show these example plugins in plugin list?{RESET}
1. {GREEN}Yes{RESET} - Enable example plugins display (recommended for learning)
2. {RED}No{RESET} - Show system plugins only
""")
        prompt = f"{YELLOW}Please select (1/2, Enter=No): {RESET}"
        yes_choice = '1'
        no_choice = '2'
    
    while True:
        try:
            choice = input(prompt).strip()
            if choice == '':
                # 默认不启用示例
                if language == 'zh':
                    print(f"{YELLOW}⚠️  示例插件显示已禁用{RESET}")
                else:
                    print(f"{YELLOW}⚠️  Example plugins display disabled{RESET}")
                return False
            if choice == yes_choice:
                if language == 'zh':
                    print(f"{GREEN}✅ 示例插件显示已启用{RESET}")
                else:
                    print(f"{GREEN}✅ Example plugins display enabled{RESET}")
                return True
            elif choice == no_choice:
                if language == 'zh':
                    print(f"{YELLOW}⚠️  示例插件显示已禁用{RESET}")
                else:
                    print(f"{YELLOW}⚠️  Example plugins display disabled{RESET}")
                return False
            else:
                if language == 'zh':
                    print(f"{RED}❌ 无效选择，请输入1或2{RESET}")
                else:
                    print(f"{RED}❌ Invalid choice. Please enter 1 or 2{RESET}")
        except KeyboardInterrupt:
            if language == 'zh':
                print(f"\n{YELLOW}⚠️  安装已取消{RESET}")
            else:
                print(f"\n{YELLOW}⚠️  Installation cancelled{RESET}")
            sys.exit(0)
        except Exception:
            if language == 'zh':
                print(f"{RED}❌ 输入无效{RESET}")
            else:
                print(f"{RED}❌ Invalid input{RESET}")

def get_language_config(lang: str) -> Dict[str, str]:
    """获取语言配置"""
    if lang == 'en':
        return {
            'install_title': "🚀 Global Scripts v6 Setup",
            'source_dir': "📁 Source Directory (SOURCE_DIR)",
            'cache_dir': "📁 Cache Directory (CACHE_DIR)", 
            'scanning': "🔍 Scanning plugin directory",
            'found_plugins': "📦 Found plugins",
            'generating_env': "📝 Generating environment script",
            'env_success': "✅ Environment script generated successfully",
            'bash_completion': "✅ Bash completion script",
            'zsh_completion': "✅ Zsh completion script",
            'config_info': "📋 Configuration Info:",
            'detected_shell': "Detected Shell",
            'config_file': "Config File",
            'shell_configured': "✅ Shell functions configured",
            'install_complete': "🎉 Installation Complete!",
            'usage_info': "📋 Usage:",
            'reload_shell': "1. Reload shell config: source",
            'use_command': "2. Use commands: gs help",
            'shortcuts': "3. Try: gs plugin list, gs status",
            'available_plugins': "📦 Available plugins:",
            'more_info': "📚 More info: README.md",
            'config_dir_info': "📝 Config directory",
            'log_file': "📄 Log file"
        }
    else:  # zh
        return {
            'install_title': "🚀 Global Scripts v6 安装程序",
            'source_dir': "📁 源码目录 (SOURCE_DIR)",
            'cache_dir': "📁 缓存目录 (CACHE_DIR)",
            'scanning': "🔍 扫描插件目录",
            'found_plugins': "📦 发现",
            'generating_env': "📝 生成环境脚本",
            'env_success': "✅ 环境脚本生成成功",
            'bash_completion': "✅ Bash补全脚本",
            'zsh_completion': "✅ Zsh补全脚本",
            'config_info': "📋 配置说明:",
            'detected_shell': "检测到Shell",
            'config_file': "配置文件",
            'shell_configured': "✅ Shell函数已配置",
            'install_complete': "🎉 安装完成!",
            'usage_info': "📋 使用方法:",
            'reload_shell': "1. 重新加载Shell配置: source",
            'use_command': "2. 使用命令: gs help",
            'shortcuts': "3. 可试试: gs plugin list, gs status",
            'available_plugins': "📦 可用插件:",
            'more_info': "📚 更多信息请参考: README.md",
            'config_dir_info': "📝 配置目录",
            'log_file': "📄 日志文件"
        }


async def discover_plugins_recursive(plugins_root: Path, parent_path: str = "") -> Dict[str, Dict]:
    """递归发现并分析插件结构，支持嵌套目录"""
    plugins = {}

    if not plugins_root.exists():
        return plugins

    for item in plugins_root.iterdir():
        # 跳过非目录、隐藏目录、__pycache__ 等无效目录
        if (not item.is_dir() or
            item.name.startswith('.') or
            item.name.startswith('__') or
            item.name in ('__pycache__', '.git', '.svn', 'node_modules')):
            continue

        # 检查是否是插件目录（包含plugin.json或plugin.py）
        plugin_json = item / "plugin.json"
        plugin_py = item / "plugin.py"

        if plugin_json.exists() or plugin_py.exists():
            # 这是一个插件目录，读取真实插件名
            if plugin_json.exists():
                try:
                    import json
                    with open(plugin_json, 'r', encoding='utf-8') as f:
                        config = json.load(f)
                    plugin_name = config.get('name')
                    if not plugin_name:
                        print(f"⚠️  插件目录 {item} 的 plugin.json 缺少 name 字段，跳过")
                        continue
                except Exception as e:
                    print(f"⚠️  读取插件配置失败 {plugin_json}: {e}，跳过")
                    continue
            else:
                # 如果只有plugin.py没有plugin.json，跳过
                print(f"⚠️  插件目录 {item} 没有 plugin.json，跳过")
                continue

            plugin_info = await _analyze_single_plugin(item, plugin_name)
            plugins[plugin_name] = plugin_info
        else:
            # 这是一个普通目录，递归搜索
            nested_path = f"{parent_path}/{item.name}" if parent_path else item.name
            nested_plugins = await discover_plugins_recursive(item, nested_path)
            plugins.update(nested_plugins)

    return plugins


async def _analyze_single_plugin(plugin_dir: Path, plugin_name: str) -> Dict:
    """分析单个插件目录"""
    plugin_info = {
        'name': plugin_name,
        'enabled': True,
        'functions': [],
        'subplugins': [],
        'subplugin_functions': {}
    }

    # 检查plugin.json配置文件
    plugin_json = plugin_dir / "plugin.json"
    if plugin_json.exists():
        try:
            import json
            with open(plugin_json, 'r', encoding='utf-8') as f:
                json_config = json.load(f)

            # 保留完整的plugin.json配置
            plugin_info.update(json_config)

            # 确保必要的字段存在
            if 'functions' not in plugin_info:
                plugin_info['functions'] = []
            if 'subplugins' not in plugin_info:
                plugin_info['subplugins'] = []
            if 'subplugin_functions' not in plugin_info:
                plugin_info['subplugin_functions'] = {}

            # 从plugin.json获取子插件列表
            if 'subplugins' in json_config:
                plugin_info['subplugins'] = json_config['subplugins']

                # 为每个子插件发现函数
                for subplugin_name in plugin_info['subplugins']:
                    subplugin_dir = plugin_dir / subplugin_name
                    if subplugin_dir.exists():
                        subplugin_functions = await _discover_subplugin_functions(subplugin_dir, subplugin_name)
                        plugin_info['subplugin_functions'][subplugin_name] = subplugin_functions

                        # 添加到总函数列表，格式为 subplugin-function
                        for func_name in subplugin_functions:
                            plugin_info['functions'].append(f"{subplugin_name}-{func_name}")

            # 处理直接命令（如navigator插件）
            if 'commands' in json_config:
                # 对于有commands字段的插件，将命令名作为函数列表
                command_names = list(json_config['commands'].keys())
                plugin_info['functions'].extend(command_names)
                # 也可以将这些命令当作"直接命令"处理
                plugin_info['direct_commands'] = command_names

        except Exception as e:
            print(f"⚠️  解析插件配置 {plugin_name} 时出错: {e}")

    # 检查Python插件文件（兼容旧格式）
    plugin_py = plugin_dir / "plugin.py"
    if plugin_py.exists():
        try:
            # 解析Python文件来提取插件结构
            with open(plugin_py, 'r', encoding='utf-8') as f:
                content = f.read()

            import re

            # 提取子插件
            subplugin_pattern = r'@subplugin\(["\']([^"\']+)["\']'
            subplugins = re.findall(subplugin_pattern, content)

            # 如果没有从JSON获取子插件，则从Python文件获取
            if not plugin_info['subplugins']:
                plugin_info['subplugins'] = subplugins

            # 为每个子插件提取函数
            for subplugin_name in subplugins:
                if subplugin_name not in plugin_info['subplugin_functions']:
                    # 查找该子插件类中的函数
                    class_pattern = rf'@subplugin\(["\']' + subplugin_name + r'["\'][\s\S]*?class\s+\w+.*?:\s*([\s\S]*?)(?=\n\n@|\nclass|\n#|\Z)'
                    class_match = re.search(class_pattern, content)

                    if class_match:
                        class_content = class_match.group(1)
                        # 在类内容中查找@plugin_function装饰器
                        func_pattern = r'@plugin_function\s*\(\s*name=["\']([^"\']+)["\']'
                        functions = re.findall(func_pattern, class_content)

                        plugin_info['subplugin_functions'][subplugin_name] = functions
                        # 也添加到总的functions列表中，格式为 subplugin-function
                        for func_name in functions:
                            plugin_info['functions'].append(f"{subplugin_name}-{func_name}")

            # 如果没有子插件，查找直接的@plugin_function装饰器
            if not plugin_info['subplugins']:
                func_pattern = r'@plugin_function\s*\(\s*name=["\']([^"\']+)["\']'
                functions = re.findall(func_pattern, content)
                plugin_info['functions'].extend(functions)

        except Exception as e:
            print(f"⚠️  解析Python插件 {plugin_name} 时出错: {e}")

    return plugin_info


async def discover_plugins(plugins_root: Path) -> Dict[str, Dict]:
    """发现并分析插件结构 - 直接使用PluginLoader，避免重复实现

    新版本直接复用gs_system.core.plugin_loader的逻辑，避免了大量的正则表达式解析。
    PluginLoader已经能够正确处理：
    - 从plugin.json读取插件名称和元数据
    - 解析Python装饰器(@plugin_function)获取函数信息
    - 处理子插件结构
    - 配置文件中的commands字段

    这比setup.py中自己实现正则解析要更可靠和maintainable。
    """
    from gscripts.core.plugin_loader import PluginLoader
    from gscripts.core.config_manager import ConfigManager

    try:
        # 使用PluginLoader加载插件
        loader = PluginLoader(plugins_root)
        plugins = await loader.load_all_plugins()

        # 获取启用状态
        try:
            config_manager = ConfigManager()
            config = config_manager.get_config() or {}
            system_plugins = config.get('system_plugins', {})
            custom_plugins = config.get('custom_plugins', {})
        except Exception:
            system_plugins = {}
            custom_plugins = {}

        result = {}
        for plugin_name, plugin in plugins.items():
            # 获取插件基本信息
            plugin_info = {
                'name': plugin.name,
                'enabled': system_plugins.get(plugin_name, custom_plugins.get(plugin_name, True)),
                'functions': [],
                'subplugins': [],
                'subplugin_functions': {}
            }

            # 从plugin对象获取元数据
            if hasattr(plugin, 'version'):
                plugin_info['version'] = plugin.version
            if hasattr(plugin, 'description'):
                plugin_info['description'] = plugin.description
            if hasattr(plugin, 'author'):
                plugin_info['author'] = plugin.author

            # 检查是否有特殊的direct_commands（如navigator）和alias配置
            is_json_plugin = False
            if hasattr(plugin, '_plugin_json_config'):
                json_config = plugin._plugin_json_config
                # 检查是否是 JSON 类型插件（type 字段为 json）
                if json_config.get('type') == 'json' and json_config.get('entry'):
                    is_json_plugin = True
                    # JSON 插件需要从 entry 文件加载命令
                    import json
                    entry_path = plugin.plugin_dir / json_config['entry']
                    if entry_path.exists():
                        with open(entry_path, 'r', encoding='utf-8') as f:
                            entry_data = json.load(f)
                        if 'commands' in entry_data:
                            command_keys = list(entry_data['commands'].keys())
                            plugin_info['direct_commands'] = command_keys
                            plugin_info['functions'] = command_keys
                elif 'direct_commands' in json_config:
                    plugin_info['direct_commands'] = json_config['direct_commands']
                # 保留alias配置（用于env.sh/env.fish生成）
                if 'alias' in json_config:
                    plugin_info['alias'] = json_config['alias']

            # 解析functions信息（仅当不是 JSON 插件时）
            if not is_json_plugin and hasattr(plugin, 'functions'):
                for func_key, func_info in plugin.functions.items():
                    if '-' in func_key:
                        # 子插件-函数格式
                        parts = func_key.split('-', 1)
                        subplugin = parts[0]
                        func_name = parts[1]

                        if subplugin not in plugin_info['subplugins']:
                            plugin_info['subplugins'].append(subplugin)
                        if subplugin not in plugin_info['subplugin_functions']:
                            plugin_info['subplugin_functions'][subplugin] = []
                        plugin_info['subplugin_functions'][subplugin].append(func_name)
                        # 也添加到总函数列表中
                        plugin_info['functions'].append(func_key)
                    else:
                        # 直接函数
                        plugin_info['functions'].append(func_key)

            result[plugin_name] = plugin_info

        return result

    except Exception as e:
        print(f"⚠️  Failed to load plugins using PluginLoader: {e}")
        # 回退到原来的方法
        return await discover_plugins_recursive(plugins_root)


async def _discover_subplugin_functions(subplugin_dir: Path, subplugin_name: str) -> List[str]:
    """发现子插件目录中的函数"""
    functions = []
    
    # 检查Python文件
    for py_file in subplugin_dir.glob("*.py"):
        try:
            with open(py_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            import re
            # 查找@plugin_function装饰器
            func_pattern = r'@plugin_function\s*\(\s*name=["\']([^"\']+)["\']'
            py_functions = re.findall(func_pattern, content)
            functions.extend(py_functions)
            
        except Exception as e:
            print(f"⚠️  解析Python文件 {py_file} 时出错: {e}")
    
    # 检查Shell脚本文件
    for sh_file in subplugin_dir.glob("*.sh"):
        try:
            with open(sh_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            import re
            # 查找Shell注解 # @plugin_function
            shell_functions = _parse_shell_annotations(content)
            functions.extend(shell_functions)
            
        except Exception as e:
            print(f"⚠️  解析Shell文件 {sh_file} 时出错: {e}")
    
    return functions


def _parse_shell_annotations(content: str) -> List[str]:
    """解析Shell脚本中的@plugin_function注解"""
    import re
    functions = []
    
    # 匹配Shell注解模式，支持多行description
    annotation_pattern = r'# @plugin_function\s*\n((?:# .*\n)*)'
    matches = re.findall(annotation_pattern, content, re.MULTILINE)
    
    for metadata_lines in matches:
        # 解析name参数
        for line in metadata_lines.strip().split('\n'):
            line_content = line.strip()
            if line_content.startswith('# name:'):
                function_name = line_content.split(':', 1)[1].strip()
                if function_name:
                    functions.append(function_name)
                    break
    
    return functions


def generate_shell_functions(plugins: Dict[str, Dict], source_dir: Path) -> List[str]:
    """基于插件生成shell函数 - 包含路由逻辑"""
    functions = []

    # 转换路径为使用$HOME的相对路径
    home_path = Path.home()
    try:
        relative_source_dir = source_dir.relative_to(home_path)
        gs_root_path = f"$HOME/{relative_source_dir}"
    except ValueError:
        # 如果不在HOME目录下，使用绝对路径
        gs_root_path = str(source_dir)

    # 生成包含路由逻辑的 gs() 函数
    gs_function = '''# Load router script
if [[ -r "$GS_ROOT/src/gscripts/scripts/gs-router.sh" ]]; then
    source "$GS_ROOT/src/gscripts/scripts/gs-router.sh"
fi

# Main gs() function with command routing
gs() {
    local router_index="${GS_CACHE_DIR}/router.json"

    # If no router index or jq not available, fall back to Python
    if [[ ! -f "$router_index" ]] || ! command -v jq &>/dev/null; then
        uv run --directory "$GS_ROOT" python -m gscripts.cli.main "$@"
        return $?
    fi

    # System commands always go to Python
    case "$1" in
        help|version|plugin|status|doctor|refresh|"")
            uv run --directory "$GS_ROOT" python -m gscripts.cli.main "$@"
            return $?
            ;;
    esac

    # Query router index to determine command type
    local plugin="$1"
    local query=""


    if [[ $# -eq 1 ]]; then
        # Single argument: might be plugin info
        query="$plugin"
    elif [[ $# -eq 2 ]]; then
        # Two arguments: plugin + command
        query="$2"
    elif [[ $# -ge 3 ]]; then
        # Three or more: try two-token form first
        local two_token="$2 $3"
        local has_two_token=$(jq -r --arg plugin "$plugin" --arg query "$two_token" \\
            ".plugins[\\$plugin].commands[\\$query] // empty" "$router_index" 2>/dev/null)


        if [[ -n "$has_two_token" ]]; then
            query="$two_token"
        else
            query="$3"
        fi
    fi

    # Get command metadata
    local meta=$(jq -c --arg plugin "$plugin" --arg query "$query" \\
        ".plugins[\\$plugin].commands[\\$query] // empty" "$router_index" 2>/dev/null)


    if [[ -z "$meta" ]] || [[ "$meta" == "null" ]]; then
        # Command not found in router, fall back to Python
        uv run --directory "$GS_ROOT" python -m gscripts.cli.main "$@"
        return $?
    fi

    # Check if plugin is enabled
    local plugin_enabled=$(jq -r --arg plugin "$plugin" \\
        '.plugins[$plugin].enabled' "$router_index" 2>/dev/null)

    if [[ -z "$plugin_enabled" ]] || [[ "$plugin_enabled" == "null" ]]; then
        plugin_enabled=true
    fi

    if [[ "$plugin_enabled" == "false" ]]; then
        echo "错误: 插件 '$plugin' 已被禁用" >&2
        echo "提示: 使用 'gs plugin enable $plugin' 启用插件" >&2
        return 1
    fi

    local kind=$(echo "$meta" | jq -r '.kind // "python"')

    # Route based on command type
    case "$kind" in
        json)
            # JSON commands: execute in current shell
            local command_tpl=$(echo "$meta" | jq -r '.command // empty')
            if [[ -z "$command_tpl" ]]; then
                echo "Error: No command template defined for json type" >&2
                return 1
            fi

            # Replace {args} placeholder if present
            shift 2  # Remove plugin and command name
            local cmd="$command_tpl"
            if [[ "$cmd" == *"{args}"* ]]; then
                cmd="${cmd//\\{args\\}/$*}"
            elif [[ $# -gt 0 ]]; then
                cmd="$cmd $*"
            fi

            # Execute command in current shell
            eval "$cmd"
            ;;
        shell)
            # Use shell router for shell scripts
            gs-router "$@"
            ;;
        *)
            # Use Python CLI (default)
            uv run --directory "$GS_ROOT" python -m gscripts.cli.main "$@"
            ;;
    esac
}'''

    functions.append(gs_function)

    return functions


def get_enabled_plugins(plugins: Dict[str, Dict]) -> Dict[str, Dict]:
    """获取启用的插件列表 (使用 ConfigManager 获取合并后的配置)"""
    try:
        from gscripts.core.config_manager import ConfigManager

        enabled_plugins: Dict[str, Dict] = {}

        # 使用 ConfigManager 获取合并后的配置（项目配置 + 用户配置）
        config_manager = ConfigManager()
        cfg = config_manager.get_config() or {}

        # 使用新的system_plugins/custom_plugins布尔映射
        system_map = cfg.get('system_plugins', {}) or {}
        custom_map = cfg.get('custom_plugins', {}) or {}

        for name, pinfo in plugins.items():
            # 检查是否在system_plugins或custom_plugins中启用
            if system_map.get(name, False) or custom_map.get(name, False):
                enabled_plugins[name] = pinfo
        return enabled_plugins
    except Exception as e:
        print(f"Warning: Failed to read plugin config, using all plugins: {e}")
        import traceback
        traceback.print_exc()
        return plugins


def generate_bash_completion(plugins: Dict[str, Dict]) -> str:
    """生成bash补全脚本 - 使用动态生成器支持无限层级"""
    from pathlib import Path
    import json

    # 读取配置
    show_descriptions = True
    show_subcommand_descriptions = True
    language = 'zh'

    try:
        from gscripts.core.config_manager import ConfigManager

        # 使用 ConfigManager 获取合并后的配置
        config_manager = ConfigManager()
        cfg = config_manager.get_config() or {}

        show_descriptions = cfg.get('completion_show_descriptions', True)
        show_subcommand_descriptions = cfg.get('completion_show_subcommand_descriptions', True)
        language = cfg.get('language', 'zh')
    except Exception:
        pass

    # 尝试使用 router index 生成动态补全
    cache_dir = Path.home() / ".config" / "global-scripts" / "cache"
    router_index = cache_dir / "router.json"

    if router_index.exists():
        try:
            from gscripts.shell_completion.dynamic_generator import DynamicCompletionGenerator
            generator = DynamicCompletionGenerator(
                router_index,
                show_descriptions=show_descriptions,
                show_subcommand_descriptions=show_subcommand_descriptions,
                language=language
            )
            return generator.generate_bash_completion()
        except Exception as e:
            print(f"⚠️  Failed to generate dynamic completion: {e}")
            print("    Falling back to static completion generator...")

    # 回退到静态生成器
    try:
        from gscripts.shell_completion.generator import CompletionGenerator
        if router_index.exists():
            generator = CompletionGenerator(router_index)
            return generator.generate_bash_completion()
    except Exception as e:
        print(f"⚠️  Failed to use CompletionGenerator: {e}")

    # 回退：使用插件分析生成补全（原来的逻辑）
    # 过滤掉被禁用的插件
    enabled_plugins = get_enabled_plugins(plugins)
    plugin_names = list(enabled_plugins.keys())
    
    completion_script = '''#!/bin/bash
# Global Scripts v6 Bash Completion - Multi-level Support

_gs_complete() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    
    # 获取所有输入的单词（除了gs）
    local words=("${COMP_WORDS[@]:1}")
    local word_count=${#words[@]}
    
    # 处理选项参数
    if [[ ${cur} == -* ]]; then
        COMPREPLY=( $(compgen -W "--help --version --verbose" -- ${cur}) )
        return 0
    fi
    
    case $word_count in
        1)
            # 第一级：gs [命令]
            local base_commands="help version plugin refresh status'''
    
    completion_script += ' ' + ' '.join(plugin_names)
    completion_script += '''"
            COMPREPLY=( $(compgen -W "${base_commands}" -- ${cur}) )
            ;;
        2)
            # 第二级：gs 插件名 [子命令]
            case ${words[0]} in
                plugin)
                    opts="list info enable disable create"
                    COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
                    ;;'''
    
    # 为每个启用的插件生成子命令补全
    for plugin_name, plugin_info in enabled_plugins.items():
        subplugins = set()
        # 从插件的subplugins字段获取子插件
        if 'subplugins' in plugin_info:
            subplugins.update(plugin_info['subplugins'])
        
        # 检查是否有直接命令
        direct_commands = plugin_info.get('direct_commands', [])
        # 检查是否有直接函数
        direct_functions = plugin_info.get('functions', [])

        if subplugins:
            subplugin_list = ' '.join(sorted(subplugins))
            completion_script += f'''
                {plugin_name})
                    opts="{subplugin_list}"
                    COMPREPLY=( $(compgen -W "${{opts}}" -- ${{cur}} ))
                    ;;'''
        elif direct_functions:
            # 对于有直接函数的插件
            function_list = ' '.join(sorted(direct_functions))
            completion_script += f'''
                {plugin_name})
                    opts="{function_list}"
                    COMPREPLY=( $(compgen -W "${{opts}}" -- ${{cur}} ))
                    ;;'''
        elif direct_commands:
            # 对于有直接命令的插件
            command_list = ' '.join(sorted(direct_commands))
            completion_script += f'''
                {plugin_name})
                    opts="{command_list}"
                    COMPREPLY=( $(compgen -W "${{opts}}" -- ${{cur}} ))
                    ;;'''
    
    completion_script += '''
            esac
            ;;
        3)
            # 第三级：gs 插件名 子插件名 [函数名] 或 gs plugin [子命令] [插件名]
            case "${words[0]}" in
                plugin)
                    # gs plugin enable/disable/info [插件名]
                    case "${words[1]}" in
                        enable|disable|info)
                            opts="''' + ' '.join(plugin_names) + '''"
                            COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
                            ;;
                    esac
                    ;;'''
    
    # 为每个启用的插件的子插件生成函数补全
    for plugin_name, plugin_info in enabled_plugins.items():
        if 'subplugins' in plugin_info and plugin_info['subplugins']:
            completion_script += f'''
                {plugin_name})
                    case "${{words[1]}}" in'''
            
            # 使用新的subplugin_functions字段
            if 'subplugin_functions' in plugin_info:
                for subplugin, functions in plugin_info['subplugin_functions'].items():
                    if functions:
                        func_list = ' '.join(functions)
                        completion_script += f'''
                        {subplugin})
                            opts="{func_list}"
                            COMPREPLY=( $(compgen -W "${{opts}}" -- ${{cur}} ))
                            ;;'''
            
            completion_script += '''
                    esac
                    ;;'''
    
    completion_script += '''
            esac
            ;;
    esac
}

complete -F _gs_complete gs
'''
    return completion_script


def generate_zsh_completion(plugins: Dict[str, Dict]) -> str:
    """生成zsh补全脚本 - 使用动态生成器支持无限层级"""
    from pathlib import Path
    import json

    # 读取配置
    show_descriptions = True
    show_subcommand_descriptions = True
    language = 'zh'

    try:
        from gscripts.core.config_manager import ConfigManager

        # 使用 ConfigManager 获取合并后的配置
        config_manager = ConfigManager()
        cfg = config_manager.get_config() or {}

        show_descriptions = cfg.get('completion_show_descriptions', True)
        show_subcommand_descriptions = cfg.get('completion_show_subcommand_descriptions', True)
        language = cfg.get('language', 'zh')
    except Exception:
        pass

    # 尝试使用 router index 生成动态补全
    cache_dir = Path.home() / ".config" / "global-scripts" / "cache"
    router_index = cache_dir / "router.json"

    if router_index.exists():
        try:
            from gscripts.shell_completion.dynamic_generator import DynamicCompletionGenerator
            generator = DynamicCompletionGenerator(
                router_index,
                show_descriptions=show_descriptions,
                show_subcommand_descriptions=show_subcommand_descriptions,
                language=language
            )
            return generator.generate_zsh_completion()
        except Exception as e:
            print(f"⚠️  Failed to generate dynamic completion: {e}")
            print("    Falling back to static completion generator...")

    # 回退到静态生成器
    try:
        from gscripts.shell_completion.generator import CompletionGenerator
        if router_index.exists():
            generator = CompletionGenerator(router_index)
            return generator.generate_zsh_completion()
    except Exception as e:
        print(f"⚠️  Failed to use CompletionGenerator: {e}")

    # 回退：使用插件分析生成补全（原来的逻辑）
    # 过滤掉被禁用的插件
    enabled_plugins = get_enabled_plugins(plugins)
    
    plugin_names = list(enabled_plugins.keys())
    
    completion_script = '''#compdef gs
# Global Scripts v6 Zsh Completion

_gs_completions() {
    # NOTE: Do NOT declare a local named `words` here — zsh completion provides a special
    # global array `$words` and an index `$CURRENT`. Declaring a local `words` would shadow
    # that array and break multi-level completion. See `man zshcompsys`.
    local cur prev
    cur="${words[$CURRENT]}"
    prev="${words[$CURRENT-1]}"

    # If option in progress
    if [[ "$cur" == -* ]]; then
        compadd -- "--help" "--version" "--verbose"
        return 0
    fi

    case $CURRENT in
        2)
            # First level: gs [command]
            compadd -- "help" "version" "plugin" "refresh" "status" "parser"
'''
    
    # Add enabled plugins to first level completion
    for plugin_name in plugin_names:
        completion_script += f"            compadd -- \"{plugin_name}\"\n"
    
    completion_script += '''            ;;
        3)
            # Second level: gs <plugin|system|...> [subcommand]
            case "$prev" in
                plugin)
                    compadd -- "list" "info" "enable" "disable" "create"
                    ;;
                parser)
                    compadd -- "list" "info" "enable" "disable" "test"
                    ;;
'''
    
    # Add subplugin completions for each enabled plugin
    for plugin_name, plugin_info in enabled_plugins.items():
        if 'subplugins' in plugin_info and plugin_info['subplugins']:
            completion_script += f"                \"{plugin_name}\")\n"
            for subplugin in plugin_info['subplugins']:
                completion_script += f"                    compadd -- \"{subplugin}\"\n"
            completion_script += "                    ;;\n"
        elif 'functions' in plugin_info and plugin_info['functions']:
            # Handle plugins with direct functions (like flyme)
            completion_script += f"                \"{plugin_name}\")\n"
            for function in plugin_info['functions']:
                completion_script += f"                    compadd -- \"{function}\"\n"
            completion_script += "                    ;;\n"
        elif 'direct_commands' in plugin_info and plugin_info['direct_commands']:
            # Handle plugins with direct commands (like navigator)
            completion_script += f"                \"{plugin_name}\")\n"
            for command in plugin_info['direct_commands']:
                completion_script += f"                    compadd -- \"{command}\"\n"
            completion_script += "                    ;;\n"
    
    completion_script += '''            esac
            ;;
        4)
            # Third level: gs <plugin> <subplugin> [function] or gs plugin [subcmd] [plugin_name]
            case "${words[2]}" in
                plugin)
                    # gs plugin enable/disable/info [插件名]
                    case "${words[3]}" in
                        enable|disable|info)
                            # 补全所有插件名
'''
    
    # Add plugin name completions for plugin subcommands
    for plugin_name in plugin_names:
        completion_script += f"                            compadd -- \"{plugin_name}\"\n"
    
    completion_script += '''                            ;;
                    esac
                    ;;
'''
    
    # Add function completions for each enabled plugin's subplugins
    for plugin_name, plugin_info in enabled_plugins.items():
        if 'subplugin_functions' in plugin_info and plugin_info['subplugin_functions']:
            completion_script += f"                \"{plugin_name}\")\n"
            completion_script += f"                    case \"$prev\" in\n"
            for subplugin, functions in plugin_info['subplugin_functions'].items():
                if functions:
                    completion_script += f"                        \"{subplugin}\")\n"
                    for func in functions:
                        completion_script += f"                            compadd -- \"{func}\"\n"
                    completion_script += "                            ;;\n"
            completion_script += "                    esac\n"
            completion_script += "                    ;;\n"
    
    completion_script += '''            esac
            ;;
    esac
}

compdef _gs_completions gs
'''
    
    return completion_script


def create_cache_structure(cache_dir: Path) -> None:
    """创建CACHE_DIR目录结构"""
    # 创建主目录
    cache_dir.mkdir(parents=True, exist_ok=True)
    
    # 创建子目录
    completions_dir = cache_dir / "completions"
    logs_dir = cache_dir / "logs"
    
    completions_dir.mkdir(exist_ok=True)
    logs_dir.mkdir(exist_ok=True)
    
    # 创建日志文件
    log_file = logs_dir / "gs.log"
    if not log_file.exists():
        log_file.touch()


def generate_env_sh(source_dir: Path, cache_dir: Path, plugins: Dict[str, Dict], language: str = 'zh', show_examples: bool = True) -> str:
    """生成 env.sh，降低 f-string 复杂度，避免反斜杠导致的表达式解析错误"""
    import datetime, json
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    gs_root_path = str(source_dir.resolve())
    cache_dir_path = str(cache_dir.resolve())
    
    # 收集并排序 alias 插件
    aliases_to_load = []
    for plugin_name, plugin_info in plugins.items():
        alias_info = plugin_info.get('alias')
        if alias_info and isinstance(alias_info, dict):
            sources = alias_info.get('sources', [])
            # 处理sources: 可能是dict(新格式)或list(旧格式)
            if isinstance(sources, dict):
                # 新格式：sources是字典，提取bash/zsh的sources
                bash_sources = sources.get('bash', [])
                zsh_sources = sources.get('zsh', [])
                # 合并去重（通常bash和zsh使用相同的.sh文件）
                sources = list(dict.fromkeys(bash_sources + zsh_sources))
            elif not isinstance(sources, list):
                sources = []

            if sources:  # 只有当有源文件时才添加
                aliases_to_load.append({
                    'name': plugin_name,
                    'interactive_only': alias_info.get('interactive_only', True),
                    'priority': alias_info.get('priority', 100),
                    'shells': alias_info.get('shells', ['bash', 'zsh']),
                    'sources': sources
                })
    
    # 按 priority 升序排序，相同 priority 按名称排序
    aliases_to_load.sort(key=lambda x: (x['priority'], x['name']))

    # 读取配置（项目级，不做合并，这里仅用于导出简单变量）
    raw_cfg = {}
    cfg_path = source_dir / 'config' / 'gs.json'
    if cfg_path.exists():
        try:
            with open(cfg_path, 'r', encoding='utf-8') as f:
                raw_cfg = json.load(f)
        except Exception:
            raw_cfg = {}

    export_lines: List[str] = []
    for k, v in raw_cfg.items():
        if k in ('system_plugins', 'custom_plugins') or isinstance(v, (dict, list)):
            continue
        env_key = f"GS_{k.upper()}"
        if isinstance(v, bool):
            export_lines.append(f'export {env_key}="{str(v).lower()}"')
        else:
            export_lines.append(f'export {env_key}="{v}"')

    # 拆分 prompt_theme (若存在) 其余作为普通导出
    prompt_line = 'export GS_PROMPT_THEME="bitstream"'
    other_exports: List[str] = []
    for line in export_lines:
        if line.startswith('export GS_PROMPT_THEME='):
            prompt_line = line
        else:
            other_exports.append(line)

    lines: List[str] = [
        '#!/bin/bash',
        '# Global Scripts V6 Environment Configuration',
        '# Generated automatically - do not edit manually',
        f'# Generated at: {timestamp}',
        f'# Configuration source: {source_dir}',
        '',
        '# Global Scripts root directory (absolute path)',
        f'export GS_ROOT="{gs_root_path}"',
        '',
        '# Language setting - Controls UI language for all commands',
        f'export GS_LANGUAGE="{language}"',
        '',
        '# V6 Configuration Variables (from gs.json)',
        *(other_exports if other_exports else ['# (no config exports found)']),
        f'export GS_CONFIG_SHOW_EXAMPLES="{str(show_examples).lower()}"',
        prompt_line,
        '',
        '# Add Global Scripts to PATH',
        '# Prepend GS_ROOT to PATH if not present',
        'case ":$PATH:" in',
        '    *":$GS_ROOT:"*) ;;',
        '    *) export PATH="$GS_ROOT:$PATH" ;;',
        'esac',
        '',
        '# Global Scripts version',
        f'export GS_VERSION="{GS_VERSION}"',
        '',
        '# Platform detection',
        f'export GS_PLATFORM="{platform.system().lower()}"',
        '',
        '# Cache directory',
        f'export GS_CACHE_DIR="{cache_dir_path}"',
        '',
        '# Plugin command functions with performance optimization',
        '',
        '# Load prompt theme (interactive shells only)',
        'if [[ $- == *i* ]]; then',
        '    if [[ -r "$GS_ROOT/themes/prompt/load.sh" ]]; then',
        '        source "$GS_ROOT/themes/prompt/load.sh"',
        '    fi',
        'fi',
        ''
    ]

    for func in generate_shell_functions(plugins, source_dir):
        lines.append(func)

    # 追加补全与 Conda 初始化段落
    lines.extend([
        '',
        '# Quick reload alias (rebuild completions, then reload env without rewriting env.sh)',
        # 使用单引号包裹 alias，内部保持 echo 双引号
        "alias gsreload='gs refresh >/dev/null 2>&1; source \"$GS_ROOT/env.sh\" && echo \"✅ Global Scripts 环境已重新加载！\"'",
        '',
        '# Initialize conda if available (lightweight detection)',
        'if ! command -v conda >/dev/null 2>&1; then',
        '    for conda_base in "$HOME/miniconda3" "$HOME/anaconda3" "$HOME/miniforge3" \\',
        '                      "/opt/miniconda3" "/opt/anaconda3" "/opt/miniforge3" \\',
        '                      "/usr/local/miniconda3" "/usr/local/anaconda3"; do',
        '        if [[ -f "$conda_base/etc/profile.d/conda.sh" ]]; then',
        '            source "$conda_base/etc/profile.d/conda.sh" 2>/dev/null',
        '            break',
        '        fi',
        '    done',
        'fi',
        '',
        '# Zsh completion system init (safe, no-op if already)',
        'if [[ -n "$ZSH_VERSION" ]]; then',
        '    autoload -U compinit',
        '    compinit -u',
        'fi',
        '',
        '# Load generated completion scripts',
        'if [[ -d "$GS_CACHE_DIR/completions" ]]; then',
        '    if [[ -n "$ZSH_VERSION" ]]; then',
        '        for comp_file in "$GS_CACHE_DIR/completions"/*.zsh; do',
        '            [[ -r "$comp_file" ]] && source "$comp_file"',
        '        done',
        '    elif [[ -n "$BASH_VERSION" ]]; then',
        '        for comp_file in "$GS_CACHE_DIR/completions"/*.bash; do',
        '            [[ -r "$comp_file" ]] && source "$comp_file"',
        '        done',
        '    else',
        '        for comp_file in "$GS_CACHE_DIR/completions"/*; do',
        '            [[ -r "$comp_file" ]] && source "$comp_file"',
        '        done',
        '    fi',
        'fi',
        '',
        '# Alias loading section',
    ])
    
    # 生成 alias 加载段
    if aliases_to_load:
        lines.extend([
            '# BEGIN aliases',
            '# Detect interactive shell for conditional loading',
            '__GS_ALIAS_IS_INTERACTIVE=0',
            'case $- in *i*) __GS_ALIAS_IS_INTERACTIVE=1 ;; esac',
            ''
        ])
        
        for alias_info in aliases_to_load:
            plugin_name = alias_info['name']
            interactive_only = alias_info['interactive_only']
            shells = alias_info['shells']
            sources = alias_info['sources']
            priority = alias_info['priority']
            
            # 生成注释
            lines.append(f'# Plugin: {plugin_name}, Priority: {priority}')
            lines.append(f'# Shells: {" ".join(shells)}, Interactive only: {interactive_only}')
            
            # 生成 shell 检测条件
            shell_conditions = []
            if 'bash' in shells:
                shell_conditions.append('[ -n "$BASH_VERSION" ]')
            if 'zsh' in shells:
                shell_conditions.append('[ -n "$ZSH_VERSION" ]')
            
            if shell_conditions:
                shell_check = ' || '.join(shell_conditions)
                lines.append(f'if {shell_check}; then')
                
                # 生成交互式检查
                if interactive_only:
                    lines.append('    if [ "$__GS_ALIAS_IS_INTERACTIVE" = "1" ]; then')
                    indent = '        '
                else:
                    indent = '    '
                
                # 生成每个 source 文件的加载
                for source_path in sources:
                    # 解析源文件路径，检查是否需要平台特定处理
                    full_path = f'"$GS_ROOT/plugins/{plugin_name}/{source_path}"'

                    if 'darwin' in source_path.lower():
                        lines.append(f'{indent}# Load Darwin-specific aliases')
                        lines.append(f'{indent}if [ "$(uname -s)" = "Darwin" ]; then')
                        lines.append(f'{indent}    [ -f {full_path} ] && . {full_path}')
                        lines.append(f'{indent}fi')
                    elif 'linux' in source_path.lower():
                        lines.append(f'{indent}# Load Linux-specific aliases')
                        lines.append(f'{indent}if [ "$(uname -s)" = "Linux" ]; then')
                        lines.append(f'{indent}    [ -f {full_path} ] && . {full_path}')
                        lines.append(f'{indent}fi')
                    else:
                        # 通用文件，直接加载
                        lines.append(f'{indent}# Load common aliases')
                        lines.append(f'{indent}[ -f {full_path} ] && . {full_path}')
                
                if interactive_only:
                    lines.append('    fi')
                lines.append('fi')
                lines.append('')
        
        lines.extend([
            '# Cleanup alias loading variables',
            'unset __GS_ALIAS_IS_INTERACTIVE',
            '# END aliases',
            ''
        ])
    
    lines.append('')
    
    return '\n'.join(lines) + '\n'


async def main():
    """主安装函数"""
    import argparse
    
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='Global Scripts Setup')
    parser.add_argument('--generate-completion', action='store_true',
                       help='Generate only completion scripts (no env.sh) without interactive prompts')
    parser.add_argument('--auto', action='store_true',
                       help='Run in automatic mode (non-interactive)')
    parser.add_argument('--lang', choices=['en', 'zh'],
                       help='Language for generated scripts (overrides auto/default)')
    parser.add_argument('--examples', choices=['true', 'false'],
                       help='Whether to show example plugins (overrides auto/default)')
    parser.add_argument('--shell', choices=['bash', 'zsh', 'fish'],
                       help='Target shell (overrides auto-detection)')
    args = parser.parse_args()
    
    # 显示banner
    show_banner()
    
    # 仅生成补全：不写 env.sh
    if args.generate_completion:
        # 基本版本检查
        if sys.version_info < (3, 8):
            print("❌ Error: Python 3.8 or higher required")
            sys.exit(1)
        # 路径和插件发现
        source_dir = Path(__file__).parent.parent.absolute()  # 从 scripts/ 向上到项目根目录
        cache_dir = Path.home() / ".config" / "global-scripts"
        create_cache_structure(cache_dir)
        plugins_root = source_dir / "plugins"
        custom_root = source_dir / "custom"
        print(f"🔍 扫描插件目录: {plugins_root}")
        plugins = await discover_plugins(plugins_root)
        # 同时扫描 custom 目录
        if custom_root.exists():
            print(f"🔍 Scanning custom directory: {custom_root}")
            custom_plugins = await discover_plugins(custom_root)
            plugins.update(custom_plugins)

        # 生成 router.json
        try:
            from gscripts.router.indexer import build_router_index, write_router_index
            from gscripts.core.plugin_loader import PluginLoader

            # 重新加载完整的 plugin 对象用于 router index
            loader = PluginLoader(plugins_root)
            full_plugins = await loader.load_all_plugins()

            # 同时扫描 custom 目录
            if custom_root.exists():
                custom_loader = PluginLoader(custom_root)
                custom_full_plugins = await custom_loader.load_all_plugins()
                full_plugins.update(custom_full_plugins)

            router_index = build_router_index(full_plugins)
            router_path = write_router_index(router_index)
            print(f"✅ Router index: {router_path}")
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"⚠️  Router index generation failed: {e}")

        # 生成补全 - 使用统一的 generator 从 router.json
        try:
            from gscripts.shell_completion.generator import generate_completions_from_index

            completions_dir = cache_dir / "completions"
            completions_dir.mkdir(parents=True, exist_ok=True)

            # Determine language for completions
            completion_lang = 'zh'  # Default
            try:
                import json
                config_path = cache_dir / "config" / "gs.json"
                if config_path.exists():
                    with open(config_path, 'r') as f:
                        config = json.load(f)
                        completion_lang = config.get('language', 'zh')
            except Exception:
                pass

            # Generate all completions from router.json
            bash_file, zsh_file, fish_file = generate_completions_from_index(
                router_path,
                completions_dir,
                language=completion_lang
            )

            print(f"✅ Bash completion script: {bash_file}")
            print(f"✅ Zsh completion script: {zsh_file}")
            print(f"✅ Fish completion script: {fish_file}")
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"⚠️  Completion generation failed: {e}")
            # Fallback to old method if needed
            print(f"⚠️  Falling back to legacy completion generation...")
            completions_dir = cache_dir / "completions"
            bash_completion = generate_bash_completion(plugins)
            bash_file = completions_dir / "gs.bash"
            with open(bash_file, 'w', encoding='utf-8') as f:
                f.write(bash_completion)
            print(f"✅ Bash completion script: {bash_file}")
            zsh_completion = generate_zsh_completion(plugins)
            zsh_file = completions_dir / "gs.zsh"
            with open(zsh_file, 'w', encoding='utf-8') as f:
                f.write(zsh_completion)
            print(f"✅ Zsh completion script: {zsh_file}")
            fish_completion = generate_fish_completion(plugins)
            fish_file = completions_dir / "gs.fish"
            with open(fish_file, 'w', encoding='utf-8') as f:
                f.write(fish_completion)
            print(f"✅ Fish completion script: {fish_file}")

        print("🎉 Completion generation complete!")
        return True
    
    # 正常安装路径：生成 env.sh + 补全
    auto_mode = args.auto
    
    # 首先尝试从配置文件读取设置（通过 ConfigManager 已合并）
    config_language, config_show_examples = load_config_from_json()
    
    # 语言设置优先级：命令行参数 > 配置文件 > 用户选择
    if args.lang:
        language = args.lang
    elif config_language:
        language = config_language
        if not auto_mode:
            print(f"✅ 使用配置文件中的语言设置: {language}")
    else:
        language = select_language(auto_mode=auto_mode)
    
    config = get_language_config(language)
    
    # 示例插件开关优先级：命令行参数 > 配置文件 > 用户选择
    if args.examples is not None:
        show_examples = True if args.examples.lower() == 'true' else False
    elif config_show_examples is not None:
        show_examples = config_show_examples
        if not auto_mode:
            print(f"✅ 使用配置文件中的示例设置: {show_examples}")
    else:
        show_examples = ask_show_examples(language=language, auto_mode=auto_mode)
    
    # 显示安装标题
    print(f"\n{'=' * 70}")
    print(f"{config['install_title']:^70}")
    print(f"{'=' * 70}\n")

    # 检查Python版本
    if sys.version_info < (3, 8):
        if language == 'en':
            print("❌ Error: Python 3.8 or higher required")
        else:
            print("❌ 错误: 需要Python 3.8或更高版本")
        sys.exit(1)

    # ========== 第一部分：环境检测 ==========
    print(f"{'[1/5] 环境检测' if language == 'zh' else '[1/5] Environment Check':^70}")
    print(f"{'-' * 70}")

    # 获取源码目录 (SOURCE_DIR)
    source_dir = Path(__file__).parent.parent.absolute()  # 从 scripts/ 向上到项目根目录
    print(f"  {config['source_dir']}")
    print(f"  └─ {source_dir}")

    # 创建缓存目录 (CACHE_DIR)
    cache_dir = Path.home() / ".config" / "global-scripts"
    create_cache_structure(cache_dir)
    print(f"\n  {config['cache_dir']}")
    print(f"  └─ {cache_dir}")

    # ========== 第二部分：插件扫描 ==========
    print(f"\n{'[2/5] 插件扫描' if language == 'zh' else '[2/5] Plugin Scanning':^70}")
    print(f"{'-' * 70}")

    # 发现插件
    plugins_root = source_dir / "plugins"
    custom_root = source_dir / "custom"
    print(f"  📦 {'扫描系统插件目录' if language == 'zh' else 'Scanning system plugins'}: {plugins_root}")
    plugins = await discover_plugins(plugins_root)
    system_count = len(plugins)

    # 同时扫描 custom 目录
    custom_count = 0
    if custom_root.exists():
        print(f"  📦 {'扫描自定义插件目录' if language == 'zh' else 'Scanning custom plugins'}: {custom_root}")
        custom_plugins = await discover_plugins(custom_root)
        plugins.update(custom_plugins)
        custom_count = len(custom_plugins)

    # 显示插件统计
    print(f"\n  {'插件统计' if language == 'zh' else 'Plugin Statistics'}:")
    print(f"  ├─ {'系统插件' if language == 'zh' else 'System plugins'}: {system_count}")
    if custom_count > 0:
        print(f"  ├─ {'自定义插件' if language == 'zh' else 'Custom plugins'}: {custom_count}")
    print(f"  └─ {'总计' if language == 'zh' else 'Total'}: {len(plugins)}")

    # ========== 第三部分：Shell 检测与环境文件生成 ==========
    print(f"\n{'[3/5] Shell 检测与环境配置' if language == 'zh' else '[3/5] Shell Detection & Environment':^70}")
    print(f"{'-' * 70}")

    # 检测当前 Shell（可通过 --shell 参数覆盖）
    if args.shell:
        current_shell = args.shell
        print(f"  🐚 {'使用指定 Shell' if language == 'zh' else 'Using specified Shell'}: {current_shell}")
    else:
        current_shell = detect_current_shell()
        print(f"  🐚 {'检测到当前 Shell' if language == 'zh' else 'Detected current Shell'}: {current_shell}")

    # 根据 shell 类型生成相应的环境文件
    if current_shell == 'fish':
        env_file = source_dir / "env.fish"
    else:
        env_file = source_dir / "env.sh"

    print(f"\n  📝 {'生成环境配置文件' if language == 'zh' else 'Generating environment file'}:")
    print(f"  └─ {env_file}")

    # 生成环境文件内容
    if current_shell == 'fish':
        env_content = generate_env_fish(source_dir, cache_dir, plugins, language, show_examples)
    else:
        env_content = generate_env_sh(source_dir, cache_dir, plugins, language, show_examples)

    # 确保可以写入环境文件（如果存在且只读，则修改权限）
    if env_file.exists():
        try:
            env_file.chmod(0o644)  # 设置为可读写
        except Exception:
            pass  # 忽略权限修改失败

    with open(env_file, 'w', encoding='utf-8') as f:
        f.write(env_content)

    env_file.chmod(0o755)
    print(f"  ✅ {'环境配置文件生成成功' if language == 'zh' else 'Environment file generated successfully'}")

    # ========== 第四部分：生成 Router Index 和补全脚本 ==========
    print(f"\n{'[4/5] 命令路由与补全脚本' if language == 'zh' else '[4/5] Command Routing & Completion':^70}")
    print(f"{'-' * 70}")

    # 生成 router.json
    print(f"  🔗 {'生成命令路由索引' if language == 'zh' else 'Generating command routing index'}...")
    try:
        from gscripts.router.indexer import build_router_index, write_router_index
        from gscripts.core.plugin_loader import PluginLoader

        # 重新加载完整的 plugin 对象用于 router index
        loader = PluginLoader(plugins_root)
        full_plugins = await loader.load_all_plugins()

        # 同时扫描 custom 目录
        if custom_root.exists():
            custom_loader = PluginLoader(custom_root)
            custom_full_plugins = await custom_loader.load_all_plugins()
            full_plugins.update(custom_full_plugins)

        router_index = build_router_index(full_plugins)
        router_path = write_router_index(router_index)
        print(f"  └─ {router_path}")
        print(f"  ✅ {'命令路由索引生成成功' if language == 'zh' else 'Router index generated successfully'}")
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"  ⚠️  {'路由索引生成失败' if language == 'zh' else 'Router index generation failed'}: {e}")

    # 生成补全脚本
    print(f"\n  ⚙️  {'生成 Shell 补全脚本' if language == 'zh' else 'Generating shell completions'}...")
    try:
        from gscripts.shell_completion.generator import generate_completions_from_index

        completions_dir = cache_dir / "completions"
        completions_dir.mkdir(parents=True, exist_ok=True)

        # Generate all completions from router.json
        bash_file, zsh_file, fish_file = generate_completions_from_index(
            router_path,
            completions_dir,
            language=language
        )

        print(f"  ├─ Bash: {bash_file.name}")
        print(f"  ├─ Zsh:  {zsh_file.name}")
        print(f"  └─ Fish: {fish_file.name}")
        print(f"  ✅ {'补全脚本生成成功' if language == 'zh' else 'Completion scripts generated successfully'}")
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"  ⚠️  {'补全生成失败，使用传统方法' if language == 'zh' else 'Completion generation failed, using fallback'}")
        # Fallback to old method
        completions_dir = cache_dir / "completions"

        # 生成bash补全
        bash_completion = generate_bash_completion(plugins)
        bash_file = completions_dir / "gs.bash"
        with open(bash_file, 'w', encoding='utf-8') as f:
            f.write(bash_completion)

        # 生成zsh补全
        zsh_completion = generate_zsh_completion(plugins)
        zsh_file = completions_dir / "gs.zsh"
        with open(zsh_file, 'w', encoding='utf-8') as f:
            f.write(zsh_completion)

        # 生成fish补全
        fish_completion = generate_fish_completion(plugins)
        fish_file = completions_dir / "gs.fish"
        with open(fish_file, 'w', encoding='utf-8') as f:
            f.write(fish_completion)

        print(f"  └─ {'使用传统方法生成成功' if language == 'zh' else 'Generated using fallback method'}")

    # ========== 第五部分：Shell 配置说明 ==========
    print(f"\n{'[5/5] Shell 配置说明' if language == 'zh' else '[5/5] Shell Configuration':^70}")
    print(f"{'-' * 70}")

    # 检测Shell类型并给出配置建议
    shell_name = current_shell

    if shell_name == 'fish':
        config_file = Path.home() / ".config" / "fish" / "config.fish"
    elif shell_name == 'zsh':
        config_file = Path.home() / ".zshrc"
    elif shell_name == 'bash':
        config_file = Path.home() / ".bashrc"
    else:
        config_file = Path.home() / ".profile"

    print(f"  {'配置信息' if language == 'zh' else 'Configuration Info'}:")
    print(f"  ├─ Shell: {shell_name}")
    print(f"  └─ {'配置文件' if language == 'zh' else 'Config file'}: {config_file}")

    # 检查是否已经配置
    if config_file.exists():
        with open(config_file, 'r', encoding='utf-8') as f:
            content = f.read()

        if str(env_file) in content:
            print(f"\n  ✅ {'Shell 配置已存在' if language == 'zh' else 'Shell already configured'}")
        else:
            print(f"\n  ⚠️  {'需要手动配置 Shell' if language == 'zh' else 'Shell configuration needed'}")
            print(f"\n  {'请在配置文件中添加以下行' if language == 'zh' else 'Please add the following line to your config file'}:")
            print(f"  {CYAN}source {env_file}{RESET}")

            # 询问是否自动添加
            try:
                prompt = "  是否自动添加到配置文件? (y/N): " if language == 'zh' else "  Automatically add to config file? (y/N): "
                response = input(prompt).strip().lower()
                if response in ['y', 'yes']:
                    with open(config_file, 'a', encoding='utf-8') as f:
                        f.write(f"\n# Global Scripts v6\nsource {env_file}\n")
                    print(f"  ✅ {'已自动添加到配置文件' if language == 'zh' else 'Automatically added to config file'}")
                else:
                    print(f"  ℹ️  {'请手动添加配置' if language == 'zh' else 'Please add configuration manually'}")
            except KeyboardInterrupt:
                print(f"\n  ⚠️  {'配置已取消' if language == 'zh' else 'Configuration cancelled'}")
    else:
        print(f"\n  ℹ️  {'配置文件不存在，请创建' if language == 'zh' else 'Config file does not exist, please create it'}: {config_file}")
        print(f"  {'并添加以下行' if language == 'zh' else 'And add the following line'}:")
        print(f"  {CYAN}source {env_file}{RESET}")

    # ========== 安装完成 ==========
    print(f"\n{'=' * 70}")
    print(f"{'🎉 ' + ('安装完成！' if language == 'zh' else 'Installation Complete!'):^70}")
    print(f"{'=' * 70}\n")

    # 显示使用说明
    print(f"{'📋 ' + ('使用说明' if language == 'zh' else 'Usage'):^70}")
    print(f"{'-' * 70}")
    print(f"  1. {'重新加载 Shell 配置' if language == 'zh' else 'Reload shell configuration'}:")
    print(f"     {CYAN}source {config_file}{RESET}")
    print(f"\n  2. {'使用命令' if language == 'zh' else 'Use commands'}:")
    print(f"     {CYAN}gs help{RESET}         # {'查看帮助' if language == 'zh' else 'Show help'}")
    print(f"     {CYAN}gs status{RESET}       # {'查看系统状态' if language == 'zh' else 'Show system status'}")
    print(f"     {CYAN}gs plugin list{RESET}  # {'查看插件列表' if language == 'zh' else 'List plugins'}")

    # 显示可用插件统计
    print(f"\n{'📦 ' + ('插件统计' if language == 'zh' else 'Plugin Statistics'):^70}")
    print(f"{'-' * 70}")

    enabled_plugins = get_enabled_plugins(plugins)
    enabled_count = len(enabled_plugins)
    total_count = len(plugins)
    disabled_count = total_count - enabled_count

    # 计算总函数数
    total_functions = sum(len(p.get('functions', [])) for p in enabled_plugins.values())

    print(f"  {'已启用插件' if language == 'zh' else 'Enabled plugins'}: {GREEN}{enabled_count}{RESET} / {total_count}")
    if disabled_count > 0:
        print(f"  {'已禁用插件' if language == 'zh' else 'Disabled plugins'}: {YELLOW}{disabled_count}{RESET}")
    print(f"  {'可用命令数' if language == 'zh' else 'Available commands'}: {CYAN}{total_functions}{RESET}")

    # 显示启用的插件列表（分组显示）
    if enabled_plugins:
        print(f"\n  {'启用的插件' if language == 'zh' else 'Enabled Plugins'}:")

        # 按类型分组
        system_plugins = {k: v for k, v in enabled_plugins.items() if k in plugins and 'custom' not in str(plugins[k].get('directory', ''))}
        custom_plugins_list = {k: v for k, v in enabled_plugins.items() if k in plugins and 'custom' in str(plugins[k].get('directory', ''))}

        if system_plugins:
            print(f"    {'系统插件' if language == 'zh' else 'System Plugins'}:")
            for plugin_name, plugin_info in sorted(system_plugins.items()):
                functions_count = len(plugin_info.get('functions', []))
                subplugins_count = len(plugin_info.get('subplugins', []))
                print(f"      {GREEN}✓{RESET} {plugin_name:15} ({functions_count} {'命令' if language == 'zh' else 'cmds'}, {subplugins_count} {'子插件' if language == 'zh' else 'subs'})")

        if custom_plugins_list:
            print(f"    {'自定义插件' if language == 'zh' else 'Custom Plugins'}:")
            for plugin_name, plugin_info in sorted(custom_plugins_list.items()):
                functions_count = len(plugin_info.get('functions', []))
                subplugins_count = len(plugin_info.get('subplugins', []))
                print(f"      {GREEN}✓{RESET} {plugin_name:15} ({functions_count} {'命令' if language == 'zh' else 'cmds'}, {subplugins_count} {'子插件' if language == 'zh' else 'subs'})")

    # 显示项目信息
    print(f"\n{'📚 ' + ('项目信息' if language == 'zh' else 'Project Info'):^70}")
    print(f"{'-' * 70}")
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
        sys.exit(1)
