#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Completion generator based on router index
"""

from pathlib import Path
from typing import Dict, Set, List, Tuple
import json

from ..core.logger import get_logger

logger = get_logger(tag="SHELL.COMPLETION", name=__name__)


class CompletionGenerator:
    """Generate shell completions from router index"""

    # System commands that should always be available
    SYSTEM_COMMANDS = ['help', 'version', 'plugin', 'refresh', 'status', 'doctor', 'parser']
    PLUGIN_SUBCOMMANDS = ['list', 'info', 'enable', 'disable', 'create']

    def __init__(self, router_index_path: Path):
        """Initialize with router index path"""
        self.router_index_path = router_index_path
        self.index = self._load_router_index()

    def _load_router_index(self) -> Dict:
        """Load router index from JSON file"""
        if not self.router_index_path.exists():
            return {}

        try:
            with open(self.router_index_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load router index: {e}")
            return {}

    def _parse_commands(self, plugin_name: str) -> Tuple[List[str], Dict[str, List[str]]]:
        """Parse commands from plugin

        Returns:
            (single_word_commands, multi_word_commands_map)

        Example:
            (['aosp', 'list'], {'brew': ['aliyun', 'github'], 'config': ['backup']})
        """
        plugins = self.index.get('plugins', {})
        plugin_data = plugins.get(plugin_name, {})
        commands = plugin_data.get('commands', {})

        single_word = []
        multi_word = {}

        for cmd_key in commands.keys():
            parts = cmd_key.split(' ', 1)
            if len(parts) == 1:
                # Single word command
                single_word.append(cmd_key)
            else:
                # Multi-word command
                first, rest = parts
                if first not in multi_word:
                    multi_word[first] = []
                multi_word[first].append(rest)

        return sorted(single_word), multi_word

    def generate_bash_completion(self) -> str:
        """Generate bash completion script"""
        plugins = self.index.get('plugins', {})
        plugin_names = sorted(plugins.keys())

        script = '''#!/bin/bash
# Global Scripts v6 Bash Completion - Auto-generated from router index

_gs_complete() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # Get all words except 'gs'
    local words=("${COMP_WORDS[@]:1}")
    local word_count=${#words[@]}

    # Handle option flags
    if [[ ${cur} == -* ]]; then
        COMPREPLY=( $(compgen -W "--help --version --verbose" -- ${cur}) )
        return 0
    fi

    case $word_count in
        1)
            # First level: gs [command]
            local base_commands="'''

        # Add system commands and plugin names
        all_level1 = self.SYSTEM_COMMANDS + plugin_names
        script += ' '.join(all_level1)
        script += '''"
            COMPREPLY=( $(compgen -W "${base_commands}" -- ${cur}) )
            ;;
        2)
            # Second level: gs <plugin> [subcommand]
            case ${words[0]} in
                plugin)
                    opts="''' + ' '.join(self.PLUGIN_SUBCOMMANDS) + '''"
                    COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
                    ;;
'''

        # Add completions for each plugin
        for plugin_name in plugin_names:
            single_word, multi_word = self._parse_commands(plugin_name)

            # Collect all level-2 commands (single word + first word of multi-word)
            level2_commands = set(single_word)
            level2_commands.update(multi_word.keys())

            if level2_commands:
                script += f'''                {plugin_name})
                    opts="{' '.join(sorted(level2_commands))}"
                    COMPREPLY=( $(compgen -W "${{opts}}" -- ${{cur}} ))
                    ;;
'''

        script += '''            esac
            ;;
        3)
            # Third level: gs <plugin> <subcommand> [args] or gs plugin <action> [plugin_name]
            case "${words[0]}" in
                plugin)
                    case "${words[1]}" in
                        enable|disable|info)
                            opts="''' + ' '.join(plugin_names) + '''"
                            COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
                            ;;
                    esac
                    ;;
'''

        # Add third-level completions for multi-word commands
        for plugin_name in plugin_names:
            single_word, multi_word = self._parse_commands(plugin_name)

            if multi_word:
                script += f'''                {plugin_name})
                    case "${{words[1]}}" in
'''
                for prefix, suffixes in sorted(multi_word.items()):
                    script += f'''                        {prefix})
                            opts="{' '.join(sorted(suffixes))}"
                            COMPREPLY=( $(compgen -W "${{opts}}" -- ${{cur}} ))
                            ;;
'''
                script += '''                    esac
                    ;;
'''

        script += '''            esac
            ;;
        4)
            # Fourth level: gs <plugin> <subcommand> <action> [args]
            case "${words[0]}" in
                system)
                    case "${words[1]}" in
                        config)
                            case "${words[2]}" in
                                install|init)
                                    opts="zsh fish vim nvim tmux git ssh"
                                    COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
                                    ;;
                            esac
                            ;;
                    esac
                    ;;
            esac
            ;;
    esac
}

complete -F _gs_complete gs
'''
        return script

    def generate_zsh_completion(self, language: str = 'zh') -> str:
        """Generate zsh completion script - Dynamic from router index"""
        router_index_path = str(self.router_index_path.resolve())

        # Get system command descriptions
        try:
            from ..utils.i18n import I18nManager
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

        script = f'''#compdef gs
# Global Scripts v6 Zsh Completion - Dynamic router index support
# Auto-generated - All data dynamically loaded from router index

# Router index path for dynamic lookup
typeset -g _GS_ROUTER_INDEX="{router_index_path}"
typeset -g _GS_LANGUAGE="{language}"

# Helper function to get plugin names with descriptions
_gs_plugins() {{
    local -a plugins descs
    if ! command -v jq &>/dev/null; then
        return
    fi

    # Get plugin names and descriptions
    local plugin_data=($(jq -r '.plugins | to_entries[] | "\\(.key):\\(.value.description.'$_GS_LANGUAGE' // .value.description.zh // .value.description.en // "")"' "$_GS_ROUTER_INDEX" 2>/dev/null))

    for item in ${{plugin_data[@]}}; do
        local name=$(echo "$item" | cut -d: -f1)
        local desc=$(echo "$item" | cut -d: -f2-)
        if [[ -n "$desc" ]]; then
            descs+=("$name:$desc")
        else
            descs+=("$name")
        fi
    done

    _describe 'plugins' descs
}}

# Helper function to get subplugins/commands with descriptions
_gs_subplugins() {{
    local plugin="${{words[2]}}"
    if [[ -z "$plugin" ]] || ! command -v jq &>/dev/null; then
        return
    fi

    local -a commands descs

    # Check if plugin has subplugins
    local subplugin_count=$(jq -r ".plugins[\\"$plugin\\"].subplugins | length" "$_GS_ROUTER_INDEX" 2>/dev/null)

    if [[ "$subplugin_count" != "null" && "$subplugin_count" != "0" ]]; then
        # Extract subplugins with descriptions
        local subplugin_data=($(jq -r ".plugins[\\"$plugin\\"].subplugins[] | \\"\\(.name):\\(.description.$_GS_LANGUAGE // .description.zh // .description.en // \\"\\")\\"" "$_GS_ROUTER_INDEX" 2>/dev/null))

        for item in ${{subplugin_data[@]}}; do
            local name=$(echo "$item" | cut -d: -f1)
            local desc=$(echo "$item" | cut -d: -f2-)
            if [[ -n "$desc" ]]; then
                descs+=("$name:$desc")
            else
                descs+=("$name")
            fi
        done
    else
        # No subplugins, extract first words from commands
        local cmd_list=($(jq -r ".plugins[\\"$plugin\\"].commands | keys[]" "$_GS_ROUTER_INDEX" 2>/dev/null))
        local -A seen_words

        for cmd in ${{cmd_list[@]}}; do
            local first_word=$(echo "$cmd" | awk '{{print $1}}')
            if [[ -z "${{seen_words[$first_word]}}" ]]; then
                seen_words[$first_word]=1
                local desc=$(jq -r ".plugins[\\"$plugin\\"].commands[\\"$cmd\\"].description.$_GS_LANGUAGE // .plugins[\\"$plugin\\"].commands[\\"$cmd\\"].description.zh // .plugins[\\"$plugin\\"].commands[\\"$cmd\\"].description.en // \\"\\\"" "$_GS_ROUTER_INDEX" 2>/dev/null)
                if [[ -n "$desc" ]]; then
                    descs+=("$first_word:$desc")
                else
                    descs+=("$first_word")
                fi
            fi
        done
    fi

    _describe 'subplugins' descs
}}

# Helper function to get functions with descriptions
_gs_functions() {{
    local plugin="${{words[2]}}"
    local subplugin="${{words[3]}}"
    if [[ -z "$plugin" ]] || ! command -v jq &>/dev/null; then
        return
    fi

    local -a functions descs
    local cmd_prefix=""

    if [[ -n "$subplugin" ]]; then
        cmd_prefix="$subplugin "
    fi

    # Get all commands matching the prefix
    local cmd_list=($(jq -r ".plugins[\\"$plugin\\"].commands | keys[] | select(startswith(\\"$cmd_prefix\\"))" "$_GS_ROUTER_INDEX" 2>/dev/null))
    local -A seen_words

    for cmd in ${{cmd_list[@]}}; do
        # Extract the next word after prefix
        local remaining=$(echo "$cmd" | sed "s/^$cmd_prefix//")
        local next_word=$(echo "$remaining" | awk '{{print $1}}')

        if [[ -n "$next_word" && -z "${{seen_words[$next_word]}}" ]]; then
            seen_words[$next_word]=1
            local desc=$(jq -r ".plugins[\\"$plugin\\"].commands[\\"$cmd\\"].description.$_GS_LANGUAGE // .plugins[\\"$plugin\\"].commands[\\"$cmd\\"].description.zh // .plugins[\\"$plugin\\"].commands[\\"$cmd\\"].description.en // \\"\\\"" "$_GS_ROUTER_INDEX" 2>/dev/null)
            if [[ -n "$desc" ]]; then
                descs+=("$next_word:$desc")
            else
                descs+=("$next_word")
            fi
        fi
    done

    _describe 'functions' descs
}}

_gs_completions() {{
    local cur prev
    cur="${{words[$CURRENT]}}"
    prev="${{words[$CURRENT-1]}}"

    # Handle option flags
    if [[ "$cur" == -* ]]; then
        _arguments \\
            '--help[{help_desc}]' \\
            '--version[{version_desc}]' \\
            '--verbose[Enable verbose output]'
        return 0
    fi

    case $CURRENT in
        2)
            # First level: gs [command]
            local -a system_commands
            system_commands=(
                'help:{help_desc}'
                'version:{version_desc}'
                'plugin:{plugin_desc}'
                'refresh:{refresh_desc}'
                'status:{status_desc}'
                'doctor:{doctor_desc}'
                'parser:{parser_desc}'
            )
            _describe 'system commands' system_commands
            _gs_plugins
            ;;
        3)
            # Second level: gs <plugin|system> [subcommand]
            case "$prev" in
                plugin)
                    local -a plugin_commands
                    plugin_commands=(
                        'list:List all plugins'
                        'info:Show plugin information'
                        'enable:Enable a plugin'
                        'disable:Disable a plugin'
                        'create:Create new plugin'
                    )
                    _describe 'plugin commands' plugin_commands
                    ;;
                parser)
                    local -a parser_commands
                    parser_commands=(
                        'list:List all parsers'
                        'info:Show parser information'
                        'enable:Enable a parser'
                        'disable:Disable a parser'
                        'test:Test file parsing'
                    )
                    _describe 'parser commands' parser_commands
                    ;;
                *)
                    _gs_subplugins
                    ;;
            esac
            ;;
        4)
            # Third level
            case "${{words[2]}}" in
                plugin)
                    case "${{words[3]}}" in
                        enable|disable|info)
                            _gs_plugins
                            ;;
                    esac
                    ;;
                parser)
                    case "${{words[3]}}" in
                        enable|disable|info)
                            # Get parser names from gs parser list
                            local -a parser_names
                            parser_names=($(gs parser list 2>/dev/null | grep -E '│.*│.*│.*│.*│' | grep -v '^┌' | grep -v '^├' | grep -v '^└' | grep -v 'Name' | awk -F'│' '{{gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2}}'))
                            compadd -a parser_names
                            ;;
                    esac
                    ;;
                *)
                    _gs_functions
                    ;;
            esac
            ;;
        *)
            # Higher levels - continue with function completion
            _gs_functions
            ;;
    esac
}}

compdef _gs_completions gs
'''

        return script

    def generate_fish_completion(self, language: str = 'zh') -> str:
        """Generate fish completion script - Dynamic from router index"""
        plugins = self.index.get('plugins', {})
        plugin_names = sorted(plugins.keys())
        router_index_path = str(self.router_index_path.resolve())

        # Get system command descriptions
        try:
            from ..utils.i18n import I18nManager
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

        script = f'''# Global Scripts v6 Fish Completion - Dynamic router index support
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
        set -l desc (jq -r ".plugins[\\"$plugin\\"].description.$_GS_LANGUAGE // .plugins[\\"$plugin\\"].description.zh // .plugins[\\"$plugin\\"].description.en // \\"\\\"" "$_GS_ROUTER_INDEX" 2>/dev/null)

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
    test (count $cmd) -eq 3; and contains -- $cmd[2] plugin
end

# Helper to check if we need parameter completion (Level 4+)
function __fish_gs_needs_parameter
    set -l cmd (commandline -opc)
    set -l count (count $cmd)
    # Check if we're at level 4 or higher
    test $count -ge 4
end

# Dynamic parameter completion - read completions from router index (Level 4+)
function __fish_gs_parameter_completions
    set -l cmd (commandline -opc)
    set -l plugin $cmd[2]
    set -l count (count $cmd)

    # Build command path from arguments
    set -l cmd_path ""
    if test $count -eq 4
        # gs plugin subplugin function [param]
        set cmd_path "$cmd[3] $cmd[4]"
    else if test $count -ge 5
        # More complex path
        set cmd_path (string join ' ' $cmd[3..-2])
    end

    # Get completions for this command from router index
    set -l completions (jq -r ".plugins[\\"$plugin\\"].commands[\\"$cmd_path\\"].completions[]?" "$_GS_ROUTER_INDEX" 2>/dev/null)

    if test -n "$completions"
        for item in $completions
            echo $item
        end
    end
end

# Helper function to get parser names
function __fish_gs_parsers
    # Run gs parser list and extract parser names from the table
    gs parser list 2>/dev/null | grep -E '│.*│.*│.*│.*│' | grep -v '^┌' | grep -v '^├' | grep -v '^└' | grep -v 'Name' | awk -F'│' '{{gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2}}'
end

# Helper to check if we need parser name completion (for parser info/enable/disable)
function __fish_gs_needs_parser_name
    set -l cmd (commandline -opc)
    # Check if we're at position 4: gs parser <subcommand> [parser_name]
    # and the subcommand is one that needs a parser name
    if test (count $cmd) -eq 3
        if test "$cmd[2]" = "parser"
            if contains -- "$cmd[3]" info enable disable
                return 0
            end
        end
    end
    return 1
end

# Main gs command completion
complete -c gs -f -n "__fish_use_subcommand" -a "help" -d "{help_desc}"
complete -c gs -f -n "__fish_use_subcommand" -a "version" -d "{version_desc}"
complete -c gs -f -n "__fish_use_subcommand" -a "plugin" -d "{plugin_desc}"
complete -c gs -f -n "__fish_use_subcommand" -a "refresh" -d "{refresh_desc}"
complete -c gs -f -n "__fish_use_subcommand" -a "status" -d "{status_desc}"
complete -c gs -f -n "__fish_use_subcommand" -a "doctor" -d "{doctor_desc}"
complete -c gs -f -n "__fish_use_subcommand" -a "parser" -d "{parser_desc}"
complete -c gs -f -n "__fish_use_subcommand" -a "(__fish_gs_plugins)"

# Plugin name completion for info/enable/disable commands
complete -c gs -f -n "__fish_gs_needs_plugin_name" -a "(__fish_gs_plugins)"

# Parser name completion for info/enable/disable commands
complete -c gs -f -n "__fish_gs_needs_parser_name" -a "(__fish_gs_parsers)"

# Dynamic subplugin completions (Level 2)
complete -c gs -f -n "__fish_gs_needs_subplugin" -a "(__fish_gs_subplugins)"

# Dynamic parameter completions (Level 4+) - Check this BEFORE Level 3!
complete -c gs -f -n "__fish_gs_needs_parameter" -a "(__fish_gs_parameter_completions)"

# Dynamic function completions (Level 3)
complete -c gs -f -n "__fish_gs_needs_function" -a "(__fish_gs_functions)"

# Plugin subcommands
complete -c gs -f -n "__fish_seen_subcommand_from plugin" -a "list" -d "List all plugins"
complete -c gs -f -n "__fish_seen_subcommand_from plugin" -a "info" -d "Show plugin information"
complete -c gs -f -n "__fish_seen_subcommand_from plugin" -a "enable" -d "Enable a plugin"
complete -c gs -f -n "__fish_seen_subcommand_from plugin" -a "disable" -d "Disable a plugin"
complete -c gs -f -n "__fish_seen_subcommand_from plugin" -a "create" -d "Create new plugin"

# Parser subcommands
complete -c gs -f -n "__fish_seen_subcommand_from parser; and not __fish_seen_subcommand_from list info enable disable test" -a "list" -d "List all parsers"
complete -c gs -f -n "__fish_seen_subcommand_from parser; and not __fish_seen_subcommand_from list info enable disable test" -a "info" -d "Show parser information"
complete -c gs -f -n "__fish_seen_subcommand_from parser; and not __fish_seen_subcommand_from list info enable disable test" -a "enable" -d "Enable a parser"
complete -c gs -f -n "__fish_seen_subcommand_from parser; and not __fish_seen_subcommand_from list info enable disable test" -a "disable" -d "Disable a parser"
complete -c gs -f -n "__fish_seen_subcommand_from parser; and not __fish_seen_subcommand_from list info enable disable test" -a "test" -d "Test file parsing"
'''
        return script


def generate_completions_from_index(router_index_path: Path, output_dir: Path, language: str = 'zh') -> Tuple[Path, Path, Path]:
    """Generate completion scripts from router index

    Args:
        router_index_path: Path to router/index.json or router.json
        output_dir: Output directory for completion scripts
        language: Language for descriptions ('zh' or 'en')

    Returns:
        (bash_file_path, zsh_file_path, fish_file_path)
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    generator = CompletionGenerator(router_index_path)

    # Generate bash completion
    bash_content = generator.generate_bash_completion()
    bash_file = output_dir / 'gs.bash'
    with open(bash_file, 'w', encoding='utf-8') as f:
        f.write(bash_content)

    # Generate zsh completion
    zsh_content = generator.generate_zsh_completion(language=language)
    zsh_file = output_dir / 'gs.zsh'
    with open(zsh_file, 'w', encoding='utf-8') as f:
        f.write(zsh_content)

    # Generate fish completion
    fish_content = generator.generate_fish_completion(language=language)
    fish_file = output_dir / 'gs.fish'
    with open(fish_file, 'w', encoding='utf-8') as f:
        f.write(fish_content)

    return bash_file, zsh_file, fish_file