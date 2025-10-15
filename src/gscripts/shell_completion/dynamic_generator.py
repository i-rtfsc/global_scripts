#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dynamic completion generator supporting unlimited command depth
Based on router index structure
"""

from pathlib import Path
from typing import Dict, List, Set, Tuple
import json

from ..core.logger import get_logger

logger = get_logger(tag="SHELL.COMPLETION", name=__name__)


class DynamicCompletionGenerator:
    """Generate dynamic shell completions supporting arbitrary command depth"""

    SYSTEM_COMMANDS = ['help', 'version', 'plugin', 'refresh', 'status', 'doctor']
    PLUGIN_SUBCOMMANDS = ['list', 'info', 'enable', 'disable', 'create']

    def __init__(self, router_index_path: Path, show_descriptions: bool = True,
                 show_subcommand_descriptions: bool = True, language: str = 'zh'):
        self.router_index_path = router_index_path
        self.show_descriptions = show_descriptions
        self.show_subcommand_descriptions = show_subcommand_descriptions
        self.language = language
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

    def _get_all_command_paths(self) -> Dict[str, List[str]]:
        """Extract all command paths from router index

        Returns:
            Dict mapping plugin_name to list of command keys
            Example: {'system': ['config install', 'config list', 'brew aliyun']}
        """
        plugins = self.index.get('plugins', {})
        result = {}

        for plugin_name, plugin_data in plugins.items():
            commands = plugin_data.get('commands', {})
            result[plugin_name] = sorted(commands.keys())

        return result

    def generate_bash_completion(self) -> str:
        """Generate dynamic bash completion supporting arbitrary depth"""
        plugins = self.index.get('plugins', {})
        plugin_names = sorted(plugins.keys())
        router_index_path = str(self.router_index_path)

        script = f'''#!/bin/bash
# Global Scripts v6 Bash Completion - Dynamic multi-level support
# Auto-generated from router index

# Router index path for dynamic lookup
_GS_ROUTER_INDEX="{router_index_path}"

_gs_complete() {{
    local cur prev opts
    COMPREPLY=()
    cur="${{COMP_WORDS[COMP_CWORD]}}"
    prev="${{COMP_WORDS[COMP_CWORD-1]}}"

    # Get all words except 'gs'
    local words=("${{COMP_WORDS[@]:1}}")
    local word_count=${{#words[@]}}

    # Handle option flags
    if [[ ${{cur}} == -* ]]; then
        COMPREPLY=( $(compgen -W "--help --version --verbose" -- ${{cur}}) )
        return 0
    fi

    # Check if jq is available for dynamic lookup
    if ! command -v jq &>/dev/null; then
        # Fallback to basic completion without jq
        case $word_count in
            1)
                local base_commands="{' '.join(self.SYSTEM_COMMANDS + plugin_names)}"
                COMPREPLY=( $(compgen -W "${{base_commands}}" -- ${{cur}}) )
                ;;
        esac
        return 0
    fi

    case $word_count in
        1)
            # Level 1: gs [command]
            local base_commands="{' '.join(self.SYSTEM_COMMANDS + plugin_names)}"
            COMPREPLY=( $(compgen -W "${{base_commands}}" -- ${{cur}}) )
            ;;
        2)
            # Level 2: gs <plugin> [subcommand]
            if [[ "${{words[0]}}" == "plugin" ]]; then
                COMPREPLY=( $(compgen -W "{' '.join(self.PLUGIN_SUBCOMMANDS)}" -- ${{cur}}) )
            else
                # Query router index for subplugins
                local plugin="${{words[0]}}"

                # First try to get subplugins list (new format with descriptions)
                local subplugins=$(jq -r ".plugins[\\"$plugin\\"].subplugins[].name" "$_GS_ROUTER_INDEX" 2>/dev/null | tr '\\n' ' ')

                if [[ -n "$subplugins" ]]; then
                    # Plugin has subplugins, use them directly
                    COMPREPLY=( $(compgen -W "$subplugins" -- ${{cur}}) )
                else
                    # No subplugins, extract first words from commands (for plugins without subplugins structure)
                    local level2_opts=$(jq -r ".plugins[\\"$plugin\\"].commands | keys[]" "$_GS_ROUTER_INDEX" 2>/dev/null | awk '{{print $1}}' | sort -u | tr '\\n' ' ')
                    if [[ -n "$level2_opts" ]]; then
                        COMPREPLY=( $(compgen -W "$level2_opts" -- ${{cur}}) )
                    fi
                fi
            fi
            ;;
        3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18|19|20)
            # Level 3+: Dynamic lookup from router index
            if [[ "${{words[0]}}" == "plugin" ]]; then
                # Special handling for plugin commands
                case "${{words[1]}}" in
                    enable|disable|info)
                        COMPREPLY=( $(compgen -W "{' '.join(plugin_names)}" -- ${{cur}}) )
                        ;;
                esac
            else
                # Build command path from all words between plugin and cursor
                local plugin="${{words[0]}}"
                local cmd_path=""

                # Build multi-word command path - skip empty words
                for ((i=1; i<=$word_count-1; i++)); do
                    # Skip empty strings (caused by cursor position)
                    [[ -z "${{words[$i]}}" ]] && continue

                    if [[ -n "$cmd_path" ]]; then
                        cmd_path="$cmd_path ${{words[$i]}}"
                    else
                        cmd_path="${{words[$i]}}"
                    fi
                done

                # First check if this exact command has completion metadata
                local cmd_completions=$(jq -r ".plugins[\\"$plugin\\"].commands[\\"$cmd_path\\"].completions[]?" "$_GS_ROUTER_INDEX" 2>/dev/null)

                if [[ -n "$cmd_completions" ]]; then
                    # Use predefined completions from router index
                    COMPREPLY=( $(compgen -W "$cmd_completions" -- ${{cur}}) )
                else
                    # Find commands that start with current path
                    local matching_cmds=$(jq -r ".plugins[\\"$plugin\\"].commands | keys[]" "$_GS_ROUTER_INDEX" 2>/dev/null | grep "^$cmd_path")

                    if [[ -n "$matching_cmds" ]]; then
                        # Extract next word from matching commands
                        local next_words=()
                        while IFS= read -r cmd; do
                            # Remove the prefix and get the next word
                            local remaining="${{cmd#$cmd_path}}"
                            remaining="${{remaining## }}"  # Trim leading spaces
                            local next_word=$(echo "$remaining" | awk '{{print $1}}')
                            if [[ -n "$next_word" ]]; then
                                next_words+=("$next_word")
                            fi
                        done <<< "$matching_cmds"

                        # Remove duplicates
                        local unique_next=$(printf "%s\\n" "${{next_words[@]}}" | sort -u)
                        COMPREPLY=( $(compgen -W "$unique_next" -- ${{cur}}) )
                    fi
                fi
            fi
            ;;
    esac
}}

complete -F _gs_complete gs
'''
        return script

    def generate_zsh_completion(self) -> str:
        """Generate dynamic zsh completion supporting arbitrary depth"""
        plugins = self.index.get('plugins', {})
        plugin_names = sorted(plugins.keys())
        router_index_path = str(self.router_index_path)

        # Helper function to get plugin/command descriptions
        def get_plugin_desc(plugin_name: str) -> str:
            """Get plugin description"""
            if not self.show_descriptions:
                return ""
            plugin_data = plugins.get(plugin_name, {})
            desc = plugin_data.get('description', '')
            if isinstance(desc, dict):
                return desc.get(self.language, desc.get('zh', desc.get('en', '')))
            return str(desc) if desc else ""

        def escape_desc(desc: str) -> str:
            """Escape special characters for zsh"""
            return desc.replace('"', '\\"').replace("'", "\\'").replace('`', '\\`')

        # Build Level 1 completions with descriptions
        level1_completions = []
        # Get system command descriptions from i18n
        try:
            from ..utils.i18n import I18nManager
            i18n_mgr = I18nManager(chinese=(self.language == 'zh'))
            system_cmd_descs = {
                'help': i18n_mgr.get_message('commands.help'),
                'version': i18n_mgr.get_message('commands.version'),
                'plugin': i18n_mgr.get_message('commands.plugin_management'),
                'refresh': i18n_mgr.get_message('commands.refresh'),
                'status': i18n_mgr.get_message('commands.system_status'),
                'doctor': i18n_mgr.get_message('commands.doctor')
            }
        except Exception:
            # Fallback to hardcoded if i18n fails
            system_cmd_descs = {
                'help': {
                    'zh': '显示帮助信息',
                    'en': 'Show help information'
                },
                'version': {
                    'zh': '显示版本信息',
                    'en': 'Show version information'
                },
                'plugin': {
                    'zh': '插件管理',
                    'en': 'Plugin management'
                },
                'refresh': {
                    'zh': '刷新系统',
                    'en': 'Refresh configuration'
                },
                'status': {
                    'zh': '显示系统状态',
                    'en': 'Show system status'
                },
                'doctor': {
                    'zh': '系统诊断',
                    'en': 'Check system health'
                }
            }
            # Extract value based on language
            for cmd in system_cmd_descs:
                if isinstance(system_cmd_descs[cmd], dict):
                    system_cmd_descs[cmd] = system_cmd_descs[cmd].get(self.language, system_cmd_descs[cmd].get('zh', ''))

        for cmd in self.SYSTEM_COMMANDS:
            if self.show_descriptions:
                desc = system_cmd_descs.get(cmd, '')
                level1_completions.append(f'"{cmd}:{escape_desc(desc)}"')
            else:
                level1_completions.append(f'"{cmd}"')

        for plugin_name in plugin_names:
            if self.show_descriptions:
                desc = get_plugin_desc(plugin_name)
                if desc:
                    level1_completions.append(f'"{plugin_name}:{escape_desc(desc)}"')
                else:
                    level1_completions.append(f'"{plugin_name}"')
            else:
                level1_completions.append(f'"{plugin_name}"')

        script = f'''#compdef gs
# Global Scripts v6 Zsh Completion - Dynamic multi-level support
# Auto-generated from router index

# Router index path for dynamic lookup
_GS_ROUTER_INDEX="{router_index_path}"
_GS_SHOW_DESCRIPTIONS={str(self.show_descriptions).lower()}
_GS_SHOW_SUBCOMMAND_DESCRIPTIONS={str(self.show_subcommand_descriptions).lower()}
_GS_LANGUAGE="{self.language}"

_gs_completions() {{
    local cur prev
    cur="${{words[$CURRENT]}}"
    prev="${{words[$CURRENT-1]}}"

    # Handle option flags
    if [[ "$cur" == -* ]]; then
        compadd -- "--help" "--version" "--verbose"
        return 0
    fi

    # Check if jq is available
    if ! command -v jq &>/dev/null; then
        # Fallback without jq - no descriptions
        case $CURRENT in
            2)
                compadd -- {' '.join(f'"{cmd}"' for cmd in self.SYSTEM_COMMANDS + plugin_names)}
                ;;
        esac
        return 0
    fi

    case $CURRENT in
        2)
            # Level 1: gs [command]
            if [[ "$_GS_SHOW_DESCRIPTIONS" == "true" ]]; then
                _describe 'command' '({' '.join(level1_completions)} )'
            else
                compadd -- {' '.join(f'"{cmd}"' for cmd in self.SYSTEM_COMMANDS + plugin_names)}
            fi
            ;;
        3)
            # Level 2: gs <plugin> [subcommand]
            if [[ "${{words[2]}}" == "plugin" ]]; then
                compadd -- {' '.join(f'"{cmd}"' for cmd in self.PLUGIN_SUBCOMMANDS)}
            else
                # Query router index for subplugins
                local plugin="${{words[2]}}"

                # First try to get subplugins list (new format with descriptions)
                local subplugin_count=$(jq -r ".plugins[\\"$plugin\\"].subplugins | length" "$_GS_ROUTER_INDEX" 2>/dev/null)

                if [[ "$subplugin_count" -gt 0 ]]; then
                    # Plugin has subplugins, extract names and descriptions
                    if [[ "$_GS_SHOW_SUBCOMMAND_DESCRIPTIONS" == "true" ]]; then
                        local -a completions
                        local i name desc
                        for ((i=0; i<subplugin_count; i++)); do
                            name=$(jq -r ".plugins[\\"$plugin\\"].subplugins[$i].name" "$_GS_ROUTER_INDEX" 2>/dev/null)
                            desc=$(jq -r ".plugins[\\"$plugin\\"].subplugins[$i].description.$_GS_LANGUAGE // .plugins[\\"$plugin\\"].subplugins[$i].description.zh // .plugins[\\"$plugin\\"].subplugins[$i].description.en // \\"\\"" "$_GS_ROUTER_INDEX" 2>/dev/null)
                            if [[ -n "$desc" ]]; then
                                completions+=("$name:$desc")
                            else
                                completions+=("$name")
                            fi
                        done
                        _describe 'subcommand' completions
                    else
                        local subplugins=($(jq -r ".plugins[\\"$plugin\\"].subplugins[].name" "$_GS_ROUTER_INDEX" 2>/dev/null))
                        compadd -- "${{subplugins[@]}}"
                    fi
                else
                    # No subplugins, extract first words from commands
                    if [[ "$_GS_SHOW_SUBCOMMAND_DESCRIPTIONS" == "true" ]]; then
                        local -a completions
                        local -A seen_commands
                        local cmd_key first_word desc

                        # Get all command keys
                        local cmd_keys=($(jq -r ".plugins[\\"$plugin\\"].commands | keys[]" "$_GS_ROUTER_INDEX" 2>/dev/null))

                        for cmd_key in "${{cmd_keys[@]}}"; do
                            first_word="${{cmd_key%% *}}"

                            # Skip if already seen
                            [[ -n "${{seen_commands[$first_word]}}" ]] && continue
                            seen_commands[$first_word]=1

                            # Try to get description for this command
                            desc=$(jq -r ".plugins[\\"$plugin\\"].commands[\\"$cmd_key\\"].description.$_GS_LANGUAGE // .plugins[\\"$plugin\\"].commands[\\"$cmd_key\\"].description.zh // .plugins[\\"$plugin\\"].commands[\\"$cmd_key\\"].description.en // \\"\\"" "$_GS_ROUTER_INDEX" 2>/dev/null)

                            if [[ -n "$desc" ]]; then
                                completions+=("$first_word:$desc")
                            else
                                completions+=("$first_word")
                            fi
                        done

                        _describe 'command' completions
                    else
                        local level2_opts=($(jq -r ".plugins[\\"$plugin\\"].commands | keys[]" "$_GS_ROUTER_INDEX" 2>/dev/null | awk '{{print $1}}' | sort -u))
                        if (( ${{#level2_opts[@]}} > 0 )); then
                            compadd -- "${{level2_opts[@]}}"
                        fi
                    fi
                fi
            fi
            ;;
        *)
            # Level 3+: Dynamic lookup
            if [[ "${{words[2]}}" == "plugin" ]]; then
                case "${{words[3]}}" in
                    enable|disable|info)
                        compadd -- {' '.join(f'"{name}"' for name in plugin_names)}
                        ;;
                esac
            else
                # Build command path from all words between plugin and cursor
                local plugin="${{words[2]}}"
                local cmd_path=""

                # Build multi-word path - skip empty words
                for ((i=3; i<=$CURRENT-1; i++)); do
                    # Skip empty strings (caused by cursor position)
                    [[ -z "${{words[$i]}}" ]] && continue

                    if [[ -n "$cmd_path" ]]; then
                        cmd_path="$cmd_path ${{words[$i]}}"
                    else
                        cmd_path="${{words[$i]}}"
                    fi
                done

                # First check if this exact command has completion metadata
                local cmd_completions=($(jq -r ".plugins[\\"$plugin\\"].commands[\\"$cmd_path\\"].completions[]?" "$_GS_ROUTER_INDEX" 2>/dev/null))

                if (( ${{#cmd_completions[@]}} > 0 )); then
                    # Use predefined completions from router index
                    compadd -- "${{cmd_completions[@]}}"
                else
                    # Find commands that start with current path and extract next word
                    local next_words=($(jq -r ".plugins[\\"$plugin\\"].commands | keys[]" "$_GS_ROUTER_INDEX" 2>/dev/null | awk -v prefix="$cmd_path" '
                        $0 ~ "^"prefix" " {{
                            sub("^"prefix" ", "")
                            print $1
                        }}
                    ' | sort -u))

                    if (( ${{#next_words[@]}} > 0 )); then
                        if [[ "$_GS_SHOW_SUBCOMMAND_DESCRIPTIONS" == "true" ]]; then
                            local -a completions
                            local word desc full_cmd
                            for word in "${{next_words[@]}}"; do
                                full_cmd="$cmd_path $word"
                                desc=$(jq -r ".plugins[\\"$plugin\\"].commands[\\"$full_cmd\\"].description.$_GS_LANGUAGE // .plugins[\\"$plugin\\"].commands[\\"$full_cmd\\"].description.zh // .plugins[\\"$plugin\\"].commands[\\"$full_cmd\\"].description.en // \\"\\"" "$_GS_ROUTER_INDEX" 2>/dev/null)
                                if [[ -n "$desc" ]]; then
                                    completions+=("$word:$desc")
                                else
                                    completions+=("$word")
                                fi
                            done
                            _describe 'command' completions
                        else
                            compadd -- "${{next_words[@]}}"
                        fi
                    fi
                fi
            fi
            ;;
    esac
}}

compdef _gs_completions gs
'''
        return script


def generate_dynamic_completions(router_index_path: Path, output_dir: Path) -> Tuple[Path, Path]:
    """Generate dynamic completion scripts

    Args:
        router_index_path: Path to router/index.json
        output_dir: Output directory for completion scripts

    Returns:
        (bash_file_path, zsh_file_path)
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    generator = DynamicCompletionGenerator(router_index_path)

    # Generate bash completion
    bash_content = generator.generate_bash_completion()
    bash_file = output_dir / 'gs.bash'
    with open(bash_file, 'w', encoding='utf-8') as f:
        f.write(bash_content)

    # Generate zsh completion
    zsh_content = generator.generate_zsh_completion()
    zsh_file = output_dir / 'gs.zsh'
    with open(zsh_file, 'w', encoding='utf-8') as f:
        f.write(zsh_content)

    return bash_file, zsh_file
