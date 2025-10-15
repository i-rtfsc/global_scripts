#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Environment Installer for Global Scripts V6
Handles shell configuration generation and environment setup
Similar to V5 design but adapted for V6 structure
"""

import os
import json
from pathlib import Path
from typing import Dict, List, Optional
import logging

from .config_manager import ConfigManager
from .plugin_manager import PluginManager
from .constants import GlobalConstants
from ..utils.i18n import get_i18n_manager


from ..core.logger import get_logger
from ..utils.logging_utils import (
    redact, redact_kv, redact_command, ctx, correlation_id, 
    duration, trunc, sanitize_path, format_size, safe_repr,
    log_context, format_exception, measure_time
)

# Module-level logger
logger = get_logger(tag="CORE.INSTALLER", name=__name__)

logger = logging.getLogger(__name__)

class EnvironmentInstaller:
    """Manages Global Scripts environment installation and configuration"""
    
    def __init__(self):
        self.constants = GlobalConstants()
        self.config_manager = ConfigManager()
        self.plugin_manager = PluginManager(self.config_manager)
        # 新结构: src/gscripts/core/installer.py → 向上4级到项目根
        self.gs_root = Path(__file__).parent.parent.parent.parent
        self.i18n = get_i18n_manager()

        # 使用常量中的配置目录
        self.config_dir = self.constants.get_config_dir()
        # Shell configuration file in working directory
        self.shell_config_file = self.gs_root / "env.sh"
        self.completion_dir = self.config_dir / "completions"
    
    def initialize_environment(self) -> bool:
        """Initialize Global Scripts environment"""
        try:
            logger.info(f"🚀 {self.i18n.get_message('setup.banner_title')}")
            
            # Create configuration directory
            self.config_dir.mkdir(parents=True, exist_ok=True)
            self.completion_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate shell configuration
            if not self._generate_shell_config():
                return False
            
            # Generate completions
            if not self._generate_completions():
                return False
            
            # Create logs directory
            logs_dir = self.config_dir / "logs"
            logs_dir.mkdir(exist_ok=True)
            
            logger.info("✅ " + self.i18n.get_message('success.config_saved'))
            return True
            
        except Exception as e:
            logger.error(f"Environment initialization failed: {e}", exc_info=True)
            logger.error("❌ " + self.i18n.get_message('errors.config_load_failed', error=str(e)))
            return False
    
    def refresh_shell_config(self) -> bool:
        """Refresh shell configuration"""
        try:
            logger.info("🔄 " + self.i18n.get_message('commands.refresh'))
            
            # Regenerate shell configuration
            if not self._generate_shell_config():
                return False
            
            # Regenerate completions
            if not self._generate_completions():
                return False
            
            logger.info("✅ " + self.i18n.get_message('success.cache_cleared'))
            return True
            
        except Exception as e:
            logger.error(f"Shell config refresh failed: {e}", exc_info=True)
            logger.error("❌ " + self.i18n.get_message('errors.execution_failed', error=str(e)))
            return False
    
    def _generate_shell_config(self) -> bool:
        """Generate shell configuration file"""
        try:
            # Get available plugins from plugin manager
            plugins = self.plugin_manager.discover_plugins()
            
            shell_content = self._build_shell_config(plugins)
            
            # Write shell configuration
            with open(self.shell_config_file, 'w', encoding='utf-8') as f:
                f.write(shell_content)
            
            # Make file executable
            os.chmod(self.shell_config_file, 0o755)
            
            logger.info(f"Shell configuration written to {self.shell_config_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to generate shell config: {e}")
            return False
    
    def _build_shell_config(self, plugins: List[Dict]) -> str:
        """Build shell configuration content"""
        gs_root = str(self.gs_root)

        # Read version from VERSION file
        version_file = self.gs_root / "VERSION"
        version = version_file.read_text().strip() if version_file.exists() else "unknown"

        # Header with version branding
        shell_content = f"""#!/bin/bash
# Global Scripts V6 Environment Configuration
# Generated automatically - do not edit manually
# Configuration source: {gs_root}

# Global Scripts root directory
export GS_ROOT="{gs_root}"

# V6 Configuration Variables
# Unified logging level (E/W/I/D/V/NANO). Default INFO unless user config overrides.
export GS_LOGGING_LEVEL="INFO"
export GS_PROMPT_THEME="minimalist"

# Add Global Scripts to PATH
if [[ ":$PATH:" != *":$GS_ROOT:"* ]]; then
    export PATH="$GS_ROOT:$PATH"
fi

# Global Scripts version
export GS_VERSION="{version}"

# Platform detection
export GS_PLATFORM="$(uname | tr '[:upper:]' '[:lower:]')"

# Plugin loading control variables
declare -A GS_PLUGIN_ENABLED
declare -A GS_PLUGIN_PRIORITY

# Function cache for performance optimization
# Cross-shell compatible associative array
if [[ -n "$ZSH_VERSION" ]]; then
    # Zsh syntax
    typeset -A __GS_LOADED
elif [[ -n "$BASH_VERSION" ]] && [[ ${{BASH_VERSINFO[0]}} -ge 4 ]]; then
    # Bash 4+ syntax
    declare -gA __GS_LOADED
fi

"""
        
        # Add plugin configuration and functions
        enabled_count = 0
        function_count = 0
        
        shell_content += "# Plugin status configuration\\n"
        for plugin in plugins:
            plugin_name = plugin['name']
            priority = plugin.get('priority', 10)
            enabled = plugin.get('enabled', True)
            
            shell_content += f'GS_PLUGIN_ENABLED["{plugin_name}"]={str(enabled).lower()}\\n'
            shell_content += f'GS_PLUGIN_PRIORITY["{plugin_name}"]={priority}\\n'
            
            if enabled:
                enabled_count += 1
        
        shell_content += "\\n# Plugin command functions\\n"
        
        # Generate shell functions for each plugin
        for plugin in plugins:
            if not plugin.get('enabled', True):
                continue
                
            plugin_name = plugin['name']
            functions = plugin.get('functions', {})
            
            for func_name, func_info in functions.items():
                shell_func_name = f"gs-{plugin_name}-{func_name}"
                shell_content += f'{shell_func_name}() {{ "$GS_ROOT/gs" {plugin_name} {func_name} "$@"; }}\\n'
                function_count += 1
        
        # Add core management functions
        shell_content += """
# Core command functions
gs() { "$GS_ROOT/gs" "$@"; }
gs-plugin() { "$GS_ROOT/gs" plugin "$@"; }
gs-plugin-enable() { 
    "$GS_ROOT/gs" plugin enable "$@"
    if [[ $? -eq 0 ]]; then
        echo "🔄 Reloading shell environment..."
        source "$GS_ROOT/env.sh"
        echo "✅ Plugin commands are now available!"
    fi
}
gs-plugin-disable() { 
    local plugin_name="$1"
    if [[ -z "$plugin_name" ]]; then
        "$GS_ROOT/gs" plugin disable "$@"
        return $?
    fi
    
    # First unset all functions for this plugin
    echo "🧹 Removing plugin functions..."
    for func in $(typeset -f | grep -o "^gs-${plugin_name}[a-zA-Z0-9_-]*" 2>/dev/null || true); do
        unset -f "$func" 2>/dev/null || true
    done
    
    "$GS_ROOT/gs" plugin disable "$@"
    if [[ $? -eq 0 ]]; then
        echo "🔄 Reloading shell environment..."
        source "$GS_ROOT/env.sh"
        echo "✅ Plugin commands are no longer available!"
    fi
}

# Environment management functions
gs-sync() { "$GS_ROOT/gs" sync "$@"; }
gs-init() { "$GS_ROOT/gs" init "$@"; }
gs-refresh() { 
    echo "🧹 Cleaning up old shell functions..."
    # Unset all existing gs-* functions
    for func in $(typeset -f | grep -o '^gs-[a-zA-Z0-9_-]*' 2>/dev/null || true); do
        unset -f "$func" 2>/dev/null || true
    done
    
    "$GS_ROOT/gs" refresh "$@"
    if [[ $? -eq 0 ]]; then
        echo "🔄 Reloading shell environment..."
        source "$GS_ROOT/env.sh"
        echo "✅ Shell environment refreshed successfully!"
    fi
}

# Initialize conda if available (without loading full shell configs to avoid loops)
if ! command -v conda >/dev/null 2>&1; then
    # Common conda installation paths across platforms
    for conda_base in "$HOME/miniconda3" "$HOME/anaconda3" "$HOME/miniforge3" \\
                      "/opt/miniconda3" "/opt/anaconda3" "/opt/miniforge3" \\
                      "/usr/local/miniconda3" "/usr/local/anaconda3"; do
        if [[ -f "$conda_base/etc/profile.d/conda.sh" ]]; then
            source "$conda_base/etc/profile.d/conda.sh" 2>/dev/null
            break
        fi
    done
fi

# Load completions
if [[ -d "${{HOME}}/.config/global-scripts/completions" ]]; then
    for comp_file in "${{HOME}}/.config/global-scripts/completions"/*; do
        [[ -r "$comp_file" ]] && source "$comp_file"
    done
fi

# Shell-specific configurations
if [[ -n "$ZSH_VERSION" ]]; then
    # Zsh-specific configuration
    autoload -U compinit
    compinit -u
elif [[ -n "$BASH_VERSION" ]]; then
    # Bash-specific configuration
    # Enable programmable completion features
    if ! shopt -oq posix; then
        if [[ -f /usr/share/bash-completion/bash_completion ]]; then
            . /usr/share/bash-completion/bash_completion
        elif [[ -f /etc/bash_completion ]]; then
            . /etc/bash_completion
        fi
    fi
fi

# Global Scripts V6 initialization complete
echo "🚀 Global Scripts V6 loaded successfully!"
echo "📍 Source: $GS_ROOT"
echo "📦 {enabled_count} plugins enabled ({function_count} functions)"
echo "💡 Use 'gs help' or 'gs plugin list' to get started"
"""
        
        return shell_content
    
    def _generate_completions(self) -> bool:
        """Generate shell completions"""
        try:
            plugins = self.plugin_manager.discover_plugins()
            
            # Generate bash completions
            bash_completion = self._build_bash_completion(plugins)
            bash_file = self.completion_dir / "gs.bash"
            with open(bash_file, 'w', encoding='utf-8') as f:
                f.write(bash_completion)
            
            # Generate zsh completions
            zsh_completion = self._build_zsh_completion(plugins)
            zsh_file = self.completion_dir / "gs.zsh"
            with open(zsh_file, 'w', encoding='utf-8') as f:
                f.write(zsh_completion)
            
            logger.info("Shell completions generated")
            return True
            
        except Exception as e:
            logger.error(f"Failed to generate completions: {e}")
            return False
    
    def _build_bash_completion(self, plugins: List[Dict]) -> str:
        """Build bash completion script"""
        # Collect all commands
        commands = ['init', 'refresh', 'version', 'help', 'plugin', 'system']
        plugin_commands = {}
        
        for plugin in plugins:
            plugin_name = plugin['name']
            commands.append(plugin_name)
            plugin_commands[plugin_name] = list(plugin.get('functions', {}).keys())
        
        completion_script = f"""
# Bash completion for Global Scripts V6

_gs_completion() {{
    local cur prev opts
    COMPREPLY=()
    cur="${{COMP_WORDS[COMP_CWORD]}}"
    prev="${{COMP_WORDS[COMP_CWORD-1]}}"
    
    # Top-level commands
    if [[ $COMP_CWORD -eq 1 ]]; then
        opts="{' '.join(commands)}"
        COMPREPLY=( $(compgen -W "${{opts}}" -- "${{cur}}") )
        return 0
    fi
    
    # Plugin commands
    case "${{COMP_WORDS[1]}}" in
"""
        
        for plugin_name, cmds in plugin_commands.items():
            if cmds:
                completion_script += f"""        {plugin_name})
            opts="{' '.join(cmds)}"
            COMPREPLY=( $(compgen -W "${{opts}}" -- "${{cur}}") )
            ;;
"""
        
        completion_script += """        plugin)
            if [[ $COMP_CWORD -eq 2 ]]; then
                opts="list info enable disable"
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            fi
            ;;
    esac
}

complete -F _gs_completion gs
"""
        
        return completion_script
    
    def _build_zsh_completion(self, plugins: List[Dict]) -> str:
        """Build zsh completion script"""
        completion_script = """
# Zsh completion for Global Scripts V6

_gs() {
    local context state state_descr line
    typeset -A opt_args
    
    _arguments -C \\
        '1: :_gs_commands' \\
        '*: :->args'
    
    case $state in
        args)
            case $words[2] in
"""
        
        for plugin in plugins:
            plugin_name = plugin['name']
            functions = list(plugin.get('functions', {}).keys())
            if functions:
                completion_script += f"""                {plugin_name})
                    _arguments \\
                        '1: :({' '.join(functions)})'
                    ;;
"""
        
        completion_script += """                plugin)
                    _arguments \\
                        '1: :(list info enable disable)'
                    ;;
            esac
            ;;
    esac
}

_gs_commands() {
    local commands
    commands=(
        'init:Initialize environment'
        'refresh:Refresh shell configuration'
        'version:Show version information'
        'help:Show help message'
        'plugin:Plugin management'
        'system:System information'
"""
        
        for plugin in plugins:
            plugin_name = plugin['name']
            description = plugin.get('description', 'Plugin command')
            completion_script += f"        '{plugin_name}:{description}'\\n"
        
        completion_script += """    )
    _describe 'command' commands
}

compdef _gs gs
"""
        
        return completion_script
    
    def get_shell_config_path(self) -> Path:
        """Get the shell configuration file path"""
        return self.shell_config_file

class InstallationError(Exception):
    """Installation related errors"""
    pass
