#!/bin/bash
# -*- coding: utf-8 -*-
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2022 anqi.huang@outlook.com
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Global Scripts Environment Loader
# Enhanced with lazy loading and improved error handling

# Initialize paths
if [ -n "$ZSH_VERSION" ]; then
    _GS_ROOT_PATH=`dirname ${(%):-%N}`
elif [ -n "$BASH_VERSION" ]; then
    _GS_ROOT_PATH=`dirname "$BASH_SOURCE"`
fi
_GS_CONFIG_PATH="${_GS_ROOT_PATH}/conf"

# Global variables for lazy loading - shell compatible
if [[ -n "$ZSH_VERSION" ]]; then
    typeset -gA _gs_loaded_plugins
    typeset -gA _gs_plugin_commands
    typeset -gA _gs_plugin_paths
else
    declare -gA _gs_loaded_plugins
    declare -gA _gs_plugin_commands
    declare -gA _gs_plugin_paths
fi

# Debug: Show array initialization
[[ "${gs_env_debug:-0}" == "1" ]] && echo "[DEBUG] Global arrays initialized for shell: ${ZSH_VERSION:+zsh}${BASH_VERSION:+bash}" >&2

function _gs_init_path() {
    local gs_path=$1

    if [ ! -d ${gs_path} ]; then
        [[ "${gs_env_debug:-0}" == "1" ]] && echo "[DEBUG] ${gs_path} don't exists" >&2
        return
    fi

    if [[ ${PATH} == *"${gs_path}"* ]]; then
        [[ "${gs_env_debug:-0}" == "1" ]] && echo "[DEBUG] has been export, ${gs_path}" >&2
    else
        [[ "${gs_env_debug:-0}" == "1" ]] && echo "[DEBUG] export path = ${gs_path}" >&2
        export PATH=$PATH:"${gs_path}"
    fi
}

# Register plugin commands for lazy loading
function _gs_register_plugin_commands() {
    local plugin_name="$1"
    local plugin_dir="$2"
    
    if [[ -d "$plugin_dir" ]]; then
        local script_files=($(find "$plugin_dir" -name "gs_*.sh" -type f 2>/dev/null))
        
        for script_file in "${script_files[@]}"; do
            local functions=($(grep -o "^function [a-zA-Z_][a-zA-Z0-9_]*" "$script_file" 2>/dev/null | sed 's/^function //'))
            
            for func in "${functions[@]}"; do
                _gs_plugin_commands["$func"]="$plugin_name"
                
                # Create lazy loading wrapper
                eval "
                    function $func() {
                        _gs_load_plugin_on_demand '$plugin_name' '$func' \"\$@\"
                    }
                "
            done
        done
        
        _gs_plugin_paths["$plugin_name"]="$plugin_dir"
    fi
}

# Load plugin on demand
function _gs_load_plugin_on_demand() {
    local plugin_name="$1"
    local func_name="$2"
    shift 2
    
    if [[ -z "${_gs_loaded_plugins[$plugin_name]:-}" ]]; then
        [[ "${gs_env_debug:-0}" == "1" ]] && echo "[DEBUG] Loading plugin on demand: $plugin_name" >&2
        
        # Get plugin path with quote compatibility
        local plugin_path="${_gs_plugin_paths[$plugin_name]:-}"
        if [[ -z "$plugin_path" ]]; then
            plugin_path="${_gs_plugin_paths[\"$plugin_name\"]:-}"
        fi
        
        if [[ -n "$plugin_path" ]]; then
            _gs_load_plugin "$plugin_name" "$plugin_path"
            _gs_loaded_plugins["$plugin_name"]=1
        else
            echo "Error: Plugin path not found for $plugin_name" >&2
            return 1
        fi
    fi
    
    if type "$func_name" >/dev/null 2>&1; then
        "$func_name" "$@"
    else
        echo "Error: Function $func_name not found in plugin $plugin_name" >&2
        return 1
    fi
}

# Actually load a plugin
function _gs_load_plugin() {
    local plugin_name="$1"
    local plugin_dir="$2"
    
    [[ "${gs_env_debug:-0}" == "1" ]] && echo "[DEBUG] Loading plugin: $plugin_name from $plugin_dir" >&2
    
    # Use find to avoid glob expansion issues
    while IFS= read -r -d '' file; do
        if [ -f "$file" ]; then
            [[ "${gs_env_debug:-0}" == "1" ]] && echo "[DEBUG] Sourcing: $file" >&2
            source "$file"
        fi
    done < <(find "$plugin_dir" -maxdepth 1 -name "gs_*.sh" -type f -print0 2>/dev/null)
    
    if [ -d ${plugin_dir}/bin ]; then
        _gs_init_path ${plugin_dir}/bin
    fi
}

# Preload critical plugins
function _gs_preload_plugin() {
    local plugin_name="$1"
    local plugin_dir="$2"
    
    _gs_load_plugin "$plugin_name" "$plugin_dir"
    _gs_loaded_plugins["$plugin_name"]=1
}

function _gs_init_global_env() {
    # Set environment variables
    export _GS_ROOT_PATH=${_GS_ROOT_PATH}
    export _GS_CONFIG_PATH=${_GS_CONFIG_PATH}
    export LC_ALL=en_US.UTF-8
    export LANG=en_US.UTF-8

    local gs_path_bin=${_GS_ROOT_PATH}/bin
    local gs_path_env=${_GS_ROOT_PATH}/env
    local gs_path_conf=${_GS_ROOT_PATH}/conf
    local gs_path_plugins=${_GS_ROOT_PATH}/plugins
    local gs_path_themes=${_GS_ROOT_PATH}/themes
    local gs_path_codestyle=${_GS_ROOT_PATH}/tools/codestyle
    local gs_path_custom_plugins=${_GS_ROOT_PATH}/custom

    # Load configuration
    local gs_config=$HOME/.gsrc
    if [ ! -f ${gs_config} ]; then
        source ${_GS_CONFIG_PATH}/.gsrc
    else
        source ${gs_config}
    fi

    # Load environment files (always loaded)
    for file in ${gs_path_env}/gs_*.sh; do
        if [ -f ${file} ]; then
            [[ "${gs_env_debug:-0}" == "1" ]] && echo "[DEBUG] Loading env: $file" >&2
            source $file
        fi
    done

    # Set up PATH
    _gs_init_path ${gs_path_bin}
    _gs_init_path ${gs_path_conf}
    _gs_init_path ${gs_path_codestyle}
    
    # Android SDK platform-tools
    platform="$(uname -s)"
    case "$platform" in
        Linux*)
            _gs_init_path $HOME/Android/Sdk/platform-tools
            ;;
        Darwin*)
            _gs_init_path $HOME/Library/Android/sdk/platform-tools
            ;;
        *)
            [[ "${gs_env_debug:-0}" == "1" ]] && echo "[DEBUG] unknown platform: $platform" >&2
    esac

    # Load zsh-specific environment
    if [ -n "$ZSH_VERSION" ]; then
        for file in ${gs_path_env}/zsh_*.sh; do
            if [ -f ${file} ]; then
                [[ "${gs_env_debug:-0}" == "1" ]] && echo "[DEBUG] Loading zsh: $file" >&2
                source ${file}
            fi
        done
    fi

    # Critical plugins that should be preloaded
    local critical_plugins=("alias/common" "git")
    
    # Load plugins with lazy loading
    for plugin in ${gs_plugins[@]}; do
        local plugin_dir=${gs_path_plugins}/${plugin}
        
        if [ -d "$plugin_dir" ]; then
            local is_critical=false
            for critical in "${critical_plugins[@]}"; do
                if [[ "$plugin" == "$critical" ]]; then
                    is_critical=true
                    break
                fi
            done
            
            if [[ "$is_critical" == true ]]; then
                _gs_preload_plugin "$plugin" "$plugin_dir"
            else
                _gs_register_plugin_commands "$plugin" "$plugin_dir"
            fi
        else
            [[ "${gs_env_debug:-0}" == "1" ]] && echo "[DEBUG] Plugin directory not found: $plugin_dir" >&2
        fi
    done

    # Load themes (always loaded for prompt)
    if [ -n "${gs_themes_prompt:-}" ]; then
        prompt_info_file=${gs_path_themes}/prompt/gs_prompt_info.sh
        if [ -f ${prompt_info_file} ]; then
            [[ "${gs_env_debug:-0}" == "1" ]] && echo "[DEBUG] Loading prompt: $prompt_info_file" >&2
            source ${prompt_info_file}
        fi

        for file in ${gs_path_themes}/prompt/${gs_themes_prompt}/gs_*.sh; do
            if [ -f ${file} ]; then
                [[ "${gs_env_debug:-0}" == "1" ]] && echo "[DEBUG] Loading theme: $file" >&2
                source ${file}
            fi
        done
    fi

    # Load custom plugins
    for plugin in ${gs_custom_plugins[@]}; do
        local plugin_dir=${gs_path_custom_plugins}/${plugin}
        
        if [ -d "$plugin_dir" ]; then
            _gs_register_plugin_commands "custom_${plugin}" "$plugin_dir"
        else
            [[ "${gs_env_debug:-0}" == "1" ]] && echo "[DEBUG] Custom plugin not found: $plugin_dir" >&2
        fi
    done

    # Show version info if debug enabled
    if [[ "${gs_env_debug:-0}" == "1" ]]; then
        gs_env_version=$(cat ${_GS_ROOT_PATH}/VERSION 2>/dev/null || echo "unknown")
        echo "[DEBUG] Global Scripts version: ${gs_env_version}" >&2
        
        # Shell-compatible way to get array keys
        if [[ -n "$ZSH_VERSION" ]]; then
            echo "[DEBUG] Loaded plugins: ${(k)_gs_loaded_plugins}" >&2
        else
            echo "[DEBUG] Loaded plugins: ${!_gs_loaded_plugins[*]}" >&2
        fi
    fi
}

# Enhanced Plugin Management Functions
function gs_reload_plugin() {
    local plugin_name="$1"
    
    if [[ -z "$plugin_name" ]]; then
        echo "Usage: gs_reload_plugin <plugin_name>"
        echo "Available plugins:"
        # Shell-compatible way to iterate over associative array keys
        if [[ -n "$ZSH_VERSION" ]]; then
            for plugin in ${(k)_gs_plugin_paths}; do
                echo "  - $plugin"
            done
        else
            for plugin in "${!_gs_plugin_paths[@]}"; do
                echo "  - $plugin"
            done
        fi
        return 1
    fi
    
    local plugin_dir="${_gs_plugin_paths[$plugin_name]:-}"
    # Try with quotes if direct lookup fails (compatibility fix)
    if [[ -z "$plugin_dir" ]]; then
        plugin_dir="${_gs_plugin_paths[\"$plugin_name\"]:-}"
    fi
    
    if [[ -z "$plugin_dir" ]]; then
        gs_error "Plugin '$plugin_name' not found. Use 'gs_list_plugins' to see available plugins."
        return 1
    fi
    
    gs_info "Reloading plugin: $plugin_name"
    
    # Unload existing functions if possible
    if [[ -n "${_gs_loaded_plugins[$plugin_name]:-}" ]]; then
        local script_files=($(find "$plugin_dir" -name "gs_*.sh" -type f 2>/dev/null))
        for script_file in "${script_files[@]}"; do
            local functions=($(grep -o "^function [a-zA-Z_][a-zA-Z0-9_]*" "$script_file" 2>/dev/null | sed 's/^function //'))
            for func in "${functions[@]}"; do
                unset -f "$func" 2>/dev/null || true
            done
        done
    fi
    
    _gs_load_plugin "$plugin_name" "$plugin_dir"
    _gs_loaded_plugins["$plugin_name"]=1
    
    gs_success "Plugin '$plugin_name' reloaded successfully"
}

function gs_list_plugins() {
    echo "=== Global Scripts Plugin Status ==="
    echo
    
    local loaded_count=0
    local available_count=0
    
    echo "Loaded plugins:"
    # Shell-compatible way to iterate over associative array keys
    if [[ -n "$ZSH_VERSION" ]]; then
        # In zsh, use ${(k)array}
        for plugin in ${(k)_gs_loaded_plugins}; do
            echo "  ✓ $plugin"
            ((loaded_count++))
        done
    else
        # In bash, use ${!array[@]}
        for plugin in "${!_gs_loaded_plugins[@]}"; do
            echo "  ✓ $plugin"
            ((loaded_count++))
        done
    fi
    
    if [[ $loaded_count -eq 0 ]]; then
        echo "  (none)"
    fi
    
    echo
    echo "Available but not loaded:"
    # Shell-compatible way to iterate over associative array keys
    if [[ -n "$ZSH_VERSION" ]]; then
        # In zsh, use ${(k)array}
        for plugin in ${(k)_gs_plugin_paths}; do
            if [[ -z "${_gs_loaded_plugins[$plugin]:-}" ]]; then
                echo "  ○ $plugin"
                ((available_count++))
            fi
        done
    else
        # In bash, use ${!array[@]}
        for plugin in "${!_gs_plugin_paths[@]}"; do
            if [[ -z "${_gs_loaded_plugins[$plugin]:-}" ]]; then
                echo "  ○ $plugin"
                ((available_count++))
            fi
        done
    fi
    
    if [[ $available_count -eq 0 ]]; then
        echo "  (none)"
    fi
    
    echo
    echo "Total: $loaded_count loaded, $available_count available"
}

function gs_plugin_info() {
    local plugin_name="$1"
    
    if [[ -z "$plugin_name" ]]; then
        echo "Usage: gs_plugin_info <plugin_name>"
        echo "Use 'gs_list_plugins' to see available plugins."
        return 1
    fi
    
    local plugin_dir="${_gs_plugin_paths[$plugin_name]:-}"
    # Try with quotes if direct lookup fails (compatibility fix)
    if [[ -z "$plugin_dir" ]]; then
        plugin_dir="${_gs_plugin_paths[\"$plugin_name\"]:-}"
    fi
    
    if [[ -z "$plugin_dir" ]]; then
        gs_error "Plugin '$plugin_name' not found"
        return 1
    fi
    
    echo "=== Plugin Information: $plugin_name ==="
    echo "Path: $plugin_dir"
    
    # Check loaded status with quote compatibility
    local loaded_status="${_gs_loaded_plugins[$plugin_name]:-}"
    if [[ -z "$loaded_status" ]]; then
        loaded_status="${_gs_loaded_plugins[\"$plugin_name\"]:-}"
    fi
    echo "Status: ${loaded_status:+Loaded}${loaded_status:-Not loaded}"
    echo
    
    # Count scripts and functions
    local script_files=($(find "$plugin_dir" -name "gs_*.sh" -type f 2>/dev/null))
    local script_count=${#script_files[@]}
    local function_count=0
    
    echo "Scripts ($script_count):"
    for script_file in "${script_files[@]}"; do
        local filename=$(basename "$script_file")
        local functions=($(grep -o "^function [a-zA-Z_][a-zA-Z0-9_]*" "$script_file" 2>/dev/null | sed 's/^function //'))
        local func_count=${#functions[@]}
        ((function_count += func_count))
        
        echo "  - $filename ($func_count functions)"
        for func in "${functions[@]}"; do
            echo "    └─ $func"
        done
    done
    
    # Check for bin directory
    if [[ -d "$plugin_dir/bin" ]]; then
        local bin_files=($(find "$plugin_dir/bin" -type f -executable 2>/dev/null))
        echo
        echo "Executables (${#bin_files[@]}):"
        for bin_file in "${bin_files[@]}"; do
            echo "  - $(basename "$bin_file")"
        done
    fi
    
    # Check for README
    if [[ -f "$plugin_dir/README.md" ]]; then
        echo
        echo "Documentation: README.md available"
    fi
    
    echo
    echo "Total functions: $function_count"
}

function gs_enable_plugin() {
    local plugin_name="$1"
    
    if [[ -z "$plugin_name" ]]; then
        echo "Usage: gs_enable_plugin <plugin_name>"
        return 1
    fi
    
    # Check if plugin exists
    local plugin_dir="${_GS_ROOT_PATH}/plugins/${plugin_name}"
    if [[ ! -d "$plugin_dir" ]]; then
        gs_error "Plugin directory not found: $plugin_dir"
        return 1
    fi
    
    # Check if already enabled
    if [[ -n "${_gs_loaded_plugins[$plugin_name]:-}" ]]; then
        gs_warn "Plugin '$plugin_name' is already loaded"
        return 0
    fi
    
    gs_info "Enabling plugin: $plugin_name"
    
    # Register plugin commands and load it immediately
    _gs_register_plugin_commands "$plugin_name" "$plugin_dir"
    _gs_load_plugin "$plugin_name" "$plugin_dir"
    _gs_loaded_plugins["$plugin_name"]=1
    _gs_plugin_paths["$plugin_name"]="$plugin_dir"
    
    # Also add to config if not already there
    local config_file="$HOME/.gsrc"
    if [[ ! -f "$config_file" ]]; then
        config_file="$_GS_CONFIG_PATH/.gsrc"
    fi
    
    # Add to config if not already there
    if ! grep -q "gs_plugins.*$plugin_name" "$config_file" 2>/dev/null; then
        gs_info "Adding plugin to configuration"
        # This would need more sophisticated config editing
        echo "# Note: Add '$plugin_name' to gs_plugins array in $config_file"
    fi
    
    gs_success "Plugin '$plugin_name' enabled for this session"
}

function gs_disable_plugin() {
    local plugin_name="$1"
    
    if [[ -z "$plugin_name" ]]; then
        echo "Usage: gs_disable_plugin <plugin_name>"
        return 1
    fi
    
    if [[ -z "${_gs_loaded_plugins[$plugin_name]:-}" ]]; then
        gs_warn "Plugin '$plugin_name' is not loaded"
        return 0
    fi
    
    gs_info "Disabling plugin: $plugin_name"
    
    # Remove functions (best effort)
    local plugin_dir="${_gs_plugin_paths[$plugin_name]:-}"
    # Try with quotes if direct lookup fails (compatibility fix)
    if [[ -z "$plugin_dir" ]]; then
        plugin_dir="${_gs_plugin_paths[\"$plugin_name\"]:-}"
    fi
    
    if [[ -n "$plugin_dir" ]]; then
        local script_files=($(find "$plugin_dir" -name "gs_*.sh" -type f 2>/dev/null))
        for script_file in "${script_files[@]}"; do
            local functions=($(grep -o "^function [a-zA-Z_][a-zA-Z0-9_]*" "$script_file" 2>/dev/null | sed 's/^function //'))
            for func in "${functions[@]}"; do
                unset -f "$func" 2>/dev/null || true
                unset "_gs_plugin_commands[$func]" 2>/dev/null || true
            done
        done
    fi
    
    unset "_gs_loaded_plugins[$plugin_name]"
    unset "_gs_plugin_paths[$plugin_name]"
    
    gs_success "Plugin '$plugin_name' disabled"
}

function gs_plugin_search() {
    local query="${1:-}"
    
    if [[ -z "$query" ]]; then
        echo "Usage: gs_plugin_search <query>"
        echo "Search for plugins by name or function"
        return 1
    fi
    
    echo "=== Plugin Search Results for: $query ==="
    echo
    
    local found=false
    
    # Search plugin names - shell compatible
    echo "Matching plugins:"
    if [[ -n "$ZSH_VERSION" ]]; then
        for plugin in ${(k)_gs_plugin_paths}; do
            if [[ "$plugin" == *"$query"* ]]; then
                echo "  Plugin: $plugin"
                echo "    Path: ${_gs_plugin_paths[$plugin]}"
                echo "    Status: ${_gs_loaded_plugins[$plugin]:+Loaded}${_gs_loaded_plugins[$plugin]:-Available}"
                found=true
            fi
        done
    else
        for plugin in "${!_gs_plugin_paths[@]}"; do
            if [[ "$plugin" == *"$query"* ]]; then
                echo "  Plugin: $plugin"
                echo "    Path: ${_gs_plugin_paths[$plugin]}"
                echo "    Status: ${_gs_loaded_plugins[$plugin]:+Loaded}${_gs_loaded_plugins[$plugin]:-Available}"
                found=true
            fi
        done
    fi
    
    # Search function names - shell compatible
    echo
    echo "Matching functions:"
    if [[ -n "$ZSH_VERSION" ]]; then
        for func in ${(k)_gs_plugin_commands}; do
            if [[ "$func" == *"$query"* ]]; then
                echo "  $func (in ${_gs_plugin_commands[$func]})"
                found=true
            fi
        done
    else
        for func in "${!_gs_plugin_commands[@]}"; do
            if [[ "$func" == *"$query"* ]]; then
                echo "  $func (in ${_gs_plugin_commands[$func]})"
                found=true
            fi
        done
    fi
    
    if [[ "$found" == false ]]; then
        echo "No plugins or functions found matching '$query'"
    fi
}

# Initialize environment
_gs_init_global_env