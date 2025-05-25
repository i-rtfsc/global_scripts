#!/usr/bin/env bash
# Global Scripts V3 - Cache Manager
# Author: Global Scripts Team
# Version: 3.0.0

# Set cache path constants
_gs_set_constant "GS_CACHE_DIR" "$(_gs_get_constant "GS_CONFIG_DIR")/cache"
_gs_set_constant "GS_SYSTEM_PLUGINS_CACHE" "$(_gs_get_constant "GS_CACHE_DIR")/system_plugins.cache"
_gs_set_constant "GS_CORE_PLUGINS_CACHE" "$(_gs_get_constant "GS_CACHE_DIR")/core_plugins.cache"
_gs_set_constant "GS_3RD_PLUGINS_CACHE" "$(_gs_get_constant "GS_CACHE_DIR")/3rd_plugins.cache"
_gs_set_constant "GS_CONFIG_FILE" "$(_gs_get_constant "GS_CONFIG_DIR")/.gsconf"

# Load plugin configuration from .gsconf
_load_plugin_config() {
    local config_file="$(_gs_get_constant "GS_CONFIG_FILE")"
    source "$config_file"
}

# Check if plugin is enabled in configuration
_is_plugin_enabled() {
    local plugin_name="$1"
    local plugin_type="$2"  # core or 3rd
    
    _load_plugin_config
    
    if [[ "$plugin_type" == "core" ]]; then
        # Check if in gs_plugins array
        for enabled_plugin in "${gs_plugins[@]}"; do
            [[ "$enabled_plugin" == "$plugin_name" ]] && return 0
        done
    elif [[ "$plugin_type" == "3rd" ]]; then
        # Check if in gs_custom_plugins array
        for enabled_plugin in "${gs_custom_plugins[@]}"; do
            [[ "$enabled_plugin" == "$plugin_name" ]] && return 0
        done
    fi
    
    return 1
}

# Generate system plugins cache
_generate_system_plugins_cache() {
    local cache_file="$(_gs_get_constant "GS_SYSTEM_PLUGINS_CACHE")"

    # Delete existing cache file first
    rm -f "$cache_file" 2>/dev/null
    
    _gs_debug "cache_manager" "Generating system plugins cache..."
    
    {
        echo "# Global Scripts V3 System Plugins Cache"
        echo "# Generated: $(date)"
        echo ""
    } > "$cache_file"
    
    if [[ -d "${GS_SYSTEM_DIR}" ]]; then
        find "${GS_SYSTEM_DIR}" -name "*.meta" -type f 2>/dev/null | sort | \
        while IFS= read -r meta_file; do
            (
                # Process each plugin in isolated subshell
                plugin_dir=$(dirname "$meta_file")
                plugin_name=$(basename "$plugin_dir")
                
                # Read plugin basic info
                name="" version="" description=""
                while IFS='=' read -r key value; do
                    case "$key" in
                        "name"|"NAME") name="${value//\"/}" ;;
                        "version"|"VERSION") version="${value//\"/}" ;;
                        "description"|"DESCRIPTION") description="${value//\"/}" ;;
                    esac
                done < "$meta_file" 2>/dev/null
                
                # Set defaults
                [[ -z "$name" ]] && name="$plugin_name"
                [[ -z "$version" ]] && version="1.0.0"
                [[ -z "$description" ]] && description="System Command"
                
                # Scan implementation file for functions
                commands_list=""
                commands_count=0
                impl_file="$plugin_dir/${plugin_name}.sh"
                
                if [[ -f "$impl_file" ]]; then
                    func_array=()
                    while IFS= read -r line; do
                        if [[ "$line" =~ ^gs_system_[a-zA-Z0-9_]+\(\) ]]; then
                            func_name=$(echo "$line" | sed 's/().*//' | awk '{print $1}')
                            cmd_name="gs-${func_name#gs_system_}"
                            func_array+=("$cmd_name")
                        fi
                    done < "$impl_file" 2>/dev/null
                    
                    commands_count=${#func_array[@]}
                    if [[ $commands_count -gt 0 ]]; then
                        IFS=','; commands_list="${func_array[*]}"; IFS=$' \t\n'
                    fi
                fi
                
                # Output format: PLUGIN:name:version:status:commands_count:description:commands
                printf "PLUGIN:%s:%s:%s:%s:%s:%s\n" "$name" "$version" "enabled" "$commands_count" "$description" "$commands_list"
            )
        done >> "$cache_file" 2>/dev/null
    fi

    _gs_debug "cache_manager" "System plugins cache generated: $cache_file"
}

# Generate core plugins cache
_generate_core_plugins_cache() {
    local cache_file="$(_gs_get_constant "GS_CORE_PLUGINS_CACHE")"

    # Delete existing cache file first
    rm -f "$cache_file" 2>/dev/null
    
    _gs_debug "cache_manager" "Generating core plugins cache..."
    
    # Load configuration once at the beginning
    _load_plugin_config
    
    {
        echo "# Global Scripts V3 Core Plugins Cache"
        echo "# Generated: $(date)"
        echo ""
    } > "$cache_file"
    
    if [[ -d "${GS_PLUGINS_DIR}" ]]; then
        # Use array to avoid pipeline subshell issues
        local meta_files=()
        while IFS= read -r -d $'\0' file; do
            meta_files+=("$file")
        done < <(find "${GS_PLUGINS_DIR}" -name "*.meta" -type f -print0 2>/dev/null | sort -z)
        
        for meta_file in "${meta_files[@]}"; do
            # Process each plugin
            local plugin_dir plugin_name name version description commands_list commands_count plugin_status
            
            plugin_dir=$(dirname "$meta_file")
            plugin_name=$(basename "$plugin_dir")
            
            # Read plugin basic info
            name="" version="" description=""
            while IFS='=' read -r key value; do
                case "$key" in
                    "name") name="${value//\"/}" ;;
                    "version") version="${value//\"/}" ;;
                    "description") description="${value//\"/}" ;;
                esac
            done < "$meta_file" 2>/dev/null
            
            # Set defaults
            [[ -z "$name" ]] && name="$plugin_name"
            [[ -z "$version" ]] && version="1.0.0"
            [[ -z "$description" ]] && description="Core Plugin"
            
            # Check plugin status based on configuration
            local plugin_status="disabled"  # default
            for enabled_plugin in "${gs_plugins[@]}"; do
                if [[ "$enabled_plugin" == "$name" ]]; then
                    plugin_status="enabled"
                    break
                fi
            done
            
            # Read commands array from meta file
            commands_list=""
            commands_count=0
            local in_commands=false
            
            while IFS= read -r line; do
                line=$(echo "$line" | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')
                
                if [[ "$line" == "commands=(" ]]; then
                    in_commands=true
                    continue
                elif [[ "$line" == ")" && "$in_commands" == "true" ]]; then
                    break
                elif [[ "$in_commands" == "true" && "$line" =~ ^\".*\"$ ]]; then
                    local cmd_def="${line//\"/}"
                    local cmd_name=$(echo "$cmd_def" | cut -d':' -f1)
                    if [[ -n "$cmd_name" ]]; then
                        if [[ -z "$commands_list" ]]; then
                            commands_list="$cmd_name"
                        else
                            commands_list="$commands_list,$cmd_name"
                        fi
                        commands_count=$((commands_count + 1))
                    fi
                fi
            done < "$meta_file" 2>/dev/null
            
            # Output format: PLUGIN:name:version:status:commands_count:description:commands
            printf "PLUGIN:%s:%s:%s:%s:%s:%s\n" "$name" "$version" "$plugin_status" "$commands_count" "$description" "$commands_list" >> "$cache_file"
        done
    fi

    _gs_debug "cache_manager" "Core plugins cache generated: $cache_file"
}

# Generate 3rd party plugins cache
_generate_3rd_plugins_cache() {
    local cache_file="$(_gs_get_constant "GS_3RD_PLUGINS_CACHE")"

    # Delete existing cache file first
    rm -f "$cache_file" 2>/dev/null
    
    _gs_debug "cache_manager" "Generating 3rd party plugins cache..."
    
    {
        echo "# Global Scripts V3 3rd Party Plugins Cache"
        echo "# Generated: $(date)"
        echo ""
        echo "# No 3rd party plugins yet"
    } > "$cache_file"
    
    # TODO: Implement 3rd party plugins directory scanning
    # When there are 3rd party plugins, use similar logic as core plugins
    # but check against gs_custom_plugins configuration

    _gs_debug "cache_manager" "3rd party plugins cache generated: $cache_file"
}

# Cache manager initialization implementation
initialize_cache_impl() {
    _gs_debug "cache_manager" "Initializing cache manager..."
    
    # Create cache directory
    [[ -d "$(_gs_get_constant "GS_CACHE_DIR")" ]] || mkdir -p "$(_gs_get_constant "GS_CACHE_DIR")" 2>/dev/null
    
    # Generate three-tier cache files
    _generate_system_plugins_cache
    _generate_core_plugins_cache
    _generate_3rd_plugins_cache
    
    _gs_debug "cache_manager" "Cache manager initialization completed"
    return 0
}

# Clear cache
clear_cache() {
    _gs_debug "cache_manager" "Clearing cache..."
    
    local system_cache="$(_gs_get_constant "GS_SYSTEM_PLUGINS_CACHE")"
    local core_cache="$(_gs_get_constant "GS_CORE_PLUGINS_CACHE")"
    local third_cache="$(_gs_get_constant "GS_3RD_PLUGINS_CACHE")"
    
    rm -f "$system_cache" "$core_cache" "$third_cache" 2>/dev/null
    
    _gs_debug "cache_manager" "Cache cleared"
}

# Get cache status
get_cache_status() {
    echo "=== Global Scripts Cache Status ==="
    echo "Cache Directory: $(_gs_get_constant "GS_CACHE_DIR")"
    
    local system_cache="$(_gs_get_constant "GS_SYSTEM_PLUGINS_CACHE")"
    local core_cache="$(_gs_get_constant "GS_CORE_PLUGINS_CACHE")"
    local third_cache="$(_gs_get_constant "GS_3RD_PLUGINS_CACHE")"
    
    if [[ -f "$system_cache" ]]; then
        local size=$(grep -c "^PLUGIN:" "$system_cache" 2>/dev/null || echo "0")
        echo "System plugins cache: Exists ($size plugins)"
    else
        echo "System plugins cache: Not found"
    fi
    
    if [[ -f "$core_cache" ]]; then
        local size=$(grep -c "^PLUGIN:" "$core_cache" 2>/dev/null || echo "0")
        echo "Core plugins cache: Exists ($size plugins)"
    else
        echo "Core plugins cache: Not found"
    fi
    
    if [[ -f "$third_cache" ]]; then
        local size=$(grep -c "^PLUGIN:" "$third_cache" 2>/dev/null || echo "0")
        echo "3rd party plugins cache: Exists ($size plugins)"
    else
        echo "3rd party plugins cache: Not found"
    fi
}