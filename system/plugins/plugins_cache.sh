#!/usr/bin/env bash
# Global Scripts V3 - Plugins Cache Reader
# Author: Global Scripts Team
# Version: 3.0.0
# Description: Read and parse three-tier plugin cache files

# Cache file paths
SYSTEM_PLUGINS_CACHE="$(_gs_get_constant "GS_CONFIG_DIR")/cache/system_plugins.cache"
CORE_PLUGINS_CACHE="$(_gs_get_constant "GS_CONFIG_DIR")/cache/core_plugins.cache"
THIRD_PLUGINS_CACHE="$(_gs_get_constant "GS_CONFIG_DIR")/cache/3rd_plugins.cache"

# Parse a single plugin line from cache
# Format: PLUGIN:name:version:status:commands_count:description:commands
_parse_plugin_line() {
    local line="$1"
    local prefix="${line%%:*}"
    
    # Skip non-plugin lines
    [[ "$prefix" != "PLUGIN" ]] && return 1
    
    # Remove PLUGIN: prefix
    line="${line#PLUGIN:}"
    
    # Split by colons (handle description and commands that may contain colons)
    local name version plugin_status commands_count description commands
    
    name="${line%%:*}"; line="${line#*:}"
    version="${line%%:*}"; line="${line#*:}"
    plugin_status="${line%%:*}"; line="${line#*:}"
    commands_count="${line%%:*}"; line="${line#*:}"
    
    # Everything remaining is description:commands
    if [[ "$line" == *:* ]]; then
        description="${line%:*}"
        commands="${line##*:}"
    else
        description="$line"
        commands=""
    fi
    
    # Export parsed values
    PLUGIN_NAME="$name"
    PLUGIN_VERSION="$version"
    PLUGIN_STATUS="$plugin_status"
    PLUGIN_COMMANDS_COUNT="$commands_count"
    PLUGIN_DESCRIPTION="$description"
    PLUGIN_COMMANDS="$commands"
    
    return 0
}

# Get all plugins from all cache files
_get_all_plugins() {
    local callback_func="$1"
    local plugin_type
    
    # Read system plugins
    if [[ -f "$SYSTEM_PLUGINS_CACHE" ]]; then
        while IFS= read -r line; do
            if _parse_plugin_line "$line"; then
                plugin_type="system"
                "$callback_func" "$plugin_type"
            fi
        done < "$SYSTEM_PLUGINS_CACHE"
    fi
    
    # Read core plugins
    if [[ -f "$CORE_PLUGINS_CACHE" ]]; then
        while IFS= read -r line; do
            if _parse_plugin_line "$line"; then
                plugin_type="core"
                "$callback_func" "$plugin_type"
            fi
        done < "$CORE_PLUGINS_CACHE"
    fi
    
    # Read 3rd party plugins
    if [[ -f "$THIRD_PLUGINS_CACHE" ]]; then
        while IFS= read -r line; do
            if _parse_plugin_line "$line"; then
                plugin_type="3rd"
                "$callback_func" "$plugin_type"
            fi
        done < "$THIRD_PLUGINS_CACHE"
    fi
}

# Get enabled plugins
_get_enabled_plugins() {
    local callback_func="$1"
    
    _callback_enabled() {
        local plugin_type="$1"
        [[ "$PLUGIN_STATUS" == "enabled" ]] && "$callback_func" "$plugin_type"
    }
    
    _get_all_plugins "_callback_enabled"
}

# Get disabled plugins
_get_disabled_plugins() {
    local callback_func="$1"
    
    _callback_disabled() {
        local plugin_type="$1"
        [[ "$PLUGIN_STATUS" == "disabled" ]] && "$callback_func" "$plugin_type"
    }
    
    _get_all_plugins "_callback_disabled"
}

# Get plugin by name
_get_plugin_by_name() {
    local target_name="$1"
    local found=0
    
    # Search system plugins first
    if [[ -f "$SYSTEM_PLUGINS_CACHE" ]]; then
        while IFS= read -r line; do
            if _parse_plugin_line "$line"; then
                if [[ "$PLUGIN_NAME" == "$target_name" ]]; then
                    FOUND_PLUGIN_TYPE="system"
                    return 0
                fi
            fi
        done < "$SYSTEM_PLUGINS_CACHE"
    fi
    
    # Search core plugins
    if [[ -f "$CORE_PLUGINS_CACHE" ]]; then
        while IFS= read -r line; do
            if _parse_plugin_line "$line"; then
                if [[ "$PLUGIN_NAME" == "$target_name" ]]; then
                    FOUND_PLUGIN_TYPE="core"
                    return 0
                fi
            fi
        done < "$CORE_PLUGINS_CACHE"
    fi
    
    # Search 3rd party plugins
    if [[ -f "$THIRD_PLUGINS_CACHE" ]]; then
        while IFS= read -r line; do
            if _parse_plugin_line "$line"; then
                if [[ "$PLUGIN_NAME" == "$target_name" ]]; then
                    FOUND_PLUGIN_TYPE="3rd"
                    return 0
                fi
            fi
        done < "$THIRD_PLUGINS_CACHE"
    fi
    
    return 1
}

# Count plugins by status
_count_plugins() {
    local total=0 enabled=0 disabled=0 total_commands=0 enabled_commands=0 disabled_commands=0
    
    _callback_count() {
        local plugin_type="$1"
        total=$((total + 1))
        total_commands=$((total_commands + PLUGIN_COMMANDS_COUNT))
        
        if [[ "$PLUGIN_STATUS" == "enabled" ]]; then
            enabled=$((enabled + 1))
            enabled_commands=$((enabled_commands + PLUGIN_COMMANDS_COUNT))
        else
            disabled=$((disabled + 1))
            disabled_commands=$((disabled_commands + PLUGIN_COMMANDS_COUNT))
        fi
    }
    
    _get_all_plugins "_callback_count"
    
    TOTAL_PLUGINS=$total
    ENABLED_PLUGINS=$enabled
    DISABLED_PLUGINS=$disabled
    TOTAL_COMMANDS=$total_commands
    ENABLED_COMMANDS=$enabled_commands
    DISABLED_COMMANDS=$disabled_commands
}

# Get plugin commands as array
_get_plugin_commands() {
    local plugin_name="$1"
    local -n commands_array_ref="$2"
    
    if _get_plugin_by_name "$plugin_name"; then
        if [[ -n "$PLUGIN_COMMANDS" ]]; then
            IFS=',' read -ra commands_array_ref <<< "$PLUGIN_COMMANDS"
        else
            commands_array_ref=()
        fi
        return 0
    else
        commands_array_ref=()
        return 1
    fi
}

# Check if plugin exists
_plugin_exists() {
    local plugin_name="$1"
    _get_plugin_by_name "$plugin_name" >/dev/null 2>&1
}

# Check if plugin is enabled
_is_plugin_enabled() {
    local plugin_name="$1"
    if _get_plugin_by_name "$plugin_name"; then
        [[ "$PLUGIN_STATUS" == "enabled" ]]
    else
        return 1
    fi
}