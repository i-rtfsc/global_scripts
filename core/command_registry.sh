#!/bin/bash
# Global Scripts V3 - 命令注册器
# 版本: 3.0.0
# 描述: 管理命令注册、去重、启用/禁用等功能

# 防止重复加载
if _gs_is_constant "_GS_COMMAND_REGISTRY_LOADED" && [[ "${GS_FORCE_RELOAD:-false}" != "true" ]]; then
    return 0
fi
_gs_set_constant "_GS_COMMAND_REGISTRY_LOADED" "true"

# 命令注册器调试输出（使用新的日志系统）
_gs_registry_debug() {
    # 如果新的日志系统可用，使用它
    if declare -F "_gs_debug" >/dev/null 2>&1; then
        _gs_debug "registry" "$1"
    elif [[ "${GS_DEBUG_MODE:-false}" == "true" ]]; then
        # 备选：使用简单输出
        echo "[DEBUG:registry] $*" >&2
    fi
}

# 转换为大写（兼容bash 3）
_gs_to_upper() {
    echo "$1" | tr '[:lower:]' '[:upper:]'
}

# 注册单个命令（避免重复）
_gs_register_command() {
    local cmd_name="$1"
    local func_name="$2"
    local source_type="$3"  # "system" 或 "plugin"
    local source_name="$4"  # 系统命令名或插件名

    # 转换source_type为大写
    local source_type_upper
    source_type_upper=$(_gs_to_upper "$source_type")

    # 检查命令是否已存在
    local existing_func
    existing_func=$(_gs_map_get "_GS_${source_type_upper}_COMMANDS" "$cmd_name")

    if [[ -n "$existing_func" ]]; then
        _gs_registry_debug "命令已存在，跳过注册: $cmd_name -> $existing_func"
        return 0
    fi

    # 验证函数是否真的存在
    if ! declare -F "$func_name" >/dev/null 2>&1; then
        _gs_registry_debug "函数不存在，跳过注册: $func_name"
        return 1
    fi

    # 注册命令
    _gs_map_set "_GS_${source_type_upper}_COMMANDS" "$cmd_name" "$func_name"
    _gs_map_set "_GS_COMMAND_SOURCES" "$cmd_name" "${source_type}:${source_name}"

    # 创建命令函数（使用declare而不是eval）
    declare -f "$cmd_name" >/dev/null 2>&1 || {
        # 只有当函数不存在时才创建
        eval "function $cmd_name() { $func_name \"\$@\"; }"
    }

    _gs_registry_debug "✓ 注册${source_type}命令: $cmd_name -> $func_name (来源: $source_name)"
    return 0
}

# 扫描并注册插件函数（只注册新增的）
_gs_register_plugin_functions() {
    local plugin_name="$1"
    local before_functions="$2"  # 加载前的函数列表
    
    _gs_registry_debug "注册插件函数: $plugin_name"
    
    # 获取当前所有函数
    local current_functions
    current_functions=$(_gs_scan_functions)
    
    # 找出新增的函数
    local new_functions
    if [[ -n "$before_functions" ]]; then
        new_functions=$(comm -13 <(echo "$before_functions" | sort) <(echo "$current_functions" | sort))
    else
        new_functions="$current_functions"
    fi
    
    # 只注册属于当前插件的新函数
    while IFS= read -r func; do
        [[ -z "$func" ]] && continue
        
        # 检查是否为公开的插件函数
        if [[ "$func" =~ ^gs_[a-zA-Z0-9_]+$ ]] && [[ ! "$func" =~ ^_gs_ ]]; then
            # 检查是否属于当前插件
            if [[ "$func" =~ ^gs_${plugin_name}_[a-zA-Z0-9_]+$ ]] || \
               [[ "$func" =~ ^gs_${plugin_name}$ ]]; then
                
                local cmd_name="${func//gs_/gs-}"
                cmd_name="${cmd_name//_/-}"
                
                _gs_register_command "$cmd_name" "$func" "plugin" "$plugin_name"
            fi
        fi
    done <<< "$new_functions"
}

# 扫描并注册系统函数（只注册新增的）
_gs_register_system_functions() {
    local system_name="$1"
    local before_functions="$2"  # 加载前的函数列表
    
    _gs_registry_debug "注册系统函数: $system_name"
    
    # 获取当前所有函数
    local current_functions
    current_functions=$(_gs_scan_functions)
    
    # 找出新增的函数
    local new_functions
    if [[ -n "$before_functions" ]]; then
        new_functions=$(comm -13 <(echo "$before_functions" | sort) <(echo "$current_functions" | sort))
    else
        new_functions="$current_functions"
    fi
    
    # 只注册属于当前系统命令的新函数
    while IFS= read -r func; do
        [[ -z "$func" ]] && continue

        # 检查是否为系统函数
        if [[ "$func" =~ ^gs_system_([a-zA-Z0-9_]+)$ ]]; then
            # 检查是否属于当前系统命令
            if [[ "$func" =~ ^gs_system_${system_name}$ ]] || \
               [[ "$func" =~ ^gs_system_${system_name}_[a-zA-Z0-9_]+$ ]]; then

                local cmd_name="${func//gs_system_/gs-}"
                cmd_name="${cmd_name//_/-}"

                _gs_register_command "$cmd_name" "$func" "system" "$system_name"
            fi
        fi
    done <<< "$new_functions"
}

# 扫描函数（使用多层备选方案）
_gs_scan_functions() {
    local functions=""

    # 方法1: Zsh使用functions命令
    if [[ "$_GS_SHELL_TYPE" == "zsh" ]]; then
        functions=$(functions | grep "^gs_" | awk '{print $1}')
    fi

    # 方法2: Bash使用declare -F
    if [[ -z "$functions" && "$_GS_SHELL_TYPE" == "bash" ]]; then
        functions=$(declare -F | awk '/declare -f gs_/ {print $3}')
    fi

    # 方法3: 使用compgen（如果可用）
    if [[ -z "$functions" ]] && command -v compgen >/dev/null 2>&1; then
        _gs_registry_debug "尝试compgen方法..."
        functions=$(compgen -A function | grep "^gs_")
    fi

    # 方法4: 使用set命令（最后备选）
    if [[ -z "$functions" ]]; then
        _gs_registry_debug "使用set命令备选方法..."
        functions=$(set | grep "^gs_.*(" | cut -d'(' -f1)
    fi

    echo "$functions"
}

# 获取加载前的函数快照
_gs_get_function_snapshot() {
    _gs_scan_functions
}

# 禁用插件命令
_gs_disable_plugin_commands() {
    local plugin_name="$1"
    
    _gs_registry_debug "禁用插件命令: $plugin_name"
    
    # 获取所有插件命令
    local plugin_commands
    plugin_commands=$(_gs_map_keys "_GS_PLUGIN_COMMANDS")
    
    # 找出属于该插件的命令并禁用
    while IFS= read -r cmd; do
        [[ -z "$cmd" ]] && continue
        
        local source_info
        source_info=$(_gs_map_get "_GS_COMMAND_SOURCES" "$cmd")
        
        if [[ "$source_info" == "plugin:$plugin_name" ]]; then
            # 移除命令别名
            unset -f "$cmd" 2>/dev/null
            
            # 从注册表中移除
            _gs_map_unset "_GS_PLUGIN_COMMANDS" "$cmd"
            _gs_map_unset "_GS_COMMAND_SOURCES" "$cmd"
            
            _gs_registry_debug "  ✓ 禁用命令: $cmd"
        fi
    done <<< "$plugin_commands"
}

# 重新加载插件命令
_gs_reload_plugin_commands() {
    local plugin_name="$1"
    
    _gs_registry_debug "重新加载插件命令: $plugin_name"
    
    # 先禁用现有命令
    _gs_disable_plugin_commands "$plugin_name"
    
    # 获取函数快照
    local before_functions
    before_functions=$(_gs_get_function_snapshot)
    
    # 重新加载插件
    local plugin_dir="${GS_PLUGINS_DIR}/$plugin_name"
    local impl_file="$plugin_dir/$plugin_name.sh"
    
    if [[ -f "$impl_file" ]]; then
        # 重新source插件文件
        if source "$impl_file"; then
            # 注册新的函数
            _gs_register_plugin_functions "$plugin_name" "$before_functions"
            _gs_registry_debug "✓ 插件重新加载成功: $plugin_name"
            return 0
        else
            _gs_registry_debug "❌ 插件重新加载失败: $plugin_name"
            return 1
        fi
    else
        _gs_registry_debug "❌ 插件文件不存在: $impl_file"
        return 1
    fi
}

# 列出所有命令
_gs_list_all_commands() {
    local filter="$1"  # "system", "plugin", 或空（全部）
    
    case "$filter" in
        "system")
            _gs_map_keys "_GS_SYSTEM_COMMANDS"
            ;;
        "plugin")
            _gs_map_keys "_GS_PLUGIN_COMMANDS"
            ;;
        *)
            # 列出所有命令
            {
                _gs_map_keys "_GS_SYSTEM_COMMANDS" | while read -r cmd; do
                    echo "$cmd [系统]"
                done
                _gs_map_keys "_GS_PLUGIN_COMMANDS" | while read -r cmd; do
                    local source_info
                    source_info=$(_gs_map_get "_GS_COMMAND_SOURCES" "$cmd")
                    echo "$cmd [${source_info#*:}]"
                done
            } | sort
            ;;
    esac
}

# 获取命令信息
_gs_get_command_info() {
    local cmd_name="$1"
    
    # 检查是否为系统命令
    local func_name
    func_name=$(_gs_map_get "_GS_SYSTEM_COMMANDS" "$cmd_name")
    
    if [[ -n "$func_name" ]]; then
        echo "类型: 系统命令"
        echo "函数: $func_name"
        echo "来源: 系统"
        return 0
    fi
    
    # 检查是否为插件命令
    func_name=$(_gs_map_get "_GS_PLUGIN_COMMANDS" "$cmd_name")
    
    if [[ -n "$func_name" ]]; then
        local source_info
        source_info=$(_gs_map_get "_GS_COMMAND_SOURCES" "$cmd_name")
        
        echo "类型: 插件命令"
        echo "函数: $func_name"
        echo "来源: ${source_info#*:}"
        return 0
    fi
    
    echo "命令不存在: $cmd_name"
    return 1
}

# 检查命令是否存在
_gs_command_exists() {
    local cmd_name="$1"
    
    [[ -n "$(_gs_map_get "_GS_SYSTEM_COMMANDS" "$cmd_name")" ]] || \
    [[ -n "$(_gs_map_get "_GS_PLUGIN_COMMANDS" "$cmd_name")" ]]
}
