#!/bin/bash
# Global Scripts V3 - 命令注册器（重构版）
# 版本: 3.1.0
# 描述: 管理命令注册、去重、启用/禁用等功能，支持优先级与多提供者

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

# 生成提供者ID
_gs_generate_provider_id() {
    local source_type="$1"
    local source_name="$2"
    local func_name="$3"
    echo "${source_type}:${source_name}:${func_name}"
}

# 注册命令提供者（新架构）
_gs_register_command_provider() {
    local cmd_name="$1"
    local func_name="$2"
    local source_type="$3"  # "system" 或 "plugin"
    local source_name="$4"  # 系统命令名或插件名
    local priority="${5:-99}"  # 优先级，默认99

    # 验证函数是否真的存在
    if ! declare -F "$func_name" >/dev/null 2>&1; then
        _gs_registry_debug "函数不存在，跳过注册: $func_name"
        return 1
    fi

    # 生成提供者ID
    local provider_id
    provider_id=$(_gs_generate_provider_id "$source_type" "$source_name" "$func_name")

    # 记录提供者信息：func|source_type|source_name|priority|enabled
    _gs_map_set "_GS_PROVIDER_INFO" "$provider_id" "${func_name}|${source_type}|${source_name}|${priority}|true"

    # 添加到命令栈
    local existing_stack
    existing_stack=$(_gs_map_get "_GS_COMMAND_STACK" "$cmd_name")
    if [[ -n "$existing_stack" ]]; then
        _gs_map_set "_GS_COMMAND_STACK" "$cmd_name" "${existing_stack};${provider_id}"
    else
        _gs_map_set "_GS_COMMAND_STACK" "$cmd_name" "$provider_id"
    fi

    _gs_registry_debug "✓ 注册提供者: $cmd_name <- $provider_id (优先级: $priority)"

    # 重新计算该命令的激活提供者
    _gs_activate_best_provider "$cmd_name"

    return 0
}

# 激活最佳提供者（按优先级）
_gs_activate_best_provider() {
    local cmd_name="$1"

    local stack
    stack=$(_gs_map_get "_GS_COMMAND_STACK" "$cmd_name")
    [[ -z "$stack" ]] && return 1

    local best_provider=""
    local best_priority=999
    local best_func=""

    # 遍历所有提供者，找到优先级最高且启用的
    IFS=';' read -ra providers <<< "$stack"
    for provider_id in "${providers[@]}"; do
        [[ -z "$provider_id" ]] && continue

        local provider_info
        provider_info=$(_gs_map_get "_GS_PROVIDER_INFO" "$provider_id")
        [[ -z "$provider_info" ]] && continue

        IFS='|' read -r func_name source_type source_name priority enabled <<< "$provider_info"

        # 只考虑启用的提供者
        if [[ "$enabled" == "true" ]] && [[ "$priority" -lt "$best_priority" ]]; then
            best_provider="$provider_id"
            best_priority="$priority"
            best_func="$func_name"
        fi
    done

    if [[ -n "$best_provider" ]]; then
        # 更新激活函数
        _gs_map_set "_GS_ACTIVE_FUNC" "$cmd_name" "$best_func"

        # 创建或更新命令函数
        if declare -f "$cmd_name" >/dev/null 2>&1; then
            unset -f "$cmd_name" 2>/dev/null
        fi
        eval "function $cmd_name() { $best_func \"\$@\"; }"

        # 更新兼容性映射
        IFS='|' read -r func_name source_type source_name priority enabled <<< "$(_gs_map_get "_GS_PROVIDER_INFO" "$best_provider")"
        _gs_map_set "_GS_COMMAND_SOURCES" "$cmd_name" "${source_type}:${source_name}"

        local source_type_upper
        source_type_upper=$(_gs_to_upper "$source_type")
        _gs_map_set "_GS_${source_type_upper}_COMMANDS" "$cmd_name" "$best_func"

        _gs_registry_debug "✓ 激活命令: $cmd_name -> $best_func (提供者: $best_provider)"
        return 0
    else
        # 没有可用提供者，移除命令
        _gs_deactivate_command "$cmd_name"
        return 1
    fi
}

# 停用命令
_gs_deactivate_command() {
    local cmd_name="$1"

    # 移除命令函数
    if declare -f "$cmd_name" >/dev/null 2>&1; then
        unset -f "$cmd_name" 2>/dev/null
    fi

    # 清理映射
    _gs_map_unset "_GS_ACTIVE_FUNC" "$cmd_name"
    _gs_map_unset "_GS_COMMAND_SOURCES" "$cmd_name"
    _gs_map_unset "_GS_SYSTEM_COMMANDS" "$cmd_name"
    _gs_map_unset "_GS_PLUGIN_COMMANDS" "$cmd_name"

    _gs_registry_debug "✓ 停用命令: $cmd_name"
}

# 扫描并注册插件函数（只注册新增的）
_gs_register_plugin_functions() {
    local plugin_name="$1"
    local before_functions="$2"  # 加载前的函数列表
    local priority="${3:-99}"    # 插件优先级

    _gs_registry_debug "注册插件函数: $plugin_name (优先级: $priority)"

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

                _gs_register_command_provider "$cmd_name" "$func" "plugin" "$plugin_name" "$priority"
            fi
        fi
    done <<< "$new_functions"
}

# 扫描并注册系统函数（只注册新增的）
_gs_register_system_functions() {
    local system_name="$1"
    local before_functions="$2"  # 加载前的函数列表
    local priority="${3:-99}"     # 系统命令优先级

    _gs_registry_debug "注册系统函数: $system_name (优先级: $priority)"

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

                _gs_register_command_provider "$cmd_name" "$func" "system" "$system_name" "$priority"
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
