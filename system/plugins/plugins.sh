#!/bin/bash
# Global Scripts V3 - 插件管理系统
# 版本: 3.0.0
# 描述: 基于三层缓存架构的插件管理系统

# ============================================================================
# 核心依赖和配置
# ============================================================================

# 引入插件缓存读取模块  
source "$GS_ROOT/system/plugins/plugins_cache.sh"

# ============================================================================
# 表格绘制函数
# ============================================================================

# 计算字符串显示宽度 (中文字符宽度为2)
_gs_string_width() {
    local str="$1"
    local width=0
    local i=0
    
    while [[ $i -lt ${#str} ]]; do
        local char="${str:$i:1}"
        # 检查是否为中文字符 (简单的ASCII范围检查)
        if [[ $(printf "%d" "'$char") -gt 127 ]]; then
            width=$((width + 2))
        else
            width=$((width + 1))
        fi
        i=$((i + 1))
    done
    
    echo $width
}

# 动态表格绘制函数
_gs_draw_table() {
    local header1="$1" header2="$2" header3="$3" header4="$4" header5="$5"
    
    # 计算每列的最大宽度
    local w1 w2 w3 w4 w5
    w1=$(_gs_string_width "$header1")
    w2=$(_gs_string_width "$header2")
    w3=$(_gs_string_width "$header3")
    w4=$(_gs_string_width "$header4")
    w5=$(_gs_string_width "$header5")
    
    # 读取所有数据行，计算每列最大宽度
    local temp_data=$(cat)
    while IFS=$'\t' read -r col1 col2 col3 col4 col5; do
        if [[ -n "$col1" ]]; then
            local cw1=$(_gs_string_width "$col1")
            local cw2=$(_gs_string_width "$col2")
            local cw3=$(_gs_string_width "$col3")
            local cw4=$(_gs_string_width "$col4")  
            local cw5=$(_gs_string_width "$col5")
            
            [[ $cw1 -gt $w1 ]] && w1=$cw1
            [[ $cw2 -gt $w2 ]] && w2=$cw2
            [[ $cw3 -gt $w3 ]] && w3=$cw3
            [[ $cw4 -gt $w4 ]] && w4=$cw4
            [[ $cw5 -gt $w5 ]] && w5=$cw5
        fi
    done <<< "$temp_data"
    
    # 最小列宽限制
    [[ $w1 -lt 8 ]] && w1=8
    [[ $w2 -lt 6 ]] && w2=6  
    [[ $w3 -lt 6 ]] && w3=6
    [[ $w4 -lt 8 ]] && w4=8
    [[ $w5 -lt 20 ]] && w5=20
    
    # 字符串填充函数（考虑中文字符宽度）
    _pad_string() {
        local str="$1"
        local target_width="$2"
        local actual_width=$(_gs_string_width "$str")
        local padding=$((target_width - actual_width))
        
        if [[ $padding -gt 0 ]]; then
            printf "%s%*s" "$str" $padding ""
        else
            printf "%s" "$str"
        fi
    }
    
    # 绘制表格顶部
    printf "┌"
    printf "%*s" $((w1 + 2)) "" | tr ' ' '─'
    printf "┬"
    printf "%*s" $((w2 + 2)) "" | tr ' ' '─'
    printf "┬"
    printf "%*s" $((w3 + 2)) "" | tr ' ' '─'
    printf "┬"
    printf "%*s" $((w4 + 2)) "" | tr ' ' '─'
    printf "┬"
    printf "%*s" $((w5 + 2)) "" | tr ' ' '─'
    printf "┐\n"
    
    # 绘制表头
    printf "│ "
    _pad_string "$header1" $w1
    printf " │ "
    _pad_string "$header2" $w2
    printf " │ "
    _pad_string "$header3" $w3
    printf " │ "
    _pad_string "$header4" $w4
    printf " │ "
    _pad_string "$header5" $w5
    printf " │\n"
    
    # 绘制表头分隔线
    printf "├"
    printf "%*s" $((w1 + 2)) "" | tr ' ' '─'
    printf "┼"
    printf "%*s" $((w2 + 2)) "" | tr ' ' '─'
    printf "┼"
    printf "%*s" $((w3 + 2)) "" | tr ' ' '─'
    printf "┼"
    printf "%*s" $((w4 + 2)) "" | tr ' ' '─'
    printf "┼"
    printf "%*s" $((w5 + 2)) "" | tr ' ' '─'
    printf "┤\n"
    
    # 绘制数据行
    while IFS=$'\t' read -r col1 col2 col3 col4 col5; do
        if [[ -n "$col1" ]]; then
            printf "│ "
            _pad_string "$col1" $w1
            printf " │ "
            _pad_string "$col2" $w2
            printf " │ "
            _pad_string "$col3" $w3
            printf " │ "
            _pad_string "$col4" $w4
            printf " │ "
            _pad_string "$col5" $w5
            printf " │\n"
        fi
    done <<< "$temp_data"
    
    # 绘制表格底部
    printf "└"
    printf "%*s" $((w1 + 2)) "" | tr ' ' '─'
    printf "┴"
    printf "%*s" $((w2 + 2)) "" | tr ' ' '─'
    printf "┴"
    printf "%*s" $((w3 + 2)) "" | tr ' ' '─'
    printf "┴"
    printf "%*s" $((w4 + 2)) "" | tr ' ' '─'
    printf "┴"
    printf "%*s" $((w5 + 2)) "" | tr ' ' '─'
    printf "┘\n"
}

# ============================================================================
# 插件列表显示
# ============================================================================

# 表格模式显示插件列表
_gs_plugins_list_table() {
    echo "Global Scripts V3 - 插件列表"
    echo "============================"
    echo
    
    # 获取统计信息
    _count_plugins
    local enabled_count=$ENABLED_PLUGINS
    local disabled_count=$DISABLED_PLUGINS
    local total_plugins=$TOTAL_PLUGINS
    local total_commands=$TOTAL_COMMANDS
    local enabled_commands=$ENABLED_COMMANDS
    local disabled_commands=$DISABLED_COMMANDS
    
    # 显示已启用插件
    if [[ $enabled_count -gt 0 ]]; then
        echo "✅ 已启用插件 ($enabled_count个):"
        
        # 直接读取缓存文件，避免回调函数嵌套
        local temp_file=$(mktemp)
        
        # 读取系统插件（都是启用的）
        if [[ -f "$SYSTEM_PLUGINS_CACHE" ]]; then
            while IFS= read -r line; do
                if _parse_plugin_line "$line"; then
                    if [[ "$PLUGIN_STATUS" == "enabled" ]]; then
                        echo -e "$PLUGIN_NAME\t正常\t$PLUGIN_VERSION\t$PLUGIN_COMMANDS_COUNT\t$PLUGIN_DESCRIPTION (系统命令)" >> "$temp_file"
                    fi
                fi
            done < "$SYSTEM_PLUGINS_CACHE"
        fi
        
        # 读取核心插件（检查启用状态）
        if [[ -f "$CORE_PLUGINS_CACHE" ]]; then
            while IFS= read -r line; do
                if _parse_plugin_line "$line"; then
                    if [[ "$PLUGIN_STATUS" == "enabled" ]]; then
                        echo -e "$PLUGIN_NAME\t正常\t$PLUGIN_VERSION\t$PLUGIN_COMMANDS_COUNT\t$PLUGIN_DESCRIPTION (核心插件)" >> "$temp_file"
                    fi
                fi
            done < "$CORE_PLUGINS_CACHE"
        fi
        
        # 读取第三方插件（检查启用状态）
        if [[ -f "$THIRD_PLUGINS_CACHE" ]]; then
            while IFS= read -r line; do
                if _parse_plugin_line "$line"; then
                    if [[ "$PLUGIN_STATUS" == "enabled" ]]; then
                        echo -e "$PLUGIN_NAME\t正常\t$PLUGIN_VERSION\t$PLUGIN_COMMANDS_COUNT\t$PLUGIN_DESCRIPTION (第三方)" >> "$temp_file"
                    fi
                fi
            done < "$THIRD_PLUGINS_CACHE"
        fi
        
        # 显示表格
        cat "$temp_file" | _gs_draw_table "插件名称" "状态" "版本" "命令数量" "描述"
        rm -f "$temp_file"
        
        echo
    fi
    
    # 显示已禁用插件
    if [[ $disabled_count -gt 0 ]]; then
        echo "❌ 已禁用插件 ($disabled_count个):"
        
        # 直接读取缓存文件，避免回调函数嵌套
        local temp_file=$(mktemp)
        
        # 读取核心插件（检查禁用状态）
        if [[ -f "$CORE_PLUGINS_CACHE" ]]; then
            while IFS= read -r line; do
                if _parse_plugin_line "$line"; then
                    if [[ "$PLUGIN_STATUS" == "disabled" ]]; then
                        echo -e "$PLUGIN_NAME\t已禁用\t$PLUGIN_VERSION\t$PLUGIN_COMMANDS_COUNT\t$PLUGIN_DESCRIPTION (核心插件)" >> "$temp_file"
                    fi
                fi
            done < "$CORE_PLUGINS_CACHE"
        fi
        
        # 读取第三方插件（检查禁用状态）
        if [[ -f "$THIRD_PLUGINS_CACHE" ]]; then
            while IFS= read -r line; do
                if _parse_plugin_line "$line"; then
                    if [[ "$PLUGIN_STATUS" == "disabled" ]]; then
                        echo -e "$PLUGIN_NAME\t已禁用\t$PLUGIN_VERSION\t$PLUGIN_COMMANDS_COUNT\t$PLUGIN_DESCRIPTION (第三方)" >> "$temp_file"
                    fi
                fi
            done < "$THIRD_PLUGINS_CACHE"
        fi
        
        # 显示表格
        cat "$temp_file" | _gs_draw_table "插件名称" "状态" "版本" "命令数量" "描述"
        rm -f "$temp_file"
        
        echo
    fi
    
    # 显示统计信息
    echo "📊 统计信息:"
    echo "总插件数: ${total_plugins}个 | 已启用: ${enabled_count}个 | 已禁用: ${disabled_count}个"
    echo "总命令数: ${total_commands}个 | 已启用: ${enabled_commands}个 | 已禁用: ${disabled_commands}个"
}

# JSON格式输出
_gs_plugins_list_json() {
    local enabled_plugins=""
    local disabled_plugins=""
    
    # 收集已启用插件数据
    _collect_enabled_json() {
        local plugin_type="$1"
        enabled_plugins+="{\"name\":\"$PLUGIN_NAME\",\"version\":\"$PLUGIN_VERSION\",\"description\":\"$PLUGIN_DESCRIPTION\",\"commands_count\":$PLUGIN_COMMANDS_COUNT,\"category\":\"$plugin_type\",\"status\":\"enabled\"},"
    }
    
    _get_enabled_plugins "_collect_enabled_json"
    
    # 收集已禁用插件数据
    _collect_disabled_json() {
        local plugin_type="$1"
        disabled_plugins+="{\"name\":\"$PLUGIN_NAME\",\"version\":\"$PLUGIN_VERSION\",\"description\":\"$PLUGIN_DESCRIPTION\",\"commands_count\":$PLUGIN_COMMANDS_COUNT,\"category\":\"$plugin_type\",\"status\":\"disabled\"},"
    }
    
    _get_disabled_plugins "_collect_disabled_json"
    
    # 移除末尾逗号
    enabled_plugins="${enabled_plugins%,}"
    disabled_plugins="${disabled_plugins%,}"
    
    # 获取统计信息
    _count_plugins
    
    # 输出JSON
    cat << EOF
{
  "enabled_plugins": [$enabled_plugins],
  "disabled_plugins": [$disabled_plugins],
  "summary": {
    "total_plugins": $TOTAL_PLUGINS,
    "enabled_count": $ENABLED_PLUGINS,
    "disabled_count": $DISABLED_PLUGINS,
    "total_commands": $TOTAL_COMMANDS
  }
}
EOF
}

# 只显示已启用插件
_gs_plugins_list_enabled_only() {
    echo "✅ 已启用插件:"
    
    _collect_enabled_simple() {
        local plugin_type="$1"
        echo "  $PLUGIN_NAME ($plugin_type) - $PLUGIN_DESCRIPTION"
    }
    
    _get_enabled_plugins "_collect_enabled_simple"
}

# 只显示已禁用插件
_gs_plugins_list_disabled_only() {
    echo "❌ 已禁用插件:"
    
    _collect_disabled_simple() {
        local plugin_type="$1"
        echo "  $PLUGIN_NAME ($plugin_type) - $PLUGIN_DESCRIPTION"
    }
    
    _get_disabled_plugins "_collect_disabled_simple"
}

# ============================================================================
# 插件信息显示
# ============================================================================

# 文本格式显示插件信息
_gs_plugins_info_text() {
    local plugin_name="$1"
    
    if ! _get_plugin_by_name "$plugin_name"; then
        echo "❌ 错误: 插件 '$plugin_name' 不存在" >&2
        echo "💡 使用 'gs-plugins list' 查看可用插件" >&2
        return 1
    fi
    
    # 确定插件状态
    local enabled_status
    if [[ "$PLUGIN_STATUS" == "enabled" ]]; then
        enabled_status="✅ 已启用"
    else
        enabled_status="❌ 已禁用"
    fi
    
    # 确定插件类型显示
    local display_category
    case "$FOUND_PLUGIN_TYPE" in
        "system") display_category="系统命令 (必须加载)" ;;
        "core") display_category="核心插件 (可配置)" ;;
        "3rd") display_category="第三方插件 (可配置)" ;;
        *) display_category="未知类型" ;;
    esac
    
    echo "Global Scripts V3 - 插件信息"
    echo "============================"
    echo
    echo "📋 $PLUGIN_DESCRIPTION"
    echo "├─ 插件名称: $PLUGIN_NAME"
    echo "├─ 版本号: $PLUGIN_VERSION"
    echo "├─ 状态: $enabled_status"
    echo "├─ 类型: $display_category"
    echo "└─ 命令数量: ${PLUGIN_COMMANDS_COUNT}个"
    echo
    
    if [[ -n "$PLUGIN_COMMANDS" && "$PLUGIN_COMMANDS" != "0" ]]; then
        echo "📝 可用命令:"
        echo "$PLUGIN_COMMANDS" | tr ',' '\n' | sed 's/^/  /'
        echo
    fi
    
    if [[ "$FOUND_PLUGIN_TYPE" != "system" ]]; then
        echo "⚙️ 管理操作:"
        if [[ "$PLUGIN_STATUS" == "enabled" ]]; then
            echo "  gs-plugins disable $PLUGIN_NAME    # 禁用插件"
        else
            echo "  gs-plugins enable $PLUGIN_NAME     # 启用插件"
        fi
        echo "  gs-plugins reload $PLUGIN_NAME     # 重新加载插件"
    else
        echo "ℹ️  系统命令不支持启用/禁用操作"
    fi
}

# JSON格式显示插件信息
_gs_plugins_info_json() {
    local plugin_name="$1"
    
    if ! _get_plugin_by_name "$plugin_name"; then
        echo "{\"error\": \"Plugin '$plugin_name' not found\"}" >&2
        return 1
    fi
    
    local is_enabled="false"
    if [[ "$PLUGIN_STATUS" == "enabled" ]]; then
        is_enabled="true"
    fi
    
    # 构建命令数组
    local commands_json=""
    if [[ -n "$PLUGIN_COMMANDS" && "$PLUGIN_COMMANDS" != "0" ]]; then
        IFS=',' read -ra cmd_array <<< "$PLUGIN_COMMANDS"
        for cmd in "${cmd_array[@]}"; do
            commands_json+="\"$cmd\","
        done
        commands_json="${commands_json%,}"
    fi
    
    cat << EOF
{
  "name": "$PLUGIN_NAME",
  "version": "$PLUGIN_VERSION", 
  "description": "$PLUGIN_DESCRIPTION",
  "category": "$FOUND_PLUGIN_TYPE",
  "enabled": $is_enabled,
  "commands_count": $PLUGIN_COMMANDS_COUNT,
  "commands": [$commands_json],
  "manageable": $(if [[ "$FOUND_PLUGIN_TYPE" == "system" ]]; then echo "false"; else echo "true"; fi)
}
EOF
}

# ============================================================================
# 插件状态管理
# ============================================================================

# 更新配置文件中的插件状态
_gs_update_plugin_config() {
    local plugin_name="$1"
    local plugin_type="$2"
    local new_status="$3"
    
    local config_file="$(_gs_get_constant "GS_CONFIG_FILE")"
    
    if [[ ! -f "$config_file" ]]; then
        echo "❌ 错误: 配置文件不存在" >&2
        return 1
    fi
    
    # 加载当前配置
    local gs_plugins=()
    local gs_custom_plugins=()
    source "$config_file" 2>/dev/null || return 1
    
    if [[ "$plugin_type" == "core" ]]; then
        if [[ "$new_status" == "enabled" ]]; then
            # 添加到gs_plugins数组
            local found=false
            for existing in "${gs_plugins[@]}"; do
                if [[ "$existing" == "$plugin_name" ]]; then
                    found=true
                    break
                fi
            done
            if [[ "$found" == "false" ]]; then
                gs_plugins+=("$plugin_name")
            fi
        else
            # 从gs_plugins数组中移除
            local new_array=()
            for existing in "${gs_plugins[@]}"; do
                if [[ "$existing" != "$plugin_name" ]]; then
                    new_array+=("$existing")
                fi
            done
            gs_plugins=("${new_array[@]}")
        fi
    elif [[ "$plugin_type" == "3rd" ]]; then
        if [[ "$new_status" == "enabled" ]]; then
            # 添加到gs_custom_plugins数组
            local found=false
            for existing in "${gs_custom_plugins[@]}"; do
                if [[ "$existing" == "$plugin_name" ]]; then
                    found=true
                    break
                fi
            done
            if [[ "$found" == "false" ]]; then
                gs_custom_plugins+=("$plugin_name")
            fi
        else
            # 从gs_custom_plugins数组中移除
            local new_array=()
            for existing in "${gs_custom_plugins[@]}"; do
                if [[ "$existing" != "$plugin_name" ]]; then
                    new_array+=("$existing")
                fi
            done
            gs_custom_plugins=("${new_array[@]}")
        fi
    fi
    
    # 重写配置文件
    local temp_file=$(mktemp)
    cat > "$temp_file" << EOF
# Global Scripts V3 插件配置

# 调试
gs_env_debug=0

# prompt 主题
gs_themes_prompt=remote

# core插件
gs_plugins=(
EOF
    
    for plugin in "${gs_plugins[@]}"; do
        echo "    $plugin" >> "$temp_file"
    done
    
    cat >> "$temp_file" << EOF
)

# 3rd插件  
gs_custom_plugins=(
EOF
    
    if [[ ${#gs_custom_plugins[@]} -eq 0 ]]; then
        echo "    # 暂无第三方插件" >> "$temp_file"
    else
        for plugin in "${gs_custom_plugins[@]}"; do
            echo "    $plugin" >> "$temp_file"
        done
    fi
    
    echo ")" >> "$temp_file"
    
    # 替换原配置文件
    mv "$temp_file" "$config_file"
}

# ============================================================================
# 主命令实现
# ============================================================================

# gs-plugins list 命令
gs_system_plugins_list() {
    local option="${1:-}"
    
    case "$option" in
        "--json")
            _gs_plugins_list_json
            ;;
        "--enabled")
            _gs_plugins_list_enabled_only
            ;;
        "--disabled")
            _gs_plugins_list_disabled_only
            ;;
        *)
            _gs_plugins_list_table
            ;;
    esac
}

# gs-plugins info 命令
gs_system_plugins_info() {
    local plugin_name="$1"
    local option="${2:-}"
    
    if [[ -z "$plugin_name" ]]; then
        echo "❌ 错误: 请指定插件名称" >&2
        echo "用法: gs-plugins info <插件名> [--json]" >&2
        return 1
    fi
    
    case "$option" in
        "--json")
            _gs_plugins_info_json "$plugin_name"
            ;;
        *)
            _gs_plugins_info_text "$plugin_name"
            ;;
    esac
}

# gs-plugins enable 命令
gs_system_plugins_enable() {
    local plugin_name="$1"
    
    if [[ -z "$plugin_name" ]]; then
        echo "❌ 错误: 请指定插件名称" >&2
        echo "用法: gs-plugins enable <插件名>" >&2
        return 1
    fi
    
    # 检查插件是否存在
    if ! _get_plugin_by_name "$plugin_name"; then
        echo "❌ 错误: 插件 '$plugin_name' 不存在" >&2
        echo "💡 使用 'gs-plugins list' 查看可用插件" >&2
        return 1
    fi
    
    # 检查是否为系统命令
    if [[ "$FOUND_PLUGIN_TYPE" == "system" ]]; then
        echo "❌ 错误: 系统命令 '$plugin_name' 不支持启用/禁用操作" >&2
        echo "ℹ️  系统命令永远处于启用状态" >&2
        return 1
    fi
    
    # 检查是否已经启用
    if [[ "$PLUGIN_STATUS" == "enabled" ]]; then
        echo "ℹ️  插件 '$plugin_name' 已经启用" >&2
        return 0
    fi
    
    # 更新配置文件
    _gs_update_plugin_config "$plugin_name" "$FOUND_PLUGIN_TYPE" "enabled"
    
    echo "✅ 插件 '$plugin_name' 已成功启用"
    echo "💡 建议重新加载环境以应用更改: source gs_env.sh"
}

# gs-plugins disable 命令
gs_system_plugins_disable() {
    local plugin_name="$1"
    
    if [[ -z "$plugin_name" ]]; then
        echo "❌ 错误: 请指定插件名称" >&2
        echo "用法: gs-plugins disable <插件名>" >&2
        return 1
    fi
    
    # 检查插件是否存在
    if ! _get_plugin_by_name "$plugin_name"; then
        echo "❌ 错误: 插件 '$plugin_name' 不存在" >&2
        echo "💡 使用 'gs-plugins list' 查看可用插件" >&2
        return 1
    fi
    
    # 检查是否为系统命令
    if [[ "$FOUND_PLUGIN_TYPE" == "system" ]]; then
        echo "❌ 错误: 系统命令 '$plugin_name' 不支持启用/禁用操作" >&2
        echo "ℹ️  系统命令永远处于启用状态" >&2
        return 1
    fi
    
    # 检查是否已经禁用
    if [[ "$PLUGIN_STATUS" == "disabled" ]]; then
        echo "ℹ️  插件 '$plugin_name' 已经禁用" >&2
        return 0
    fi
    
    # 更新配置文件
    _gs_update_plugin_config "$plugin_name" "$FOUND_PLUGIN_TYPE" "disabled"
    
    echo "✅ 插件 '$plugin_name' 已成功禁用"
    echo "💡 建议重新加载环境以应用更改: source gs_env.sh"
}

# gs-plugins reload 命令
gs_system_plugins_reload() {
    local plugin_name="$1"
    
    if [[ -z "$plugin_name" ]]; then
        echo "🔄 重新加载所有插件..."
        echo "💡 请执行: source gs_env.sh"
        return 0
    fi
    
    # 检查插件是否存在
    if ! _get_plugin_by_name "$plugin_name"; then
        echo "❌ 错误: 插件 '$plugin_name' 不存在" >&2
        return 1
    fi
    
    echo "🔄 重新加载插件: $plugin_name"
    echo "💡 请执行: source gs_env.sh"
}

# 显示帮助信息
_gs_plugins_show_help() {
    cat << 'EOF'
Global Scripts V3 - 插件管理系统

用法:
  gs-plugins <子命令> [选项] [参数]

子命令:
  list [选项]                显示插件列表
    --json                   JSON格式输出
    --enabled                只显示已启用插件
    --disabled               只显示已禁用插件
    
  info <插件名> [选项]        显示插件详细信息
    --json                   JSON格式输出
    
  enable <插件名>            启用插件
  disable <插件名>           禁用插件
  reload [插件名]            重新加载插件
  
  help                       显示此帮助信息

示例:
  gs-plugins list            # 显示所有插件
  gs-plugins list --enabled # 只显示已启用插件
  gs-plugins info generator # 显示generator插件信息
  gs-plugins enable generator # 启用generator插件
  gs-plugins disable generator # 禁用generator插件

注意:
- 系统命令 (help, version, status, plugins) 不支持启用/禁用操作
- 配置更改后建议重新加载环境: source gs_env.sh
EOF
}

# ============================================================================
# 主入口函数
# ============================================================================

# 主gs-plugins命令分发
gs_system_plugins() {
    local subcommand="${1:-list}"
    shift
    
    case "$subcommand" in
        "list"|"ls")
            gs_system_plugins_list "$@"
            ;;
        "info"|"show")
            gs_system_plugins_info "$@"
            ;;
        "enable")
            gs_system_plugins_enable "$@"
            ;;
        "disable")
            gs_system_plugins_disable "$@"
            ;;
        "reload")
            gs_system_plugins_reload "$@"
            ;;
        "--help"|"-h"|"help")
            _gs_plugins_show_help
            ;;
        *)
            echo "❌ 未知子命令: $subcommand" >&2
            echo "💡 使用 'gs-plugins help' 查看帮助" >&2
            return 1
            ;;
    esac
}