#!/bin/bash
# Global Scripts V3 - 命令注册表
# 作者: Solo
# 版本: 1.0.0
# 描述: 基于Shell+Python混合架构的命令注册，简化为文件存储，Python处理复杂逻辑

# 加载依赖模块 (兼容bash/zsh)
if [[ -z "${_GS_REGISTRY_DIR:-}" ]]; then
    if [[ -n "${BASH_SOURCE:-}" ]]; then
        readonly _GS_REGISTRY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    elif [[ -n "${(%):-%x}" ]] 2>/dev/null; then
        readonly _GS_REGISTRY_DIR="$(cd "$(dirname "${(%):-%x}")" && pwd)"
    else
        readonly _GS_REGISTRY_DIR="$(cd "$(dirname "$0")" && pwd)"
    fi
fi
if [[ -z "${_GS_ROOT:-}" ]]; then
    readonly _GS_ROOT="$(cd "$_GS_REGISTRY_DIR/.." && pwd)"
fi

source "$_GS_ROOT/lib/utils.sh"
source "$_GS_ROOT/lib/logger.sh"
source "$_GS_ROOT/lib/error.sh"
source "$_GS_ROOT/lib/python_compat.sh"

# 注册表文件路径
if [[ -z "${_GS_REGISTRY_HOME:-}" ]]; then
    readonly _GS_REGISTRY_HOME="${HOME}/.local/share/global_scripts"
fi
if [[ -z "${_GS_COMMAND_REGISTRY_FILE:-}" ]]; then
    readonly _GS_COMMAND_REGISTRY_FILE="$_GS_REGISTRY_HOME/commands.json"
fi
if [[ -z "${_GS_ALIAS_REGISTRY_FILE:-}" ]]; then
    readonly _GS_ALIAS_REGISTRY_FILE="$_GS_REGISTRY_HOME/aliases.json"
fi
if [[ -z "${_GS_PLUGIN_REGISTRY_FILE:-}" ]]; then
    readonly _GS_PLUGIN_REGISTRY_FILE="$_GS_REGISTRY_HOME/plugins.json"
fi

# 注册表状态
_GS_REGISTRY_LOADED=false
_GS_REGISTRY_VERSION=1

# ===================================
# 命令注册功能
# ===================================

# 注册命令
gs_registry_register_command() {
    local command_name="$1"
    local command_path="$2"
    local description="${3:-}"
    local version="${4:-1.0.0}"
    local plugin_name="${5:-}"
    
    gs_check_not_empty "$command_name" "命令名"
    gs_check_not_empty "$command_path" "命令路径"
    
    gs_log_debug "注册命令: $command_name -> $command_path"
    
    # 验证命令路径
    if [[ ! -f "$command_path" ]]; then
        gs_error_file_not_found "命令文件不存在: $command_path"
        return $_GS_ERROR_FILE_NOT_FOUND
    fi
    
    if [[ ! -x "$command_path" ]]; then
        gs_error_permission "命令文件不可执行: $command_path"
        return $_GS_ERROR_PERMISSION
    fi
    
    # 确保注册表目录存在
    gs_dir_create "$_GS_REGISTRY_HOME" 755
    
    # 使用Python处理JSON注册
    if gs_python_available; then
        # 创建命令信息JSON字符串
        local command_info
        command_info=$(cat <<EOF
{
    "path": "$command_path",
    "description": "$description",
    "version": "$version",
    "plugin": "$plugin_name",
    "registered_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
)
        if gs_python_call json_set "$_GS_COMMAND_REGISTRY_FILE" "$command_name" "$command_info"; then
            gs_log_info "命令注册成功: $command_name"
            return 0
        else
            gs_error_config "命令注册失败: $command_name"
            return $_GS_ERROR_CONFIG
        fi
    else
        # Python不可用时的简单文件存储降级
        gs_log_warn "Python不可用，使用简单文件存储"
        local registry_line="$command_name|$command_path|$description|$version|$plugin_name"
        echo "$registry_line" >> "$_GS_COMMAND_REGISTRY_FILE.txt"
        gs_log_info "命令注册成功(简单模式): $command_name"
        return 0
    fi
}

# 取消注册命令
gs_registry_unregister_command() {
    local command_name="$1"
    
    gs_check_not_empty "$command_name" "命令名"
    
    gs_log_debug "取消注册命令: $command_name"
    
    # 检查命令是否存在
    if ! gs_registry_has_command "$command_name"; then
        gs_error_invalid_arg "命令不存在: $command_name"
        return $_GS_ERROR_INVALID_ARG
    fi
    
    # 使用Python删除命令
    if gs_python_available; then
        # 读取当前注册表
        if [[ -f "$_GS_COMMAND_REGISTRY_FILE" ]]; then
            # 使用jq删除键（如果可用）
            if command -v jq >/dev/null 2>&1; then
                local temp_file
                temp_file=$(gs_file_mktemp registry_del)
                if jq "del(.$command_name)" "$_GS_COMMAND_REGISTRY_FILE" > "$temp_file"; then
                    mv "$temp_file" "$_GS_COMMAND_REGISTRY_FILE"
                    gs_log_info "命令取消注册成功: $command_name"
                    return 0
                fi
                rm -f "$temp_file"
            fi
        fi
    else
        # 简单模式：从文本文件中删除行
        if [[ -f "$_GS_COMMAND_REGISTRY_FILE.txt" ]]; then
            local temp_file
            temp_file=$(gs_file_mktemp registry_del)
            if grep -v "^$command_name|" "$_GS_COMMAND_REGISTRY_FILE.txt" > "$temp_file"; then
                mv "$temp_file" "$_GS_COMMAND_REGISTRY_FILE.txt"
                gs_log_info "命令取消注册成功(简单模式): $command_name"
                return 0
            fi
            rm -f "$temp_file"
        fi
    fi
    
    gs_error_config "取消注册命令失败: $command_name"
    return $_GS_ERROR_CONFIG
}

# 查找命令
gs_registry_find_command() {
    local command_name="$1"
    
    gs_check_not_empty "$command_name" "命令名"
    
    # 首先检查是否为别名
    local real_command
    real_command=$(gs_registry_resolve_alias "$command_name" 2>/dev/null)
    if [[ $? -eq 0 && "$real_command" != "$command_name" ]]; then
        command_name="$real_command"
    fi
    
    # 使用Python查找命令
    if gs_python_available && [[ -f "$_GS_COMMAND_REGISTRY_FILE" ]]; then
        local command_info
        if command_info=$(gs_python_call json_get "$_GS_COMMAND_REGISTRY_FILE" "$command_name.path" ""); then
            if [[ -n "$command_info" && "$command_info" != "__NOT_FOUND__" ]]; then
                echo "$command_info"
                return 0
            fi
        fi
    else
        # 简单模式：从文本文件查找
        if [[ -f "$_GS_COMMAND_REGISTRY_FILE.txt" ]]; then
            local line
            if line=$(grep "^$command_name|" "$_GS_COMMAND_REGISTRY_FILE.txt" | head -1); then
                # 提取路径（第二个字段）
                echo "$line" | cut -d'|' -f2
                return 0
            fi
        fi
    fi
    
    gs_log_debug "命令未找到: $command_name"
    return 1
}

# 检查命令是否存在
gs_registry_has_command() {
    local command_name="$1"
    gs_registry_find_command "$command_name" >/dev/null 2>&1
}

# 获取命令信息
gs_registry_get_command_info() {
    local command_name="$1"
    local info_key="${2:-}"
    
    gs_check_not_empty "$command_name" "命令名"
    
    # 使用Python获取详细信息
    if gs_python_available && [[ -f "$_GS_COMMAND_REGISTRY_FILE" ]]; then
        if [[ -n "$info_key" ]]; then
            # 获取特定字段
            gs_python_call json_get "$_GS_COMMAND_REGISTRY_FILE" "$command_name.$info_key" ""
        else
            # 获取所有信息
            gs_python_call json_get "$_GS_COMMAND_REGISTRY_FILE" "$command_name" ""
        fi
    else
        # 简单模式
        if [[ -f "$_GS_COMMAND_REGISTRY_FILE.txt" ]]; then
            local line
            if line=$(grep "^$command_name|" "$_GS_COMMAND_REGISTRY_FILE.txt" | head -1); then
                case "$info_key" in
                    "path") echo "$line" | cut -d'|' -f2 ;;
                    "description") echo "$line" | cut -d'|' -f3 ;;
                    "version") echo "$line" | cut -d'|' -f4 ;;
                    "plugin") echo "$line" | cut -d'|' -f5 ;;
                    *) echo "$line" ;;
                esac
            fi
        fi
    fi
}

# 列出所有命令
gs_registry_list_commands() {
    local pattern="${1:-}"
    
    # 使用Python列出命令
    if gs_python_available && [[ -f "$_GS_COMMAND_REGISTRY_FILE" ]]; then
        local commands
        if commands=$(gs_python_call json_keys "$_GS_COMMAND_REGISTRY_FILE"); then
            if [[ -n "$pattern" ]]; then
                echo "$commands" | grep "$pattern"
            else
                echo "$commands"
            fi
        fi
    else
        # 简单模式
        if [[ -f "$_GS_COMMAND_REGISTRY_FILE.txt" ]]; then
            if [[ -n "$pattern" ]]; then
                cut -d'|' -f1 "$_GS_COMMAND_REGISTRY_FILE.txt" | grep "$pattern"
            else
                cut -d'|' -f1 "$_GS_COMMAND_REGISTRY_FILE.txt"
            fi
        fi
    fi
}

# ===================================
# 别名管理功能
# ===================================

# 创建别名
gs_registry_create_alias() {
    local alias_name="$1"
    local command_name="$2"
    
    gs_check_not_empty "$alias_name" "别名"
    gs_check_not_empty "$command_name" "命令名"
    
    # 检查目标命令是否存在
    if ! gs_registry_has_command "$command_name"; then
        gs_error_invalid_arg "目标命令不存在: $command_name"
        return $_GS_ERROR_INVALID_ARG
    fi
    
    # 检查别名是否与现有命令冲突
    if gs_registry_has_command "$alias_name"; then
        gs_error_invalid_arg "别名与现有命令冲突: $alias_name"
        return $_GS_ERROR_INVALID_ARG
    fi
    
    gs_log_debug "创建别名: $alias_name -> $command_name"
    
    # 使用Python创建别名
    if gs_python_available; then
        if gs_python_call json_set "$_GS_ALIAS_REGISTRY_FILE" "$alias_name" "$command_name"; then
            gs_log_info "别名创建成功: $alias_name -> $command_name"
            return 0
        fi
    else
        # 简单模式
        echo "$alias_name|$command_name" >> "$_GS_ALIAS_REGISTRY_FILE.txt"
        gs_log_info "别名创建成功(简单模式): $alias_name -> $command_name"
        return 0
    fi
    
    gs_error_config "别名创建失败: $alias_name"
    return $_GS_ERROR_CONFIG
}

# 删除别名
gs_registry_remove_alias() {
    local alias_name="$1"
    
    gs_check_not_empty "$alias_name" "别名"
    
    gs_log_debug "删除别名: $alias_name"
    
    # 使用Python删除别名
    if gs_python_available && [[ -f "$_GS_ALIAS_REGISTRY_FILE" ]]; then
        if command -v jq >/dev/null 2>&1; then
            local temp_file
            temp_file=$(gs_file_mktemp alias_del)
            if jq "del(.$alias_name)" "$_GS_ALIAS_REGISTRY_FILE" > "$temp_file"; then
                mv "$temp_file" "$_GS_ALIAS_REGISTRY_FILE"
                gs_log_info "别名删除成功: $alias_name"
                return 0
            fi
            rm -f "$temp_file"
        fi
    else
        # 简单模式
        if [[ -f "$_GS_ALIAS_REGISTRY_FILE.txt" ]]; then
            local temp_file
            temp_file=$(gs_file_mktemp alias_del)
            if grep -v "^$alias_name|" "$_GS_ALIAS_REGISTRY_FILE.txt" > "$temp_file"; then
                mv "$temp_file" "$_GS_ALIAS_REGISTRY_FILE.txt"
                gs_log_info "别名删除成功(简单模式): $alias_name"
                return 0
            fi
            rm -f "$temp_file"
        fi
    fi
    
    gs_error_config "别名删除失败: $alias_name"
    return $_GS_ERROR_CONFIG
}

# 解析别名
gs_registry_resolve_alias() {
    local alias_name="$1"
    
    # 使用Python解析别名
    if gs_python_available && [[ -f "$_GS_ALIAS_REGISTRY_FILE" ]]; then
        local real_command
        if real_command=$(gs_python_call json_get "$_GS_ALIAS_REGISTRY_FILE" "$alias_name" ""); then
            if [[ -n "$real_command" && "$real_command" != "__NOT_FOUND__" ]]; then
                echo "$real_command"
                return 0
            fi
        fi
    else
        # 简单模式
        if [[ -f "$_GS_ALIAS_REGISTRY_FILE.txt" ]]; then
            local line
            if line=$(grep "^$alias_name|" "$_GS_ALIAS_REGISTRY_FILE.txt" | head -1); then
                echo "$line" | cut -d'|' -f2
                return 0
            fi
        fi
    fi
    
    # 如果不是别名，返回原名
    echo "$alias_name"
    return 1
}

# 列出别名
gs_registry_list_aliases() {
    local command_name="${1:-}"
    
    if [[ -n "$command_name" ]]; then
        # 列出指定命令的别名
        if gs_python_available && [[ -f "$_GS_ALIAS_REGISTRY_FILE" ]]; then
            gs_python_call json_keys "$_GS_ALIAS_REGISTRY_FILE" | while read -r alias; do
                local target
                target=$(gs_python_call json_get "$_GS_ALIAS_REGISTRY_FILE" "$alias" "")
                if [[ "$target" == "$command_name" ]]; then
                    echo "$alias"
                fi
            done
        else
            # 简单模式
            if [[ -f "$_GS_ALIAS_REGISTRY_FILE.txt" ]]; then
                awk -F'|' -v cmd="$command_name" '$2 == cmd { print $1 }' "$_GS_ALIAS_REGISTRY_FILE.txt"
            fi
        fi
    else
        # 列出所有别名
        if gs_python_available && [[ -f "$_GS_ALIAS_REGISTRY_FILE" ]]; then
            gs_python_call json_keys "$_GS_ALIAS_REGISTRY_FILE"
        else
            # 简单模式
            if [[ -f "$_GS_ALIAS_REGISTRY_FILE.txt" ]]; then
                cut -d'|' -f1 "$_GS_ALIAS_REGISTRY_FILE.txt"
            fi
        fi
    fi
}

# ===================================
# 插件管理功能
# ===================================

# 注册插件
gs_registry_register_plugin() {
    local plugin_name="$1"
    local plugin_path="$2"
    local description="${3:-}"
    local version="${4:-1.0.0}"
    
    gs_check_not_empty "$plugin_name" "插件名"
    gs_check_not_empty "$plugin_path" "插件路径"
    
    gs_log_debug "注册插件: $plugin_name -> $plugin_path"
    
    # 验证插件路径
    if [[ ! -d "$plugin_path" ]]; then
        gs_error_file_not_found "插件目录不存在: $plugin_path"
        return $_GS_ERROR_FILE_NOT_FOUND
    fi
    
    # 使用Python注册插件
    if gs_python_available; then
        local plugin_info
        plugin_info=$(cat <<EOF
{
    "path": "$plugin_path",
    "description": "$description",
    "version": "$version",
    "registered_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
)
        if gs_python_call json_set "$_GS_PLUGIN_REGISTRY_FILE" "$plugin_name" "$plugin_info"; then
            gs_log_info "插件注册成功: $plugin_name"
            return 0
        fi
    else
        # 简单模式
        echo "$plugin_name|$plugin_path|$description|$version" >> "$_GS_PLUGIN_REGISTRY_FILE.txt"
        gs_log_info "插件注册成功(简单模式): $plugin_name" 
        return 0
    fi
    
    gs_error_config "插件注册失败: $plugin_name"
    return $_GS_ERROR_CONFIG
}

# 加载插件命令
gs_registry_load_plugin_commands() {
    local plugin_name="$1"
    
    # 获取插件路径
    local plugin_path
    if gs_python_available && [[ -f "$_GS_PLUGIN_REGISTRY_FILE" ]]; then
        plugin_path=$(gs_python_call json_get "$_GS_PLUGIN_REGISTRY_FILE" "$plugin_name.path" "")
    else
        # 简单模式
        if [[ -f "$_GS_PLUGIN_REGISTRY_FILE.txt" ]]; then
            local line
            if line=$(grep "^$plugin_name|" "$_GS_PLUGIN_REGISTRY_FILE.txt" | head -1); then
                plugin_path=$(echo "$line" | cut -d'|' -f2)
            fi
        fi
    fi
    
    if [[ -z "$plugin_path" ]]; then
        gs_error_invalid_arg "插件不存在: $plugin_name"
        return $_GS_ERROR_INVALID_ARG
    fi
    
    gs_log_debug "加载插件命令: $plugin_name ($plugin_path)"
    
    # 查找插件中的命令文件
    local commands_dir="$plugin_path/commands"
    if [[ -d "$commands_dir" ]]; then
        local cmd_file
        for cmd_file in "$commands_dir"/*.sh; do
            [[ -f "$cmd_file" ]] || continue
            
            local cmd_name
            cmd_name=$(basename "$cmd_file" .sh)
            
            # 注册插件命令
            gs_registry_register_command "$cmd_name" "$cmd_file" "插件命令: $plugin_name" "1.0.0" "$plugin_name"
        done
    fi
    
    gs_log_info "插件命令加载完成: $plugin_name"
    return 0
}

# ===================================
# 注册表管理
# ===================================

# 初始化注册表
gs_registry_init() {
    gs_log_debug "初始化命令注册表"
    
    # 确保注册表目录存在
    gs_dir_create "$_GS_REGISTRY_HOME" 755
    
    # 初始化空的JSON文件（如果不存在）
    if gs_python_available; then
        for registry_file in "$_GS_COMMAND_REGISTRY_FILE" "$_GS_ALIAS_REGISTRY_FILE" "$_GS_PLUGIN_REGISTRY_FILE"; do
            if [[ ! -f "$registry_file" ]]; then
                echo "{}" > "$registry_file"
            fi
        done
    fi
    
    _GS_REGISTRY_LOADED=true
    gs_log_debug "注册表初始化完成"
    return 0
}

# 清理注册表
gs_registry_clear() {
    gs_log_debug "清理命令注册表"
    
    # 清理JSON文件
    if gs_python_available; then
        for registry_file in "$_GS_COMMAND_REGISTRY_FILE" "$_GS_ALIAS_REGISTRY_FILE" "$_GS_PLUGIN_REGISTRY_FILE"; do
            echo "{}" > "$registry_file"
        done
    fi
    
    # 清理文本文件（简单模式）
    for txt_file in "$_GS_COMMAND_REGISTRY_FILE.txt" "$_GS_ALIAS_REGISTRY_FILE.txt" "$_GS_PLUGIN_REGISTRY_FILE.txt"; do
        [[ -f "$txt_file" ]] && rm -f "$txt_file"
    done
    
    _GS_REGISTRY_LOADED=false
    gs_log_debug "注册表清理完成"
    return 0
}

# 验证注册表完整性
gs_registry_verify() {
    gs_log_debug "验证注册表完整性"
    
    local issues=0
    
    # 检查注册表目录
    if [[ ! -d "$_GS_REGISTRY_HOME" ]]; then
        gs_log_error "注册表目录不存在: $_GS_REGISTRY_HOME"
        issues=$((issues + 1))
    fi
    
    # 检查JSON文件格式
    if gs_python_available; then
        for registry_file in "$_GS_COMMAND_REGISTRY_FILE" "$_GS_ALIAS_REGISTRY_FILE" "$_GS_PLUGIN_REGISTRY_FILE"; do
            if [[ -f "$registry_file" ]]; then
                if ! gs_python_call json_validate "$registry_file" >/dev/null 2>&1; then
                    gs_log_error "注册表JSON格式无效: $registry_file"
                    issues=$((issues + 1))
                fi
            fi
        done
    fi
    
    # 验证命令路径的有效性
    if gs_registry_list_commands >/dev/null 2>&1; then
        gs_registry_list_commands | while read -r cmd_name; do
            [[ -z "$cmd_name" ]] && continue
            local cmd_path
            cmd_path=$(gs_registry_find_command "$cmd_name" 2>/dev/null)
            if [[ -n "$cmd_path" && ! -f "$cmd_path" ]]; then
                gs_log_warn "命令文件不存在: $cmd_name -> $cmd_path"
                issues=$((issues + 1))
            fi
        done
    fi
    
    if [[ $issues -eq 0 ]]; then
        gs_log_debug "注册表验证通过"
        return 0
    else
        gs_log_error "注册表验证失败，发现 $issues 个问题"
        return 1
    fi
}

# 获取注册表统计信息
gs_registry_stats() {
    printf "=== 命令注册表统计 ===\n"
    printf "注册表状态: %s\n" "$([[ "$_GS_REGISTRY_LOADED" == "true" ]] && echo "已加载" || echo "未加载")"
    printf "注册表版本: %d\n" "$_GS_REGISTRY_VERSION"
    printf "存储目录: %s\n" "$_GS_REGISTRY_HOME"
    printf "Python环境: %s\n" "$(gs_python_available && echo "可用($_GS_PYTHON_CMD)" || echo "不可用")"
    
    # 统计数量
    local cmd_count=0
    local alias_count=0
    local plugin_count=0
    
    if gs_python_available; then
        # 使用Python统计
        if [[ -f "$_GS_COMMAND_REGISTRY_FILE" ]]; then
            cmd_count=$(gs_python_call json_keys "$_GS_COMMAND_REGISTRY_FILE" | wc -l | gs_str_trim)
        fi
        if [[ -f "$_GS_ALIAS_REGISTRY_FILE" ]]; then
            alias_count=$(gs_python_call json_keys "$_GS_ALIAS_REGISTRY_FILE" | wc -l | gs_str_trim)
        fi
        if [[ -f "$_GS_PLUGIN_REGISTRY_FILE" ]]; then
            plugin_count=$(gs_python_call json_keys "$_GS_PLUGIN_REGISTRY_FILE" | wc -l | gs_str_trim)
        fi
    else
        # 简单模式统计
        [[ -f "$_GS_COMMAND_REGISTRY_FILE.txt" ]] && cmd_count=$(wc -l < "$_GS_COMMAND_REGISTRY_FILE.txt" | gs_str_trim)
        [[ -f "$_GS_ALIAS_REGISTRY_FILE.txt" ]] && alias_count=$(wc -l < "$_GS_ALIAS_REGISTRY_FILE.txt" | gs_str_trim)
        [[ -f "$_GS_PLUGIN_REGISTRY_FILE.txt" ]] && plugin_count=$(wc -l < "$_GS_PLUGIN_REGISTRY_FILE.txt" | gs_str_trim)
    fi
    
    printf "注册命令数: %d\n" "$cmd_count"
    printf "别名数量: %d\n" "$alias_count" 
    printf "插件数量: %d\n" "$plugin_count"
}