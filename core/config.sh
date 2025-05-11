#!/bin/bash
# Global Scripts V3 - 配置管理核心
# 作者: Solo
# 版本: 1.0.0
# 描述: 基于Shell+Python混合架构的配置管理，Shell负责文件操作，Python负责JSON处理

# 加载依赖模块 (兼容bash/zsh)
if [[ -z "${_GS_CONFIG_DIR:-}" ]]; then
    if [[ -n "${BASH_SOURCE:-}" ]]; then
        readonly _GS_CONFIG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    elif [[ -n "${(%):-%x}" ]] 2>/dev/null; then
        readonly _GS_CONFIG_DIR="$(cd "$(dirname "${(%):-%x}")" && pwd)"
    else
        readonly _GS_CONFIG_DIR="$(cd "$(dirname "$0")" && pwd)"
    fi
fi
if [[ -z "${_GS_ROOT:-}" ]]; then
    readonly _GS_ROOT="$(cd "$_GS_CONFIG_DIR/.." && pwd)"
fi

source "$_GS_ROOT/lib/utils.sh"
source "$_GS_ROOT/lib/logger.sh" 
source "$_GS_ROOT/lib/error.sh"
source "$_GS_ROOT/lib/python_compat.sh"

# 配置管理变量 - 避免重复定义readonly变量
if [[ -z "${_GS_CONFIG_HOME:-}" ]]; then
    readonly _GS_CONFIG_HOME="${HOME}/.local/share/global_scripts"
fi
if [[ -z "${_GS_CONFIG_CACHE_DIR:-}" ]]; then
    readonly _GS_CONFIG_CACHE_DIR="${_GS_CONFIG_HOME}/cache"
fi
if [[ -z "${_GS_CONFIG_DEFAULT_FILE:-}" ]]; then
    readonly _GS_CONFIG_DEFAULT_FILE="$_GS_ROOT/config/default.json"
fi
if [[ -z "${_GS_CONFIG_USER_FILE:-}" ]]; then
    readonly _GS_CONFIG_USER_FILE="${_GS_CONFIG_HOME}/config.json"
fi
if [[ -z "${_GS_CONFIG_CACHE_TTL:-}" ]]; then
    readonly _GS_CONFIG_CACHE_TTL=300  # 5分钟缓存
fi

# 配置缓存 - 使用简单变量存储
_GS_CONFIG_CACHE_DATA=""
_GS_CONFIG_CACHE_TIME=0
_GS_CONFIG_CACHE_FILE=""

# 配置状态
_GS_CONFIG_LOADED=false
_GS_CONFIG_DIRTY=false

# ===================================
# 配置缓存管理（简化版）
# ===================================

# 检查缓存是否有效
_gs_config_is_cache_valid() {
    local config_file="$1"
    local current_time age
    
    # 检查缓存文件是否匹配
    [[ "$_GS_CONFIG_CACHE_FILE" != "$config_file" ]] && return 1
    
    # 检查缓存时间
    [[ "$_GS_CONFIG_CACHE_TIME" -eq 0 ]] && return 1
    
    current_time=$(gs_time_ms)
    age=$((current_time - _GS_CONFIG_CACHE_TIME))
    
    # 缓存时间以毫秒计算
    [[ $age -lt $((_GS_CONFIG_CACHE_TTL * 1000)) ]]
}

# 设置缓存
_gs_config_set_cache() {
    local config_file="$1"
    local data="$2"
    
    _GS_CONFIG_CACHE_FILE="$config_file"
    _GS_CONFIG_CACHE_DATA="$data"
    _GS_CONFIG_CACHE_TIME=$(gs_time_ms)
    
    gs_log_debug "配置缓存已更新: $config_file"
}

# 获取缓存
_gs_config_get_cache() {
    local config_file="$1"
    
    if _gs_config_is_cache_valid "$config_file"; then
        echo "$_GS_CONFIG_CACHE_DATA"
        gs_log_debug "配置缓存命中: $config_file"
        return 0
    else
        gs_log_debug "配置缓存未命中: $config_file"
        return 1
    fi
}

# 清理缓存
_gs_config_clear_cache() {
    _GS_CONFIG_CACHE_FILE=""
    _GS_CONFIG_CACHE_DATA=""
    _GS_CONFIG_CACHE_TIME=0
    gs_log_debug "配置缓存已清理"
}

# ===================================
# 配置读写API（基于Python）
# ===================================

# 读取配置值
gs_config_get() {
    local key="$1"
    local default_value="${2:-}"
    local config_file="${3:-$_GS_CONFIG_USER_FILE}"
    
    gs_check_not_empty "$key" "配置键"
    
    # 检查配置文件是否存在
    if [[ ! -f "$config_file" ]]; then
        gs_log_debug "配置文件不存在: $config_file"
        # 尝试从默认配置读取
        if [[ "$config_file" != "$_GS_CONFIG_DEFAULT_FILE" ]] && [[ -f "$_GS_CONFIG_DEFAULT_FILE" ]]; then
            gs_log_debug "从默认配置读取: $key"
            gs_config_get "$key" "$default_value" "$_GS_CONFIG_DEFAULT_FILE"
            return $?
        fi
        echo "$default_value"
        return 0
    fi
    
    # 检查权限
    if [[ ! -r "$config_file" ]]; then
        gs_error_permission "无法读取配置文件: $config_file"
        echo "$default_value"
        return $_GS_ERROR_PERMISSION
    fi
    
    # 使用Python处理JSON
    if gs_python_available; then
        local result
        if result=$(gs_python_call json_get "$config_file" "$key" "$default_value"); then
            gs_log_debug "配置读取成功: $key = $result"
            echo "$result"
            return 0
        else
            gs_log_warn "Python JSON处理失败，使用默认值: $key"
            echo "$default_value"
            return 1
        fi
    else
        # Python不可用时的降级处理
        gs_log_warn "Python环境不可用，无法读取JSON配置，使用默认值"
        echo "$default_value"
        return 1
    fi
}

# 设置配置值
gs_config_set() {
    local key="$1"
    local value="$2"
    local config_file="${3:-$_GS_CONFIG_USER_FILE}"
    
    gs_check_not_empty "$key" "配置键"
    
    # 确保配置目录存在
    local config_dir
    config_dir=$(dirname "$config_file")
    if [[ ! -d "$config_dir" ]]; then
        if ! gs_dir_create "$config_dir" 755; then
            gs_error_permission "无法创建配置目录: $config_dir"
            return $_GS_ERROR_PERMISSION
        fi
    fi
    
    # 备份现有配置
    if [[ -f "$config_file" ]]; then
        gs_file_backup "$config_file" ".bak" true
    fi
    
    # 使用Python处理JSON
    if gs_python_available; then
        if gs_python_call json_set "$config_file" "$key" "$value"; then
            # 清理缓存
            _gs_config_clear_cache
            _GS_CONFIG_DIRTY=true
            gs_log_debug "配置已设置: $key = $value"
            return 0
        else
            gs_error_config "设置配置失败: $key = $value"
            return $_GS_ERROR_CONFIG
        fi
    else
        gs_error_dependency "Python环境不可用，无法设置JSON配置"
        return $_GS_ERROR_DEPENDENCY
    fi
}

# 删除配置键
gs_config_unset() {
    local key="$1"
    local config_file="${2:-$_GS_CONFIG_USER_FILE}"
    
    gs_check_not_empty "$key" "配置键"
    
    if [[ ! -f "$config_file" ]]; then
        gs_log_debug "配置文件不存在，无需删除: $config_file"
        return 0
    fi
    
    # 使用Python删除键（设置为特殊值表示删除）
    if gs_python_available; then
        # 读取当前配置
        local config_content
        if config_content=$(cat "$config_file" 2>/dev/null); then
            # 使用jq删除键（如果可用）
            if command -v jq >/dev/null 2>&1; then
                local new_content
                new_content=$(echo "$config_content" | jq "del(.$key)")
                if echo "$new_content" > "$config_file"; then
                    _gs_config_clear_cache
                    _GS_CONFIG_DIRTY=true
                    gs_log_debug "配置键已删除: $key"
                    return 0
                fi
            else
                gs_log_warn "删除配置键需要jq命令: $key"
                return $_GS_ERROR_UNSUPPORTED
            fi
        fi
    else
        gs_error_dependency "Python环境不可用"
        return $_GS_ERROR_DEPENDENCY
    fi
}

# 检查配置键是否存在
gs_config_has() {
    local key="$1"
    local config_file="${2:-$_GS_CONFIG_USER_FILE}"
    
    if [[ ! -f "$config_file" ]]; then
        return 1
    fi
    
    # 使用Python检查键存在性
    if gs_python_available; then
        gs_python_call json_has_key "$config_file" "$key"
        return $?
    else
        # 降级处理：尝试读取，如果不是默认值则认为存在
        local value
        value=$(gs_config_get "$key" "__NOT_FOUND__" "$config_file")
        [[ "$value" != "__NOT_FOUND__" ]]
    fi
}

# ===================================
# 配置管理操作
# ===================================

# 初始化配置系统
gs_config_init() {
    gs_log_debug "初始化配置系统"
    
    # 确保配置目录存在
    if [[ ! -d "$_GS_CONFIG_HOME" ]]; then
        gs_dir_create "$_GS_CONFIG_HOME" 755
    fi
    
    if [[ ! -d "$_GS_CONFIG_CACHE_DIR" ]]; then
        gs_dir_create "$_GS_CONFIG_CACHE_DIR" 755
    fi
    
    # 如果用户配置不存在，从默认配置复制
    if [[ ! -f "$_GS_CONFIG_USER_FILE" ]] && [[ -f "$_GS_CONFIG_DEFAULT_FILE" ]]; then
        gs_log_info "创建用户配置文件"
        cp "$_GS_CONFIG_DEFAULT_FILE" "$_GS_CONFIG_USER_FILE"
    fi
    
    _GS_CONFIG_LOADED=true
    gs_log_debug "配置系统初始化完成"
    return 0
}

# 重新加载配置
gs_config_reload() {
    gs_log_debug "重新加载配置"
    
    # 清理缓存
    _gs_config_clear_cache
    
    _GS_CONFIG_DIRTY=false
    gs_log_debug "配置已重新加载"
    return 0
}

# 验证配置
gs_config_validate() {
    local config_file="${1:-$_GS_CONFIG_USER_FILE}"
    local schema_file="${2:-$_GS_ROOT/config/schema/core.schema.json}"
    
    gs_log_debug "验证配置文件: $config_file"
    
    if [[ ! -f "$config_file" ]]; then
        gs_error_file_not_found "配置文件不存在: $config_file"
        return $_GS_ERROR_FILE_NOT_FOUND
    fi
    
    # 使用Python进行增强配置验证
    if gs_python_available; then
        # 如果提供了Schema文件，进行Schema验证
        if [[ -f "$schema_file" ]]; then
            if gs_python_call config_validate "$config_file" "$schema_file"; then
                gs_log_debug "配置文件验证通过（包含Schema验证）"
                return 0
            else
                gs_error_config "配置文件验证失败: $config_file"
                return $_GS_ERROR_CONFIG
            fi
        else
            # 仅进行基础配置验证
            if gs_python_call config_validate "$config_file"; then
                gs_log_debug "配置文件基础验证通过"
                return 0
            else
                gs_error_config "配置文件基础验证失败: $config_file"
                return $_GS_ERROR_CONFIG
            fi
        fi
    else
        # 降级处理：简单的JSON格式检查
        if command -v jq >/dev/null 2>&1; then
            if jq . "$config_file" >/dev/null 2>&1; then
                gs_log_debug "配置文件JSON格式检查通过"
                return 0
            else
                gs_error_config "配置文件JSON格式错误: $config_file"
                return $_GS_ERROR_CONFIG
            fi
        else
            # 最基础的文件检查
            if file "$config_file" | grep -q "text"; then
                gs_log_debug "配置文件基本格式检查通过"
                return 0
            else
                gs_error_config "配置文件格式可能有问题: $config_file"
                return $_GS_ERROR_CONFIG
            fi
        fi
    fi
}

# 备份配置
gs_config_backup() {
    local backup_name="${1:-config_backup_$(date +%Y%m%d_%H%M%S).json}"
    local backup_dir="${_GS_CONFIG_HOME}/backups"
    
    # 确保备份目录存在
    gs_dir_create "$backup_dir" 755
    
    if [[ -f "$_GS_CONFIG_USER_FILE" ]]; then
        local backup_file="$backup_dir/$backup_name"
        if cp "$_GS_CONFIG_USER_FILE" "$backup_file"; then
            gs_log_info "配置已备份到: $backup_file"
            echo "$backup_file"
            return 0
        else
            gs_error_permission "无法创建配置备份"
            return $_GS_ERROR_PERMISSION
        fi
    else
        gs_log_warn "用户配置文件不存在，无需备份"
        return 1
    fi
}

# 恢复配置
gs_config_restore() {
    local backup_file="$1"
    
    gs_check_file_exists "$backup_file"
    
    # 验证备份文件
    if ! gs_config_validate "$backup_file"; then
        gs_error_config "备份文件格式错误: $backup_file"
        return $_GS_ERROR_CONFIG
    fi
    
    # 当前配置备份
    gs_config_backup "before_restore_$(date +%Y%m%d_%H%M%S).json"
    
    # 恢复配置
    if cp "$backup_file" "$_GS_CONFIG_USER_FILE"; then
        gs_config_reload
        gs_log_info "配置已恢复自: $backup_file"
        return 0
    else
        gs_error_permission "无法恢复配置"
        return $_GS_ERROR_PERMISSION
    fi
}

# 合并配置文件
gs_config_merge() {
    local base_file="${1:-$_GS_CONFIG_DEFAULT_FILE}"
    local override_file="${2:-$_GS_CONFIG_USER_FILE}"
    local output_file="${3:-$_GS_CONFIG_USER_FILE}"
    
    gs_log_debug "合并配置文件: $base_file + $override_file -> $output_file"
    
    # 检查输入文件是否存在
    if [[ ! -f "$base_file" ]]; then
        gs_error_file_not_found "基础配置文件不存在: $base_file"
        return $_GS_ERROR_FILE_NOT_FOUND
    fi
    
    # 如果覆盖文件不存在，直接复制基础文件
    if [[ ! -f "$override_file" ]]; then
        gs_log_debug "覆盖文件不存在，复制基础配置: $base_file -> $output_file"
        cp "$base_file" "$output_file"
        return 0
    fi
    
    # 使用Python进行深度合并
    if gs_python_available; then
        if gs_python_call config_merge "$base_file" "$override_file" "$output_file"; then
            gs_log_debug "配置文件合并成功"
            _gs_config_clear_cache
            return 0
        else
            gs_error_config "配置文件合并失败"
            return $_GS_ERROR_CONFIG
        fi
    else
        # 降级处理：简单覆盖
        gs_log_warn "Python不可用，使用简单配置覆盖"
        if cp "$override_file" "$output_file"; then
            gs_log_debug "配置文件覆盖成功"
            return 0
        else
            gs_error_permission "无法写入配置文件: $output_file"
            return $_GS_ERROR_PERMISSION
        fi
    fi
}

# 重置为默认配置
gs_config_reset() {
    gs_log_warn "重置配置为默认值"
    
    # 备份当前配置
    gs_config_backup "before_reset_$(date +%Y%m%d_%H%M%S).json"
    
    # 复制默认配置
    if [[ -f "$_GS_CONFIG_DEFAULT_FILE" ]]; then
        if cp "$_GS_CONFIG_DEFAULT_FILE" "$_GS_CONFIG_USER_FILE"; then
            gs_config_reload
            gs_log_info "配置已重置为默认值"
            return 0
        else
            gs_error_permission "无法重置配置"
            return $_GS_ERROR_PERMISSION
        fi
    else
        gs_error_file_not_found "默认配置文件不存在"
        return $_GS_ERROR_FILE_NOT_FOUND
    fi
}

# 显示配置信息
gs_config_info() {
    printf "=== Global Scripts 配置信息 ===\n"
    printf "配置目录: %s\n" "$_GS_CONFIG_HOME"
    printf "用户配置: %s\n" "$_GS_CONFIG_USER_FILE"
    printf "默认配置: %s\n" "$_GS_CONFIG_DEFAULT_FILE"
    printf "缓存目录: %s\n" "$_GS_CONFIG_CACHE_DIR"
    printf "配置状态: %s\n" "$([[ "$_GS_CONFIG_LOADED" == "true" ]] && echo "已加载" || echo "未加载")"
    printf "是否修改: %s\n" "$([[ "$_GS_CONFIG_DIRTY" == "true" ]] && echo "是" || echo "否")"
    printf "Python环境: %s\n" "$(gs_python_available && echo "可用($_GS_PYTHON_CMD)" || echo "不可用")"
    
    if [[ -f "$_GS_CONFIG_USER_FILE" ]]; then
        local file_size
        file_size=$(gs_file_size "$_GS_CONFIG_USER_FILE")
        printf "文件大小: %s字节\n" "$file_size"
    fi
}