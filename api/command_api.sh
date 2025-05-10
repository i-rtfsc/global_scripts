#!/bin/bash
# Global Scripts V3 - 命令处理API
# 作者: Solo
# 版本: 1.0.0
# 描述: 统一命令路由、参数解析和结果格式化输出，采用Shell+Python混合架构

# 获取脚本目录
if [[ -z "${_GS_API_DIR:-}" ]]; then
    if [[ -n "${BASH_SOURCE:-}" ]]; then
        readonly _GS_API_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    elif [[ -n "${(%):-%x}" ]] 2>/dev/null; then
        readonly _GS_API_DIR="$(cd "$(dirname "${(%):-%x}")" && pwd)"
    else
        readonly _GS_API_DIR="$(cd "$(dirname "$0")" && pwd)"
    fi
fi

if [[ -z "${_GS_ROOT:-}" ]]; then
    readonly _GS_ROOT="$(cd "$_GS_API_DIR/.." && pwd)"
fi

# 加载依赖模块
source "$_GS_ROOT/lib/utils.sh"
source "$_GS_ROOT/lib/logger.sh"
source "$_GS_ROOT/lib/error.sh"
source "$_GS_ROOT/core/registry.sh"

# ===================================
# 命令路由和分发系统
# ===================================

# 命令分发主函数
gs_command_dispatch() {
    local command_name="$1"
    shift
    local args=("$@")
    
    gs_log_debug "分发命令: $command_name ${args[*]}"
    
    # 检查命令是否存在
    if ! gs_registry_has_command "$command_name"; then
        gs_error_command_not_found "未知命令: $command_name"
        return $_GS_ERROR_COMMAND_NOT_FOUND
    fi
    
    # 获取命令处理函数
    local handler_function
    handler_function=$(gs_registry_get_command "$command_name")
    
    if [[ -z "$handler_function" ]]; then
        gs_error_internal "命令处理函数未定义: $command_name"
        return $_GS_ERROR_INTERNAL
    fi
    
    # 执行命令前的预处理
    if ! _gs_command_pre_process "$command_name" "${args[@]}"; then
        return $?
    fi
    
    # 执行命令处理函数
    local exit_code=0
    if declare -F "$handler_function" >/dev/null 2>&1; then
        "$handler_function" "${args[@]}"
        exit_code=$?
    else
        gs_error_internal "命令处理函数不存在: $handler_function"
        return $_GS_ERROR_INTERNAL
    fi
    
    # 执行命令后的后处理
    _gs_command_post_process "$command_name" $exit_code "${args[@]}"
    
    return $exit_code
}

# 命令预处理
_gs_command_pre_process() {
    local command_name="$1"
    shift
    local args=("$@")
    
    # 权限检查
    if ! _gs_command_check_permission "$command_name"; then
        gs_error_permission "没有权限执行命令: $command_name"
        return $_GS_ERROR_PERMISSION
    fi
    
    # 依赖检查
    if ! _gs_command_check_dependencies "$command_name"; then
        gs_error_dependency "命令依赖检查失败: $command_name"
        return $_GS_ERROR_DEPENDENCY
    fi
    
    gs_log_debug "命令预处理完成: $command_name"
    return 0
}

# 命令后处理
_gs_command_post_process() {
    local command_name="$1"
    local exit_code="$2"
    shift 2
    local args=("$@")
    
    # 记录命令执行结果
    if [[ $exit_code -eq 0 ]]; then
        gs_log_debug "命令执行成功: $command_name"
    else
        gs_log_warn "命令执行失败: $command_name (退出码: $exit_code)"
    fi
    
    # 清理临时资源
    _gs_command_cleanup_resources "$command_name"
    
    return $exit_code
}

# 权限检查
_gs_command_check_permission() {
    local command_name="$1"
    
    # 检查命令是否需要特殊权限
    case "$command_name" in
        gs-config-set|gs-config-reset|gs-plugins-*install*|gs-plugins-*uninstall*)
            # 这些命令需要写权限检查
            if [[ ! -w "${HOME}/.local/share/global_scripts" ]] 2>/dev/null; then
                return 1
            fi
            ;;
        gs-tools-cache-clear|gs-tools-performance-reset)
            # 系统级操作需要额外检查
            return 0
            ;;
    esac
    
    return 0
}

# 依赖检查
_gs_command_check_dependencies() {
    local command_name="$1"
    
    # 检查命令特定依赖
    case "$command_name" in
        gs-android-*)
            command -v adb >/dev/null 2>&1 || return 1
            ;;
        gs-git-*)
            command -v git >/dev/null 2>&1 || return 1
            ;;
        gs-config-validate|gs-config-set)
            # 需要Python环境或jq
            gs_python_available || command -v jq >/dev/null 2>&1 || return 1
            ;;
    esac
    
    return 0
}

# 清理资源
_gs_command_cleanup_resources() {
    local command_name="$1"
    
    # 清理临时文件
    if [[ -n "${_GS_COMMAND_TEMP_FILES:-}" ]]; then
        for temp_file in $_GS_COMMAND_TEMP_FILES; do
            [[ -f "$temp_file" ]] && rm -f "$temp_file"
        done
        unset _GS_COMMAND_TEMP_FILES
    fi
    
    gs_log_debug "资源清理完成: $command_name"
}

# ===================================
# 参数解析和验证系统
# ===================================

# 通用参数解析器
gs_parse_arguments() {
    local -n parsed_args_ref="$1"
    shift
    local raw_args=("$@")
    
    # 初始化解析结果
    parsed_args_ref=(
        ["command"]=""
        ["verbose"]="false"
        ["quiet"]="false"
        ["help"]="false"
        ["json"]="false"
        ["format"]="text"
        ["config"]=""
        ["no_color"]="false"
        ["debug"]="false"
    )
    
    local positional_args=()
    local i=0
    
    while [[ $i -lt ${#raw_args[@]} ]]; do
        local arg="${raw_args[$i]}"
        
        case "$arg" in
            -h|--help)
                parsed_args_ref["help"]="true"
                ;;
            -v|--verbose)
                parsed_args_ref["verbose"]="true"
                ;;
            -q|--quiet)
                parsed_args_ref["quiet"]="true"
                ;;
            --json)
                parsed_args_ref["json"]="true"
                parsed_args_ref["format"]="json"
                ;;
            --format)
                if [[ $((i + 1)) -lt ${#raw_args[@]} ]]; then
                    parsed_args_ref["format"]="${raw_args[$((i + 1))]}"
                    ((i++))
                else
                    gs_error "--format 需要指定格式参数"
                    return $_GS_ERROR_PARAMETER
                fi
                ;;
            --config)
                if [[ $((i + 1)) -lt ${#raw_args[@]} ]]; then
                    parsed_args_ref["config"]="${raw_args[$((i + 1))]}"
                    ((i++))
                else
                    gs_error "--config 需要指定配置文件路径"
                    return $_GS_ERROR_PARAMETER
                fi
                ;;
            --no-color)
                parsed_args_ref["no_color"]="true"
                ;;
            --debug)
                parsed_args_ref["debug"]="true"
                ;;
            --)
                # 后续参数作为位置参数处理
                ((i++))
                while [[ $i -lt ${#raw_args[@]} ]]; do
                    positional_args+=("${raw_args[$i]}")
                    ((i++))
                done
                break
                ;;
            -*)
                gs_error "未知选项: $arg"
                return $_GS_ERROR_PARAMETER
                ;;
            *)
                positional_args+=("$arg")
                ;;
        esac
        ((i++))
    done
    
    # 保存位置参数
    parsed_args_ref["positional"]="${positional_args[*]}"
    
    # 参数验证
    if ! _gs_validate_parsed_arguments parsed_args_ref; then
        return $_GS_ERROR_PARAMETER
    fi
    
    gs_log_debug "参数解析完成: ${#positional_args[@]} 个位置参数"
    return 0
}

# 验证解析后的参数
_gs_validate_parsed_arguments() {
    local -n args_ref="$1"
    
    # 检查格式参数
    case "${args_ref["format"]}" in
        text|json|table|yaml|csv)
            ;;
        *)
            gs_error "不支持的输出格式: ${args_ref["format"]}"
            return $_GS_ERROR_PARAMETER
            ;;
    esac
    
    # 检查配置文件路径
    if [[ -n "${args_ref["config"]}" ]] && [[ ! -f "${args_ref["config"]}" ]]; then
        gs_error_file_not_found "配置文件不存在: ${args_ref["config"]}"
        return $_GS_ERROR_FILE_NOT_FOUND
    fi
    
    # 互斥参数检查
    if [[ "${args_ref["verbose"]}" == "true" && "${args_ref["quiet"]}" == "true" ]]; then
        gs_error "--verbose 和 --quiet 不能同时使用"
        return $_GS_ERROR_PARAMETER
    fi
    
    return 0
}

# 特定命令参数验证
gs_validate_command_arguments() {
    local command_name="$1"
    local -n args_ref="$2"
    
    case "$command_name" in
        gs-config-get)
            _gs_validate_config_get_args args_ref
            ;;
        gs-config-set)
            _gs_validate_config_set_args args_ref
            ;;
        gs-plugins-enable|gs-plugins-disable)
            _gs_validate_plugins_args args_ref
            ;;
        *)
            # 默认验证通过
            return 0
            ;;
    esac
}

# 配置获取命令参数验证
_gs_validate_config_get_args() {
    local -n args_ref="$1"
    local positional=(${args_ref["positional"]})
    
    if [[ ${#positional[@]} -eq 0 ]]; then
        gs_error "gs-config-get 需要指定配置键"
        return $_GS_ERROR_PARAMETER
    fi
    
    # 验证配置键格式
    local key="${positional[0]}"
    if [[ ! "$key" =~ ^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)*$ ]]; then
        gs_error "无效的配置键格式: $key"
        return $_GS_ERROR_PARAMETER
    fi
    
    return 0
}

# 配置设置命令参数验证
_gs_validate_config_set_args() {
    local -n args_ref="$1"
    local positional=(${args_ref["positional"]})
    
    if [[ ${#positional[@]} -lt 2 ]]; then
        gs_error "gs-config-set 需要指定配置键和值"
        return $_GS_ERROR_PARAMETER
    fi
    
    # 验证配置键格式
    local key="${positional[0]}"
    if [[ ! "$key" =~ ^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)*$ ]]; then
        gs_error "无效的配置键格式: $key"
        return $_GS_ERROR_PARAMETER
    fi
    
    return 0
}

# 插件命令参数验证
_gs_validate_plugins_args() {
    local -n args_ref="$1"
    local positional=(${args_ref["positional"]})
    
    if [[ ${#positional[@]} -eq 0 ]]; then
        gs_error "需要指定插件名称"
        return $_GS_ERROR_PARAMETER
    fi
    
    return 0
}

# ===================================
# 结果格式化输出系统
# ===================================

# 通用结果格式化输出
gs_format_output() {
    local format="$1"
    local data="$2"
    local title="${3:-}"
    
    case "$format" in
        json)
            _gs_format_json "$data" "$title"
            ;;
        table)
            _gs_format_table "$data" "$title"
            ;;
        yaml)
            _gs_format_yaml "$data" "$title"
            ;;
        csv)
            _gs_format_csv "$data" "$title"
            ;;
        text|*)
            _gs_format_text "$data" "$title"
            ;;
    esac
}

# JSON格式输出
_gs_format_json() {
    local data="$1"
    local title="$2"
    
    # 检查数据是否已经是JSON格式
    if echo "$data" | jq . >/dev/null 2>&1; then
        echo "$data" | jq .
    else
        # 将普通文本转换为JSON
        local json_data
        if gs_python_available; then
            json_data=$(gs_python_call json_format_text "$data" "$title")
        else
            # 简单的JSON包装
            printf '{"title": "%s", "content": "%s", "timestamp": "%s"}\n' \
                "$title" "$(echo "$data" | sed 's/"/\\"/g')" "$(date -Iseconds)"
        fi
        echo "$json_data" | jq .
    fi
}

# 表格格式输出
_gs_format_table() {
    local data="$1"
    local title="$2"
    
    if [[ -n "$title" ]]; then
        echo "=== $title ==="
        echo
    fi
    
    # 如果数据是JSON，尝试转换为表格
    if echo "$data" | jq . >/dev/null 2>&1; then
        if gs_python_available; then
            gs_python_call json_to_table "$data"
        else
            # 简单的键值对显示
            echo "$data" | jq -r 'to_entries[] | "\(.key): \(.value)"'
        fi
    else
        echo "$data"
    fi
}

# YAML格式输出
_gs_format_yaml() {
    local data="$1"
    local title="$2"
    
    if [[ -n "$title" ]]; then
        echo "# $title"
        echo
    fi
    
    # 如果数据是JSON，转换为YAML
    if echo "$data" | jq . >/dev/null 2>&1; then
        if command -v yq >/dev/null 2>&1; then
            echo "$data" | yq eval -P
        elif gs_python_available; then
            gs_python_call json_to_yaml "$data"
        else
            # 简单的键值对显示
            echo "$data" | jq -r 'to_entries[] | "\(.key): \(.value)"'
        fi
    else
        echo "$data"
    fi
}

# CSV格式输出
_gs_format_csv() {
    local data="$1"
    local title="$2"
    
    # 如果数据是JSON数组，转换为CSV
    if echo "$data" | jq . >/dev/null 2>&1; then
        if gs_python_available; then
            gs_python_call json_to_csv "$data"
        else
            # 简单的CSV输出
            echo "key,value"
            echo "$data" | jq -r 'to_entries[] | "\(.key),\(.value)"'
        fi
    else
        echo "$data"
    fi
}

# 文本格式输出
_gs_format_text() {
    local data="$1"
    local title="$2"
    
    if [[ -n "$title" ]]; then
        echo "=== $title ==="
        echo
    fi
    
    echo "$data"
}

# 成功消息格式化
gs_format_success() {
    local message="$1"
    local format="${2:-text}"
    
    case "$format" in
        json)
            printf '{"status": "success", "message": "%s", "timestamp": "%s"}\n' \
                "$message" "$(date -Iseconds)"
            ;;
        *)
            gs_color_green "✓ $message"
            ;;
    esac
}

# 错误消息格式化
gs_format_error() {
    local message="$1"
    local format="${2:-text}"
    local error_code="${3:-1}"
    
    case "$format" in
        json)
            printf '{"status": "error", "message": "%s", "error_code": %d, "timestamp": "%s"}\n' \
                "$message" "$error_code" "$(date -Iseconds)"
            ;;
        *)
            gs_color_red "✗ $message" >&2
            ;;
    esac
}

# 警告消息格式化
gs_format_warning() {
    local message="$1"
    local format="${2:-text}"
    
    case "$format" in
        json)
            printf '{"status": "warning", "message": "%s", "timestamp": "%s"}\n' \
                "$message" "$(date -Iseconds)"
            ;;
        *)
            gs_color_yellow "⚠ $message"
            ;;
    esac
}

# ===================================
# 命令别名系统
# ===================================

# 注册命令别名
gs_register_command_alias() {
    local alias_name="$1"
    local command_name="$2"
    
    gs_check_not_empty "$alias_name" "别名名称"
    gs_check_not_empty "$command_name" "命令名称"
    
    # 检查目标命令是否存在
    if ! gs_registry_has_command "$command_name"; then
        gs_error "目标命令不存在: $command_name"
        return $_GS_ERROR_PARAMETER
    fi
    
    # 注册别名
    gs_registry_set_alias "$alias_name" "$command_name"
    gs_log_debug "注册命令别名: $alias_name -> $command_name"
    
    return 0
}

# 解析命令别名
gs_resolve_command_alias() {
    local command_name="$1"
    
    # 检查是否为别名
    if gs_registry_has_alias "$command_name"; then
        local resolved_command
        resolved_command=$(gs_registry_get_alias "$command_name")
        echo "$resolved_command"
        return 0
    fi
    
    # 不是别名，返回原命令名
    echo "$command_name"
    return 0
}

# ===================================
# 命令生命周期钩子
# ===================================

# 执行命令前钩子
gs_execute_before_hooks() {
    local command_name="$1"
    shift
    local args=("$@")
    
    # 全局前置钩子
    if declare -F "gs_hook_before_all_commands" >/dev/null 2>&1; then
        gs_hook_before_all_commands "$command_name" "${args[@]}"
    fi
    
    # 命令特定前置钩子
    local hook_function="gs_hook_before_$command_name"
    hook_function="${hook_function//-/_}"
    
    if declare -F "$hook_function" >/dev/null 2>&1; then
        "$hook_function" "${args[@]}"
    fi
}

# 执行命令后钩子
gs_execute_after_hooks() {
    local command_name="$1"
    local exit_code="$2"
    shift 2
    local args=("$@")
    
    # 命令特定后置钩子
    local hook_function="gs_hook_after_$command_name"
    hook_function="${hook_function//-/_}"
    
    if declare -F "$hook_function" >/dev/null 2>&1; then
        "$hook_function" "$exit_code" "${args[@]}"
    fi
    
    # 全局后置钩子
    if declare -F "gs_hook_after_all_commands" >/dev/null 2>&1; then
        gs_hook_after_all_commands "$command_name" "$exit_code" "${args[@]}"
    fi
}

# ===================================
# 自测代码
# ===================================

# 仅在非测试模式下执行自测
if [[ "${_GS_TEST_MODE:-}" != 1 ]]; then
    gs_log_debug "命令处理API模块加载完成"
fi