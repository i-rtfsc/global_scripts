#!/bin/bash
# Global Scripts V3 - 错误处理框架
# 作者: Solo
# 版本: 1.0.0
# 描述: 统一错误处理，错误码定义，错误恢复建议

# 加载兼容性支持和日志系统
source "$(dirname "${BASH_SOURCE[0]:-$0}")/declare_compat.sh"
source "$(dirname "${BASH_SOURCE[0]:-$0}")/logger.sh"

# 错误码定义
readonly _GS_ERROR_SUCCESS=0           # 成功
readonly _GS_ERROR_GENERIC=1           # 通用错误
readonly _GS_ERROR_INVALID_ARG=2       # 无效参数
readonly _GS_ERROR_FILE_NOT_FOUND=3    # 文件未找到
readonly _GS_ERROR_PERMISSION=4        # 权限错误
readonly _GS_ERROR_NETWORK=5           # 网络错误
readonly _GS_ERROR_CONFIG=6            # 配置错误
readonly _GS_ERROR_DEPENDENCY=7        # 依赖错误
readonly _GS_ERROR_TIMEOUT=8           # 超时错误
readonly _GS_ERROR_DISK_SPACE=9        # 磁盘空间不足
readonly _GS_ERROR_MEMORY=10           # 内存不足
readonly _GS_ERROR_PLUGIN=11           # 插件错误
readonly _GS_ERROR_COMMAND_NOT_FOUND=12 # 命令未找到
readonly _GS_ERROR_UNSUPPORTED=13      # 不支持的操作
readonly _GS_ERROR_INTERRUPTED=14      # 操作中断
readonly _GS_ERROR_VALIDATION=15       # 验证失败

# 错误消息映射
gs_declare_A _GS_ERROR_MESSAGES
gs_array_set _GS_ERROR_MESSAGES "$_GS_ERROR_SUCCESS" "操作成功"
gs_array_set _GS_ERROR_MESSAGES "$_GS_ERROR_GENERIC" "通用错误"
gs_array_set _GS_ERROR_MESSAGES "$_GS_ERROR_INVALID_ARG" "无效参数"
gs_array_set _GS_ERROR_MESSAGES "$_GS_ERROR_FILE_NOT_FOUND" "文件未找到"
gs_array_set _GS_ERROR_MESSAGES "$_GS_ERROR_PERMISSION" "权限不足"
gs_array_set _GS_ERROR_MESSAGES "$_GS_ERROR_NETWORK" "网络连接错误"
gs_array_set _GS_ERROR_MESSAGES "$_GS_ERROR_CONFIG" "配置错误"
gs_array_set _GS_ERROR_MESSAGES "$_GS_ERROR_DEPENDENCY" "依赖错误"
gs_array_set _GS_ERROR_MESSAGES "$_GS_ERROR_TIMEOUT" "操作超时"
gs_array_set _GS_ERROR_MESSAGES "$_GS_ERROR_DISK_SPACE" "磁盘空间不足"
gs_array_set _GS_ERROR_MESSAGES "$_GS_ERROR_MEMORY" "内存不足"
gs_array_set _GS_ERROR_MESSAGES "$_GS_ERROR_PLUGIN" "插件错误"
gs_array_set _GS_ERROR_MESSAGES "$_GS_ERROR_COMMAND_NOT_FOUND" "命令未找到"
gs_array_set _GS_ERROR_MESSAGES "$_GS_ERROR_UNSUPPORTED" "不支持的操作"
gs_array_set _GS_ERROR_MESSAGES "$_GS_ERROR_INTERRUPTED" "操作被中断"
gs_array_set _GS_ERROR_MESSAGES "$_GS_ERROR_VALIDATION" "验证失败"

# 错误恢复建议映射
gs_declare_A _GS_ERROR_SUGGESTIONS
gs_array_set _GS_ERROR_SUGGESTIONS "$_GS_ERROR_INVALID_ARG" "请检查命令参数格式和值"
gs_array_set _GS_ERROR_SUGGESTIONS "$_GS_ERROR_FILE_NOT_FOUND" "请确认文件路径是否正确，文件是否存在"
gs_array_set _GS_ERROR_SUGGESTIONS "$_GS_ERROR_PERMISSION" "请检查文件权限或使用sudo运行"
gs_array_set _GS_ERROR_SUGGESTIONS "$_GS_ERROR_NETWORK" "请检查网络连接和防火墙设置"
gs_array_set _GS_ERROR_SUGGESTIONS "$_GS_ERROR_CONFIG" "请检查配置文件语法和值的正确性"
gs_array_set _GS_ERROR_SUGGESTIONS "$_GS_ERROR_DEPENDENCY" "请安装缺失的依赖包"
gs_array_set _GS_ERROR_SUGGESTIONS "$_GS_ERROR_TIMEOUT" "请重试或增加超时时间"
gs_array_set _GS_ERROR_SUGGESTIONS "$_GS_ERROR_DISK_SPACE" "请清理磁盘空间"
gs_array_set _GS_ERROR_SUGGESTIONS "$_GS_ERROR_MEMORY" "请关闭其他程序释放内存"
gs_array_set _GS_ERROR_SUGGESTIONS "$_GS_ERROR_PLUGIN" "请检查插件配置和依赖"
gs_array_set _GS_ERROR_SUGGESTIONS "$_GS_ERROR_COMMAND_NOT_FOUND" "请安装相关命令或检查PATH环境变量"
gs_array_set _GS_ERROR_SUGGESTIONS "$_GS_ERROR_UNSUPPORTED" "请检查系统兼容性或更新版本"
gs_array_set _GS_ERROR_SUGGESTIONS "$_GS_ERROR_INTERRUPTED" "操作已中断，可以重新运行"
gs_array_set _GS_ERROR_SUGGESTIONS "$_GS_ERROR_VALIDATION" "请检查输入数据格式和完整性"

# 全局错误处理配置
_GS_ERROR_EXIT_ON_ERROR="${_GS_ERROR_EXIT_ON_ERROR:-true}"
_GS_ERROR_SHOW_STACK="${_GS_ERROR_SHOW_STACK:-false}"
_GS_ERROR_LOG_ERRORS="${_GS_ERROR_LOG_ERRORS:-true}"

# 导出配置变量
export _GS_ERROR_EXIT_ON_ERROR _GS_ERROR_SHOW_STACK _GS_ERROR_LOG_ERRORS

# 获取错误消息
gs_error_get_message() {
    local error_code="$1"
    local message
    message="$(gs_array_get _GS_ERROR_MESSAGES "$error_code")"
    echo "${message:-未知错误}"
}

# 获取错误建议
gs_error_get_suggestion() {
    local error_code="$1"
    local suggestion
    suggestion="$(gs_array_get _GS_ERROR_SUGGESTIONS "$error_code")"
    echo "${suggestion:-请联系技术支持}"
}

# 获取调用栈信息
_gs_error_get_stack() {
    local skip="${1:-1}"
    local i
    for ((i = skip; i < ${#BASH_SOURCE[@]}; i++)); do
        local file="${BASH_SOURCE[i]:-unknown}"
        local line="${BASH_LINENO[i-1]:-0}"
        local func="${FUNCNAME[i]:-main}"
        printf "  at %s() (%s:%d)\\n" "$func" "$file" "$line"
    done
}

# 核心错误处理函数
gs_error() {
    local error_code="${1:-$_GS_ERROR_GENERIC}"
    local error_message="${2:-}"
    local caller_info="${3:-}"
    
    # 获取标准错误消息
    local std_message
    std_message="$(gs_error_get_message "$error_code")"
    
    # 组合完整错误消息
    local full_message="$std_message"
    if [[ -n "$error_message" ]]; then
        full_message="$std_message: $error_message"
    fi
    
    # 记录错误日志
    if [[ "$_GS_ERROR_LOG_ERRORS" == "true" ]]; then
        gs_log_error "Error[$error_code] $full_message"
    fi
    
    # 输出错误信息
    printf "❌ 错误 [%d]: %s\\n" "$error_code" "$full_message" >&2
    
    # 显示恢复建议
    local suggestion
    suggestion="$(gs_error_get_suggestion "$error_code")"
    printf "💡 建议: %s\\n" "$suggestion" >&2
    
    # 显示调用栈
    if [[ "$_GS_ERROR_SHOW_STACK" == "true" ]]; then
        printf "📍 调用栈:\\n" >&2
        _gs_error_get_stack 2 >&2
    fi
    
    # 是否退出程序
    if [[ "$_GS_ERROR_EXIT_ON_ERROR" == "true" ]]; then
        exit "$error_code"
    fi
    
    return "$error_code"
}

# 特定错误类型的便捷函数
gs_error_invalid_arg() {
    gs_error "$_GS_ERROR_INVALID_ARG" "$*"
}

gs_error_file_not_found() {
    gs_error "$_GS_ERROR_FILE_NOT_FOUND" "$*"
}

gs_error_permission() {
    gs_error "$_GS_ERROR_PERMISSION" "$*"
}

gs_error_network() {
    gs_error "$_GS_ERROR_NETWORK" "$*"
}

gs_error_config() {
    gs_error "$_GS_ERROR_CONFIG" "$*"
}

gs_error_dependency() {
    gs_error "$_GS_ERROR_DEPENDENCY" "$*"
}

gs_error_timeout() {
    gs_error "$_GS_ERROR_TIMEOUT" "$*"
}

gs_error_disk_space() {
    gs_error "$_GS_ERROR_DISK_SPACE" "$*"
}

gs_error_memory() {
    gs_error "$_GS_ERROR_MEMORY" "$*"
}

gs_error_plugin() {
    gs_error "$_GS_ERROR_PLUGIN" "$*"
}

gs_error_command_not_found() {
    gs_error "$_GS_ERROR_COMMAND_NOT_FOUND" "$*"
}

gs_error_unsupported() {
    gs_error "$_GS_ERROR_UNSUPPORTED" "$*"
}

gs_error_interrupted() {
    gs_error "$_GS_ERROR_INTERRUPTED" "$*"
}

gs_error_validation() {
    gs_error "$_GS_ERROR_VALIDATION" "$*"
}

# 条件错误检查函数
gs_check_file_exists() {
    local file="$1"
    local message="${2:-文件不存在: $file}"
    [[ -f "$file" ]] || gs_error_file_not_found "$message"
}

gs_check_dir_exists() {
    local dir="$1"
    local message="${2:-目录不存在: $dir}"
    [[ -d "$dir" ]] || gs_error_file_not_found "$message"
}

gs_check_command_exists() {
    local cmd="$1"
    local message="${2:-命令不存在: $cmd}"
    command -v "$cmd" >/dev/null 2>&1 || gs_error_command_not_found "$message"
}

gs_check_not_empty() {
    local value="$1"
    local name="${2:-参数}"
    [[ -n "$value" ]] || gs_error_invalid_arg "$name 不能为空"
}

gs_check_numeric() {
    local value="$1"
    local name="${2:-参数}"
    [[ "$value" =~ ^[0-9]+$ ]] || gs_error_invalid_arg "$name 必须是数字: $value"
}

gs_check_permission() {
    local file="$1"
    local perm="${2:-r}"
    local message="${3:-权限不足: $file}"
    
    case "$perm" in
        r) [[ -r "$file" ]] || gs_error_permission "$message" ;;
        w) [[ -w "$file" ]] || gs_error_permission "$message" ;;
        x) [[ -x "$file" ]] || gs_error_permission "$message" ;;
        *) gs_error_invalid_arg "未知权限类型: $perm" ;;
    esac
}

# 错误配置管理函数
gs_error_set_exit_on_error() {
    _GS_ERROR_EXIT_ON_ERROR="${1:-true}"
    export _GS_ERROR_EXIT_ON_ERROR
}

gs_error_set_show_stack() {
    _GS_ERROR_SHOW_STACK="${1:-true}"
    export _GS_ERROR_SHOW_STACK
}

gs_error_set_log_errors() {
    _GS_ERROR_LOG_ERRORS="${1:-true}"
    export _GS_ERROR_LOG_ERRORS
}

# 错误状态查询
gs_error_get_config() {
    printf "Exit on Error: %s\\n" "$_GS_ERROR_EXIT_ON_ERROR"
    printf "Show Stack: %s\\n" "$_GS_ERROR_SHOW_STACK"
    printf "Log Errors: %s\\n" "$_GS_ERROR_LOG_ERRORS"
}

# 安全执行函数
gs_safe_exec() {
    local cmd="$*"
    local output
    local exit_code
    
    gs_log_debug "执行命令: $cmd"
    
    # 执行命令并捕获输出
    if output=$(eval "$cmd" 2>&1); then
        exit_code=0
        gs_log_debug "命令执行成功"
        echo "$output"
    else
        exit_code=$?
        gs_log_error "命令执行失败: $cmd"
        gs_log_error "错误输出: $output"
        gs_error "$_GS_ERROR_GENERIC" "命令执行失败: $cmd"
        return $exit_code
    fi
    
    return $exit_code
}

# Try-catch 模拟
gs_try() {
    local exit_on_error_backup="$_GS_ERROR_EXIT_ON_ERROR"
    gs_error_set_exit_on_error false
    
    "$@"
    local result=$?
    
    gs_error_set_exit_on_error "$exit_on_error_backup"
    return $result
}

# 错误码列表
gs_error_list_codes() {
    printf "错误码列表:\\n"
    printf "%-3s %-25s %s\\n" "码" "名称" "描述"
    printf "%-3s %-25s %s\\n" "---" "-------------------------" "-------------------------"
    printf "%-3d %-25s %s\\n" "$_GS_ERROR_SUCCESS" "SUCCESS" "$(gs_error_get_message $_GS_ERROR_SUCCESS)"
    printf "%-3d %-25s %s\\n" "$_GS_ERROR_GENERIC" "GENERIC" "$(gs_error_get_message $_GS_ERROR_GENERIC)"
    printf "%-3d %-25s %s\\n" "$_GS_ERROR_INVALID_ARG" "INVALID_ARG" "$(gs_error_get_message $_GS_ERROR_INVALID_ARG)"
    printf "%-3d %-25s %s\\n" "$_GS_ERROR_FILE_NOT_FOUND" "FILE_NOT_FOUND" "$(gs_error_get_message $_GS_ERROR_FILE_NOT_FOUND)"
    printf "%-3d %-25s %s\\n" "$_GS_ERROR_PERMISSION" "PERMISSION" "$(gs_error_get_message $_GS_ERROR_PERMISSION)"
    printf "%-3d %-25s %s\\n" "$_GS_ERROR_NETWORK" "NETWORK" "$(gs_error_get_message $_GS_ERROR_NETWORK)"
    printf "%-3d %-25s %s\\n" "$_GS_ERROR_CONFIG" "CONFIG" "$(gs_error_get_message $_GS_ERROR_CONFIG)"
    printf "%-3d %-25s %s\\n" "$_GS_ERROR_DEPENDENCY" "DEPENDENCY" "$(gs_error_get_message $_GS_ERROR_DEPENDENCY)"
    printf "%-3d %-25s %s\\n" "$_GS_ERROR_TIMEOUT" "TIMEOUT" "$(gs_error_get_message $_GS_ERROR_TIMEOUT)"
    printf "%-3d %-25s %s\\n" "$_GS_ERROR_DISK_SPACE" "DISK_SPACE" "$(gs_error_get_message $_GS_ERROR_DISK_SPACE)"
    printf "%-3d %-25s %s\\n" "$_GS_ERROR_MEMORY" "MEMORY" "$(gs_error_get_message $_GS_ERROR_MEMORY)"
    printf "%-3d %-25s %s\\n" "$_GS_ERROR_PLUGIN" "PLUGIN" "$(gs_error_get_message $_GS_ERROR_PLUGIN)"
    printf "%-3d %-25s %s\\n" "$_GS_ERROR_COMMAND_NOT_FOUND" "COMMAND_NOT_FOUND" "$(gs_error_get_message $_GS_ERROR_COMMAND_NOT_FOUND)"
    printf "%-3d %-25s %s\\n" "$_GS_ERROR_UNSUPPORTED" "UNSUPPORTED" "$(gs_error_get_message $_GS_ERROR_UNSUPPORTED)"
    printf "%-3d %-25s %s\\n" "$_GS_ERROR_INTERRUPTED" "INTERRUPTED" "$(gs_error_get_message $_GS_ERROR_INTERRUPTED)"
    printf "%-3d %-25s %s\\n" "$_GS_ERROR_VALIDATION" "VALIDATION" "$(gs_error_get_message $_GS_ERROR_VALIDATION)"
}

# 如果直接执行此脚本，运行测试
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
    echo "=== Global Scripts Error Handler Test ==="
    
    # 配置测试环境
    gs_error_set_exit_on_error false
    gs_error_set_show_stack true
    
    echo
    echo "1. 测试错误码列表:"
    gs_error_list_codes
    
    echo
    echo "2. 测试基本错误处理:"
    gs_error_invalid_arg "这是一个无效参数测试"
    
    echo
    echo "3. 测试文件检查:"
    gs_try gs_check_file_exists "/nonexistent/file" || echo "文件检查测试通过"
    
    echo
    echo "4. 测试命令检查:"
    gs_try gs_check_command_exists "nonexistent_command_xyz" || echo "命令检查测试通过"
    
    echo
    echo "5. 测试安全执行:"
    gs_try gs_safe_exec "echo '安全执行测试成功'" || echo "安全执行测试失败"
    
    echo
    echo "6. 错误配置状态:"
    gs_error_get_config
    
    echo
    echo "✓ Error handler test completed"
fi