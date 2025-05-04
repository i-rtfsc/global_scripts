#!/bin/bash
# Global Scripts V3 - 多级日志系统
# 作者: Solo
# 版本: 1.0.0
# 描述: 支持多级别日志输出，彩色终端显示，文件记录

# 加载兼容性支持
source "$(dirname "${BASH_SOURCE[0]:-$0}")/time_compat.sh"

# 日志级别定义
if [[ -z "${LOG_LEVEL_DEBUG:-}" ]]; then
    readonly LOG_LEVEL_DEBUG=0
    readonly LOG_LEVEL_INFO=1
    readonly LOG_LEVEL_WARN=2
    readonly LOG_LEVEL_ERROR=3
    readonly LOG_LEVEL_FATAL=4
fi

# 获取日志级别名称 - 简化实现避免关联数组问题
_gs_log_get_level_name() {
    local level="$1"
    case "$level" in
        0) echo "DEBUG" ;;
        1) echo "INFO" ;;
        2) echo "WARN" ;;
        3) echo "ERROR" ;;
        4) echo "FATAL" ;;
        *) echo "UNKNOWN" ;;
    esac
}

# 获取日志级别颜色 - 简化实现避免关联数组问题  
_gs_log_get_level_color() {
    local level="$1"
    case "$level" in
        0) echo "$COLOR_DEBUG" ;;
        1) echo "$COLOR_INFO" ;;
        2) echo "$COLOR_WARN" ;;
        3) echo "$COLOR_ERROR" ;;
        4) echo "$COLOR_FATAL" ;;
        *) echo "" ;;
    esac
}

# 颜色定义
if [[ -z "${COLOR_DEBUG:-}" ]]; then
    readonly COLOR_DEBUG='\033[0;36m'    # 青色
    readonly COLOR_INFO='\033[0;32m'     # 绿色
    readonly COLOR_WARN='\033[1;33m'     # 黄色
    readonly COLOR_ERROR='\033[0;31m'    # 红色
    readonly COLOR_FATAL='\033[1;31m'    # 亮红色
    readonly COLOR_RESET='\033[0m'       # 重置
fi


# 全局配置变量
_GS_LOG_LEVEL="${_GS_LOG_LEVEL:-$LOG_LEVEL_INFO}"
_GS_LOG_FILE="${_GS_LOG_FILE:-${_GS_LOG_DIR:-${HOME}/.local/share/global_scripts/logs}/gs.log}"
_GS_LOG_ENABLE_COLOR="${_GS_LOG_ENABLE_COLOR:-true}"
_GS_LOG_ENABLE_FILE="${_GS_LOG_ENABLE_FILE:-true}"
_GS_LOG_MAX_FILE_SIZE="${_GS_LOG_MAX_FILE_SIZE:-10485760}"  # 10MB
_GS_LOG_MAX_FILES="${_GS_LOG_MAX_FILES:-5}"

# 导出配置变量
export _GS_LOG_LEVEL _GS_LOG_FILE _GS_LOG_ENABLE_COLOR _GS_LOG_ENABLE_FILE
export _GS_LOG_MAX_FILE_SIZE _GS_LOG_MAX_FILES

# 确保日志目录存在
_gs_log_ensure_dir() {
    local log_dir
    log_dir="$(dirname "$_GS_LOG_FILE")"
    [[ -d "$log_dir" ]] || mkdir -p "$log_dir"
}

# 日志文件轮转
_gs_log_rotate() {
    local log_file="$1"
    
    # 检查文件大小
    if [[ -f "$log_file" ]] && [[ $(stat -f%z "$log_file" 2>/dev/null || stat -c%s "$log_file" 2>/dev/null) -gt $_GS_LOG_MAX_FILE_SIZE ]]; then
        # 轮转日志文件
        for ((i = _GS_LOG_MAX_FILES - 1; i >= 1; i--)); do
            local old_file="${log_file}.${i}"
            local new_file="${log_file}.$((i + 1))"
            [[ -f "$old_file" ]] && mv "$old_file" "$new_file"
        done
        [[ -f "$log_file" ]] && mv "$log_file" "${log_file}.1"
    fi
}

# 格式化时间戳
_gs_log_timestamp() {
    date "+%Y-%m-%d %H:%M:%S"
}

# 获取调用者信息
_gs_log_caller() {
    local caller_info="${BASH_SOURCE[3]:-unknown}:${BASH_LINENO[2]:-0}"
    local function_name="${FUNCNAME[3]:-main}"
    echo "${caller_info}:${function_name}"
}

# 核心日志函数
_gs_log() {
    local level="$1"
    local message="$2"
    local caller_info="${3:-$(_gs_log_caller)}"
    
    # 检查日志级别
    [[ $level -lt $_GS_LOG_LEVEL ]] && return 0
    
    local level_name
    level_name="$(_gs_log_get_level_name "$level")"
    
    local timestamp
    timestamp="$(_gs_log_timestamp)"
    
    local log_entry="[$timestamp] [$level_name] [$caller_info] $message"
    
    # 终端输出
    if [[ -t 2 ]] && [[ "$_GS_LOG_ENABLE_COLOR" == "true" ]]; then
        local color
        color="$(_gs_log_get_level_color "$level")"
        printf "${color}%s${COLOR_RESET}\n" "$log_entry" >&2
    else
        printf "%s\n" "$log_entry" >&2
    fi
    
    # 文件输出
    if [[ "$_GS_LOG_ENABLE_FILE" == "true" ]]; then
        _gs_log_ensure_dir
        _gs_log_rotate "$_GS_LOG_FILE"
        printf "%s\n" "$log_entry" >> "$_GS_LOG_FILE"
    fi
    
    # FATAL级别退出程序
    if [[ $level -eq $LOG_LEVEL_FATAL ]]; then
        exit 1
    fi
}

# 公共日志接口函数
gs_log_debug() {
    _gs_log "$LOG_LEVEL_DEBUG" "$*"
}

gs_log_info() {
    _gs_log "$LOG_LEVEL_INFO" "$*"
}

gs_log_warn() {
    _gs_log "$LOG_LEVEL_WARN" "$*"
}

gs_log_error() {
    _gs_log "$LOG_LEVEL_ERROR" "$*"
}

gs_log_fatal() {
    _gs_log "$LOG_LEVEL_FATAL" "$*"
}

# 简化别名
gs_log() {
    local level="$1"
    shift
    case "$level" in
        DEBUG|debug|0) gs_log_debug "$@" ;;
        INFO|info|1) gs_log_info "$@" ;;
        WARN|warn|2) gs_log_warn "$@" ;;
        ERROR|error|3) gs_log_error "$@" ;;
        FATAL|fatal|4) gs_log_fatal "$@" ;;
        *) gs_log_error "Unknown log level: $level" ;;
    esac
}

# 配置管理函数
gs_log_set_level() {
    local level="$1"
    case "$level" in
        DEBUG|debug|0) _GS_LOG_LEVEL=$LOG_LEVEL_DEBUG ;;
        INFO|info|1) _GS_LOG_LEVEL=$LOG_LEVEL_INFO ;;
        WARN|warn|2) _GS_LOG_LEVEL=$LOG_LEVEL_WARN ;;
        ERROR|error|3) _GS_LOG_LEVEL=$LOG_LEVEL_ERROR ;;
        FATAL|fatal|4) _GS_LOG_LEVEL=$LOG_LEVEL_FATAL ;;
        *) gs_log_error "Invalid log level: $level"; return 1 ;;
    esac
    export _GS_LOG_LEVEL
}

gs_log_set_file() {
    _GS_LOG_FILE="$1"
    export _GS_LOG_FILE
}

gs_log_enable_color() {
    _GS_LOG_ENABLE_COLOR="${1:-true}"
    export _GS_LOG_ENABLE_COLOR
}

gs_log_enable_file() {
    _GS_LOG_ENABLE_FILE="${1:-true}"
    export _GS_LOG_ENABLE_FILE
}

# 日志状态查询
gs_log_get_level() {
    case "$_GS_LOG_LEVEL" in
        "$LOG_LEVEL_DEBUG") echo "DEBUG" ;;
        "$LOG_LEVEL_INFO") echo "INFO" ;;
        "$LOG_LEVEL_WARN") echo "WARN" ;;
        "$LOG_LEVEL_ERROR") echo "ERROR" ;;
        "$LOG_LEVEL_FATAL") echo "FATAL" ;;
        *) echo "UNKNOWN" ;;
    esac
}

gs_log_get_file() {
    echo "$_GS_LOG_FILE"
}

gs_log_status() {
    printf "Log Level: %s (%d)\n" "$(gs_log_get_level)" "$_GS_LOG_LEVEL"
    printf "Log File: %s\n" "$_GS_LOG_FILE"
    printf "Color Enabled: %s\n" "$_GS_LOG_ENABLE_COLOR"
    printf "File Logging: %s\n" "$_GS_LOG_ENABLE_FILE"
    if [[ -f "$_GS_LOG_FILE" ]]; then
        printf "Log File Size: %s bytes\n" "$(stat -f%z "$_GS_LOG_FILE" 2>/dev/null || stat -c%s "$_GS_LOG_FILE" 2>/dev/null || echo "unknown")"
    fi
}

# 清理日志文件
gs_log_clear() {
    if [[ -f "$_GS_LOG_FILE" ]]; then
        > "$_GS_LOG_FILE"
        # 注意：不要在清理后立即写日志，避免测试冲突
    fi
}

# 初始化日志系统
_gs_log_init() {
    # 确保日志目录存在
    _gs_log_ensure_dir
    
    # 输出初始化信息
    gs_log_debug "Logger initialized - Level: $(gs_log_get_level), File: $_GS_LOG_FILE"
}

