#!/bin/bash
# Global Scripts V3 - 日志系统 (Zsh兼容版本)
# 版本: 3.0.1
# 描述: 统一的日志管理系统，支持等级、颜色、文件输出，兼容bash和zsh

# 每次都重新加载（与gs_env.sh保持一致）

# Shell兼容性检测
_gs_detect_shell() {
    if [[ -n "${ZSH_VERSION:-}" ]]; then
        echo "zsh"
    elif [[ -n "${BASH_VERSION:-}" ]]; then
        echo "bash"
    else
        echo "unknown"
    fi
}

# 确保基础库已加载
if ! _gs_is_constant "_GS_BASE_LOADED"; then
    echo "[ERROR:logger] 基础库未加载，请先加载 lib/base.sh" >&2
    return 1
fi

# 使用常量保护机制设置日志等级
_gs_set_constant "_GS_SHELL_TYPE" "$(_gs_detect_shell)"
_gs_set_constant "_GS_LOGGER_LOADED" "true"

# 日志等级常量定义
_gs_set_constant "GS_LOG_LEVEL_TRACE" "0"
_gs_set_constant "GS_LOG_LEVEL_DEBUG" "1"
_gs_set_constant "GS_LOG_LEVEL_INFO" "2"
_gs_set_constant "GS_LOG_LEVEL_WARN" "3"
_gs_set_constant "GS_LOG_LEVEL_ERROR" "4"
_gs_set_constant "GS_LOG_LEVEL_FATAL" "5"

# 日志等级名称映射（兼容bash 3和zsh）
_gs_get_level_name() {
    case "$1" in
        0) echo "TRACE";;
        1) echo "DEBUG";;
        2) echo "INFO";;
        3) echo "WARN";;
        4) echo "ERROR";;
        5) echo "FATAL";;
        *) echo "UNKNOWN";;
    esac
}

# 颜色定义（支持禁用）
_gs_init_colors() {
    # 如果已经初始化过，直接返回
    if [[ -n "${_GS_COLOR_INIT_DONE:-}" ]]; then
        return 0
    fi
    
    # 检查是否应该启用颜色
    local enable_color=false

    case "${GS_LOG_COLOR:-auto}" in
        "always")
            enable_color=true
            ;;
        "never")
            enable_color=false
            ;;
        "auto")
            # 检查是否为交互式终端或支持颜色的环境
            if [[ -t 1 || -t 2 ]]; then
                enable_color=true
            # 检查 TERM 环境变量
            elif [[ -n "${TERM:-}" && "$TERM" != "dumb" ]]; then
                enable_color=true
            fi
            ;;
    esac



    # 设置颜色变量（使用常量保护机制，支持重新加载）
    if [[ "$enable_color" == "true" ]]; then
        # 启用颜色
        _gs_reset_constant "_GS_COLOR_RESET" "\033[0m"
        _gs_reset_constant "_GS_COLOR_BOLD" "\033[1m"
        _gs_reset_constant "_GS_COLOR_DIM" "\033[2m"
        _gs_reset_constant "_GS_COLOR_RED" "\033[31m"
        _gs_reset_constant "_GS_COLOR_GREEN" "\033[32m"
        _gs_reset_constant "_GS_COLOR_YELLOW" "\033[33m"
        _gs_reset_constant "_GS_COLOR_BLUE" "\033[34m"
        _gs_reset_constant "_GS_COLOR_MAGENTA" "\033[35m"
        _gs_reset_constant "_GS_COLOR_CYAN" "\033[36m"
        _gs_reset_constant "_GS_COLOR_WHITE" "\033[37m"
    else
        # 禁用颜色
        _gs_reset_constant "_GS_COLOR_RESET" ""
        _gs_reset_constant "_GS_COLOR_BOLD" ""
        _gs_reset_constant "_GS_COLOR_DIM" ""
        _gs_reset_constant "_GS_COLOR_RED" ""
        _gs_reset_constant "_GS_COLOR_GREEN" ""
        _gs_reset_constant "_GS_COLOR_YELLOW" ""
        _gs_reset_constant "_GS_COLOR_BLUE" ""
        _gs_reset_constant "_GS_COLOR_MAGENTA" ""
        _gs_reset_constant "_GS_COLOR_CYAN" ""
        _gs_reset_constant "_GS_COLOR_WHITE" ""
    fi

    # 标记初始化完成
    _gs_set_constant "_GS_COLOR_INIT_DONE" "true"
}

# 日志等级颜色映射
_gs_get_level_color() {
    local level="$1"
    case "$level" in
        0) echo "$_GS_COLOR_DIM";;      # TRACE - 暗色
        1) echo "$_GS_COLOR_CYAN";;     # DEBUG - 青色
        2) echo "$_GS_COLOR_GREEN";;    # INFO - 绿色
        3) echo "$_GS_COLOR_YELLOW";;   # WARN - 黄色
        4) echo "$_GS_COLOR_RED";;      # ERROR - 红色
        5) echo "$_GS_COLOR_MAGENTA";;  # FATAL - 紫色
        *) echo "$_GS_COLOR_RESET";;
    esac
}

# 获取文件大小（跨平台兼容）
_gs_get_file_size() {
    local file="$1"
    local size=0
    
    if [[ ! -f "$file" ]]; then
        echo 0
        return
    fi
    
    # 尝试不同的方法获取文件大小
    if command -v stat >/dev/null 2>&1; then
        # macOS/BSD stat
        if stat -f%z "$file" >/dev/null 2>&1; then
            size=$(stat -f%z "$file" 2>/dev/null)
        # GNU/Linux stat
        elif stat -c%s "$file" >/dev/null 2>&1; then
            size=$(stat -c%s "$file" 2>/dev/null)
        fi
    fi
    
    # 如果stat失败，使用wc作为后备
    if [[ "$size" -eq 0 ]] && command -v wc >/dev/null 2>&1; then
        size=$(wc -c < "$file" 2>/dev/null || echo 0)
    fi
    
    echo "${size:-0}"
}

# 初始化日志系统
_gs_init_logger() {
    # 设置默认日志等级
    GS_LOG_LEVEL="${GS_LOG_LEVEL:-${GS_LOG_LEVEL_INFO:-2}}"
    
    # 设置日志文件
    GS_LOG_FILE="${GS_LOG_FILE:-${GS_ROOT}/logs/gs.log}"
    
    # 设置日志格式
    GS_LOG_FORMAT="${GS_LOG_FORMAT:-[%T] [%L] [%C] %M}"
    
    # 创建日志目录
    local log_dir
    log_dir=$(dirname "$GS_LOG_FILE")
    if [[ ! -d "$log_dir" ]]; then
        mkdir -p "$log_dir" 2>/dev/null || true
    fi
    
    # 初始化颜色
    _gs_init_colors
    
    # 日志轮转（保留最近10个文件）
    _gs_rotate_logs
}

# 日志轮转（zsh兼容版本）
_gs_rotate_logs() {
    local log_file="$GS_LOG_FILE"
    local max_size="${GS_LOG_MAX_SIZE:-10485760}"  # 10MB
    local current_size
    
    current_size=$(_gs_get_file_size "$log_file")
    
    # 检查日志文件大小
    if [[ "$current_size" -gt "$max_size" ]]; then
        # 轮转日志文件（使用明确的循环，避免zsh范围表达式问题）
        local i
        for i in 9 8 7 6 5 4 3 2 1; do
            if [[ -f "${log_file}.$i" ]]; then
                mv "${log_file}.$i" "${log_file}.$((i+1))" 2>/dev/null || true
            fi
        done
        
        if [[ -f "$log_file" ]]; then
            mv "$log_file" "${log_file}.1" 2>/dev/null || true
        fi
    fi
}

# 格式化日志消息
_gs_format_log_message() {
    local level="$1"
    local component="$2"
    local message="$3"
    local timestamp="$4"

    # 获取等级名称
    local level_name
    level_name=$(_gs_get_level_name "$level")

    # 使用简单直接的格式，避免复杂的字符串替换
    echo "[$timestamp] [$level_name] [$component] $message"
}

_gs_log() {
    local level="$1"
    local component="$2"
    local message="$3"

    # 检查日志等级
    if [[ $level -lt ${GS_LOG_LEVEL:-2} ]]; then
        return 0
    fi
    
    # 生成时间戳
    local timestamp
    if command -v date >/dev/null 2>&1; then
        timestamp=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date)
    else
        timestamp="$(date 2>/dev/null || echo 'unknown')"
    fi
    
    # 格式化消息
    local formatted_message
    formatted_message=$(_gs_format_log_message "$level" "$component" "$message" "$timestamp")
    
    # 控制台输出（带颜色）
    if [[ $level -ge ${GS_LOG_CONSOLE_LEVEL:-${GS_LOG_LEVEL_INFO:-2}} ]]; then
        local color
        color=$(_gs_get_level_color "$level")

        if [[ $level -ge ${GS_LOG_LEVEL_ERROR:-4} ]]; then
            # 错误和致命错误输出到stderr
            printf "%b%s%b\n" "$color" "$formatted_message" "${_GS_COLOR_RESET:-}" >&2
        else
            # 其他等级输出到stdout
            printf "%b%s%b\n" "$color" "$formatted_message" "${_GS_COLOR_RESET:-}"
        fi
    fi
    
    # 文件输出（无颜色）
    if [[ -n "${GS_LOG_FILE:-}" ]] && [[ $level -ge ${GS_LOG_FILE_LEVEL:-${GS_LOG_LEVEL_DEBUG:-1}} ]]; then
        printf "%s\n" "$formatted_message" >> "$GS_LOG_FILE" 2>/dev/null || true
    fi
}

# 便捷日志函数
_gs_trace() {
    local component="${1:-gs}"
    local message="$2"
    _gs_log "${GS_LOG_LEVEL_TRACE:-0}" "$component" "$message"
}

_gs_debug() {
    local component="${1:-gs}"
    local message="$2"
    _gs_log "${GS_LOG_LEVEL_DEBUG:-1}" "$component" "$message"
}

_gs_info() {
    local component="${1:-gs}"
    local message="$2"
    _gs_log "${GS_LOG_LEVEL_INFO:-2}" "$component" "$message"
}

_gs_warn() {
    local component="${1:-gs}"
    local message="$2"
    _gs_log "${GS_LOG_LEVEL_WARN:-3}" "$component" "$message"
}

_gs_error() {
    local component="${1:-gs}"
    local message="$2"
    _gs_log "${GS_LOG_LEVEL_ERROR:-4}" "$component" "$message"
}

_gs_fatal() {
    local component="${1:-gs}"
    local message="$2"
    _gs_log "${GS_LOG_LEVEL_FATAL:-5}" "$component" "$message"
}

# 兼容性函数（保持向后兼容）
_gs_plugin_debug() {
    _gs_debug "plugin" "$1"
}

_gs_registry_debug() {
    _gs_debug "registry" "$1"
}

# Shell兼容的大小写转换
_gs_to_upper() {
    local input="$1"
    if [[ "$_GS_SHELL_TYPE" == "zsh" ]]; then
        # Zsh内置大小写转换
        echo "${input:u}"
    else
        # Bash/其他shell使用tr
        echo "$input" | tr '[:lower:]' '[:upper:]'
    fi
}

# 设置日志等级
_gs_set_log_level() {
    local level_name="$1"
    # 转换为大写（shell兼容）
    level_name=$(_gs_to_upper "$level_name")

    case "$level_name" in
        "TRACE") GS_LOG_LEVEL=${GS_LOG_LEVEL_TRACE:-0};;
        "DEBUG") GS_LOG_LEVEL=${GS_LOG_LEVEL_DEBUG:-1};;
        "INFO")  GS_LOG_LEVEL=${GS_LOG_LEVEL_INFO:-2};;
        "WARN")  GS_LOG_LEVEL=${GS_LOG_LEVEL_WARN:-3};;
        "ERROR") GS_LOG_LEVEL=${GS_LOG_LEVEL_ERROR:-4};;
        "FATAL") GS_LOG_LEVEL=${GS_LOG_LEVEL_FATAL:-5};;
        *)
            _gs_error "logger" "无效的日志等级: $level_name"
            return 1
            ;;
    esac
    # 延迟日志输出，确保格式化已初始化
    if [[ "${_GS_LOGGER_LOADED:-}" == "true" ]]; then
        _gs_info "logger" "日志等级设置为: $level_name"
    fi
}

# 获取当前日志等级
_gs_get_log_level() {
    _gs_get_level_name "$GS_LOG_LEVEL"
}

# 日志系统状态
_gs_log_status() {
    echo "=== Global Scripts 日志系统状态 ==="
    echo "Shell类型: $_GS_SHELL_TYPE"
    echo "当前等级: $(_gs_get_log_level)"
    echo "控制台等级: $(_gs_get_level_name "${GS_LOG_CONSOLE_LEVEL:-${GS_LOG_LEVEL_INFO:-2}}")"
    echo "文件等级: $(_gs_get_level_name "${GS_LOG_FILE_LEVEL:-${GS_LOG_LEVEL_DEBUG:-1}}")"
    echo "日志文件: ${GS_LOG_FILE:-未设置}"
    echo "颜色支持: ${GS_LOG_COLOR:-auto}"
    echo "日志格式: $GS_LOG_FORMAT"
    
    if [[ -f "${GS_LOG_FILE:-}" ]]; then
        local file_size
        file_size=$(_gs_get_file_size "$GS_LOG_FILE")
        echo "文件大小: $file_size 字节"
    fi
}

# 清理日志文件
_gs_log_clean() {
    local log_file="${GS_LOG_FILE:-}"
    if [[ -n "$log_file" ]]; then
        rm -f "$log_file"* 2>/dev/null || true
        _gs_info "logger" "日志文件已清理"
    fi
}
