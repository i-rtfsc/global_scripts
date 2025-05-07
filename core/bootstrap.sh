#!/bin/bash
# Global Scripts V3 - 系统引导程序
# 作者: Solo
# 版本: 1.0.0
# 描述: 系统环境检测、初始化、依赖检查和性能监控

# 加载依赖模块 (兼容bash/zsh)
if [[ -z "${_GS_BOOTSTRAP_DIR:-}" ]]; then
    if [[ -n "${BASH_SOURCE:-}" ]]; then
        readonly _GS_BOOTSTRAP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    elif [[ -n "${(%):-%x}" ]] 2>/dev/null; then
        readonly _GS_BOOTSTRAP_DIR="$(cd "$(dirname "${(%):-%x}")" && pwd)"
    else
        readonly _GS_BOOTSTRAP_DIR="$(cd "$(dirname "$0")" && pwd)"
    fi
fi
if [[ -z "${_GS_ROOT:-}" ]]; then
    readonly _GS_ROOT="$(cd "$_GS_BOOTSTRAP_DIR/.." && pwd)"
fi

# declare_compat.sh 已删除，改为简单的变量声明
source "$_GS_ROOT/lib/time_compat.sh"
source "$_GS_ROOT/lib/utils.sh"
source "$_GS_ROOT/lib/logger.sh"
source "$_GS_ROOT/lib/error.sh"
source "$_GS_ROOT/lib/python_compat.sh"

# 引导状态跟踪 - 使用简单变量
_GS_BOOTSTRAP_STATUS="not_started"
_GS_BOOTSTRAP_START_TIME=0
_GS_BOOTSTRAP_ERRORS=""

# 引导配置
if [[ -z "${_GS_MIN_BASH_VERSION:-}" ]]; then
    readonly _GS_MIN_BASH_VERSION="3.2"
    readonly _GS_REQUIRED_COMMANDS=("cat" "grep" "sed" "awk" "find" "sort" "head" "tail")
    readonly _GS_OPTIONAL_COMMANDS=("jq" "curl" "wget" "git")
fi

# 性能监控变量 - 使用Python处理复杂数据
_GS_BOOTSTRAP_METRICS_FILE="$HOME/.local/share/global_scripts/bootstrap_metrics.json"
_GS_SYSTEM_INFO_FILE="$HOME/.local/share/global_scripts/system_info.json"

# 简化的全局变量存储关键信息
_GS_SYSTEM_OS=""
_GS_SYSTEM_ARCH=""
_GS_SYSTEM_BASH_VERSION=""
_GS_SYSTEM_NETWORK_STATUS="unknown"

# ===================================
# 系统信息存储辅助函数
# ===================================

# 设置系统信息
_gs_bootstrap_set_info() {
    local key="$1"
    local value="$2"
    
    # 确保目录存在
    mkdir -p "$(dirname "$_GS_SYSTEM_INFO_FILE")"
    
    # 使用Python存储，如果不可用则存储到全局变量
    if gs_python_available; then
        gs_python_call json_set "$_GS_SYSTEM_INFO_FILE" "$key" "$value"
    else
        # 简单模式：存储到关键的全局变量
        case "$key" in
            "os") _GS_SYSTEM_OS="$value" ;;
            "arch") _GS_SYSTEM_ARCH="$value" ;;
            "bash_version") _GS_SYSTEM_BASH_VERSION="$value" ;;
            "network") _GS_SYSTEM_NETWORK_STATUS="$value" ;;
        esac
    fi
}

# 获取系统信息
_gs_bootstrap_get_info() {
    local key="$1"
    
    if gs_python_available && [[ -f "$_GS_SYSTEM_INFO_FILE" ]]; then
        gs_python_call json_get "$_GS_SYSTEM_INFO_FILE" "$key" ""
    else
        # 简单模式：从全局变量获取
        case "$key" in
            "os") echo "$_GS_SYSTEM_OS" ;;
            "arch") echo "$_GS_SYSTEM_ARCH" ;;
            "bash_version") echo "$_GS_SYSTEM_BASH_VERSION" ;;
            "network") echo "$_GS_SYSTEM_NETWORK_STATUS" ;;
            *) echo "" ;;
        esac
    fi
}

# 设置性能指标
_gs_bootstrap_set_metric() {
    local key="$1"
    local value="$2"
    
    # 确保目录存在
    mkdir -p "$(dirname "$_GS_BOOTSTRAP_METRICS_FILE")"
    
    # 使用Python存储
    if gs_python_available; then
        gs_python_call json_set "$_GS_BOOTSTRAP_METRICS_FILE" "$key" "$value"
    fi
}

# 获取性能指标
_gs_bootstrap_get_metric() {
    local key="$1"
    
    if gs_python_available && [[ -f "$_GS_BOOTSTRAP_METRICS_FILE" ]]; then
        gs_python_call json_get "$_GS_BOOTSTRAP_METRICS_FILE" "$key" ""
    else
        echo ""
    fi
}

# ===================================
# 系统环境检测
# ===================================

# 检测Bash版本
_gs_bootstrap_check_bash_version() {
    # 确保BASH_VERSION存在
    local bash_version="${BASH_VERSION:-$(bash --version 2>/dev/null | head -1 | awk '{print $4}' | cut -d'(' -f1)}"
    [[ -z "$bash_version" ]] && bash_version="3.2.0"  # 默认假设最低支持版本
    
    # 提取主版本号，确保是整数
    local current_version="${bash_version%%.*}"
    local required_version="${_GS_MIN_BASH_VERSION%%.*}"
    
    # 确保版本号是有效整数
    [[ "$current_version" =~ ^[0-9]+$ ]] || current_version="3"
    [[ "$required_version" =~ ^[0-9]+$ ]] || required_version="3"
    
    gs_log_debug "检测Bash版本: $bash_version (要求: $_GS_MIN_BASH_VERSION+)"
    
    if [[ $current_version -lt $required_version ]]; then
        gs_error_dependency "Bash版本过低: $bash_version (要求: $_GS_MIN_BASH_VERSION+)"
        return $_GS_ERROR_DEPENDENCY
    fi
    
    _gs_bootstrap_set_info "bash_version" "$bash_version"
    gs_log_debug "Bash版本检测通过: $bash_version"
    return 0
}

# 检测操作系统环境
_gs_bootstrap_check_system() {
    local os arch shell user
    
    os="$(gs_sys_os)"
    arch="$(gs_sys_arch)"
    shell="$(gs_sys_shell)"
    user="$(gs_sys_username)"
    
    gs_log_debug "系统环境检测: OS=$os, ARCH=$arch, SHELL=$shell, USER=$user"
    
    # 存储系统信息
    _gs_bootstrap_set_info "os" "$os"
    _gs_bootstrap_set_info "arch" "$arch"
    _gs_bootstrap_set_info "shell" "$shell"
    _gs_bootstrap_set_info "user" "$user"
    _gs_bootstrap_set_info "cpu_cores" "$(gs_sys_cpu_cores)"
    _gs_bootstrap_set_info "memory_mb" "$(gs_sys_memory)"
    
    # 检查支持的系统
    case "$os" in
        macos|linux)
            gs_log_debug "支持的操作系统: $os"
            ;;
        windows)
            gs_log_warn "Windows环境支持有限，建议使用WSL"
            ;;
        unknown)
            gs_log_warn "未知操作系统，可能存在兼容性问题"
            ;;
    esac
    
    return 0
}

# 检测必需命令
_gs_bootstrap_check_required_commands() {
    local missing_commands=()
    local cmd
    
    gs_log_debug "检测必需命令: ${_GS_REQUIRED_COMMANDS[*]}"
    
    for cmd in "${_GS_REQUIRED_COMMANDS[@]}"; do
        if ! gs_sys_command_exists "$cmd"; then
            missing_commands+=("$cmd")
            gs_log_error "缺失必需命令: $cmd"
        else
            gs_log_debug "命令可用: $cmd"
        fi
    done
    
    if [[ ${#missing_commands[@]} -gt 0 ]]; then
        gs_error_dependency "缺失必需命令: ${missing_commands[*]}"
        return $_GS_ERROR_DEPENDENCY
    fi
    
    return 0
}

# 检测可选命令
_gs_bootstrap_check_optional_commands() {
    local available_optional=()
    local cmd
    
    gs_log_debug "检测可选命令: ${_GS_OPTIONAL_COMMANDS[*]}"
    
    for cmd in "${_GS_OPTIONAL_COMMANDS[@]}"; do
        if gs_sys_command_exists "$cmd"; then
            available_optional+=("$cmd")
            gs_log_debug "可选命令可用: $cmd"
        else
            gs_log_debug "可选命令不可用: $cmd"
        fi
    done
    
    _gs_bootstrap_set_info "optional_commands" "${available_optional[*]}"
    
    if [[ ${#available_optional[@]} -gt 0 ]]; then
        gs_log_info "可用的可选命令: ${available_optional[*]}"
    fi
    
    return 0
}

# 检测网络连接
_gs_bootstrap_check_network() {
    gs_log_debug "检测网络连接"
    
    if gs_sys_network_check "8.8.8.8" 3; then
        _gs_bootstrap_set_info "network" "available"
        gs_log_debug "网络连接可用"
    else
        _gs_bootstrap_set_info "network" "unavailable"
        gs_log_warn "网络连接不可用，部分功能可能受限"
    fi
    
    return 0
}

# ===================================
# 目录结构检测和初始化
# ===================================

# 检测项目目录结构
_gs_bootstrap_check_directories() {
    local required_dirs=("lib" "core" "api" "config" "plugins" "tests")
    local missing_dirs=()
    local dir
    
    gs_log_debug "检测项目目录结构"
    
    for dir in "${required_dirs[@]}"; do
        local dir_path="$_GS_ROOT/$dir"
        if [[ ! -d "$dir_path" ]]; then
            missing_dirs+=("$dir")
            gs_log_error "缺失目录: $dir_path"
        else
            gs_log_debug "目录存在: $dir_path"
        fi
    done
    
    if [[ ${#missing_dirs[@]} -gt 0 ]]; then
        gs_error_config "缺失必需目录: ${missing_dirs[*]}"
        return $_GS_ERROR_CONFIG
    fi
    
    return 0
}

# 初始化运行时目录
_gs_bootstrap_init_runtime_dirs() {
    local runtime_dirs=(
        "$HOME/.local/share/global_scripts"
        "$HOME/.local/share/global_scripts/logs"
        "$HOME/.local/share/global_scripts/cache"
        "$HOME/.local/share/global_scripts/data"
        "$HOME/.local/share/global_scripts/tmp"
    )
    
    gs_log_debug "初始化运行时目录"
    
    local dir
    for dir in "${runtime_dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            if gs_dir_create "$dir" 755; then
                gs_log_debug "创建运行时目录: $dir"
            else
                gs_log_warn "无法创建运行时目录: $dir"
            fi
        else
            gs_log_debug "运行时目录已存在: $dir"
        fi
    done
    
    return 0
}

# ===================================
# 性能监控初始化
# ===================================

# 启动性能监控
_gs_bootstrap_start_performance_monitoring() {
    gs_log_debug "启动性能监控"
    
    # 记录引导开始时间
    _GS_BOOTSTRAP_START_TIME=$(gs_time_ms)
    _gs_bootstrap_set_metric "start_time" "$_GS_BOOTSTRAP_START_TIME"
    
    # 记录系统负载
    if gs_sys_command_exists "uptime"; then
        local load_avg
        load_avg=$(uptime | awk -F'load average:' '{print $2}' | gs_str_trim)
        _gs_bootstrap_set_metric "load_average" "$load_avg"
        gs_log_debug "系统负载: $load_avg"
    fi
    
    # 记录可用磁盘空间
    local disk_space
    disk_space=$(gs_sys_disk_space "$_GS_ROOT")
    _gs_bootstrap_set_metric "disk_space_mb" "$disk_space"
    gs_log_debug "可用磁盘空间: ${disk_space}MB"
    
    return 0
}

# 完成性能监控
_gs_bootstrap_finish_performance_monitoring() {
    local end_time duration
    end_time=$(gs_time_ms)
    duration=$((end_time - _GS_BOOTSTRAP_START_TIME))
    
    _gs_bootstrap_set_metric "end_time" "$end_time"
    _gs_bootstrap_set_metric "duration_ms" "$duration"
    
    gs_log_info "引导完成，耗时: ${duration}ms"
    
    return 0
}

# ===================================
# 主引导流程
# ===================================

# 执行完整的系统引导
gs_bootstrap_system() {
    gs_log_info "开始Global Scripts V3系统引导"
    _GS_BOOTSTRAP_STATUS="running"
    
    # 启动性能监控
    _gs_bootstrap_start_performance_monitoring
    
    # 系统环境检测
    gs_log_debug "=== 系统环境检测阶段 ==="
    if ! _gs_bootstrap_check_bash_version; then
        _GS_BOOTSTRAP_STATUS="failed"
        return $_GS_ERROR_DEPENDENCY
    fi
    
    if ! _gs_bootstrap_check_system; then
        _GS_BOOTSTRAP_STATUS="failed"
        return $_GS_ERROR_GENERIC
    fi
    
    # 依赖检查
    gs_log_debug "=== 依赖检查阶段 ==="
    if ! _gs_bootstrap_check_required_commands; then
        _GS_BOOTSTRAP_STATUS="failed"
        return $_GS_ERROR_DEPENDENCY
    fi
    
    _gs_bootstrap_check_optional_commands
    _gs_bootstrap_check_network
    
    # 目录结构检测和初始化
    gs_log_debug "=== 目录初始化阶段 ==="
    if ! _gs_bootstrap_check_directories; then
        _GS_BOOTSTRAP_STATUS="failed"
        return $_GS_ERROR_CONFIG
    fi
    
    _gs_bootstrap_init_runtime_dirs
    
    # 完成引导
    _gs_bootstrap_finish_performance_monitoring
    _GS_BOOTSTRAP_STATUS="completed"
    
    gs_log_info "系统引导完成"
    return 0
}

# 快速引导（跳过可选检查）
gs_bootstrap_quick() {
    gs_log_info "开始快速引导模式"
    _GS_BOOTSTRAP_STATUS="running"
    
    _gs_bootstrap_start_performance_monitoring
    
    # 仅执行必要检查
    _gs_bootstrap_check_bash_version || return $?
    _gs_bootstrap_check_required_commands || return $?
    _gs_bootstrap_check_directories || return $?
    
    _gs_bootstrap_finish_performance_monitoring
    _GS_BOOTSTRAP_STATUS="completed"
    
    gs_log_info "快速引导完成"
    return 0
}

# 获取引导状态
gs_bootstrap_get_status() {
    echo "$_GS_BOOTSTRAP_STATUS"
}

# 获取系统信息
gs_bootstrap_get_system_info() {
    local key="${1:-}"
    
    if [[ -n "$key" ]]; then
        _gs_bootstrap_get_info "$key"
    else
        # 输出所有系统信息
        printf "=== 系统信息 ===\n"
        printf "操作系统: %s\n" "$(_gs_bootstrap_get_info "os")"
        printf "架构: %s\n" "$(_gs_bootstrap_get_info "arch")"
        printf "Shell: %s\n" "$(_gs_bootstrap_get_info "shell")"
        printf "Bash版本: %s\n" "$(_gs_bootstrap_get_info "bash_version")"
        printf "用户: %s\n" "$(_gs_bootstrap_get_info "user")"
        printf "CPU核心: %s\n" "$(_gs_bootstrap_get_info "cpu_cores")"
        printf "内存: %sMB\n" "$(_gs_bootstrap_get_info "memory_mb")"
        printf "网络: %s\n" "$(_gs_bootstrap_get_info "network")"
        
        local optional_cmds
        optional_cmds="$(_gs_bootstrap_get_info "optional_commands")"
        [[ -n "$optional_cmds" ]] && printf "可选命令: %s\n" "$optional_cmds"
    fi
}

# 获取性能指标
gs_bootstrap_get_metrics() {
    local key="${1:-}"
    
    if [[ -n "$key" ]]; then
        _gs_bootstrap_get_metric "$key"
    else
        # 输出所有性能指标
        printf "=== 引导性能指标 ===\n"
        printf "引导耗时: %sms\n" "$(_gs_bootstrap_get_metric "duration_ms")"
        printf "系统负载: %s\n" "$(_gs_bootstrap_get_metric "load_average")"
        printf "可用磁盘: %sMB\n" "$(_gs_bootstrap_get_metric "disk_space_mb")"
    fi
}

# 诊断系统问题
gs_bootstrap_diagnose() {
    gs_log_info "开始系统诊断"
    
    printf "=== Global Scripts V3 系统诊断 ===\n\n"
    
    # 显示引导状态
    printf "引导状态: %s\n\n" "$_GS_BOOTSTRAP_STATUS"
    
    # 显示系统信息
    gs_bootstrap_get_system_info
    printf "\n"
    
    # 显示性能指标
    if [[ "$_GS_BOOTSTRAP_STATUS" == "completed" ]]; then
        gs_bootstrap_get_metrics
        printf "\n"
    fi
    
    # 检查常见问题
    printf "=== 常见问题检查 ===\n"
    
    # 检查权限
    if [[ ! -w "$_GS_ROOT" ]]; then
        printf "⚠️  项目目录无写权限: %s\n" "$_GS_ROOT"
    else
        printf "✅ 项目目录权限正常\n"
    fi
    
    # 检查磁盘空间
    local disk_space
    disk_space=$(gs_sys_disk_space "$_GS_ROOT")
    if [[ $disk_space -lt 100 ]]; then
        printf "⚠️  磁盘空间不足: %dMB\n" "$disk_space"
    else
        printf "✅ 磁盘空间充足: %dMB\n" "$disk_space"
    fi
    
    # 检查关键文件
    local critical_files=("VERSION" "gs_env.sh" "lib/logger.sh" "lib/utils.sh")
    local file
    for file in "${critical_files[@]}"; do
        if [[ -f "$_GS_ROOT/$file" ]]; then
            printf "✅ 关键文件存在: %s\n" "$file"
        else
            printf "❌ 关键文件缺失: %s\n" "$file"
        fi
    done
    
    printf "\n诊断完成\n"
}

