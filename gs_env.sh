#!/bin/bash
# Global Scripts V3 - 主环境入口文件
# 作者: Solo
# 版本: 1.4.0
# 描述: V3版本主入口，系统初始化流程、环境变量设置、核心模块加载、错误边界处理

# ===================================
# 全局变量定义与环境变量设置
# ===================================

# 核心路径变量 (兼容bash/zsh)
if [[ -z "${_GS_ROOT:-}" ]]; then
    if [[ -n "${BASH_SOURCE:-}" ]]; then
        readonly _GS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    elif [[ -n "${(%):-%x}" ]] 2>/dev/null; then
        # zsh compatibility
        readonly _GS_ROOT="$(cd "$(dirname "${(%):-%x}")" && pwd)"
    else
        readonly _GS_ROOT="$(cd "$(dirname "$0")" && pwd)"
    fi
fi
readonly _GS_VERSION="$(cat "${_GS_ROOT}/VERSION" 2>/dev/null || echo "unknown")"
readonly _GS_LIB_DIR="${_GS_ROOT}/lib"
readonly _GS_CORE_DIR="${_GS_ROOT}/core"
readonly _GS_API_DIR="${_GS_ROOT}/api"
readonly _GS_CONFIG_DIR="${_GS_ROOT}/config"
readonly _GS_PLUGINS_DIR="${_GS_ROOT}/plugins"
readonly _GS_CUSTOM_DIR="${_GS_ROOT}/custom"
readonly _GS_COMPLETION_DIR="${_GS_ROOT}/completion"
readonly _GS_TESTS_DIR="${_GS_ROOT}/tests"

# 运行时目录变量
readonly _GS_RUNTIME_DIR="${HOME}/.local/share/global_scripts"
readonly _GS_CACHE_DIR="${_GS_RUNTIME_DIR}/cache"
readonly _GS_LOG_DIR="${_GS_RUNTIME_DIR}/logs"
readonly _GS_DATA_DIR="${_GS_RUNTIME_DIR}/data"
readonly _GS_TMP_DIR="${_GS_RUNTIME_DIR}/tmp"

# 系统状态变量
_GS_INITIALIZED=false
_GS_BOOTSTRAP_STATUS="not_started"
_GS_ERROR_COUNT=0
_GS_STARTUP_TIME=0
_GS_DEBUG_MODE=false

# 导出核心环境变量
export _GS_VERSION _GS_ROOT _GS_LIB_DIR _GS_CORE_DIR _GS_API_DIR
export _GS_CONFIG_DIR _GS_PLUGINS_DIR _GS_CUSTOM_DIR _GS_COMPLETION_DIR
export _GS_TESTS_DIR _GS_RUNTIME_DIR _GS_CACHE_DIR _GS_LOG_DIR _GS_DATA_DIR _GS_TMP_DIR
export _GS_INITIALIZED _GS_BOOTSTRAP_STATUS _GS_DEBUG_MODE

# ===================================
# 错误边界处理
# ===================================

# 错误处理函数 (兼容bash/zsh)
_gs_handle_error() {
    local exit_code=$?
    local line_number="${1:-${LINENO:-unknown}}"
    local bash_lineno="${2:-${BASH_LINENO:-unknown}}"
    local last_command="${3:-unknown}"
    
    # 获取当前脚本文件名 (兼容bash/zsh)
    local script_file="$0"
    if [[ -n "${BASH_SOURCE:-}" ]]; then
        script_file="${BASH_SOURCE[1]:-$0}"
    elif [[ -n "${funcfiletrace:-}" ]]; then
        script_file="${funcfiletrace[1]%%:*}"
    fi
    
    _GS_ERROR_COUNT=$((_GS_ERROR_COUNT + 1))
    
    printf "\n❌ [FATAL ERROR] Global Scripts V3 启动失败\n" >&2
    printf "错误位置: %s:%s\n" "$script_file" "$line_number" >&2
    printf "失败命令: %s\n" "$last_command" >&2
    printf "退出码: %d\n" "$exit_code" >&2
    printf "错误时间: %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" >&2
    printf "Shell环境: %s\n" "${ZSH_VERSION:+zsh $ZSH_VERSION}${BASH_VERSION:+bash $BASH_VERSION}" >&2
    
    # 如果日志目录可用，写入错误日志
    if [[ -d "$_GS_LOG_DIR" ]]; then
        {
            printf "[%s] FATAL ERROR in %s:%s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$script_file" "$line_number"
            printf "Command: %s\n" "$last_command"
            printf "Exit code: %d\n" "$exit_code"
            printf "Shell: %s\n" "${ZSH_VERSION:+zsh $ZSH_VERSION}${BASH_VERSION:+bash $BASH_VERSION}"
            printf "Total errors: %d\n" "$_GS_ERROR_COUNT"
        } >> "$_GS_LOG_DIR/startup_errors.log"
    fi
    
    # 清理和退出
    _gs_cleanup_on_error
    exit $exit_code
}

# 中断处理函数
_gs_handle_interrupt() {
    local signal=$1
    printf "\n⚠️  收到信号 %s，正在清理...\n" "$signal" >&2
    _gs_cleanup_on_error
    exit 130
}

# 错误清理函数
_gs_cleanup_on_error() {
    # 重置系统状态
    _GS_INITIALIZED=false
    _GS_BOOTSTRAP_STATUS="failed"
    
    # 可以在这里添加更多清理逻辑
    printf "🧹 错误清理完成\n" >&2
}

# 设置基本错误处理 (仅在直接执行脚本时使用)
_gs_setup_error_handling() {
    # 只在直接执行脚本时设置错误处理，不在source时设置
    if ! _gs_is_sourced && [[ $- != *i* ]]; then
        if [[ -n "${BASH_VERSION:-}" ]]; then
            set -euo pipefail
            trap '_gs_handle_error ${LINENO} ${BASH_LINENO} "$BASH_COMMAND"' ERR
        elif [[ -n "${ZSH_VERSION:-}" ]]; then
            set -eo pipefail
            trap '_gs_handle_error ${LINENO:-0} ${LINENO:-0} "unknown"' ERR
        fi
        trap '_gs_handle_interrupt SIGINT' INT
        trap '_gs_handle_interrupt SIGTERM' TERM
    fi
}

# ===================================
# 兼容性检查和基础模块加载
# ===================================

# 加载必需的兼容性模块
_gs_load_compatibility() {
    # 首先加载基础的logger模块（简化版本，只提供日志函数）
    local basic_logger_path="${_GS_LIB_DIR}/logger.sh"
    if [[ -f "$basic_logger_path" ]]; then
        source "$basic_logger_path"
    fi
    
    local compat_modules=("time_compat.sh" "python_compat.sh")
    local module_path
    
    for module in "${compat_modules[@]}"; do
        module_path="${_GS_LIB_DIR}/$module"
        if [[ -f "$module_path" ]]; then
            source "$module_path"
        else
            printf "⚠️  兼容性模块缺失: %s\n" "$module" >&2
            return 1
        fi
    done
    
    return 0
}

# 环境检查函数  
gs_check_environment() {
    local errors=0
    
    printf "🔍 检查系统环境...\n"
    
    # 检查bash版本
    if [[ ${BASH_MAJOR_VERSION:-3} -lt 3 ]]; then
        printf "❌ bash版本过低: %s (需要3.0+)\n" "${BASH_VERSION:-未知}" >&2
        ((errors++))
    else
        printf "✅ bash版本: %s\n" "${BASH_VERSION}"
    fi
    
    # 检查必需的系统命令
    local required_commands=("cat" "grep" "sed" "awk" "find" "sort")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            printf "❌ 缺少必需命令: %s\n" "$cmd" >&2
            ((errors++))
        fi
    done
    
    # 检查可选但推荐的命令
    local optional_commands=("jq" "curl" "git")
    for cmd in "${optional_commands[@]}"; do
        if command -v "$cmd" >/dev/null 2>&1; then
            printf "✅ 可选命令可用: %s\n" "$cmd"
        else
            printf "⚠️  可选命令不可用: %s\n" "$cmd"
        fi
    done
    
    # 检查Python环境（如果Python兼容性模块已加载）
    if command -v gs_python_available >/dev/null 2>&1; then
        if gs_python_available; then
            printf "✅ Python环境: 可用\n"
        else
            printf "⚠️  Python环境: 不可用（部分功能将受限）\n"
        fi
    fi
    
    if [[ $errors -eq 0 ]]; then
        printf "✅ 环境检查通过\n"
        return 0
    else
        printf "❌ 环境检查失败，发现 %d 个问题\n" "$errors" >&2
        return 1
    fi
}

# ===================================
# 系统初始化流程
# ===================================

# 创建必要目录结构
_gs_create_directories() {
    printf "📁 创建运行时目录...\n"
    
    local dirs=(
        "$_GS_RUNTIME_DIR"
        "$_GS_CACHE_DIR" 
        "$_GS_LOG_DIR"
        "$_GS_DATA_DIR"
        "$_GS_TMP_DIR"
    )
    
    for dir in "${dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            if mkdir -p "$dir" 2>/dev/null; then
                printf "✅ 创建目录: %s\n" "$dir"
            else
                printf "❌ 无法创建目录: %s\n" "$dir" >&2
                return 1
            fi
        fi
    done
    
    return 0
}

# 核心模块加载
_gs_load_core_modules() {
    printf "🔧 加载核心模块...\n"
    
    local core_modules=(
        "utils.sh"
        "error.sh"
    )
    local module_path
    
    # 加载lib模块 (logger.sh已在兼容性阶段加载)
    for module in "${core_modules[@]}"; do
        module_path="${_GS_LIB_DIR}/$module"
        if [[ -f "$module_path" ]]; then
            source "$module_path"
            printf "✅ 加载lib模块: %s\n" "$module"
        else
            printf "❌ lib模块缺失: %s\n" "$module" >&2
            return 1
        fi
    done
    
    # 加载core模块
    local bootstrap_module="${_GS_CORE_DIR}/bootstrap.sh"
    if [[ -f "$bootstrap_module" ]]; then
        source "$bootstrap_module"
        printf "✅ 加载核心模块: bootstrap.sh\n"
        
        # 执行系统引导
        if gs_bootstrap_system; then
            _GS_BOOTSTRAP_STATUS="completed"
            printf "✅ 系统引导完成\n"
        else
            printf "❌ 系统引导失败\n" >&2
            return 1
        fi
    else
        printf "❌ 核心引导模块缺失: bootstrap.sh\n" >&2
        return 1
    fi
    
    return 0
}

# 主系统初始化函数
gs_initialize() {
    printf "\n🚀 Global Scripts V%s 初始化开始...\n" "$_GS_VERSION"
    
    # 记录启动时间
    _GS_STARTUP_TIME=$(gs_time_ms 2>/dev/null || date +%s000)
    
    # 1. 加载兼容性模块
    if ! _gs_load_compatibility; then
        printf "❌ 兼容性模块加载失败\n" >&2
        return 1
    fi
    printf "✅ 兼容性模块加载完成\n"
    
    # 2. 环境检查
    if ! gs_check_environment; then
        printf "❌ 环境检查失败，请修复上述问题后重试\n" >&2
        return 1
    fi
    
    # 3. 创建必要目录
    if ! _gs_create_directories; then
        printf "❌ 目录创建失败\n" >&2
        return 1
    fi
    
    # 4. 加载核心模块
    if ! _gs_load_core_modules; then
        printf "❌ 核心模块加载失败\n" >&2
        return 1
    fi
    
    # 5. 标记初始化完成
    _GS_INITIALIZED=true
    
    # 计算启动时间
    local end_time
    end_time=$(gs_time_ms 2>/dev/null || date +%s000)
    local startup_duration
    startup_duration=$((end_time - _GS_STARTUP_TIME))
    
    printf "\n🎉 Global Scripts V%s 初始化成功！\n" "$_GS_VERSION"
    printf "⏱️  启动耗时: %d毫秒\n" "$startup_duration"
    printf "📂 运行时目录: %s\n" "$_GS_RUNTIME_DIR"
    printf "🐍 Python支持: %s\n" "$(gs_python_available 2>/dev/null && echo "可用" || echo "不可用")"
    
    return 0
}

# ===================================
# 调试和诊断功能
# ===================================

# 启用调试模式
gs_enable_debug() {
    _GS_DEBUG_MODE=true
    export _GS_DEBUG_MODE
    printf "🐛 调试模式已启用\n"
}

# 显示系统状态
gs_status() {
    printf "\n=== Global Scripts V%s 系统状态 ===\n" "$_GS_VERSION"
    printf "初始化状态: %s\n" "$([[ "$_GS_INITIALIZED" == "true" ]] && echo "✅ 已初始化" || echo "❌ 未初始化")"
    printf "引导状态: %s\n" "$_GS_BOOTSTRAP_STATUS"
    printf "调试模式: %s\n" "$([[ "$_GS_DEBUG_MODE" == "true" ]] && echo "🐛 启用" || echo "关闭")"
    printf "错误计数: %d\n" "$_GS_ERROR_COUNT"
    printf "运行时目录: %s\n" "$_GS_RUNTIME_DIR"
    
    if [[ "$_GS_INITIALIZED" == "true" ]] && command -v gs_bootstrap_get_system_info >/dev/null 2>&1; then
        printf "\n"
        gs_bootstrap_get_system_info
    fi
}

# ===================================
# 主函数和入口点
# ===================================

# 主函数
main() {
    # 设置错误处理（仅在直接执行时）
    _gs_setup_error_handling
    
    local action="${1:-initialize}"
    
    case "$action" in
        "initialize"|"init")
            gs_initialize
            ;;
        "status")
            gs_status
            ;;
        "debug")
            gs_enable_debug
            gs_initialize
            ;;
        "help"|"--help"|"-h")
            printf "Global Scripts V%s 主入口文件\n\n" "$_GS_VERSION"
            printf "用法: %s [命令]\n\n" "${BASH_SOURCE[0]:-$0}"
            printf "命令:\n"
            printf "  initialize, init  初始化系统 (默认)\n"
            printf "  status           显示系统状态\n"
            printf "  debug            启用调试模式并初始化\n"
            printf "  help             显示此帮助信息\n"
            ;;
        *)
            printf "未知命令: %s\n" "$action" >&2
            printf "使用 '%s help' 查看可用命令\n" "${BASH_SOURCE[0]:-$0}" >&2
            return 1
            ;;
    esac
}

# 当直接执行此脚本时，运行主函数 (兼容bash/zsh)
_gs_is_sourced() {
    if [[ -n "${BASH_VERSION:-}" ]]; then
        [[ "${BASH_SOURCE[0]}" != "${0}" ]]
    elif [[ -n "${ZSH_VERSION:-}" ]]; then
        [[ "${(%):-%x}" != "${(%):-%N}" ]]
    else
        # 通用方法：检查调用栈
        return 1  # 假设未被source
    fi
}

if ! _gs_is_sourced; then
    main "$@"
fi