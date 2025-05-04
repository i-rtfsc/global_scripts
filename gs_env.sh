#!/bin/bash
# Global Scripts V3 - 主环境入口文件
# 作者: Solo
# 版本: 动态从VERSION文件读取
# 描述: V3版本主入口，完全去除V2兼容性

# 严格模式
set -euo pipefail

# 全局变量定义  
readonly _GS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
readonly _GS_VERSION="$(cat "${_GS_ROOT}/VERSION" 2>/dev/null || echo "unknown")"
readonly _GS_LIB_DIR="${_GS_ROOT}/lib"
readonly _GS_CORE_DIR="${_GS_ROOT}/core"
readonly _GS_API_DIR="${_GS_ROOT}/api"
readonly _GS_CONFIG_DIR="${_GS_ROOT}/config"
readonly _GS_PLUGINS_DIR="${_GS_ROOT}/plugins"
readonly _GS_CUSTOM_DIR="${_GS_ROOT}/custom"
readonly _GS_COMPLETION_DIR="${_GS_ROOT}/completion"
readonly _GS_TESTS_DIR="${_GS_ROOT}/tests"
readonly _GS_CACHE_DIR="${HOME}/.cache/global_scripts"
readonly _GS_LOG_DIR="${HOME}/.local/share/global_scripts/logs"

# 导出全局变量
export _GS_VERSION _GS_ROOT _GS_LIB_DIR _GS_CORE_DIR _GS_API_DIR
export _GS_CONFIG_DIR _GS_PLUGINS_DIR _GS_CUSTOM_DIR _GS_COMPLETION_DIR
export _GS_TESTS_DIR _GS_CACHE_DIR _GS_LOG_DIR

# 加载兼容性支持
source "${_GS_LIB_DIR}/time_compat.sh"

# 初始化启动时间监控
_GS_STARTUP_TIME=$(gs_time_ms)
export _GS_STARTUP_TIME

# 创建必要目录
mkdir -p "${_GS_CACHE_DIR}" "${_GS_LOG_DIR}"

# 环境检查函数
gs_check_environment() {
    local errors=0
    
    # 检查必需的系统命令
    local required_commands=("bash" "jq" "sed" "awk" "grep")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "错误: 缺少必需命令: $cmd" >&2
            ((errors++))
        fi
    done
    
    # 检查bash版本
    if [[ ${BASH_MAJOR_VERSION:-3} -lt 3 ]]; then
        echo "错误: 需要bash 3.0+，当前版本: ${BASH_VERSION:-未知}" >&2
        ((errors++))
    fi
    
    return $errors
}

# 系统初始化
gs_initialize() {
    # 环境检查
    if ! gs_check_environment; then
        echo "环境检查失败，请修复上述问题后重试" >&2
        return 1
    fi
    
    # 加载核心模块（后续实现）
    # source "${GS_CORE_DIR}/bootstrap.sh"
    
    # 输出初始化成功信息
    local end_time
    end_time=$(gs_time_ms)
    local startup_duration
    startup_duration=$(gs_time_diff_ms "$_GS_STARTUP_TIME" "$end_time")
    
    echo "Global Scripts V${_GS_VERSION} initialized successfully in $(gs_time_format "$startup_duration")"
    return 0
}

# 主函数
main() {
    # 如果直接执行此脚本，进行初始化
    if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
        gs_initialize
    fi
}

# 执行主函数
main "$@"