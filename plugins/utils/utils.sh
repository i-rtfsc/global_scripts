#!/bin/bash

# Global Scripts Utils Plugin - V3版本的bin工具等价实现
# 提供CPU架构检测、天气预报、Gerrit工具、repo管理等功能

# 工具函数：检查依赖
_gs_utils_check_deps() {
    local deps=("curl" "jq")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            echo "错误: 缺少依赖 '$dep'" >&2
            return 1
        fi
    done
}

# 工具函数：JSON输出支持
_gs_utils_json_output() {
    local data="$1"
    if [[ "${GS_OUTPUT_JSON:-false}" == "true" ]]; then
        echo "$data" | jq '.'
    else
        echo "$data"
    fi
}

# 主入口函数
gs_utils_main() {
    echo "Global Scripts Utils Plugin v3.0.0"
    echo "系统工具集合 - 提供多种实用工具"
    echo ""
    echo "可用子模块:"
    echo "  cpu      - CPU架构检测与系统信息"
    echo "  forecast - 天气预报查询工具"
    echo "  gerrit   - Gerrit代码审查工具"
    echo "  repo     - Android repo工具管理"
    echo ""
    echo "使用方法: gs-utils-<submodule> [options]"
}

# 状态检查函数
gs_utils_status() {
    echo "Utils Plugin Status:"
    echo "- CPU模块: $([ -f "${GS_PLUGIN_DIR}/utils/cpu/cpu.sh" ] && echo "可用" || echo "不可用")"
    echo "- Forecast模块: $([ -f "${GS_PLUGIN_DIR}/utils/forecast/forecast.sh" ] && echo "可用" || echo "不可用")"
    echo "- Gerrit模块: $([ -f "${GS_PLUGIN_DIR}/utils/gerrit/gerrit.sh" ] && echo "可用" || echo "不可用")"
    echo "- Repo模块: $([ -f "${GS_PLUGIN_DIR}/utils/repo/repo.sh" ] && echo "可用" || echo "不可用")"
}

# 帮助函数
gs_utils_help() {
    cat << 'EOF'
Global Scripts Utils Plugin

用法:
    gs-utils-cpu [options]      CPU架构检测与系统信息
    gs-utils-forecast [options] 天气预报查询
    gs-utils-gerrit [options]   Gerrit代码审查工具
    gs-utils-repo [options]     Android repo工具

通用选项:
    --json      JSON格式输出
    --verbose   详细输出模式
    --help      显示帮助信息

示例:
    gs-utils-cpu --arch         显示CPU架构
    gs-utils-forecast beijing   查询北京天气
    gs-utils-gerrit --push      推送到Gerrit
    gs-utils-repo --init        初始化repo

更多信息请使用各子模块的 --help 选项。
EOF
}