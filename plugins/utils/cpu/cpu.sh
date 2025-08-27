#!/bin/bash

# CPU架构检测与系统信息工具
# 基于V2版本的gs_cpu_arch功能实现

# 获取CPU架构信息
gs_utils_cpu_arch() {
    local arch_info
    arch_info=$(uname -m)
    
    case "$arch_info" in
        x86_64|amd64)
            echo "x86_64"
            ;;
        aarch64|arm64)
            echo "arm64"
            ;;
        armv7*|armhf)
            echo "arm32"
            ;;
        i386|i686)
            echo "x86"
            ;;
        *)
            echo "$arch_info"
            ;;
    esac
}

# 获取详细系统信息
gs_utils_cpu_info() {
    local json_output=""
    local os_name os_version kernel_version cpu_model cpu_cores
    
    # 基本信息
    os_name=$(uname -s)
    kernel_version=$(uname -r)
    cpu_arch=$(gs_utils_cpu_arch)
    
    # macOS特定信息
    if [[ "$os_name" == "Darwin" ]]; then
        os_version=$(sw_vers -productVersion 2>/dev/null || echo "Unknown")
        cpu_model=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "Unknown")
        cpu_cores=$(sysctl -n hw.ncpu 2>/dev/null || echo "Unknown")
    # Linux特定信息
    elif [[ "$os_name" == "Linux" ]]; then
        os_version=$(lsb_release -d 2>/dev/null | cut -f2 || echo "Unknown")
        cpu_model=$(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | sed 's/^ *//' || echo "Unknown")
        cpu_cores=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo || echo "Unknown")
    else
        os_version="Unknown"
        cpu_model="Unknown"
        cpu_cores="Unknown"
    fi
    
    if [[ "${GS_OUTPUT_JSON:-false}" == "true" ]]; then
        cat << EOF
{
  "os": {
    "name": "$os_name",
    "version": "$os_version",
    "kernel": "$kernel_version"
  },
  "cpu": {
    "architecture": "$cpu_arch",
    "model": "$cpu_model",
    "cores": "$cpu_cores"
  }
}
EOF
    else
        cat << EOF
系统信息:
  操作系统: $os_name $os_version
  内核版本: $kernel_version
  CPU架构:  $cpu_arch
  CPU型号:  $cpu_model
  CPU核心:  $cpu_cores
EOF
    fi
}

# 检查系统兼容性
gs_utils_cpu_compat() {
    local target_arch="${1:-x86_64}"
    local current_arch
    current_arch=$(gs_utils_cpu_arch)
    
    if [[ "$current_arch" == "$target_arch" ]]; then
        echo "兼容: 当前架构 $current_arch 与目标架构 $target_arch 匹配"
        return 0
    else
        echo "不兼容: 当前架构 $current_arch 与目标架构 $target_arch 不匹配"
        return 1
    fi
}

# 主入口函数
gs_utils_cpu_main() {
    local action=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --arch|-a)
                action="arch"
                shift
                ;;
            --info|-i)
                action="info"
                shift
                ;;
            --compat|-c)
                action="compat"
                shift
                ;;
            --json)
                export GS_OUTPUT_JSON=true
                shift
                ;;
            --help|-h)
                gs_utils_cpu_help
                return 0
                ;;
            *)
                echo "错误: 未知参数 '$1'" >&2
                gs_utils_cpu_help
                return 1
                ;;
        esac
    done
    
    case "$action" in
        "arch")
            gs_utils_cpu_arch
            ;;
        "info")
            gs_utils_cpu_info
            ;;
        "compat")
            gs_utils_cpu_compat "$2"
            ;;
        *)
            gs_utils_cpu_info
            ;;
    esac
}

# 帮助函数
gs_utils_cpu_help() {
    cat << 'EOF'
CPU架构检测与系统信息工具

用法:
    gs-utils-cpu [选项]

选项:
    --arch, -a      仅显示CPU架构
    --info, -i      显示详细系统信息(默认)
    --compat, -c    检查架构兼容性
    --json          JSON格式输出
    --help, -h      显示此帮助信息

示例:
    gs-utils-cpu --arch          显示CPU架构
    gs-utils-cpu --info          显示详细系统信息
    gs-utils-cpu --json          JSON格式输出
    gs-utils-cpu --compat x86_64 检查x86_64兼容性

支持的架构:
    x86_64, arm64, arm32, x86
EOF
}

# 如果直接执行此脚本
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    gs_utils_cpu_main "$@"
fi