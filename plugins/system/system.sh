#!/bin/bash
# System系统工具插件
# System Tools Plugin
# 提供系统工具和配置管理功能

# 检查系统平台
_gs_system_check_platform() {
    case "$(uname -s)" in
        Darwin)
            echo "macOS"
            return 0
            ;;
        Linux)
            echo "Linux"
            return 0
            ;;
        *)
            echo "unknown"
            return 1
            ;;
    esac
}

# 获取系统信息
gs_system_info() {
    local show_detailed=false
    local output_format="table"
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--detailed)
                show_detailed=true
                shift
                ;;
            --json)
                output_format="json"
                shift
                ;;
            -h|--help)
                echo "用法: gs-system-info [选项]"
                echo "显示系统信息"
                echo ""
                echo "选项:"
                echo "  -d, --detailed          显示详细信息"
                echo "  --json                  JSON格式输出"
                echo "  -h, --help              显示此帮助信息"
                return 0
                ;;
            *)
                echo "错误: 未知参数 $1"
                return 1
                ;;
        esac
    done
    
    # 收集系统信息
    local platform
    platform=$(_gs_system_check_platform)
    local hostname=$(hostname)
    local username=$(whoami)
    local shell_type="$SHELL"
    local current_path="$PWD"
    local home_path="$HOME"
    
    # macOS特有信息
    local os_version=""
    local hardware=""
    if [[ "$platform" == "macOS" ]]; then
        os_version=$(sw_vers -productVersion 2>/dev/null || echo "未知")
        hardware=$(uname -m)
    elif [[ "$platform" == "Linux" ]]; then
        if [[ -f /etc/os-release ]]; then
            os_version=$(grep '^PRETTY_NAME=' /etc/os-release | cut -d'"' -f2)
        else
            os_version=$(uname -r)
        fi
        hardware=$(uname -m)
    fi
    
    if [[ "$output_format" == "json" ]]; then
        # JSON格式输出
        cat <<EOF
{
  "system": {
    "platform": "$platform",
    "os_version": "$os_version",
    "hardware": "$hardware",
    "hostname": "$hostname",
    "username": "$username",
    "shell": "$shell_type",
    "current_path": "$current_path",
    "home_path": "$home_path"
  }
}
EOF
    else
        # 表格格式输出
        echo "系统信息"
        echo "========"
        echo "平台:     $platform"
        echo "版本:     $os_version"
        echo "架构:     $hardware"
        echo "主机名:   $hostname"
        echo "用户名:   $username"
        echo "Shell:    $shell_type"
        echo "当前路径: $current_path"
        echo "用户目录: $home_path"
        
        if [[ "$show_detailed" == true ]]; then
            echo ""
            echo "详细信息"
            echo "========"
            
            # 显示环境变量
            echo "重要环境变量:"
            echo "  PATH: $PATH"
            echo "  LANG: ${LANG:-未设置}"
            echo "  TERM: ${TERM:-未设置}"
            
            # 显示磁盘空间
            echo ""
            echo "磁盘使用情况:"
            df -h / 2>/dev/null || echo "  无法获取磁盘信息"
            
            # 显示内存信息
            echo ""
            echo "内存信息:"
            if [[ "$platform" == "macOS" ]]; then
                vm_stat 2>/dev/null | head -5 || echo "  无法获取内存信息"
            elif [[ "$platform" == "Linux" ]]; then
                free -h 2>/dev/null || echo "  无法获取内存信息"
            fi
        fi
    fi
    
    return 0
}

# 系统状态检查
gs_system_status() {
    local check_type="basic"
    local output_format="table"
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            --basic)
                check_type="basic"
                shift
                ;;
            --detailed)
                check_type="detailed"
                shift
                ;;
            --json)
                output_format="json"
                shift
                ;;
            -h|--help)
                echo "用法: gs-system-status [选项]"
                echo "检查系统状态"
                echo ""
                echo "选项:"
                echo "  --basic                 基础状态检查（默认）"
                echo "  --detailed              详细状态检查"
                echo "  --json                  JSON格式输出"
                echo "  -h, --help              显示此帮助信息"
                return 0
                ;;
            *)
                echo "错误: 未知参数 $1"
                return 1
                ;;
        esac
    done
    
    # 基础检查项目
    local platform
    platform=$(_gs_system_check_platform)
    
    # 检查重要工具
    local tools_status=()
    tools_status+=("Git:$(command -v git >/dev/null && echo "✅" || echo "❌")")
    tools_status+=("Curl:$(command -v curl >/dev/null && echo "✅" || echo "❌")")
    tools_status+=("Wget:$(command -v wget >/dev/null && echo "✅" || echo "❌")")
    
    if [[ "$platform" == "macOS" ]]; then
        tools_status+=("Brew:$(command -v brew >/dev/null && echo "✅" || echo "❌")")
        tools_status+=("Xcode Tools:$(xcode-select -p >/dev/null 2>&1 && echo "✅" || echo "❌")")
    fi
    
    # 检查网络连接
    local network_status="❌"
    if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        network_status="✅"
    fi
    
    # 检查代理设置
    local proxy_status="❌"
    if [[ -n "$http_proxy" ]] || [[ -n "$HTTP_PROXY" ]]; then
        proxy_status="✅ (已设置)"
    else
        proxy_status="⚪ (未设置)"
    fi
    
    if [[ "$output_format" == "json" ]]; then
        # JSON格式输出
        local tools_json=""
        for tool in "${tools_status[@]}"; do
            local name="${tool%%:*}"
            local status="${tool##*:}"
            local available=$([ "$status" == "✅" ] && echo "true" || echo "false")
            tools_json+=",\"$name\":$available"
        done
        tools_json="${tools_json#,}"
        
        cat <<EOF
{
  "system_status": {
    "platform": "$platform",
    "tools": {$tools_json},
    "network": $([ "$network_status" == "✅" ] && echo "true" || echo "false"),
    "proxy": $([ "$proxy_status" == "✅ (已设置)" ] && echo "true" || echo "false")
  }
}
EOF
    else
        # 表格格式输出
        echo "系统状态检查"
        echo "============"
        echo "平台: $platform"
        echo ""
        echo "工具状态:"
        for tool in "${tools_status[@]}"; do
            local name="${tool%%:*}"
            local status="${tool##*:}"
            printf "  %-15s %s\n" "$name:" "$status"
        done
        echo ""
        echo "网络状态:"
        echo "  网络连接:     $network_status"
        echo "  代理设置:     $proxy_status"
        
        if [[ "$check_type" == "detailed" ]]; then
            echo ""
            echo "详细状态"
            echo "========"
            
            # 显示服务状态
            echo "系统服务:"
            if [[ "$platform" == "macOS" ]]; then
                echo "  SSH:         $(launchctl list | grep -q ssh && echo "✅" || echo "❌")"
            elif [[ "$platform" == "Linux" ]]; then
                echo "  SSH:         $(systemctl is-active ssh 2>/dev/null | grep -q active && echo "✅" || echo "❌")"
            fi
            
            # 显示端口监听
            echo ""
            echo "端口监听:"
            if command -v netstat >/dev/null; then
                echo "  开放端口数: $(netstat -tuln 2>/dev/null | grep LISTEN | wc -l | xargs)"
            else
                echo "  无法获取端口信息"
            fi
        fi
    fi
    
    return 0
}

# 系统配置管理
gs_system_config() {
    local action="$1"
    local key="$2"
    local value="$3"
    
    case $action in
        get)
            if [[ -z "$key" ]]; then
                echo "错误: 请指定配置键名"
                echo "用法: gs-system-config get <key>"
                return 1
            fi
            
            # 获取环境变量
            local env_value
            env_value=$(printenv "$key" 2>/dev/null)
            if [[ -n "$env_value" ]]; then
                echo "$env_value"
            else
                echo "配置项 '$key' 未设置"
                return 1
            fi
            ;;
            
        set)
            if [[ -z "$key" ]] || [[ -z "$value" ]]; then
                echo "错误: 请指定配置键名和值"
                echo "用法: gs-system-config set <key> <value>"
                return 1
            fi
            
            # 设置环境变量（仅当前会话）
            export "$key=$value"
            echo "已设置 $key=$value （当前会话）"
            echo "要永久保存，请添加到 ~/.bashrc 或 ~/.zshrc"
            ;;
            
        list)
            echo "当前环境变量:"
            env | sort | head -20
            echo "..."
            echo "总计: $(env | wc -l | xargs) 个环境变量"
            ;;
            
        *)
            echo "用法: gs-system-config <command> [options]"
            echo ""
            echo "命令:"
            echo "  get <key>           获取配置值"
            echo "  set <key> <value>   设置配置值"
            echo "  list                列出所有配置"
            echo ""
            echo "示例:"
            echo "  gs-system-config get PATH"
            echo "  gs-system-config set MY_VAR value"
            echo "  gs-system-config list"
            return 1
            ;;
    esac
    
    return 0
}

# 帮助信息
gs_system_help() {
    echo "System 系统工具插件"
    echo "=================="
    echo ""
    echo "可用命令:"
    echo "  gs-system-info        显示系统信息"
    echo "  gs-system-status      检查系统状态"
    echo "  gs-system-config      系统配置管理"
    echo "  gs-system-help        显示此帮助信息"
    echo ""
    echo "子模块命令:"
    echo "  gs-system-brew-*      Homebrew包管理器配置"
    echo "  gs-system-proxy-*     系统代理管理"
    echo "  gs-system-repo-*      Git仓库管理"
    echo ""
    echo "常用操作:"
    echo "  1. 查看系统信息:"
    echo "     gs-system-info --detailed"
    echo ""
    echo "  2. 检查系统状态:"
    echo "     gs-system-status --detailed"
    echo ""
    echo "  3. 管理系统代理:"
    echo "     gs-system-proxy-on"
    echo "     gs-system-proxy-off"
    echo ""
    echo "  4. 配置Homebrew镜像:"
    echo "     gs-system-brew-ustc"
    echo "     gs-system-brew-tsinghua"
    echo ""
    echo "使用 'gs-system-<command> --help' 查看特定命令的详细帮助"
    
    return 0
}