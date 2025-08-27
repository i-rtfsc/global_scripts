#!/bin/bash
# 系统代理管理子模块
# System Proxy Management Submodule
# 提供系统代理配置和管理功能

# 默认代理配置
_GS_PROXY_DEFAULT_IP="127.0.0.1"
_GS_PROXY_DEFAULT_PORT="7890"
_GS_PROXY_CONFIG_FILE="$HOME/.gs_proxy_config"

# 加载代理配置
_gs_system_proxy_load_config() {
    local ip="$_GS_PROXY_DEFAULT_IP"
    local port="$_GS_PROXY_DEFAULT_PORT"
    
    # 从配置文件加载
    if [[ -f "$_GS_PROXY_CONFIG_FILE" ]]; then
        source "$_GS_PROXY_CONFIG_FILE"
        ip="${GS_PROXY_IP:-$_GS_PROXY_DEFAULT_IP}"
        port="${GS_PROXY_PORT:-$_GS_PROXY_DEFAULT_PORT}"
    fi
    
    echo "$ip:$port"
}

# 保存代理配置
_gs_system_proxy_save_config() {
    local ip="$1"
    local port="$2"
    
    cat > "$_GS_PROXY_CONFIG_FILE" <<EOF
# Global Scripts Proxy Configuration
# 代理配置文件
GS_PROXY_IP="$ip"
GS_PROXY_PORT="$port"
EOF
    
    echo "代理配置已保存到: $_GS_PROXY_CONFIG_FILE"
}

# 检查代理连接
_gs_system_proxy_check_connection() {
    local proxy_url="$1"
    local timeout="${2:-5}"
    
    # 使用curl测试代理连接
    if command -v curl >/dev/null 2>&1; then
        if curl --proxy "$proxy_url" --connect-timeout "$timeout" --silent --head "http://www.google.com" >/dev/null 2>&1; then
            return 0
        fi
    fi
    
    return 1
}

# 开启系统代理
gs_system_proxy_on() {
    local ip=""
    local port=""
    local test_connection=true
    local save_config=false
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -i|--ip)
                ip="$2"
                shift 2
                ;;
            -p|--port)
                port="$2"
                shift 2
                ;;
            --no-test)
                test_connection=false
                shift
                ;;
            --save)
                save_config=true
                shift
                ;;
            -h|--help)
                echo "用法: gs-system-proxy-on [选项]"
                echo "开启系统代理"
                echo ""
                echo "选项:"
                echo "  -i, --ip IP             代理服务器IP (默认: $_GS_PROXY_DEFAULT_IP)"
                echo "  -p, --port PORT         代理服务器端口 (默认: $_GS_PROXY_DEFAULT_PORT)"
                echo "  --no-test               跳过连接测试"
                echo "  --save                  保存配置到文件"
                echo "  -h, --help              显示此帮助信息"
                echo ""
                echo "示例:"
                echo "  gs-system-proxy-on                      # 使用默认配置"
                echo "  gs-system-proxy-on -i 127.0.0.1 -p 8080 # 指定IP和端口"
                echo "  gs-system-proxy-on --save               # 保存配置"
                return 0
                ;;
            *)
                echo "错误: 未知参数 $1"
                return 1
                ;;
        esac
    done
    
    # 如果未指定，从配置加载或使用默认值
    if [[ -z "$ip" ]] || [[ -z "$port" ]]; then
        local config
        config=$(_gs_system_proxy_load_config)
        ip="${ip:-${config%:*}}"
        port="${port:-${config#*:}}"
    fi
    
    # 验证IP和端口
    if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] && [[ "$ip" != "localhost" ]]; then
        echo "错误: 无效的IP地址: $ip"
        return 1
    fi
    
    if [[ ! "$port" =~ ^[0-9]+$ ]] || [[ "$port" -lt 1 ]] || [[ "$port" -gt 65535 ]]; then
        echo "错误: 无效的端口号: $port"
        return 1
    fi
    
    local proxy_url="http://${ip}:${port}"
    
    # 测试代理连接
    if [[ "$test_connection" == true ]]; then
        echo "正在测试代理连接: $proxy_url"
        if ! _gs_system_proxy_check_connection "$proxy_url"; then
            echo "⚠️ 警告: 代理服务器连接测试失败"
            read -p "是否继续设置代理? (y/N): " confirm
            if [[ ! $confirm =~ ^[Yy]$ ]]; then
                echo "代理设置已取消"
                return 1
            fi
        else
            echo "✅ 代理连接测试成功"
        fi
    fi
    
    # 设置代理环境变量
    export http_proxy="$proxy_url"
    export https_proxy="$proxy_url" 
    export HTTP_PROXY="$proxy_url"
    export HTTPS_PROXY="$proxy_url"
    export no_proxy="localhost,127.0.0.1,::1"
    export NO_PROXY="localhost,127.0.0.1,::1"
    
    echo "✅ 系统代理已开启"
    echo "   HTTP/HTTPS: $proxy_url"
    echo "   排除地址: $no_proxy"
    
    # 保存配置
    if [[ "$save_config" == true ]]; then
        _gs_system_proxy_save_config "$ip" "$port"
    fi
    
    # 显示使用建议
    echo ""
    echo "💡 使用建议:"
    echo "   - 使用 'gs-system-proxy-status' 检查代理状态"
    echo "   - 使用 'gs-system-proxy-off' 关闭代理"
    echo "   - 当前设置仅对当前Shell会话有效"
    
    return 0
}

# 关闭系统代理
gs_system_proxy_off() {
    local show_status=true
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -q|--quiet)
                show_status=false
                shift
                ;;
            -h|--help)
                echo "用法: gs-system-proxy-off [选项]"
                echo "关闭系统代理"
                echo ""
                echo "选项:"
                echo "  -q, --quiet             静默模式，不显示状态信息"
                echo "  -h, --help              显示此帮助信息"
                return 0
                ;;
            *)
                echo "错误: 未知参数 $1"
                return 1
                ;;
        esac
    done
    
    # 检查是否有代理设置
    local had_proxy=false
    if [[ -n "$http_proxy" ]] || [[ -n "$HTTP_PROXY" ]] || [[ -n "$https_proxy" ]] || [[ -n "$HTTPS_PROXY" ]]; then
        had_proxy=true
    fi
    
    # 清除代理环境变量
    unset http_proxy
    unset https_proxy
    unset HTTP_PROXY
    unset HTTPS_PROXY
    unset no_proxy
    unset NO_PROXY
    
    if [[ "$show_status" == true ]]; then
        if [[ "$had_proxy" == true ]]; then
            echo "✅ 系统代理已关闭"
        else
            echo "ℹ️ 系统代理本来就是关闭状态"
        fi
        
        echo ""
        echo "💡 提示:"
        echo "   - 使用 'gs-system-proxy-status' 验证代理状态"
        echo "   - 当前设置仅对当前Shell会话有效"
    fi
    
    return 0
}

# 显示代理状态
gs_system_proxy_status() {
    local output_format="table" 
    local test_connection=false
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            --json)
                output_format="json"
                shift
                ;;
            -t|--test)
                test_connection=true
                shift
                ;;
            -h|--help)
                echo "用法: gs-system-proxy-status [选项]"
                echo "显示系统代理状态"
                echo ""
                echo "选项:"
                echo "  --json                  JSON格式输出"
                echo "  -t, --test              测试代理连接"
                echo "  -h, --help              显示此帮助信息"
                return 0
                ;;
            *)
                echo "错误: 未知参数 $1"
                return 1
                ;;
        esac
    done
    
    # 检查代理状态
    local proxy_enabled=false
    local http_proxy_value="${http_proxy:-$HTTP_PROXY}"
    local https_proxy_value="${https_proxy:-$HTTPS_PROXY}"
    local no_proxy_value="${no_proxy:-$NO_PROXY}"
    
    if [[ -n "$http_proxy_value" ]] || [[ -n "$https_proxy_value" ]]; then
        proxy_enabled=true
    fi
    
    # 连接测试结果
    local connection_status="未测试"
    if [[ "$test_connection" == true ]] && [[ "$proxy_enabled" == true ]]; then
        local test_proxy="${http_proxy_value:-$https_proxy_value}"
        if _gs_system_proxy_check_connection "$test_proxy"; then
            connection_status="连接正常"
        else
            connection_status="连接失败"
        fi
    fi
    
    if [[ "$output_format" == "json" ]]; then
        # JSON格式输出
        cat <<EOF
{
  "proxy_status": {
    "enabled": $proxy_enabled,
    "http_proxy": "${http_proxy_value:-null}",
    "https_proxy": "${https_proxy_value:-null}",
    "no_proxy": "${no_proxy_value:-null}",
    "connection_test": "$connection_status"
  }
}
EOF
    else
        # 表格格式输出
        echo "系统代理状态"
        echo "============"
        
        if [[ "$proxy_enabled" == true ]]; then
            echo "状态:       ✅ 已启用"
            echo "HTTP代理:   ${http_proxy_value:-未设置}"
            echo "HTTPS代理:  ${https_proxy_value:-未设置}"
            echo "排除地址:   ${no_proxy_value:-未设置}"
            
            if [[ "$test_connection" == true ]]; then
                case $connection_status in
                    "连接正常")
                        echo "连接测试:   ✅ $connection_status"
                        ;;
                    "连接失败")
                        echo "连接测试:   ❌ $connection_status"
                        ;;
                    *)
                        echo "连接测试:   ⚪ $connection_status"
                        ;;
                esac
            fi
        else
            echo "状态:       ❌ 未启用"
            echo ""
            echo "💡 使用 'gs-system-proxy-on' 开启代理"
        fi
        
        # 显示配置文件信息
        if [[ -f "$_GS_PROXY_CONFIG_FILE" ]]; then
            echo ""
            echo "配置文件:   $_GS_PROXY_CONFIG_FILE"
            local config
            config=$(_gs_system_proxy_load_config)
            echo "默认配置:   ${config}"
        fi
    fi
    
    return 0
}

# 配置代理设置
gs_system_proxy_config() {
    local action="$1"
    local key="$2"
    local value="$3"
    
    case $action in
        get)
            if [[ -z "$key" ]]; then
                echo "当前代理配置:"
                if [[ -f "$_GS_PROXY_CONFIG_FILE" ]]; then
                    cat "$_GS_PROXY_CONFIG_FILE"
                else
                    echo "配置文件不存在，使用默认配置:"
                    echo "GS_PROXY_IP=\"$_GS_PROXY_DEFAULT_IP\""
                    echo "GS_PROXY_PORT=\"$_GS_PROXY_DEFAULT_PORT\""
                fi
                return 0
            fi
            
            # 获取特定配置项
            if [[ -f "$_GS_PROXY_CONFIG_FILE" ]]; then
                local config_value
                config_value=$(grep "^$key=" "$_GS_PROXY_CONFIG_FILE" | cut -d'=' -f2 | tr -d '"')
                if [[ -n "$config_value" ]]; then
                    echo "$config_value"
                else
                    echo "配置项 '$key' 未找到"
                    return 1
                fi
            else
                echo "配置文件不存在"
                return 1
            fi
            ;;
            
        set)
            if [[ -z "$key" ]] || [[ -z "$value" ]]; then
                echo "错误: 请指定配置项和值"
                echo "用法: gs-system-proxy-config set <key> <value>"
                return 1
            fi
            
            # 验证配置项
            case $key in
                GS_PROXY_IP)
                    if [[ ! "$value" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] && [[ "$value" != "localhost" ]]; then
                        echo "错误: 无效的IP地址: $value"
                        return 1
                    fi
                    ;;
                GS_PROXY_PORT)
                    if [[ ! "$value" =~ ^[0-9]+$ ]] || [[ "$value" -lt 1 ]] || [[ "$value" -gt 65535 ]]; then
                        echo "错误: 无效的端口号: $value"
                        return 1
                    fi
                    ;;
                *)
                    echo "错误: 未知的配置项: $key"
                    echo "支持的配置项: GS_PROXY_IP, GS_PROXY_PORT"
                    return 1
                    ;;
            esac
            
            # 更新配置文件
            local temp_file="/tmp/gs_proxy_config.tmp"
            if [[ -f "$_GS_PROXY_CONFIG_FILE" ]]; then
                # 更新现有配置
                grep -v "^$key=" "$_GS_PROXY_CONFIG_FILE" > "$temp_file" 2>/dev/null || true
                echo "$key=\"$value\"" >> "$temp_file"
                mv "$temp_file" "$_GS_PROXY_CONFIG_FILE"
            else
                # 创建新配置文件
                mkdir -p "$(dirname "$_GS_PROXY_CONFIG_FILE")"
                echo "# Global Scripts Proxy Configuration" > "$_GS_PROXY_CONFIG_FILE"
                echo "$key=\"$value\"" >> "$_GS_PROXY_CONFIG_FILE"
            fi
            
            echo "配置已更新: $key=$value"
            ;;
            
        reset)
            if [[ -f "$_GS_PROXY_CONFIG_FILE" ]]; then
                rm "$_GS_PROXY_CONFIG_FILE"
                echo "配置文件已删除，恢复默认设置"
            else
                echo "配置文件不存在，无需重置"
            fi
            ;;
            
        *)
            echo "用法: gs-system-proxy-config <command> [options]"
            echo ""
            echo "命令:"
            echo "  get [key]               获取配置（不指定key则显示全部）"
            echo "  set <key> <value>       设置配置项"
            echo "  reset                   重置为默认配置"
            echo ""
            echo "配置项:"
            echo "  GS_PROXY_IP             代理服务器IP地址"
            echo "  GS_PROXY_PORT           代理服务器端口"
            echo ""
            echo "示例:"
            echo "  gs-system-proxy-config get"
            echo "  gs-system-proxy-config set GS_PROXY_IP 127.0.0.1"
            echo "  gs-system-proxy-config set GS_PROXY_PORT 8080"
            echo "  gs-system-proxy-config reset"
            return 1
            ;;
    esac
    
    return 0
}

# 代理切换
gs_system_proxy_toggle() {
    # 检查当前代理状态
    if [[ -n "$http_proxy" ]] || [[ -n "$HTTP_PROXY" ]] || [[ -n "$https_proxy" ]] || [[ -n "$HTTPS_PROXY" ]]; then
        echo "检测到代理已启用，正在关闭..."
        gs_system_proxy_off
    else
        echo "检测到代理未启用，正在开启..."
        gs_system_proxy_on
    fi
    
    return $?
}

# 帮助信息
gs_system_proxy_help() {
    echo "System Proxy 子模块 - 系统代理管理"
    echo "==============================="
    echo ""
    echo "可用命令:"
    echo "  gs-system-proxy-on        开启系统代理"
    echo "  gs-system-proxy-off       关闭系统代理"
    echo "  gs-system-proxy-status    显示代理状态"
    echo "  gs-system-proxy-config    配置代理设置"
    echo "  gs-system-proxy-toggle    切换代理状态"
    echo "  gs-system-proxy-help      显示此帮助信息"
    echo ""
    echo "常用操作:"
    echo "  1. 开启代理（默认配置）:"
    echo "     gs-system-proxy-on"
    echo ""
    echo "  2. 开启代理（指定IP和端口）:"
    echo "     gs-system-proxy-on -i 127.0.0.1 -p 8080"
    echo ""
    echo "  3. 检查代理状态:"
    echo "     gs-system-proxy-status"
    echo "     gs-system-proxy-status --test    # 包含连接测试"
    echo ""
    echo "  4. 关闭代理:"
    echo "     gs-system-proxy-off"
    echo ""
    echo "  5. 配置管理:"
    echo "     gs-system-proxy-config get"
    echo "     gs-system-proxy-config set GS_PROXY_IP 192.168.1.100"
    echo ""
    echo "  6. 快速切换:"
    echo "     gs-system-proxy-toggle"
    echo ""
    echo "环境变量说明:"
    echo "  http_proxy/HTTP_PROXY     HTTP代理设置"
    echo "  https_proxy/HTTPS_PROXY   HTTPS代理设置"
    echo "  no_proxy/NO_PROXY         代理排除列表"
    echo ""
    echo "注意事项:"
    echo "  - 代理设置仅对当前Shell会话有效"
    echo "  - 要永久设置，请将export语句添加到~/.bashrc或~/.zshrc"
    echo "  - 使用--save选项可以保存配置到文件"
    
    return 0
}