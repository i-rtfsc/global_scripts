#!/bin/bash
# Global Scripts V3 - 错误处理框架
# 作者: Solo
# 版本: 1.0.0
# 描述: 统一错误处理，错误码定义，错误恢复建议

# 加载兼容性支持和日志系统 (如果尚未加载)
if ! declare -f gs_log_info >/dev/null 2>&1; then
    source "$(dirname "${BASH_SOURCE[0]:-$0}")/logger.sh"
fi

# 错误码定义 (防止重复定义)
[[ -z "${_GS_ERROR_SUCCESS:-}" ]] && readonly _GS_ERROR_SUCCESS=0           # 成功
[[ -z "${_GS_ERROR_GENERIC:-}" ]] && readonly _GS_ERROR_GENERIC=1           # 通用错误
[[ -z "${_GS_ERROR_INVALID_ARG:-}" ]] && readonly _GS_ERROR_INVALID_ARG=2       # 无效参数
[[ -z "${_GS_ERROR_FILE_NOT_FOUND:-}" ]] && readonly _GS_ERROR_FILE_NOT_FOUND=3    # 文件未找到
[[ -z "${_GS_ERROR_PERMISSION:-}" ]] && readonly _GS_ERROR_PERMISSION=4        # 权限错误
[[ -z "${_GS_ERROR_NETWORK:-}" ]] && readonly _GS_ERROR_NETWORK=5           # 网络错误
[[ -z "${_GS_ERROR_CONFIG:-}" ]] && readonly _GS_ERROR_CONFIG=6            # 配置错误
[[ -z "${_GS_ERROR_DEPENDENCY:-}" ]] && readonly _GS_ERROR_DEPENDENCY=7        # 依赖错误
[[ -z "${_GS_ERROR_TIMEOUT:-}" ]] && readonly _GS_ERROR_TIMEOUT=8           # 超时错误
[[ -z "${_GS_ERROR_DISK_SPACE:-}" ]] && readonly _GS_ERROR_DISK_SPACE=9        # 磁盘空间不足
[[ -z "${_GS_ERROR_MEMORY:-}" ]] && readonly _GS_ERROR_MEMORY=10           # 内存不足
[[ -z "${_GS_ERROR_PLUGIN:-}" ]] && readonly _GS_ERROR_PLUGIN=11           # 插件错误
[[ -z "${_GS_ERROR_COMMAND_NOT_FOUND:-}" ]] && readonly _GS_ERROR_COMMAND_NOT_FOUND=12 # 命令未找到
[[ -z "${_GS_ERROR_UNSUPPORTED:-}" ]] && readonly _GS_ERROR_UNSUPPORTED=13      # 不支持的操作
[[ -z "${_GS_ERROR_INTERRUPTED:-}" ]] && readonly _GS_ERROR_INTERRUPTED=14      # 操作中断
[[ -z "${_GS_ERROR_VALIDATION:-}" ]] && readonly _GS_ERROR_VALIDATION=15       # 验证失败

# 错误消息映射 - 简化为函数实现
_gs_get_error_message() {
    local error_code="$1"
    case "$error_code" in
        "$_GS_ERROR_SUCCESS") echo "操作成功" ;;
        "$_GS_ERROR_GENERIC") echo "通用错误" ;;
        "$_GS_ERROR_INVALID_ARG") echo "无效参数" ;;
        "$_GS_ERROR_FILE_NOT_FOUND") echo "文件未找到" ;;
        "$_GS_ERROR_PERMISSION") echo "权限不足" ;;
        "$_GS_ERROR_NETWORK") echo "网络连接错误" ;;
        "$_GS_ERROR_CONFIG") echo "配置错误" ;;
        "$_GS_ERROR_DEPENDENCY") echo "依赖错误" ;;
        "$_GS_ERROR_TIMEOUT") echo "操作超时" ;;
        "$_GS_ERROR_DISK_SPACE") echo "磁盘空间不足" ;;
        "$_GS_ERROR_MEMORY") echo "内存不足" ;;
        "$_GS_ERROR_PLUGIN") echo "插件错误" ;;
        "$_GS_ERROR_COMMAND_NOT_FOUND") echo "命令未找到" ;;
        "$_GS_ERROR_UNSUPPORTED") echo "不支持的操作" ;;
        "$_GS_ERROR_INTERRUPTED") echo "操作被中断" ;;
        "$_GS_ERROR_VALIDATION") echo "验证失败" ;;
        *) echo "未知错误" ;;
    esac
}

# 错误恢复建议映射 - 简化为函数实现
_gs_get_error_suggestion() {
    local error_code="$1"
    case "$error_code" in
        "$_GS_ERROR_INVALID_ARG") echo "请检查命令参数格式和值" ;;
        "$_GS_ERROR_FILE_NOT_FOUND") echo "请确认文件路径是否正确，文件是否存在" ;;
        "$_GS_ERROR_PERMISSION") echo "请检查文件权限或使用sudo运行" ;;
        "$_GS_ERROR_NETWORK") echo "请检查网络连接和防火墙设置" ;;
        "$_GS_ERROR_CONFIG") echo "请检查配置文件语法和值的正确性" ;;
        "$_GS_ERROR_DEPENDENCY") echo "请安装缺失的依赖包" ;;
        "$_GS_ERROR_TIMEOUT") echo "请重试或增加超时时间" ;;
        "$_GS_ERROR_DISK_SPACE") echo "请清理磁盘空间" ;;
        "$_GS_ERROR_MEMORY") echo "请关闭其他程序释放内存" ;;
        "$_GS_ERROR_PLUGIN") echo "请检查插件配置和依赖" ;;
        "$_GS_ERROR_COMMAND_NOT_FOUND") echo "请安装相关命令或检查PATH环境变量" ;;
        "$_GS_ERROR_UNSUPPORTED") echo "请检查系统兼容性或更新版本" ;;
        "$_GS_ERROR_INTERRUPTED") echo "操作已中断，可以重新运行" ;;
        "$_GS_ERROR_VALIDATION") echo "请检查输入数据格式和完整性" ;;
        *) echo "请查阅文档或联系技术支持" ;;
    esac
}

# 全局错误处理配置
_GS_ERROR_EXIT_ON_ERROR="${_GS_ERROR_EXIT_ON_ERROR:-true}"
_GS_ERROR_SHOW_STACK="${_GS_ERROR_SHOW_STACK:-false}"
_GS_ERROR_LOG_ERRORS="${_GS_ERROR_LOG_ERRORS:-true}"

# 导出配置变量
export _GS_ERROR_EXIT_ON_ERROR _GS_ERROR_SHOW_STACK _GS_ERROR_LOG_ERRORS

# 获取错误消息
gs_error_get_message() {
    local error_code="$1"
    _gs_get_error_message "$error_code"
}

# 获取错误建议
gs_error_get_suggestion() {
    local error_code="$1"
    _gs_get_error_suggestion "$error_code"
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

# =================================================================
# 友好错误信息显示系统 (任务2.4)
# =================================================================

# 友好错误信息显示
gs_error_friendly() {
    local error_code="$1"
    local error_message="$2"
    local context="${3:-未知上下文}"
    
    [[ "$_GS_ERROR_FRIENDLY_MODE" != "true" ]] && {
        gs_error "$error_message"
        return $error_code
    }
    
    local friendly_message
    friendly_message=$(_gs_get_error_message "$error_code")
    local suggestion
    suggestion=$(_gs_get_error_suggestion "$error_code")
    
    # 友好错误格式显示
    echo -e "\n❌ ${_GS_COLOR_RED}出现错误${_GS_COLOR_RESET}"
    echo -e "${_GS_COLOR_BOLD}错误类型:${_GS_COLOR_RESET} $friendly_message"
    echo -e "${_GS_COLOR_BOLD}错误详情:${_GS_COLOR_RESET} $error_message"
    echo -e "${_GS_COLOR_BOLD}发生位置:${_GS_COLOR_RESET} $context"
    
    # 显示恢复建议
    if [[ "$_GS_ERROR_SHOW_RECOVERY" == "true" && -n "$suggestion" ]]; then
        echo -e "\n💡 ${_GS_COLOR_YELLOW}建议解决方案:${_GS_COLOR_RESET}"
        echo -e "   $suggestion"
    fi
    
    # 自动诊断
    if [[ "$_GS_ERROR_AUTO_DIAGNOSE" == "true" ]]; then
        local diagnosis
        diagnosis=$(_gs_auto_diagnose "$error_code" "$error_message")
        if [[ -n "$diagnosis" ]]; then
            echo -e "\n🔍 ${_GS_COLOR_CYAN}自动诊断:${_GS_COLOR_RESET}"
            echo -e "   $diagnosis"
        fi
    fi
    
    echo ""
    
    # 记录错误统计
    _gs_error_update_stats "$error_code"
    
    # 记录日志
    if [[ "$_GS_ERROR_LOG_ERRORS" == "true" ]]; then
        gs_log_error "[$context] $friendly_message: $error_message"
    fi
    
    return $error_code
}

# 常见错误自动诊断
_gs_auto_diagnose() {
    local error_code="$1"
    local error_message="$2"
    
    case "$error_code" in
        "$_GS_ERROR_FILE_NOT_FOUND")
            # 检查文件路径和权限
            if echo "$error_message" | grep -q "/"; then
                local file_path
                file_path=$(echo "$error_message" | grep -o '[^[:space:]]*/[^[:space:]]*' | head -1)
                if [[ -n "$file_path" ]]; then
                    local dir_path
                    dir_path=$(dirname "$file_path")
                    if [[ ! -d "$dir_path" ]]; then
                        echo "目录 '$dir_path' 不存在"
                    elif [[ ! -r "$dir_path" ]]; then
                        echo "目录 '$dir_path' 没有读取权限"
                    else
                        echo "文件 '$file_path' 确实不存在"
                    fi
                fi
            fi
            ;;
        "$_GS_ERROR_PERMISSION")
            # 检查当前用户和权限
            echo "当前用户: $(whoami), UID: $(id -u)"
            if [[ $(id -u) -ne 0 ]]; then
                echo "尝试使用 'sudo' 获取管理员权限"
            fi
            ;;
        "$_GS_ERROR_NETWORK")
            # 检查网络连接
            if command -v ping >/dev/null 2>&1; then
                if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
                    echo "基础网络连接正常，可能是特定服务问题"
                else
                    echo "网络连接不可用，请检查网络设置"
                fi
            fi
            ;;
        "$_GS_ERROR_DEPENDENCY")
            # 检查系统和包管理器
            local os_type
            os_type=$(uname -s)
            case "$os_type" in
                "Darwin")
                    if command -v brew >/dev/null 2>&1; then
                        echo "建议使用 'brew install <package>' 安装依赖"
                    else
                        echo "建议安装 Homebrew 包管理器"
                    fi
                    ;;
                "Linux")
                    if command -v apt >/dev/null 2>&1; then
                        echo "建议使用 'sudo apt install <package>' 安装依赖"
                    elif command -v yum >/dev/null 2>&1; then
                        echo "建议使用 'sudo yum install <package>' 安装依赖"
                    fi
                    ;;
            esac
            ;;
        "$_GS_ERROR_DISK_SPACE")
            # 检查磁盘使用情况
            if command -v df >/dev/null 2>&1; then
                echo "磁盘使用情况: $(df -h / | tail -1 | awk '{print $5 " 已使用"}')"
            fi
            ;;
        "$_GS_ERROR_CONFIG")
            # 检查配置文件
            if [[ -f "$_GS_USER_CONFIG_FILE" ]]; then
                echo "配置文件存在: $_GS_USER_CONFIG_FILE"
                if command -v jq >/dev/null 2>&1 && ! jq . "$_GS_USER_CONFIG_FILE" >/dev/null 2>&1; then
                    echo "配置文件JSON格式错误"
                fi
            else
                echo "用户配置文件不存在，将使用默认配置"
            fi
            ;;
        *)
            # 通用诊断
            echo "错误码: $error_code"
            ;;
    esac
}

# 更新错误统计
_gs_error_update_stats() {
    local error_code="$1"
    
    _GS_ERROR_STATS_TOTAL=$((_GS_ERROR_STATS_TOTAL + 1))
    
    # 简单的统计更新（避免关联数组）
    local error_name
    error_name=$(_gs_get_error_message "$error_code")
    if echo "$_GS_ERROR_STATS_BY_TYPE" | grep -q "$error_name:"; then
        # 更新现有统计
        local count
        count=$(echo "$_GS_ERROR_STATS_BY_TYPE" | grep -o "$error_name:[0-9]*" | cut -d':' -f2)
        count=$((count + 1))
        _GS_ERROR_STATS_BY_TYPE=$(echo "$_GS_ERROR_STATS_BY_TYPE" | sed "s/$error_name:[0-9]*/$error_name:$count/")
    else
        # 添加新统计
        if [[ -n "$_GS_ERROR_STATS_BY_TYPE" ]]; then
            _GS_ERROR_STATS_BY_TYPE="$_GS_ERROR_STATS_BY_TYPE|$error_name:1"
        else
            _GS_ERROR_STATS_BY_TYPE="$error_name:1"
        fi
    fi
}

# 显示错误统计
gs_error_show_stats() {
    local format="${1:-text}"
    
    if [[ "$format" == "json" ]]; then
        echo "{"
        echo "  \"total_errors\": $_GS_ERROR_STATS_TOTAL,"
        echo "  \"error_types\": {"
        
        if [[ -n "$_GS_ERROR_STATS_BY_TYPE" ]]; then
            local first=true
            local entry
            local IFS_backup="$IFS"
            IFS='|'
            for entry in $_GS_ERROR_STATS_BY_TYPE; do
                local error_name count
                error_name=$(echo "$entry" | cut -d':' -f1)
                count=$(echo "$entry" | cut -d':' -f2)
                
                [[ "$first" == "true" ]] && first=false || echo ","
                echo "    \"$error_name\": $count"
            done
            IFS="$IFS_backup"
            echo ""
        fi
        
        echo "  }"
        echo "}"
    else
        echo "📊 错误统计报告"
        echo "==============="
        echo "总错误数: $_GS_ERROR_STATS_TOTAL"
        echo ""
        
        if [[ -n "$_GS_ERROR_STATS_BY_TYPE" ]]; then
            echo "错误类型分布:"
            local entry
            local IFS_backup="$IFS"
            IFS='|'
            for entry in $_GS_ERROR_STATS_BY_TYPE; do
                local error_name count
                error_name=$(echo "$entry" | cut -d':' -f1)
                count=$(echo "$entry" | cut -d':' -f2)
                printf "  %-20s: %d\n" "$error_name" "$count"
            done
            IFS="$IFS_backup"
        else
            echo "暂无错误记录"
        fi
    fi
}

# 清除错误统计
gs_error_clear_stats() {
    _GS_ERROR_STATS_TOTAL=0
    _GS_ERROR_STATS_BY_TYPE=""
    gs_log_info "错误统计已清除"
}

# 错误恢复助手
gs_error_recovery_helper() {
    local error_code="$1"
    local auto_fix="${2:-false}"
    
    local error_name
    error_name=$(_gs_get_error_message "$error_code")
    
    echo "🛠️  错误恢复助手: $error_name"
    echo "============================="
    
    case "$error_code" in
        "$_GS_ERROR_CONFIG")
            echo "配置问题恢复选项:"
            echo "1. 重置配置到默认值: gs-config-reset"
            echo "2. 验证配置文件: gs-config-validate"
            echo "3. 备份当前配置: gs-config-backup"
            
            if [[ "$auto_fix" == "true" ]]; then
                echo "\n🔧 尝试自动修复..."
                if gs_config_validate >/dev/null 2>&1; then
                    echo "✅ 配置验证通过"
                else
                    echo "❌ 配置验证失败，重置为默认配置"
                    gs_config_reset
                fi
            fi
            ;;
        "$_GS_ERROR_DEPENDENCY")
            echo "依赖问题恢复选项:"
            echo "1. 检查系统状态: gs-status"
            echo "2. 重新初始化: source gs_env.sh"
            
            if [[ "$auto_fix" == "true" ]]; then
                echo "\n🔧 尝试自动修复..."
                echo "重新初始化系统..."
                # 这里可以添加自动修复逻辑
            fi
            ;;
        "$_GS_ERROR_PERMISSION")
            echo "权限问题恢复选项:"
            echo "1. 检查文件权限: ls -la"
            echo "2. 修复权限: chmod 755 <file>"
            echo "3. 使用管理员权限: sudo <command>"
            ;;
        *)
            echo "通用恢复选项:"
            echo "1. 查看系统状态: gs-status"
            echo "2. 查看日志: tail ~/.local/share/global_scripts/logs/gs.log"
            echo "3. 重启系统: source gs_env.sh"
            ;;
    esac
    
    echo ""
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

# ===================================
# 任务2.4: 错误处理完善
# ===================================

# 2.4.1 友好错误信息显示
gs_format_error() {
    local message="$1"
    local format="${2:-text}"
    local error_code="${3:-$_GS_ERROR_GENERIC}"
    
    case "$format" in
        json)
            local json_output
            json_output=$(printf '{"status": "error", "code": %d, "message": "%s", "suggestion": "%s", "timestamp": "%s"}' \
                "$error_code" "$message" "$(gs_error_get_suggestion "$error_code")" "$(date -Iseconds)")
            echo "$json_output" | jq . 2>/dev/null || echo "$json_output"
            ;;
        *)
            # 使用颜色和图标增强可读性
            if [[ "${_GS_NO_COLOR:-}" != "1" ]]; then
                printf "\033[31m❌ 错误\033[0m: %s\n" "$message" >&2
                printf "\033[33m💡 建议\033[0m: %s\n" "$(gs_error_get_suggestion "$error_code")" >&2
            else
                printf "❌ 错误: %s\n" "$message" >&2
                printf "💡 建议: %s\n" "$(gs_error_get_suggestion "$error_code")" >&2
            fi
            ;;
    esac
}

gs_format_success() {
    local message="$1"
    local format="${2:-text}"
    
    case "$format" in
        json)
            local json_output
            json_output=$(printf '{"status": "success", "message": "%s", "timestamp": "%s"}' \
                "$message" "$(date -Iseconds)")
            echo "$json_output" | jq . 2>/dev/null || echo "$json_output"
            ;;
        *)
            if [[ "${_GS_NO_COLOR:-}" != "1" ]]; then
                printf "\033[32m✅ 成功\033[0m: %s\n" "$message"
            else
                printf "✅ 成功: %s\n" "$message"
            fi
            ;;
    esac
}

gs_format_warning() {
    local message="$1"
    local format="${2:-text}"
    
    case "$format" in
        json)
            local json_output
            json_output=$(printf '{"status": "warning", "message": "%s", "timestamp": "%s"}' \
                "$message" "$(date -Iseconds)")
            echo "$json_output" | jq . 2>/dev/null || echo "$json_output"
            ;;
        *)
            if [[ "${_GS_NO_COLOR:-}" != "1" ]]; then
                printf "\033[33m⚠️  警告\033[0m: %s\n" "$message" >&2
            else
                printf "⚠️  警告: %s\n" "$message" >&2
            fi
            ;;
    esac
}

gs_format_info() {
    local message="$1"
    local format="${2:-text}"
    
    case "$format" in
        json)
            local json_output
            json_output=$(printf '{"status": "info", "message": "%s", "timestamp": "%s"}' \
                "$message" "$(date -Iseconds)")
            echo "$json_output" | jq . 2>/dev/null || echo "$json_output"
            ;;
        *)
            if [[ "${_GS_NO_COLOR:-}" != "1" ]]; then
                printf "\033[34mℹ️  信息\033[0m: %s\n" "$message"
            else
                printf "ℹ️  信息: %s\n" "$message"
            fi
            ;;
    esac
}

# 2.4.2 错误恢复建议系统增强
gs_error_suggest_recovery() {
    local error_code="$1"
    local context="${2:-}"
    local format="${3:-text}"
    
    local base_suggestion
    base_suggestion="$(gs_error_get_suggestion "$error_code")"
    
    # 根据上下文提供更具体的建议 - 使用换行分隔而不是管道
    local specific_suggestions=""
    case "$error_code" in
        "$_GS_ERROR_FILE_NOT_FOUND")
            if [[ "$context" == *"config"* ]]; then
                specific_suggestions="运行 'gs-config-init' 初始化配置文件
检查配置目录权限: $HOME/.gs/"
            elif [[ "$context" == *"plugin"* ]]; then
                specific_suggestions="运行 'gs-plugins-list' 查看可用插件
检查插件是否正确安装"
            fi
            ;;
        "$_GS_ERROR_PERMISSION")
            specific_suggestions="检查文件所有者: ls -la <文件路径>
尝试使用 sudo 运行命令
修改文件权限: chmod +r <文件路径>"
            ;;
        "$_GS_ERROR_DEPENDENCY")
            if [[ "$context" == *"python"* ]]; then
                specific_suggestions="安装Python: brew install python (macOS) 或 apt install python3 (Ubuntu)
检查Python路径: which python3"
            elif [[ "$context" == *"jq"* ]]; then
                specific_suggestions="安装jq: brew install jq (macOS) 或 apt install jq (Ubuntu)"
            fi
            ;;
        "$_GS_ERROR_CONFIG")
            specific_suggestions="验证配置文件: gs-config-validate
重置为默认配置: gs-config-reset
查看配置Schema: gs-config-schema show"
            ;;
    esac
    
    case "$format" in
        json)
            local suggestions_json="[]"
            if [[ -n "$specific_suggestions" ]]; then
                # 将换行分隔的字符串转换为JSON数组
                local suggestions_str=""
                # 使用while循环读取每一行
                while IFS= read -r suggestion; do
                    if [[ -n "$suggestion" ]]; then
                        suggestions_str="$suggestions_str\"$suggestion\","
                    fi
                done <<< "$specific_suggestions"
                suggestions_str="${suggestions_str%,}"  # 移除最后的逗号
                suggestions_json="[$suggestions_str]"
            fi
            
            local json_output
            json_output=$(printf '{"base_suggestion": "%s", "specific_suggestions": %s, "context": "%s"}' \
                "$base_suggestion" "$suggestions_json" "$context")
            echo "$json_output" | jq . 2>/dev/null || echo "$json_output"
            ;;
        *)
            echo "💡 恢复建议:"
            echo "   基本建议: $base_suggestion"
            if [[ -n "$specific_suggestions" ]]; then
                echo "   具体步骤:"
                # 使用while循环读取每一行
                local i=1
                while IFS= read -r suggestion; do
                    if [[ -n "$suggestion" ]]; then
                        printf "   %d. %s\n" $i "$suggestion"
                        ((i++))
                    fi
                done <<< "$specific_suggestions"
            fi
            ;;
    esac
}

# 2.4.3 常见错误自动诊断
gs_error_diagnose() {
    local error_type="$1"
    local context="${2:-}"
    local format="${3:-text}"
    
    local diagnosis_result=""
    local error_code=$_GS_ERROR_GENERIC
    local auto_fix_available=false
    local auto_fix_command=""
    
    case "$error_type" in
        "config_not_found")
            diagnosis_result="配置文件不存在或无法访问"
            error_code=$_GS_ERROR_FILE_NOT_FOUND
            
            # 自动诊断配置问题
            local config_file="${context:-$HOME/.gs/config.json}"
            if [[ ! -d "$(dirname "$config_file")" ]]; then
                diagnosis_result="$diagnosis_result\n   原因: 配置目录不存在"
                auto_fix_available=true
                auto_fix_command="mkdir -p $(dirname "$config_file")"
            elif [[ ! -r "$config_file" ]]; then
                diagnosis_result="$diagnosis_result\n   原因: 配置文件权限问题"
                auto_fix_available=true
                auto_fix_command="chmod +r $config_file"
            fi
            ;;
            
        "python_not_found")
            diagnosis_result="Python环境未找到或不可用"
            error_code=$_GS_ERROR_DEPENDENCY
            
            # 检查Python安装情况
            if ! command -v python3 >/dev/null 2>&1 && ! command -v python >/dev/null 2>&1; then
                diagnosis_result="$diagnosis_result\n   原因: 系统未安装Python"
                if command -v brew >/dev/null 2>&1; then
                    auto_fix_available=true
                    auto_fix_command="brew install python"
                elif command -v apt >/dev/null 2>&1; then
                    auto_fix_available=true
                    auto_fix_command="sudo apt update && sudo apt install python3"
                fi
            fi
            ;;
            
        "permission_denied")
            diagnosis_result="权限被拒绝"
            error_code=$_GS_ERROR_PERMISSION
            
            # 检查具体权限问题
            local target_file="$context"
            if [[ -n "$target_file" && -f "$target_file" ]]; then
                local file_perms
                file_perms=$(ls -la "$target_file" 2>/dev/null | awk '{print $1}')
                diagnosis_result="$diagnosis_result\n   文件权限: $file_perms"
                
                if [[ ! -r "$target_file" ]]; then
                    diagnosis_result="$diagnosis_result\n   原因: 缺少读取权限"
                    auto_fix_available=true
                    auto_fix_command="chmod +r $target_file"
                fi
            fi
            ;;
            
        "command_not_found")
            diagnosis_result="命令未找到"
            error_code=$_GS_ERROR_COMMAND_NOT_FOUND
            
            local command_name="$context"
            if [[ -n "$command_name" ]]; then
                diagnosis_result="$diagnosis_result: $command_name"
                
                # 检查常见命令的安装建议
                case "$command_name" in
                    "jq")
                        if command -v brew >/dev/null 2>&1; then
                            auto_fix_available=true
                            auto_fix_command="brew install jq"
                        elif command -v apt >/dev/null 2>&1; then
                            auto_fix_available=true
                            auto_fix_command="sudo apt install jq"
                        fi
                        ;;
                    "curl")
                        if command -v apt >/dev/null 2>&1; then
                            auto_fix_available=true
                            auto_fix_command="sudo apt install curl"
                        fi
                        ;;
                    "git")
                        if command -v brew >/dev/null 2>&1; then
                            auto_fix_available=true
                            auto_fix_command="brew install git"
                        elif command -v apt >/dev/null 2>&1; then
                            auto_fix_available=true
                            auto_fix_command="sudo apt install git"
                        fi
                        ;;
                esac
            fi
            ;;
            
        "network_error")
            diagnosis_result="网络连接问题"
            error_code=$_GS_ERROR_NETWORK
            
            # 简单网络连接测试
            if ! ping -c 1 8.8.8.8 >/dev/null 2>&1; then
                diagnosis_result="$diagnosis_result\n   原因: 无法连接到互联网"
            elif ! nslookup google.com >/dev/null 2>&1; then
                diagnosis_result="$diagnosis_result\n   原因: DNS解析问题"
            fi
            ;;
    esac
    
    case "$format" in
        json)
            local json_output
            json_output=$(printf '{"error_type": "%s", "diagnosis": "%s", "error_code": %d, "auto_fix_available": %s, "auto_fix_command": "%s"}' \
                "$error_type" "$diagnosis_result" "$error_code" "$auto_fix_available" "$auto_fix_command")
            echo "$json_output" | jq . 2>/dev/null || echo "$json_output"
            ;;
        *)
            echo "🔍 错误诊断结果:"
            echo -e "   $diagnosis_result"
            
            if [[ "$auto_fix_available" == "true" ]]; then
                echo
                echo "🔧 自动修复建议:"
                echo "   运行命令: $auto_fix_command"
                echo
                echo "   要执行自动修复，请运行:"
                echo "   gs-tools-doctor --fix"
            fi
            
            # 显示恢复建议
            echo
            gs_error_suggest_recovery "$error_code" "$context" "$format"
            ;;
    esac
    
    return $error_code
}

# 智能错误分析 (结合诊断和建议)
gs_error_analyze() {
    local error_message="$1"
    local context="${2:-}"
    local format="${3:-text}"
    
    # 根据错误消息自动判断错误类型
    local error_type=""
    if [[ "$error_message" == *"No such file"* ]] || [[ "$error_message" == *"not found"* ]]; then
        if [[ "$error_message" == *"config"* ]]; then
            error_type="config_not_found"
        else
            error_type="command_not_found"
        fi
    elif [[ "$error_message" == *"Permission denied"* ]]; then
        error_type="permission_denied"
    elif [[ "$error_message" == *"python"* ]] || [[ "$error_message" == *"Python"* ]]; then
        error_type="python_not_found"
    elif [[ "$error_message" == *"network"* ]] || [[ "$error_message" == *"connection"* ]]; then
        error_type="network_error"
    fi
    
    if [[ -n "$error_type" ]]; then
        gs_error_diagnose "$error_type" "$context" "$format"
    else
        # 通用错误处理
        gs_format_error "$error_message" "$format"
    fi
}

# 错误处理统计 - 避免使用declare -g，改用简单变量
_GS_ERROR_STATS_TOTAL=0
_GS_ERROR_STATS_BY_TYPE=""

# 友好错误信息配置
_GS_ERROR_FRIENDLY_MODE="${_GS_ERROR_FRIENDLY_MODE:-true}"
_GS_ERROR_AUTO_DIAGNOSE="${_GS_ERROR_AUTO_DIAGNOSE:-true}"
_GS_ERROR_SHOW_RECOVERY="${_GS_ERROR_SHOW_RECOVERY:-true}"

# 导出友好错误配置
export _GS_ERROR_FRIENDLY_MODE _GS_ERROR_AUTO_DIAGNOSE _GS_ERROR_SHOW_RECOVERY

gs_error_record_stats() {
    local error_code="$1"
    _GS_ERROR_STATS_TOTAL=$((${_GS_ERROR_STATS_TOTAL} + 1))
    
    # 简单统计，避免使用关联数组
    local error_name
    error_name="$(gs_error_get_message "$error_code" | tr ' ' '_')"
    _GS_ERROR_STATS_BY_TYPE="$_GS_ERROR_STATS_BY_TYPE $error_name"
}

gs_error_show_stats() {
    local format="${1:-text}"
    
    case "$format" in
        json)
            local json_output
            json_output=$(printf '{"total_errors": %d, "error_types": "%s"}' \
                "$_GS_ERROR_STATS_TOTAL" "$_GS_ERROR_STATS_BY_TYPE")
            echo "$json_output" | jq . 2>/dev/null || echo "$json_output"
            ;;
        *)
            echo "📊 错误统计:"
            echo "   总错误数: $_GS_ERROR_STATS_TOTAL"
            if [[ -n "$_GS_ERROR_STATS_BY_TYPE" ]]; then
                echo "   错误类型: $_GS_ERROR_STATS_BY_TYPE"
            fi
            ;;
    esac
}

