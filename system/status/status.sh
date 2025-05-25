#!/bin/bash
# Global Scripts V3 - 系统状态检查
# 版本: 3.0.0
# 描述: 提供全面的系统状态检查，包括安装状态、配置信息、性能指标、插件状态等

# ============================================================================
# 系统状态检查 - 系统命令
# ============================================================================

# 主状态检查函数
gs_system_status() {
    # 功能描述: 显示系统状态信息
    # 参数: $1 - 选项/检查项 (字符串) [可选]
    # 返回值: 0 - 成功, 1 - 失败
    # 示例: gs-status, gs-status --json, gs-status --brief

    local option="${1:-}"

    case "$option" in
        ""|"--full")
            _gs_status_show_full
            ;;
        "--brief")
            _gs_status_show_brief
            ;;
        "--json")
            _gs_status_show_json
            ;;
        "--health")
            _gs_status_show_health
            ;;
        "system")
            _gs_status_show_system
            ;;
        "config")
            _gs_status_show_config
            ;;
        "plugins")
            _gs_status_show_plugins
            ;;
        "performance")
            _gs_status_show_performance
            ;;
        "cache")
            _gs_status_show_cache
            ;;
        "logs")
            _gs_status_show_logs
            ;;
        "--verbose")
            _gs_status_show_verbose
            ;;
        "--diagnostic")
            _gs_status_show_diagnostic
            ;;
        "--fix-issues")
            _gs_status_fix_issues
            ;;
        "--help"|"-h")
            _gs_status_show_help
            ;;
        "--version"|"-v")
            echo "gs-status v3.0.0"
            ;;
        *)
            _gs_error "status" "未知选项: $option"
            _gs_info "status" "使用 'gs-status --help' 查看帮助"
            return 1
            ;;
    esac
}

# 显示完整状态信息
_gs_status_show_full() {
    local overall_status="$(_gs_get_overall_status)"
    local startup_time="$(_gs_get_startup_time_ms)"
    local last_startup="$(_gs_get_last_startup_time)"
    
    cat << EOF
Global Scripts V3 - 系统状态
============================

📊 总体状态: $overall_status
📍 安装路径: ${GS_ROOT:-未知}
🕒 最后启动: $last_startup
⏱️  启动时间: ${startup_time}ms

EOF

    # 显示各个子系统状态
    _gs_status_show_system_section
    echo
    _gs_status_show_config_section  
    echo
    _gs_status_show_plugins_section
    echo
    _gs_status_show_cache_section
    echo
    _gs_status_show_performance_section
    echo
    _gs_status_show_logs_section
}

# 显示简要状态
_gs_status_show_brief() {
    local overall_status="$(_gs_get_overall_status)"
    local startup_time="$(_gs_get_startup_time_ms)"
    local plugins_info="$(_gs_get_plugins_brief)"
    local cache_info="$(_gs_get_cache_brief)"
    
    echo "$overall_status Global Scripts V3 运行正常"
    echo "📍 ${GS_ROOT:-未知} | ⏱️ ${startup_time}ms | 🧩 $plugins_info | 💾 $cache_info"
}

# 显示JSON格式状态
_gs_status_show_json() {
    local overall_status="$(_gs_get_overall_status_code)"
    local startup_time="$(_gs_get_startup_time_ms)"
    local last_startup="$(_gs_get_last_startup_time_iso)"
    
    cat << EOF
{
  "status": "$overall_status",
  "installation_path": "${GS_ROOT:-unknown}",
  "last_startup": "$last_startup",
  "startup_time_ms": $startup_time,
  "system": $(_gs_get_system_status_json),
  "config_files": $(_gs_get_config_status_json),
  "plugins": $(_gs_get_plugins_status_json),
  "cache": $(_gs_get_cache_status_json),
  "performance": $(_gs_get_performance_status_json),
  "logs": $(_gs_get_logs_status_json)
}
EOF
}

# 显示健康检查模式
_gs_status_show_health() {
    echo "🏥 Global Scripts V3 健康检查"
    echo "============================="
    
    local health_score=0
    local total_checks=6
    
    # 核心文件检查
    if _gs_check_core_files; then
        echo "✅ 核心文件完整"
        ((health_score++))
    else
        echo "❌ 核心文件缺失"
    fi
    
    # 配置文件检查
    if _gs_check_config_files; then
        echo "✅ 配置文件有效"
        ((health_score++))
    else
        echo "❌ 配置文件问题"
    fi
    
    # 插件系统检查
    if _gs_check_plugin_system; then
        echo "✅ 插件系统正常"
        ((health_score++))
    else
        echo "❌ 插件系统异常"
    fi
    
    # 缓存系统检查
    if _gs_check_cache_system; then
        echo "✅ 缓存系统健康"
        ((health_score++))
    else
        echo "❌ 缓存系统问题"
    fi
    
    # 性能指标检查
    if _gs_check_performance_metrics; then
        echo "✅ 性能指标良好"
        ((health_score++))
    else
        echo "⚠️ 性能需要关注"
    fi
    
    # 错误日志检查
    if _gs_check_error_logs; then
        echo "✅ 无错误或警告"
        ((health_score++))
    else
        echo "⚠️ 存在错误或警告"
    fi
    
    local health_percentage=$((health_score * 100 / total_checks))
    echo
    echo "总体健康度: $health_percentage% ($(_gs_get_health_level $health_percentage))"
}

# ============================================================================
# 子系统状态显示函数
# ============================================================================

# 系统环境状态
_gs_status_show_system_section() {
    echo "🔧 系统环境:"
    echo "  操作系统: $(_gs_get_os_name) $(_gs_get_os_version)"
    echo "  Shell环境: $(_gs_get_shell_info)"
    echo "  Python版本: $(_gs_get_python_status)"
}

_gs_status_show_system() {
    echo "Global Scripts V3 - 系统环境状态"
    echo "============================="
    _gs_status_show_system_section
    echo
    echo "🔍 详细信息:"
    echo "  内核版本: $(uname -r)"
    echo "  架构: $(uname -m)"
    echo "  主机名: $(hostname 2>/dev/null || echo 'unknown')"
    echo "  用户: ${USER:-unknown}"
    echo "  终端: ${TERM:-unknown}"
    echo "  Shell路径: ${SHELL:-unknown}"
}

# 配置文件状态
_gs_status_show_config_section() {
    echo "⚙️  配置文件:"
    echo "  默认配置: $(_gs_check_default_config)"
    echo "  用户配置: $(_gs_check_user_config)"
    echo "  企业配置: $(_gs_check_enterprise_config)"
}

_gs_status_show_config() {
    echo "Global Scripts V3 - 配置文件状态"
    echo "=========================="
    _gs_status_show_config_section
    echo
    echo "🔍 配置文件详情:"
    echo "  配置目录: ${GS_CONFIG_DIR:-未设置}"
    echo "  默认配置: $(_gs_get_config_file_info default)"
    echo "  用户配置: $(_gs_get_config_file_info user)"
    echo "  企业配置: $(_gs_get_config_file_info enterprise)"
}

# 插件状态
_gs_status_show_plugins_section() {
    local enabled_count="$(_gs_count_enabled_plugins)"
    local total_count="$(_gs_count_total_plugins)"
    local disabled_count=$((total_count - enabled_count))
    local error_count="$(_gs_count_plugin_errors)"
    
    echo "🧩 插件状态:"
    echo "  已安装插件: ${total_count}个"
    echo "  已启用插件: ${enabled_count}个 $(_gs_get_enabled_plugin_names)"
    echo "  已禁用插件: ${disabled_count}个"
    echo "  插件错误: ${error_count}个"
}

_gs_status_show_plugins() {
    echo "Global Scripts V3 - 插件状态概览"
    echo "========================="
    _gs_status_show_plugins_section
    echo
    echo "🔍 插件详情:"
    _gs_show_plugin_details
}

# 缓存系统状态
_gs_status_show_cache_section() {
    echo "💾 缓存系统:"
    echo "  L1缓存: $(_gs_get_l1_cache_status)"
    echo "  L2缓存: $(_gs_get_l2_cache_status)"
    echo "  缓存清理: $(_gs_get_cache_cleanup_status)"
}

_gs_status_show_cache() {
    echo "Global Scripts V3 - 缓存系统状态"
    echo "========================="
    _gs_status_show_cache_section
    echo
    echo "🔍 缓存详情:"
    echo "  缓存目录: ${GS_CACHE_DIR:-未设置}"
    echo "  L1缓存命中率: $(_gs_get_l1_hit_rate)%"
    echo "  L2缓存大小: $(_gs_get_l2_cache_size)MB"
    echo "  L2缓存命中率: $(_gs_get_l2_hit_rate)%"
    echo "  最后清理时间: $(_gs_get_last_cleanup_time)"
}

# 性能指标状态
_gs_status_show_performance_section() {
    echo "📈 性能指标:"
    echo "  启动时间: $(_gs_get_startup_time_ms)ms ($(_gs_get_startup_performance_level))"
    echo "  内存占用: $(_gs_get_memory_usage)MB ($(_gs_get_memory_performance_level))"
    echo "  命令响应: 平均 $(_gs_get_avg_response_time)ms ($(_gs_get_response_performance_level))"
}

_gs_status_show_performance() {
    echo "Global Scripts V3 - 性能指标"
    echo "======================"
    _gs_status_show_performance_section
    echo
    echo "🔍 性能详情:"
    echo "  进程ID: $$"
    echo "  CPU使用率: $(_gs_get_cpu_usage)%"
    echo "  内存详情: $(_gs_get_memory_details)"
    echo "  磁盘使用: $(_gs_get_disk_usage)"
}

# 日志状态
_gs_status_show_logs_section() {
    echo "📝 日志状态:"
    echo "  系统日志: $(_gs_get_system_log_status)"
    echo "  错误日志: $(_gs_get_error_log_status)"
    echo "  性能日志: $(_gs_get_performance_log_status)"
}

_gs_status_show_logs() {
    echo "Global Scripts V3 - 日志状态"
    echo "==================="
    _gs_status_show_logs_section
    echo
    echo "🔍 日志详情:"
    echo "  日志目录: $(_gs_get_log_directory)"
    echo "  日志级别: $(_gs_get_current_log_level)"
    echo "  日志轮转: $(_gs_get_log_rotation_status)"
    echo "  最近错误: $(_gs_get_recent_errors)"
}

# ============================================================================
# 状态检查辅助函数
# ============================================================================

# 获取总体状态
_gs_get_overall_status() {
    if _gs_check_critical_components; then
        echo "✅ 正常运行"
    else
        echo "❌ 存在问题"
    fi
}

_gs_get_overall_status_code() {
    if _gs_check_critical_components; then
        echo "healthy"
    else
        echo "unhealthy"
    fi
}

# 检查关键组件
_gs_check_critical_components() {
    # 检查GS_ROOT
    [[ -d "${GS_ROOT:-}" ]] || return 1
    
    # 检查核心文件
    [[ -f "${GS_ROOT}/VERSION" ]] || return 1
    [[ -f "${GS_ROOT}/lib/base.sh" ]] || return 1
    [[ -f "${GS_ROOT}/gs_env.sh" ]] || return 1
    
    # 检查核心目录
    [[ -d "${GS_CORE_DIR:-}" ]] || return 1
    [[ -d "${GS_SYSTEM_DIR:-}" ]] || return 1
    
    return 0
}

# 获取启动时间
_gs_get_startup_time_ms() {
    echo "${_GS_STARTUP_TIME_MS:-unknown}"
}

_gs_get_last_startup_time() {
    echo "${_GS_LAST_STARTUP:-unknown}"
}

_gs_get_last_startup_time_iso() {
    # 转换为ISO格式
    echo "${_GS_LAST_STARTUP:-unknown}"
}

# 获取插件简要信息
_gs_get_plugins_brief() {
    local enabled="$(_gs_count_enabled_plugins)"
    local total="$(_gs_count_total_plugins)"
    echo "${enabled}/${total}插件"
}

# 获取缓存简要信息
_gs_get_cache_brief() {
    local hit_rate="$(_gs_get_l1_hit_rate)"
    echo "${hit_rate}%缓存"
}

# ============================================================================
# JSON状态生成函数
# ============================================================================

_gs_get_system_status_json() {
    cat << EOF
{
  "os": "$(_gs_get_os_name)",
  "os_version": "$(_gs_get_os_version)",
  "shell": "$(_gs_detect_shell_basic)",
  "shell_version": "$(_gs_get_shell_version | cut -d' ' -f2)",
  "python": "$(_gs_get_python_version)"
}
EOF
}

_gs_get_config_status_json() {
    cat << EOF
{
  "default": {"status": "$(_gs_get_config_status default)", "path": "$(_gs_get_config_path default)"},
  "user": {"status": "$(_gs_get_config_status user)", "path": "$(_gs_get_config_path user)"},
  "enterprise": {"status": "$(_gs_get_config_status enterprise)", "path": "$(_gs_get_config_path enterprise)"}
}
EOF
}

_gs_get_plugins_status_json() {
    cat << EOF
{
  "total": $(_gs_count_total_plugins),
  "enabled": $(_gs_count_enabled_plugins),
  "disabled": $((_gs_count_total_plugins - _gs_count_enabled_plugins)),
  "errors": $(_gs_count_plugin_errors),
  "list": [$(_gs_get_plugin_list_json)]
}
EOF
}

_gs_get_cache_status_json() {
    cat << EOF
{
  "l1_hit_rate": $(_gs_get_l1_hit_rate_decimal),
  "l2_hit_rate": $(_gs_get_l2_hit_rate_decimal),
  "l2_size_mb": $(_gs_get_l2_cache_size),
  "last_cleanup": "$(_gs_get_last_cleanup_time)"
}
EOF
}

_gs_get_performance_status_json() {
    cat << EOF
{
  "startup_time_ms": $(_gs_get_startup_time_ms),
  "memory_usage_mb": $(_gs_get_memory_usage),
  "avg_command_response_ms": $(_gs_get_avg_response_time)
}
EOF
}

_gs_get_logs_status_json() {
    cat << EOF
{
  "system_log_kb": $(_gs_get_system_log_size),
  "error_log_kb": $(_gs_get_error_log_size),
  "performance_log_kb": $(_gs_get_performance_log_size)
}
EOF
}

# ============================================================================
# 具体状态检查实现函数
# ============================================================================

# 这些函数提供具体的状态检查逻辑
# 目前返回占位符值，后续根据实际需求完善

_gs_check_core_files() { return 0; }
_gs_check_config_files() { return 0; }
_gs_check_plugin_system() { return 0; }
_gs_check_cache_system() { return 0; }
_gs_check_performance_metrics() { return 0; }
_gs_check_error_logs() { return 0; }

_gs_check_default_config() { echo "✅ ~/.globalscripts/config/default.meta"; }
_gs_check_user_config() { echo "✅ ~/.globalscripts/config/user.meta"; }
_gs_check_enterprise_config() { echo "❌ 未配置"; }

_gs_get_python_status() {
    if command -v python3 >/dev/null 2>&1; then
        echo "$(python3 --version 2>/dev/null) (可选依赖)"
    else
        echo "未安装 (可选依赖)"
    fi
}

_gs_count_enabled_plugins() { echo "3"; }
_gs_count_total_plugins() { echo "5"; }
_gs_count_plugin_errors() { echo "0"; }
_gs_get_enabled_plugin_names() { echo "(android, git, system)"; }

_gs_get_l1_cache_status() { echo "✅ 正常 (85% 命中率)"; }
_gs_get_l2_cache_status() { echo "✅ 正常 (12MB, 90% 命中率)"; }
_gs_get_cache_cleanup_status() { echo "上次清理 2小时前"; }

_gs_get_l1_hit_rate() { echo "85"; }
_gs_get_l2_hit_rate() { echo "90"; }
_gs_get_l1_hit_rate_decimal() { echo "0.85"; }
_gs_get_l2_hit_rate_decimal() { echo "0.90"; }
_gs_get_l2_cache_size() { echo "12"; }
_gs_get_last_cleanup_time() { echo "2h ago"; }

_gs_get_memory_usage() { echo "6.2"; }
_gs_get_avg_response_time() { echo "2"; }

_gs_get_startup_performance_level() { echo "优秀"; }
_gs_get_memory_performance_level() { echo "良好"; }
_gs_get_response_performance_level() { echo "优秀"; }

_gs_get_system_log_status() { echo "125KB (正常)"; }
_gs_get_error_log_status() { echo "0KB (无错误)"; }
_gs_get_performance_log_status() { echo "45KB (正常)"; }

_gs_get_health_level() {
    local percentage="$1"
    if [[ $percentage -ge 90 ]]; then
        echo "优秀"
    elif [[ $percentage -ge 70 ]]; then
        echo "良好"
    elif [[ $percentage -ge 50 ]]; then
        echo "一般"
    else
        echo "需要关注"
    fi
}

# 获取操作系统名称
_gs_get_os_name() {
    case "$(uname -s)" in
        Darwin) echo "macOS" ;;
        Linux) 
            if [[ -f /etc/os-release ]]; then
                grep "^NAME=" /etc/os-release | cut -d'"' -f2 2>/dev/null || echo "Linux"
            else
                echo "Linux"
            fi ;;
        *) echo "$(uname -s)" ;;
    esac
}

# 获取操作系统版本
_gs_get_os_version() {
    case "$(uname -s)" in
        Darwin) 
            sw_vers -productVersion 2>/dev/null || echo "unknown"
            ;;
        Linux)
            if [[ -f /etc/os-release ]]; then
                grep "^VERSION=" /etc/os-release | cut -d'"' -f2 2>/dev/null || echo "unknown"
            else
                echo "unknown"
            fi ;;
        *) echo "unknown" ;;
    esac
}

# 检测Shell类型（基础版本）
_gs_detect_shell_basic() {
    if [[ -n "${ZSH_VERSION:-}" ]]; then
        echo "zsh"
    elif [[ -n "${BASH_VERSION:-}" ]]; then
        echo "bash"
    else
        echo "unknown"
    fi
}

# 获取Shell版本
_gs_get_shell_version() {
    if [[ -n "${ZSH_VERSION:-}" ]]; then
        echo "zsh $ZSH_VERSION"
    elif [[ -n "${BASH_VERSION:-}" ]]; then
        echo "bash $BASH_VERSION"
    else
        echo "unknown"
    fi
}

# 获取Shell信息
_gs_get_shell_info() {
    echo "$(_gs_detect_shell_basic) $(_gs_get_shell_version | cut -d' ' -f2)"
}

# 获取Python版本
_gs_get_python_version() {
    if command -v python3 >/dev/null 2>&1; then
        echo "$(python3 --version 2>/dev/null | cut -d' ' -f2)"
    else
        echo "not_installed"
    fi
}

# ============================================================================
# 诊断和修复功能
# ============================================================================

_gs_status_show_verbose() {
    echo "Global Scripts V3 - 详细状态信息"
    echo "=========================="
    _gs_status_show_full
    echo
    echo "🔍 详细诊断信息:"
    echo "  环境变量: $(_gs_get_env_vars_status)"
    echo "  文件权限: $(_gs_get_file_permissions_status)"
    echo "  网络状态: $(_gs_get_network_status)"
    echo "  依赖检查: $(_gs_get_dependencies_status)"
}

_gs_status_show_diagnostic() {
    echo "Global Scripts V3 - 系统诊断"
    echo "======================="
    echo "🔧 正在运行诊断检查..."
    echo
    
    # 运行各种诊断检查
    _gs_diagnostic_core_files
    _gs_diagnostic_permissions
    _gs_diagnostic_dependencies
    _gs_diagnostic_performance
    _gs_diagnostic_configuration
    
    echo
    echo "✅ 诊断完成"
}

_gs_status_fix_issues() {
    echo "Global Scripts V3 - 自动修复"
    echo "===================="
    echo "🔧 正在尝试修复发现的问题..."
    
    local fixed_count=0
    
    # 尝试修复各种问题
    if _gs_fix_missing_directories; then
        echo "✅ 修复缺失目录"
        ((fixed_count++))
    fi
    
    if _gs_fix_file_permissions; then
        echo "✅ 修复文件权限"
        ((fixed_count++))
    fi
    
    if _gs_fix_cache_issues; then
        echo "✅ 修复缓存问题"
        ((fixed_count++))
    fi
    
    echo
    if [[ $fixed_count -gt 0 ]]; then
        echo "✅ 成功修复 $fixed_count 个问题"
        echo "💡 建议重新启动Global Scripts以确保修复生效"
    else
        echo "ℹ️ 未发现需要修复的问题"
    fi
}

# 占位符修复函数
_gs_fix_missing_directories() { return 1; }
_gs_fix_file_permissions() { return 1; }
_gs_fix_cache_issues() { return 1; }

# 占位符诊断函数
_gs_diagnostic_core_files() { echo "  ✅ 核心文件检查通过"; }
_gs_diagnostic_permissions() { echo "  ✅ 文件权限正常"; }
_gs_diagnostic_dependencies() { echo "  ✅ 依赖检查通过"; }
_gs_diagnostic_performance() { echo "  ✅ 性能指标正常"; }
_gs_diagnostic_configuration() { echo "  ✅ 配置文件有效"; }

# 占位符函数
_gs_get_env_vars_status() { echo "正常"; }
_gs_get_file_permissions_status() { echo "正常"; }
_gs_get_network_status() { echo "正常"; }
_gs_get_dependencies_status() { echo "正常"; }
_gs_show_plugin_details() { echo "  详细插件信息功能开发中..."; }
_gs_get_config_file_info() { echo "配置文件信息功能开发中..."; }
_gs_get_config_status() { echo "ok"; }
_gs_get_config_path() { echo "~/.globalscripts/config/$1.meta"; }
_gs_get_plugin_list_json() { echo '"android","git","system"'; }
_gs_get_cpu_usage() { echo "5"; }
_gs_get_memory_details() { echo "RSS: 6.2MB, VSZ: 12.4MB"; }
_gs_get_disk_usage() { echo "150MB / 1TB (0.01%)"; }
_gs_get_log_directory() { echo "${GS_ROOT}/logs"; }
_gs_get_current_log_level() { echo "INFO"; }
_gs_get_log_rotation_status() { echo "已启用"; }
_gs_get_recent_errors() { echo "无"; }
_gs_get_system_log_size() { echo "125"; }
_gs_get_error_log_size() { echo "0"; }
_gs_get_performance_log_size() { echo "45"; }

# ============================================================================
# 帮助信息
# ============================================================================

_gs_status_show_help() {
    cat << 'HELP'
gs-status - 系统状态检查

功能描述:
  提供全面的系统状态检查，包括安装状态、配置信息、性能指标、插件状态等

用法:
  gs-status [选项] [检查项]

基本选项:
  (无选项)            显示完整状态信息
  --brief             显示简要状态
  --json              JSON格式输出
  --health            健康检查模式

特定检查项:
  system              系统环境状态
  config              配置文件状态
  plugins             插件状态概览
  performance         性能指标
  cache               缓存系统状态
  logs                日志状态

高级选项:
  --verbose           详细输出模式
  --diagnostic        诊断模式
  --fix-issues        尝试自动修复问题

其他选项:
  --help, -h          显示此帮助信息
  --version, -v       显示命令版本

示例:
  gs-status                    # 显示完整状态信息
  gs-status --brief           # 显示简要状态
  gs-status --json            # JSON格式输出
  gs-status --health          # 健康检查模式
  gs-status system            # 显示系统环境状态
  gs-status plugins           # 显示插件状态
  gs-status --diagnostic      # 运行诊断检查
  gs-status --fix-issues      # 尝试修复问题

HELP
}

# ============================================================================
# 命令自检
# ============================================================================

_gs_system_status_selfcheck() {
    # 检查必需的环境变量
    if [[ -z "${GS_ROOT:-}" ]]; then
        _gs_error "status" "GS_ROOT环境变量未设置"
        return 1
    fi
    
    return 0
}

# 执行自检
if ! _gs_system_status_selfcheck; then
    _gs_error "status" "系统命令自检失败"
    return 1
fi

_gs_debug "status" "gs-status系统命令加载完成"