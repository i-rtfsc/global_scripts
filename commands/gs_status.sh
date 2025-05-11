#!/bin/bash
# Global Scripts V3 - Status Command
# 作者: Solo
# 版本: 3.0.0
# 描述: 系统状态检查命令，显示系统环境、配置、插件和性能状态

# 防止重复加载
if [[ -n "${_GS_STATUS_LOADED:-}" ]]; then
    return 0
fi
readonly _GS_STATUS_LOADED=1

# 设置基础路径
if [[ -z "${_GS_ROOT:-}" ]]; then
    readonly _GS_ROOT="$(cd "$(dirname "$(dirname "${BASH_SOURCE[0]}")")" && pwd)"
fi

# 加载依赖模块
source "${_GS_ROOT}/lib/utils.sh"
source "${_GS_ROOT}/lib/logger.sh"
source "${_GS_ROOT}/lib/error.sh"
source "${_GS_ROOT}/core/config.sh"
source "${_GS_ROOT}/api/command_api.sh"
source "${_GS_ROOT}/lib/time_compat.sh"

# ===================================
# 状态检查函数
# ===================================

# 检查系统环境状态
gs_status_check_system() {
    local check_status="healthy"
    local issues=()
    
    # 检查必需命令
    local required_commands=("bash" "python3" "jq" "git" "curl")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            check_status="warning"
            issues+=("缺少必需命令: $cmd")
        fi
    done
    
    # 检查Shell版本
    if [[ -n "${BASH_VERSION:-}" ]]; then
        local bash_major bash_minor
        bash_major=$(echo "$BASH_VERSION" | cut -d. -f1)
        bash_minor=$(echo "$BASH_VERSION" | cut -d. -f2)
        if [[ $bash_major -lt 3 ]] || [[ $bash_major -eq 3 && $bash_minor -lt 2 ]]; then
            check_status="error"
            issues+=("Bash版本过低: $BASH_VERSION (需要 >= 3.2)")
        fi
    fi
    
    # 检查Python版本
    if command -v python3 >/dev/null 2>&1; then
        local python_version
        python_version=$(python3 --version 2>&1 | cut -d' ' -f2)
        local python_major python_minor
        python_major=$(echo "$python_version" | cut -d. -f1)
        python_minor=$(echo "$python_version" | cut -d. -f2)
        if [[ $python_major -lt 3 ]] || [[ $python_major -eq 3 && $python_minor -lt 6 ]]; then
            check_status="warning"
            issues+=("Python版本较低: $python_version (推荐 >= 3.6)")
        fi
    fi
    
    echo "status:$check_status,issues:$(IFS='|'; echo "${issues[*]}")"
}

# 检查配置文件状态
gs_status_check_config() {
    local config_status="healthy"
    local config_issues=""
    local config_files_checked=0
    local config_files_valid=0
    
    # 检查默认配置文件
    if [[ -f "${_GS_ROOT}/config/default.json" ]]; then
        config_files_checked=$((config_files_checked + 1))
        if jq . "${_GS_ROOT}/config/default.json" >/dev/null 2>&1; then
            config_files_valid=$((config_files_valid + 1))
        else
            config_status="error"
            config_issues="${config_issues}|默认配置文件格式错误"
        fi
    else
        config_status="error"
        config_issues="${config_issues}|缺少默认配置文件"
    fi
    
    # 检查Schema文件
    if [[ -f "${_GS_ROOT}/config/schema/core.schema.json" ]]; then
        config_files_checked=$((config_files_checked + 1))
        if jq . "${_GS_ROOT}/config/schema/core.schema.json" >/dev/null 2>&1; then
            config_files_valid=$((config_files_valid + 1))
        else
            config_status="warning"
            config_issues="${config_issues}|Schema文件格式错误"
        fi
    else
        config_status="warning"
        config_issues="${config_issues}|缺少Schema文件"
    fi
    
    # 检查用户配置文件
    local user_config="${HOME}/.gs/config.json"
    if [[ -f "$user_config" ]]; then
        config_files_checked=$((config_files_checked + 1))
        if jq . "$user_config" >/dev/null 2>&1; then
            config_files_valid=$((config_files_valid + 1))
        else
            config_status="error"
            config_issues="${config_issues}|用户配置文件格式错误"
        fi
    fi
    
    # 安全的配置验证检查 - 跨平台兼容
    if command -v gs_config_validate >/dev/null 2>&1; then
        # 使用子shell和错误捕获来安全调用配置验证
        if (gs_config_validate >/dev/null 2>&1); then
            # 验证成功，无需添加警告
            :
        else
            # 验证失败，添加警告但不崩溃
            config_status="warning"
            config_issues="${config_issues}|配置验证失败"
        fi
    fi
    
    # 清理issues字符串前导的|符号
    config_issues="${config_issues#|}"
    
    echo "status:$config_status,checked:$config_files_checked,valid:$config_files_valid,issues:$config_issues"
}

# 检查插件状态
gs_status_check_plugins() {
    local check_status="healthy"
    local issues=()
    local plugins_total=0
    local plugins_loaded=0
    
    # 检查插件目录
    if [[ -d "${_GS_ROOT}/plugins" ]]; then
        # 统计插件目录数量
        while IFS= read -r -d '' plugin_dir; do
            plugins_total=$((plugins_total + 1))
        done < <(find "${_GS_ROOT}/plugins" -maxdepth 1 -type d -not -path "${_GS_ROOT}/plugins" -print0 2>/dev/null)
    else
        issues+=("插件目录不存在")
    fi
    
    # 检查注册表中的插件加载状态
    if command -v gs_registry_get_stats >/dev/null 2>&1; then
        local registry_stats
        registry_stats=$(gs_registry_get_stats 2>/dev/null || echo "commands:0,plugins:0")
        plugins_loaded=$(echo "$registry_stats" | grep -o 'plugins:[0-9]*' | cut -d: -f2)
    fi
    
    # 判断插件状态
    if [[ $plugins_total -eq 0 ]]; then
        check_status="warning"
        issues+=("没有可用插件")
    elif [[ $plugins_loaded -lt $plugins_total ]]; then
        check_status="warning"
        issues+=("部分插件未加载")
    fi
    
    echo "status:$check_status,total:$plugins_total,loaded:$plugins_loaded,issues:$(IFS='|'; echo "${issues[*]}")"
}

# 检查缓存状态
gs_status_check_cache() {
    local check_status="healthy"
    local issues=()
    local cache_dir="${HOME}/.gs/cache"
    local cache_files=0
    local cache_size=0
    
    if [[ -d "$cache_dir" ]]; then
        # 统计缓存文件
        while IFS= read -r -d '' cache_file; do
            cache_files=$((cache_files + 1))
            if [[ -f "$cache_file" ]]; then
                local file_size
                file_size=$(wc -c < "$cache_file" 2>/dev/null || echo 0)
                cache_size=$((cache_size + file_size))
            fi
        done < <(find "$cache_dir" -type f -print0 2>/dev/null)
    else
        check_status="warning"
        issues+=("缓存目录不存在")
    fi
    
    # 检查缓存大小（超过100MB警告）
    if [[ $cache_size -gt 104857600 ]]; then
        check_status="warning"
        issues+=("缓存大小过大: $(( cache_size / 1024 / 1024 ))MB")
    fi
    
    echo "status:$check_status,files:$cache_files,size:$cache_size,issues:$(IFS='|'; echo "${issues[*]}")"
}

# 检查性能指标
gs_status_check_performance() {
    local check_status="healthy"
    local issues=()
    local startup_time load_time
    
    # 测量启动时间
    local start_time end_time
    start_time=$(gs_time_ms)
    
    # 模拟核心加载过程
    source "${_GS_ROOT}/lib/utils.sh" >/dev/null 2>&1
    source "${_GS_ROOT}/core/config.sh" >/dev/null 2>&1
    
    end_time=$(gs_time_ms)
    startup_time=$((end_time - start_time))
    
    # 测量配置加载时间
    start_time=$(gs_time_ms)
    gs_config_init >/dev/null 2>&1 || true
    end_time=$(gs_time_ms)
    load_time=$((end_time - start_time))
    
    # 性能阈值检查
    if [[ $startup_time -gt 500 ]]; then
        check_status="warning"
        issues+=("启动时间较慢: ${startup_time}ms")
    fi
    
    if [[ $load_time -gt 200 ]]; then
        check_status="warning"
        issues+=("配置加载较慢: ${load_time}ms")
    fi
    
    echo "status:$check_status,startup:$startup_time,load:$load_time,issues:$(IFS='|'; echo "${issues[*]}")"
}

# 执行健康检查
gs_status_health_check() {
    local overall_status="healthy"
    local total_issues=0
    
    echo "执行系统健康检查..."
    echo
    
    # 系统环境检查
    local system_result
    system_result=$(gs_status_check_system)
    local system_status
    system_status=$(echo "$system_result" | cut -d, -f1 | cut -d: -f2)
    if [[ "$system_status" != "healthy" ]]; then
        overall_status="warning"
        if [[ "$system_status" == "error" ]]; then
            overall_status="error"
        fi
    fi
    
    # 配置文件检查
    local config_result
    config_result=$(gs_status_check_config)
    local config_status
    config_status=$(echo "$config_result" | cut -d, -f1 | cut -d: -f2)
    if [[ "$config_status" != "healthy" ]]; then
        overall_status="warning"
        if [[ "$config_status" == "error" ]]; then
            overall_status="error"
        fi
    fi
    
    # 插件状态检查
    local plugins_result
    plugins_result=$(gs_status_check_plugins)
    local plugins_status
    plugins_status=$(echo "$plugins_result" | cut -d, -f1 | cut -d: -f2)
    if [[ "$plugins_status" != "healthy" ]]; then
        overall_status="warning"
    fi
    
    # 缓存状态检查
    local cache_result
    cache_result=$(gs_status_check_cache)
    local cache_status
    cache_status=$(echo "$cache_result" | cut -d, -f1 | cut -d: -f2)
    if [[ "$cache_status" != "healthy" ]]; then
        overall_status="warning"
    fi
    
    # 性能检查
    local perf_result
    perf_result=$(gs_status_check_performance)
    local perf_status
    perf_status=$(echo "$perf_result" | cut -d, -f1 | cut -d: -f2)
    if [[ "$perf_status" != "healthy" ]]; then
        overall_status="warning"
    fi
    
    echo "健康检查完成，总体状态: $overall_status"
    echo "system:$system_result"
    echo "config:$config_result" 
    echo "plugins:$plugins_result"
    echo "cache:$cache_result"
    echo "performance:$perf_result"
}

# ===================================
# 状态信息格式化输出
# ===================================

# 文本格式输出基本状态
gs_status_show_basic_text() {
    echo "Global Scripts V3 - 系统状态"
    echo "============================="
    echo
    
    # 系统环境状态
    local system_result
    system_result=$(gs_status_check_system)
    local system_status system_issues
    system_status=$(echo "$system_result" | cut -d, -f1 | cut -d: -f2)
    system_issues=$(echo "$system_result" | cut -d, -f2- | cut -d: -f2-)
    
    echo "🖥️  系统环境: $(gs_status_format_status "$system_status")"
    if [[ -n "$system_issues" && "$system_issues" != "issues:" ]]; then
        echo "   问题: ${system_issues//|/, }"
    fi
    
    # 配置状态
    local config_result
    config_result=$(gs_status_check_config)
    local config_status config_checked config_valid config_issues
    config_status=$(echo "$config_result" | cut -d, -f1 | cut -d: -f2)
    config_checked=$(echo "$config_result" | cut -d, -f2 | cut -d: -f2)
    config_valid=$(echo "$config_result" | cut -d, -f3 | cut -d: -f2)
    config_issues=$(echo "$config_result" | cut -d, -f4- | cut -d: -f2-)
    
    echo "⚙️  配置文件: $(gs_status_format_status "$config_status") ($config_valid/$config_checked 个有效)"
    if [[ -n "$config_issues" && "$config_issues" != "issues:" ]]; then
        echo "   问题: ${config_issues//|/, }"
    fi
    
    # 插件状态
    local plugins_result  
    plugins_result=$(gs_status_check_plugins)
    local plugins_status plugins_total plugins_loaded plugins_issues
    plugins_status=$(echo "$plugins_result" | cut -d, -f1 | cut -d: -f2)
    plugins_total=$(echo "$plugins_result" | cut -d, -f2 | cut -d: -f2)
    plugins_loaded=$(echo "$plugins_result" | cut -d, -f3 | cut -d: -f2)
    plugins_issues=$(echo "$plugins_result" | cut -d, -f4- | cut -d: -f2-)
    
    echo "🔌 插件状态: $(gs_status_format_status "$plugins_status") ($plugins_loaded/$plugins_total 个已加载)"
    if [[ -n "$plugins_issues" && "$plugins_issues" != "issues:" ]]; then
        echo "   问题: ${plugins_issues//|/, }"
    fi
    
    # 缓存状态
    local cache_result
    cache_result=$(gs_status_check_cache)
    local cache_status cache_files cache_size cache_issues
    cache_status=$(echo "$cache_result" | cut -d, -f1 | cut -d: -f2)
    cache_files=$(echo "$cache_result" | cut -d, -f2 | cut -d: -f2)
    cache_size=$(echo "$cache_result" | cut -d, -f3 | cut -d: -f2)
    cache_issues=$(echo "$cache_result" | cut -d, -f4- | cut -d: -f2-)
    
    local cache_size_mb=$((cache_size / 1024 / 1024))
    echo "💾 缓存状态: $(gs_status_format_status "$cache_status") ($cache_files 个文件, ${cache_size_mb}MB)"
    if [[ -n "$cache_issues" && "$cache_issues" != "issues:" ]]; then
        echo "   问题: ${cache_issues//|/, }"
    fi
}

# 格式化状态显示
gs_status_format_status() {
    local status_value="$1"
    case "$status_value" in
        "healthy")
            echo "✅ 正常"
            ;;
        "warning")
            echo "⚠️  警告"
            ;;
        "error")
            echo "❌ 错误"
            ;;
        *)
            echo "❓ 未知"
            ;;
    esac
}

# 文本格式输出详细状态
gs_status_show_verbose_text() {
    gs_status_show_basic_text
    
    echo
    echo "性能指标:"
    
    local perf_result
    perf_result=$(gs_status_check_performance)
    local perf_status startup_time load_time perf_issues
    perf_status=$(echo "$perf_result" | cut -d, -f1 | cut -d: -f2)
    startup_time=$(echo "$perf_result" | cut -d, -f2 | cut -d: -f2)
    load_time=$(echo "$perf_result" | cut -d, -f3 | cut -d: -f2)
    perf_issues=$(echo "$perf_result" | cut -d, -f4- | cut -d: -f2-)
    
    echo "  启动时间: ${startup_time}ms"
    echo "  配置加载: ${load_time}ms"
    echo "  状态: $(gs_status_format_status "$perf_status")"
    
    if [[ -n "$perf_issues" && "$perf_issues" != "issues:" ]]; then
        echo "  问题: ${perf_issues//|/, }"
    fi
    
    echo
    echo "系统信息:"
    echo "  安装路径: $_GS_ROOT"
    echo "  Shell: $(echo "$0" | grep -o '[^/]*$' | cut -d. -f1) $(echo "${BASH_VERSION:-${ZSH_VERSION:-unknown}}")"
    echo "  操作系统: $(uname -s) $(uname -r)"
}

# JSON格式输出状态
gs_status_show_json() {
    local system_result config_result plugins_result cache_result perf_result
    system_result=$(gs_status_check_system)
    config_result=$(gs_status_check_config)
    plugins_result=$(gs_status_check_plugins)
    cache_result=$(gs_status_check_cache)
    perf_result=$(gs_status_check_performance)
    
    cat << EOF
{
  "overall_status": "$(gs_status_determine_overall_status "$system_result" "$config_result" "$plugins_result" "$cache_result")",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "components": {
    "system": $(gs_status_parse_result_json "$system_result"),
    "config": $(gs_status_parse_config_result_json "$config_result"),
    "plugins": $(gs_status_parse_plugins_result_json "$plugins_result"),
    "cache": $(gs_status_parse_cache_result_json "$cache_result"),
    "performance": $(gs_status_parse_perf_result_json "$perf_result")
  },
  "environment": {
    "install_path": "$_GS_ROOT",
    "shell": "${BASH_VERSION:-${ZSH_VERSION:-unknown}}",
    "os": "$(uname -s) $(uname -r)"
  }
}
EOF
}

# 辅助函数：确定总体状态
gs_status_determine_overall_status() {
    local system_status config_status plugins_status cache_status
    system_status=$(echo "$1" | cut -d, -f1 | cut -d: -f2)
    config_status=$(echo "$2" | cut -d, -f1 | cut -d: -f2)
    plugins_status=$(echo "$3" | cut -d, -f1 | cut -d: -f2)
    cache_status=$(echo "$4" | cut -d, -f1 | cut -d: -f2)
    
    if [[ "$system_status" == "error" || "$config_status" == "error" ]]; then
        echo "error"
    elif [[ "$system_status" == "warning" || "$config_status" == "warning" || "$plugins_status" == "warning" || "$cache_status" == "warning" ]]; then
        echo "warning"
    else
        echo "healthy"
    fi
}

# 辅助函数：解析结果为JSON
gs_status_parse_result_json() {
    local result="$1"
    local status_val issues
    status=$(echo "$result" | cut -d, -f1 | cut -d: -f2)
    issues=$(echo "$result" | cut -d, -f2- | cut -d: -f2-)
    
    echo "{"
    echo "  \"status\": \"$status\","
    if [[ -n "$issues" && "$issues" != "issues:" ]]; then
        echo "  \"issues\": [$(echo "$issues" | sed 's/|/", "/g' | sed 's/^/"/;s/$/"/')]"
    else
        echo "  \"issues\": []"
    fi
    echo "}"
}

# 辅助函数：解析配置结果为JSON
gs_status_parse_config_result_json() {
    local result="$1"
    local status checked valid issues
    status=$(echo "$result" | cut -d, -f1 | cut -d: -f2)
    checked=$(echo "$result" | cut -d, -f2 | cut -d: -f2)
    valid=$(echo "$result" | cut -d, -f3 | cut -d: -f2)
    issues=$(echo "$result" | cut -d, -f4- | cut -d: -f2-)
    
    # 处理空值
    [[ -z "$status" ]] && status="unknown"
    [[ -z "$checked" ]] && checked="0"
    [[ -z "$valid" ]] && valid="0"
    
    echo "{"
    echo "  \"status\": \"$status\","
    echo "  \"files_checked\": $checked,"
    echo "  \"files_valid\": $valid,"
    if [[ -n "$issues" && "$issues" != "issues:" ]]; then
        echo "  \"issues\": [$(echo "$issues" | sed 's/|/", "/g' | sed 's/^/"/;s/$/"/')]"
    else
        echo "  \"issues\": []"
    fi
    echo "}"
}

# 辅助函数：解析插件结果为JSON
gs_status_parse_plugins_result_json() {
    local result="$1"
    local status total loaded issues
    status=$(echo "$result" | cut -d, -f1 | cut -d: -f2)
    total=$(echo "$result" | cut -d, -f2 | cut -d: -f2)
    loaded=$(echo "$result" | cut -d, -f3 | cut -d: -f2)
    issues=$(echo "$result" | cut -d, -f4- | cut -d: -f2-)
    
    echo "{"
    echo "  \"status\": \"$status\","
    echo "  \"total_plugins\": $total,"
    echo "  \"loaded_plugins\": $loaded,"
    if [[ -n "$issues" && "$issues" != "issues:" ]]; then
        echo "  \"issues\": [$(echo "$issues" | sed 's/|/", "/g' | sed 's/^/"/;s/$/"/')]"
    else
        echo "  \"issues\": []"
    fi
    echo "}"
}

# 辅助函数：解析缓存结果为JSON
gs_status_parse_cache_result_json() {
    local result="$1"
    local status files size issues
    status=$(echo "$result" | cut -d, -f1 | cut -d: -f2)
    files=$(echo "$result" | cut -d, -f2 | cut -d: -f2)
    size=$(echo "$result" | cut -d, -f3 | cut -d: -f2)
    issues=$(echo "$result" | cut -d, -f4- | cut -d: -f2-)
    
    echo "{"
    echo "  \"status\": \"$status\","
    echo "  \"cache_files\": $files,"
    echo "  \"cache_size_bytes\": $size,"
    if [[ -n "$issues" && "$issues" != "issues:" ]]; then
        echo "  \"issues\": [$(echo "$issues" | sed 's/|/", "/g' | sed 's/^/"/;s/$/"/')]"
    else
        echo "  \"issues\": []"
    fi
    echo "}"
}

# 辅助函数：解析性能结果为JSON
gs_status_parse_perf_result_json() {
    local result="$1"
    local status startup load issues
    status=$(echo "$result" | cut -d, -f1 | cut -d: -f2)
    startup=$(echo "$result" | cut -d, -f2 | cut -d: -f2)
    load=$(echo "$result" | cut -d, -f3 | cut -d: -f2)
    issues=$(echo "$result" | cut -d, -f4- | cut -d: -f2-)
    
    echo "{"
    echo "  \"status\": \"$status\","
    echo "  \"startup_time_ms\": $startup,"
    echo "  \"config_load_time_ms\": $load,"
    if [[ -n "$issues" && "$issues" != "issues:" ]]; then
        echo "  \"issues\": [$(echo "$issues" | sed 's/|/", "/g' | sed 's/^/"/;s/$/"/')]"
    else
        echo "  \"issues\": []"
    fi
    echo "}"
}

# ===================================
# 简化的参数解析函数
# ===================================
gs_status_parse_args() {
    local format="text"
    local verbose="false"
    local check_health="false"
    local performance="false"
    local help="false"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --format)
                format="$2"
                shift 2
                ;;
            --verbose)
                verbose="true"
                shift
                ;;
            --check-health)
                check_health="true"
                shift
                ;;
            --performance)
                performance="true"
                shift
                ;;
            --help|-h)
                help="true"
                shift
                ;;
            -*)
                gs_error 1 "未知选项: $1"
                ;;
            *)
                shift
                ;;
        esac
    done
    
    # 输出解析结果
    echo "$format|$verbose|$check_health|$performance|$help"
}

# ===================================
# 主要的状态命令函数
# ===================================

gs_status_cmd() {
    local parsed_result
    parsed_result=$(gs_status_parse_args "$@")
    
    local format verbose check_health performance help
    IFS='|' read -r format verbose check_health performance help <<< "$parsed_result"
    
    # 处理帮助请求
    if [[ "$help" == "true" ]]; then
        echo "gs-status - 系统状态检查

用法: gs-status [options]

选项:
  --format FORMAT     输出格式 (text|json)
  --verbose          详细状态信息
  --check-health     执行健康检查
  --performance      显示性能指标
  --help, -h         显示此帮助信息

示例:
  gs-status                   显示基本状态
  gs-status --verbose         详细状态信息
  gs-status --format json     JSON格式输出
  gs-status --check-health    执行完整健康检查"
        return 0
    fi
    
    # 验证格式参数
    if [[ "$format" != "text" && "$format" != "json" ]]; then
        gs_error 1 "不支持的输出格式: $format (支持: text, json)"
    fi
    
    # 执行健康检查
    if [[ "$check_health" == "true" ]]; then
        gs_status_health_check
        return 0
    fi
    
    # 显示性能指标
    if [[ "$performance" == "true" ]]; then
        local perf_result
        perf_result=$(gs_status_check_performance)
        case "$format" in
            "json")
                echo "$(gs_status_parse_perf_result_json "$perf_result")"
                ;;
            *)
                echo "性能指标:"
                local startup_time load_time
                startup_time=$(echo "$perf_result" | cut -d, -f2 | cut -d: -f2)
                load_time=$(echo "$perf_result" | cut -d, -f3 | cut -d: -f2)
                echo "  启动时间: ${startup_time}ms"
                echo "  配置加载: ${load_time}ms"
                ;;
        esac
        return 0
    fi
    
    # 显示状态信息
    case "$format" in
        "json")
            gs_status_show_json
            ;;
        *)
            if [[ "$verbose" == "true" ]]; then
                gs_status_show_verbose_text
            else
                gs_status_show_basic_text
            fi
            ;;
    esac
}

# ===================================
# 命令注册
# ===================================

# 注册status命令到系统
gs_status_register() {
    if command -v gs_registry_register_command >/dev/null 2>&1; then
        # 获取当前文件路径
        local script_path
        if [[ -n "${BASH_SOURCE:-}" ]]; then
            script_path="${BASH_SOURCE[0]}"
        elif [[ -n "${(%):-%x}" ]] 2>/dev/null; then
            script_path="${(%):-%x}"
        else
            script_path="$0"
        fi
        gs_registry_register_command "gs-status" "$script_path" "显示系统状态" "3.0.0" "core"
    fi
}

# 如果直接执行此脚本
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    gs_status_cmd "$@"
fi