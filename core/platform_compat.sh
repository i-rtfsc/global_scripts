#!/bin/bash
# Global Scripts V3 - 平台兼容性模块
# 版本: 3.0.0
# 描述: 处理跨平台、跨Shell版本的兼容性问题

# 防止重复加载
if _gs_is_constant "_GS_PLATFORM_COMPAT_LOADED" && [[ "${GS_FORCE_RELOAD:-false}" != "true" ]]; then
    return 0
fi
_gs_set_constant "_GS_PLATFORM_COMPAT_LOADED" "true"

# 兼容性检查和初始化
_gs_check_compatibility() {
    # 检查Shell类型和版本（避免重复设置只读变量）
    if [[ -z "${_GS_SHELL_TYPE:-}" ]]; then
        if [[ -n "${BASH_VERSION:-}" ]]; then
            _GS_SHELL_TYPE="bash"
            _GS_SHELL_VERSION="${BASH_VERSION%%.*}"
        elif [[ -n "${ZSH_VERSION:-}" ]]; then
            _GS_SHELL_TYPE="zsh"
            _GS_SHELL_VERSION="${ZSH_VERSION%%.*}"
        else
            _GS_SHELL_TYPE="unknown"
            _GS_SHELL_VERSION="0"
        fi
    fi
    
    # 检查关联数组支持
    if [[ "$_GS_SHELL_TYPE" == "bash" && "$_GS_SHELL_VERSION" -ge 4 ]] || \
       [[ "$_GS_SHELL_TYPE" == "zsh" ]]; then
        _GS_ARRAYS_SUPPORTED=true
    else
        _GS_ARRAYS_SUPPORTED=false
    fi
    
    # 检查时间命令支持
    _gs_check_time_support
    
    # 检查其他平台特性
    _gs_check_platform_features
    
    # 使用新的日志系统（如果可用）
    if declare -F "_gs_debug" >/dev/null 2>&1; then
        _gs_debug "compat" "Shell: $_GS_SHELL_TYPE $_GS_SHELL_VERSION"
        _gs_debug "compat" "关联数组支持: $_GS_ARRAYS_SUPPORTED"
        _gs_debug "compat" "时间获取方式: $_GS_TIME_METHOD"
        _gs_debug "compat" "操作系统: $_GS_OS_TYPE"
    elif [[ "${GS_DEBUG_MODE:-false}" == "true" ]]; then
        # 备选：使用简单输出
        echo "[DEBUG:compat] Shell: $_GS_SHELL_TYPE $_GS_SHELL_VERSION" >&2
        echo "[DEBUG:compat] 关联数组支持: $_GS_ARRAYS_SUPPORTED" >&2
        echo "[DEBUG:compat] 时间获取方式: $_GS_TIME_METHOD" >&2
        echo "[DEBUG:compat] 操作系统: $_GS_OS_TYPE" >&2
    fi
}

# 检查时间获取支持
_gs_check_time_support() {
    if date +%s%3N >/dev/null 2>&1; then
        # 进一步检查是否真的支持毫秒
        if date +%s%3N 2>/dev/null | grep -q 'N$'; then
            _GS_TIME_METHOD="date_s"  # 不支持毫秒，降级
        else
            _GS_TIME_METHOD="date_ms"  # 支持毫秒
        fi
    elif [[ "$_GS_SHELL_TYPE" == "zsh" ]] && [[ -n "${EPOCHREALTIME:-}" ]]; then
        _GS_TIME_METHOD="zsh_epoch"
    elif command -v python3 >/dev/null 2>&1; then
        _GS_TIME_METHOD="python3"
    elif command -v python >/dev/null 2>&1; then
        _GS_TIME_METHOD="python"
    else
        _GS_TIME_METHOD="date_s"
    fi
}

# 检查平台特性
_gs_check_platform_features() {
    # 检测操作系统
    case "$(uname -s)" in
        "Darwin")
            _GS_OS_TYPE="macos"
            ;;
        "Linux")
            _GS_OS_TYPE="linux"
            ;;
        "CYGWIN"*|"MINGW"*|"MSYS"*)
            _GS_OS_TYPE="windows"
            ;;
        "FreeBSD"|"OpenBSD"|"NetBSD")
            _GS_OS_TYPE="bsd"
            ;;
        *)
            _GS_OS_TYPE="unknown"
            ;;
    esac
    
    # 设置平台特定的命令别名
    _gs_setup_platform_aliases
}

# 设置平台特定的命令别名
_gs_setup_platform_aliases() {
    case "$_GS_OS_TYPE" in
        "macos")
            # macOS使用GNU工具替代BSD工具（如果可用）
            command -v ggrep >/dev/null 2>&1 && _GS_GREP_CMD="ggrep" || _GS_GREP_CMD="grep"
            command -v gsed >/dev/null 2>&1 && _GS_SED_CMD="gsed" || _GS_SED_CMD="sed"
            command -v gawk >/dev/null 2>&1 && _GS_AWK_CMD="gawk" || _GS_AWK_CMD="awk"
            ;;
        *)
            _GS_GREP_CMD="grep"
            _GS_SED_CMD="sed"
            _GS_AWK_CMD="awk"
            ;;
    esac
}

# 获取毫秒时间戳（跨平台兼容）
_gs_get_timestamp_ms() {
    case "$_GS_TIME_METHOD" in
        "date_ms")
            date +%s%3N
            ;;
        "zsh_epoch")
            local epoch_real="${EPOCHREALTIME:-}"
            if [[ -n "$epoch_real" ]]; then
                echo $((${epoch_real%.*}${epoch_real#*.}/1000))
            else
                echo $(($(date +%s) * 1000))
            fi
            ;;
        "python3")
            python3 -c "import time; print(int(time.time() * 1000))" 2>/dev/null || \
            echo $(($(date +%s) * 1000))
            ;;
        "python")
            python -c "import time; print(int(time.time() * 1000))" 2>/dev/null || \
            echo $(($(date +%s) * 1000))
            ;;
        "date_s")
            echo $(($(date +%s) * 1000))
            ;;
        *)
            echo $(($(date +%s) * 1000))
            ;;
    esac
}

# 初始化全局数据结构
_gs_init_data_structures() {
    if [[ "$_GS_ARRAYS_SUPPORTED" == "true" ]]; then
        # 使用关联数组
        declare -gA _GS_SYSTEM_COMMANDS 2>/dev/null || declare -A _GS_SYSTEM_COMMANDS
        declare -gA _GS_PLUGIN_COMMANDS 2>/dev/null || declare -A _GS_PLUGIN_COMMANDS
        declare -gA _GS_LOADED_PLUGINS 2>/dev/null || declare -A _GS_LOADED_PLUGINS
        declare -gA _GS_LOADED_SYSTEMS 2>/dev/null || declare -A _GS_LOADED_SYSTEMS
        declare -gA _GS_COMMAND_SOURCES 2>/dev/null || declare -A _GS_COMMAND_SOURCES  # 记录当前激活命令来源

        # 新的命令注册/提供者数据结构
        declare -gA _GS_COMMAND_STACK 2>/dev/null || declare -A _GS_COMMAND_STACK      # cmd -> provider_id 列表（; 分隔）
        declare -gA _GS_PROVIDER_INFO 2>/dev/null || declare -A _GS_PROVIDER_INFO      # provider_id -> func|source_type|source_name|priority|enabled
        declare -gA _GS_ACTIVE_FUNC 2>/dev/null || declare -A _GS_ACTIVE_FUNC          # cmd -> 当前激活 func

        # 记录优先级
        declare -gA _GS_PLUGIN_PRIORITIES 2>/dev/null || declare -A _GS_PLUGIN_PRIORITIES  # plugin_name -> priority
        declare -gA _GS_SYSTEM_PRIORITIES 2>/dev/null || declare -A _GS_SYSTEM_PRIORITIES  # system_name -> priority
    else
        # 兼容模式：使用变量前缀模拟
        [[ "${GS_DEBUG_MODE:-false}" == "true" ]] && \
        echo "[DEBUG:compat] 使用兼容模式（模拟关联数组）" >&2
    fi
}

# 统一的数据结构操作接口
_gs_map_set() {
    local map_name="$1"
    local key="$2"
    local value="$3"
    
    if [[ "$_GS_ARRAYS_SUPPORTED" == "true" ]]; then
        eval "${map_name}[\"$key\"]=\"$value\""
    else
        # 使用变量名编码模拟关联数组
        local var_name="${map_name}_$(echo "$key" | $_GS_SED_CMD 's/[^a-zA-Z0-9]/_/g')"
        eval "$var_name=\"$value\""
    fi
}

_gs_map_get() {
    local map_name="$1"
    local key="$2"
    
    if [[ "$_GS_ARRAYS_SUPPORTED" == "true" ]]; then
        eval "echo \"\${${map_name}[\"$key\"]:-}\""
    else
        local var_name="${map_name}_$(echo "$key" | $_GS_SED_CMD 's/[^a-zA-Z0-9]/_/g')"
        eval "echo \"\${$var_name:-}\""
    fi
}

_gs_map_keys() {
    local map_name="$1"
    
    if [[ "$_GS_ARRAYS_SUPPORTED" == "true" ]]; then
        eval "echo \"\${!${map_name}[@]}\""
    else
        # 列出所有匹配的变量名并转换回key
        set | $_GS_GREP_CMD "^${map_name}_" | cut -d'=' -f1 | \
        $_GS_SED_CMD "s/^${map_name}_//" | $_GS_SED_CMD 's/_/-/g'
    fi
}

_gs_map_count() {
    local map_name="$1"
    
    if [[ "$_GS_ARRAYS_SUPPORTED" == "true" ]]; then
        eval "echo \"\${#${map_name}[@]}\""
    else
        set | $_GS_GREP_CMD -c "^${map_name}_" || echo "0"
    fi
}

_gs_map_unset() {
    local map_name="$1"
    local key="$2"
    
    if [[ "$_GS_ARRAYS_SUPPORTED" == "true" ]]; then
        eval "unset ${map_name}[\"$key\"]"
    else
        local var_name="${map_name}_$(echo "$key" | $_GS_SED_CMD 's/[^a-zA-Z0-9]/_/g')"
        eval "unset $var_name"
    fi
}

# 兼容性错误处理
_gs_handle_compatibility_error() {
    local error_type="$1"
    local details="$2"
    
    case "$error_type" in
        "shell_version")
            echo "警告: Shell版本过低 ($details)" >&2
            echo "建议: 升级到Bash 4.0+或Zsh 5.0+" >&2
            echo "当前: 使用兼容模式运行" >&2
            ;;
        "missing_command")
            echo "错误: 缺少必需命令: $details" >&2
            echo "建议: 安装相应的软件包" >&2
            ;;
        "feature_unavailable")
            echo "警告: 功能不可用: $details" >&2
            echo "当前: 使用降级功能" >&2
            ;;
    esac
}

# 检查命令可用性
_gs_check_command() {
    local cmd="$1"
    local alternatives="$2"
    
    if command -v "$cmd" >/dev/null 2>&1; then
        return 0
    fi
    
    # 检查备选命令
    if [[ -n "$alternatives" ]]; then
        IFS=',' read -ra alts <<< "$alternatives"
        for alt in "${alts[@]}"; do
            alt=$(echo "$alt" | xargs)  # 去除空格
            if command -v "$alt" >/dev/null 2>&1; then
                [[ "${GS_DEBUG_MODE:-false}" == "true" ]] && \
                echo "[DEBUG:compat] 使用备选命令: $alt (替代 $cmd)" >&2
                return 0
            fi
        done
    fi
    
    return 1
}

# ============================================================================
# 常量保护机制（替代readonly）
# ============================================================================

# 标记兼容性模块已加载（使用常量保护机制）
_gs_set_constant "_GS_COMPAT_LOADED" "true"
