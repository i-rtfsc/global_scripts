#!/bin/bash
# Global Scripts V3 - 通用工具库
# 作者: Solo
# 版本: 1.0.0
# 描述: 字符串处理、文件操作、系统检测等通用功能

# 加载兼容性支持
source "$(dirname "${BASH_SOURCE[0]:-$0}")/declare_compat.sh"
source "$(dirname "${BASH_SOURCE[0]:-$0}")/time_compat.sh"

# ===============================
# 字符串处理函数
# ===============================

# 去除字符串首尾空白
gs_str_trim() {
    local str="$1"
    # 去除前导空白
    str="${str#"${str%%[![:space:]]*}"}"
    # 去除尾部空白
    str="${str%"${str##*[![:space:]]}"}"
    echo "$str"
}

# 去除字符串前导空白
gs_str_ltrim() {
    local str="$1"
    str="${str#"${str%%[![:space:]]*}"}"
    echo "$str"
}

# 去除字符串尾部空白
gs_str_rtrim() {
    local str="$1"
    str="${str%"${str##*[![:space:]]}"}"
    echo "$str"
}

# 字符串转小写
gs_str_lower() {
    local str="$1"
    echo "${str,,}"
}

# 字符串转大写
gs_str_upper() {
    local str="$1"
    echo "${str^^}"
}

# 字符串长度
gs_str_length() {
    local str="$1"
    echo "${#str}"
}

# 字符串是否为空
gs_str_is_empty() {
    local str="$1"
    [[ -z "$str" ]]
}

# 字符串是否不为空
gs_str_is_not_empty() {
    local str="$1"
    [[ -n "$str" ]]
}

# 字符串包含检查
gs_str_contains() {
    local haystack="$1"
    local needle="$2"
    [[ "$haystack" == *"$needle"* ]]
}

# 字符串前缀检查
gs_str_starts_with() {
    local str="$1"
    local prefix="$2"
    [[ "$str" == "$prefix"* ]]
}

# 字符串后缀检查
gs_str_ends_with() {
    local str="$1"
    local suffix="$2"
    [[ "$str" == *"$suffix" ]]
}

# 字符串替换（第一个匹配）
gs_str_replace_first() {
    local str="$1"
    local old="$2"
    local new="$3"
    echo "${str/$old/$new}"
}

# 字符串替换（所有匹配）
gs_str_replace_all() {
    local str="$1"
    local old="$2"
    local new="$3"
    echo "${str//$old/$new}"
}

# 字符串分割
gs_str_split() {
    local str="$1"
    local delimiter="${2:-,}"
    local -a result
    
    IFS="$delimiter" read -ra result <<< "$str"
    printf '%s\n' "${result[@]}"
}

# 字符串连接
gs_str_join() {
    local delimiter="$1"
    shift
    local first="$1"
    shift
    printf %s "$first" "${@/#/$delimiter}"
}

# 字符串重复
gs_str_repeat() {
    local str="$1"
    local count="$2"
    local result=""
    local i
    
    for ((i = 0; i < count; i++)); do
        result+="$str"
    done
    echo "$result"
}

# 字符串填充（左侧）
gs_str_pad_left() {
    local str="$1"
    local length="$2"
    local pad_char="${3:- }"
    local str_len="${#str}"
    
    if [[ $str_len -ge $length ]]; then
        echo "$str"
        return
    fi
    
    local pad_len=$((length - str_len))
    local padding
    padding="$(gs_str_repeat "$pad_char" $pad_len)"
    echo "${padding}${str}"
}

# 字符串填充（右侧）
gs_str_pad_right() {
    local str="$1"
    local length="$2"
    local pad_char="${3:- }"
    local str_len="${#str}"
    
    if [[ $str_len -ge $length ]]; then
        echo "$str"
        return
    fi
    
    local pad_len=$((length - str_len))
    local padding
    padding="$(gs_str_repeat "$pad_char" $pad_len)"
    echo "${str}${padding}"
}

# 字符串截取
gs_str_substring() {
    local str="$1"
    local start="$2"
    local length="${3:-}"
    
    if [[ -n "$length" ]]; then
        echo "${str:$start:$length}"
    else
        echo "${str:$start}"
    fi
}

# 数字格式验证
gs_str_is_number() {
    local str="$1"
    [[ "$str" =~ ^-?[0-9]+(\.[0-9]+)?$ ]]
}

# 整数格式验证
gs_str_is_integer() {
    local str="$1"
    [[ "$str" =~ ^-?[0-9]+$ ]]
}

# 邮箱格式验证
gs_str_is_email() {
    local str="$1"
    [[ "$str" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]
}

# URL格式验证
gs_str_is_url() {
    local str="$1"
    [[ "$str" =~ ^https?://[a-zA-Z0-9.-]+(\.[a-zA-Z]{2,})?(/.*)?$ ]]
}

# IP地址格式验证
gs_str_is_ip() {
    local str="$1"
    local ip_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    
    if [[ ! "$str" =~ $ip_regex ]]; then
        return 1
    fi
    
    # 检查每个数字段是否在0-255范围内
    IFS='.' read -ra segments <<< "$str"
    local segment
    for segment in "${segments[@]}"; do
        if [[ $segment -gt 255 ]] || [[ $segment -lt 0 ]]; then
            return 1
        fi
    done
    
    return 0
}

# ===============================
# 文件操作函数
# ===============================

# 获取文件大小（字节）
gs_file_size() {
    local file="$1"
    [[ -f "$file" ]] || return 1
    
    # 跨平台获取文件大小
    if command -v stat >/dev/null 2>&1; then
        # macOS和Linux的stat命令参数不同
        if [[ "$(uname)" == "Darwin" ]]; then
            stat -f%z "$file" 2>/dev/null
        else
            stat -c%s "$file" 2>/dev/null
        fi
    elif command -v wc >/dev/null 2>&1; then
        wc -c < "$file" 2>/dev/null
    else
        return 1
    fi
}

# 获取文件行数
gs_file_lines() {
    local file="$1"
    [[ -f "$file" ]] || return 1
    local lines
    lines=$(wc -l < "$file" 2>/dev/null)
    echo "${lines// /}"  # 去除前导空格
}

# 文件是否为空
gs_file_is_empty() {
    local file="$1"
    [[ -f "$file" ]] && [[ ! -s "$file" ]]
}

# 文件是否存在且可读
gs_file_is_readable() {
    local file="$1"
    [[ -f "$file" ]] && [[ -r "$file" ]]
}

# 文件是否存在且可写
gs_file_is_writable() {
    local file="$1"
    [[ -f "$file" ]] && [[ -w "$file" ]]
}

# 文件是否存在且可执行
gs_file_is_executable() {
    local file="$1"
    [[ -f "$file" ]] && [[ -x "$file" ]]
}

# 目录是否存在
gs_dir_exists() {
    local dir="$1"
    [[ -d "$dir" ]]
}

# 创建目录（支持递归）
gs_dir_create() {
    local dir="$1"
    local mode="${2:-755}"
    mkdir -p "$dir" && chmod "$mode" "$dir"
}

# 获取文件扩展名
gs_file_extension() {
    local file="$1"
    echo "${file##*.}"
}

# 获取文件基名（不含扩展名）
gs_file_basename() {
    local file="$1"
    local name="${file##*/}"
    echo "${name%.*}"
}

# 获取文件目录
gs_file_dirname() {
    local file="$1"
    echo "${file%/*}"
}

# 获取绝对路径
gs_file_realpath() {
    local file="$1"
    
    if command -v realpath >/dev/null 2>&1; then
        realpath "$file" 2>/dev/null
    else
        # 兼容性实现
        cd "$(dirname "$file")" && pwd -P && cd - >/dev/null
    fi
}

# 临时文件创建
gs_file_mktemp() {
    local prefix="${1:-gs_tmp}"
    local suffix="${2:-}"
    
    if command -v mktemp >/dev/null 2>&1; then
        mktemp -t "${prefix}.XXXXXX${suffix}"
    else
        # 兼容性实现
        local temp_dir="${TMPDIR:-/tmp}"
        local temp_file="${temp_dir}/${prefix}.$$${suffix}"
        touch "$temp_file" && echo "$temp_file"
    fi
}

# 临时目录创建
gs_dir_mktemp() {
    local prefix="${1:-gs_tmp_dir}"
    
    if command -v mktemp >/dev/null 2>&1; then
        mktemp -d -t "${prefix}.XXXXXX"
    else
        # 兼容性实现
        local temp_dir="${TMPDIR:-/tmp}"
        local temp_path="${temp_dir}/${prefix}.$$"
        mkdir -p "$temp_path" && echo "$temp_path"
    fi
}

# 文件备份
gs_file_backup() {
    local file="$1"
    local backup_suffix="${2:-.bak}"
    local timestamp="${3:-}"
    
    [[ -f "$file" ]] || return 1
    
    if [[ -n "$timestamp" ]]; then
        local backup_file="${file}${backup_suffix}.$(date +%Y%m%d_%H%M%S)"
    else
        local backup_file="${file}${backup_suffix}"
    fi
    
    cp "$file" "$backup_file"
}

# 安全删除文件
gs_file_remove() {
    local file="$1"
    local confirm="${2:-false}"
    
    [[ -f "$file" ]] || return 1
    
    if [[ "$confirm" == "true" ]]; then
        printf "确定要删除文件 %s 吗? (y/N): " "$file"
        read -r response
        [[ "$response" =~ ^[Yy] ]] || return 1
    fi
    
    rm -f "$file"
}

# ===============================
# 系统检测函数
# ===============================

# 获取操作系统类型
gs_sys_os() {
    case "$(uname -s)" in
        Darwin) echo "macos" ;;
        Linux) echo "linux" ;;
        CYGWIN*|MINGW*|MSYS*) echo "windows" ;;
        *) echo "unknown" ;;
    esac
}

# 获取系统架构
gs_sys_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo "x64" ;;
        i386|i686) echo "x32" ;;
        arm64|aarch64) echo "arm64" ;;
        arm*) echo "arm" ;;
        *) echo "unknown" ;;
    esac
}

# 检查命令是否存在
gs_sys_command_exists() {
    local cmd="$1"
    command -v "$cmd" >/dev/null 2>&1
}

# 获取Shell类型
gs_sys_shell() {
    if [[ -n "$ZSH_VERSION" ]]; then
        echo "zsh"
    elif [[ -n "$BASH_VERSION" ]]; then
        echo "bash"
    elif [[ -n "$FISH_VERSION" ]]; then
        echo "fish"
    else
        echo "unknown"
    fi
}

# 获取Shell版本
gs_sys_shell_version() {
    case "$(gs_sys_shell)" in
        bash) echo "${BASH_VERSION:-unknown}" ;;
        zsh) echo "${ZSH_VERSION:-unknown}" ;;
        *) echo "unknown" ;;
    esac
}

# 检查是否为root用户
gs_sys_is_root() {
    [[ $EUID -eq 0 ]]
}

# 获取当前用户名
gs_sys_username() {
    echo "${USER:-${LOGNAME:-$(whoami 2>/dev/null || echo unknown)}}"
}

# 获取主目录
gs_sys_home() {
    echo "${HOME:-$(eval echo ~$(gs_sys_username) 2>/dev/null || echo /tmp)}"
}

# 检查网络连接
gs_sys_network_check() {
    local host="${1:-8.8.8.8}"
    local timeout="${2:-5}"
    
    if command -v ping >/dev/null 2>&1; then
        case "$(gs_sys_os)" in
            macos|linux)
                ping -c 1 -W "$timeout" "$host" >/dev/null 2>&1
                ;;
            *)
                return 1
                ;;
        esac
    else
        return 1
    fi
}

# 获取CPU核心数
gs_sys_cpu_cores() {
    if command -v nproc >/dev/null 2>&1; then
        nproc
    elif command -v sysctl >/dev/null 2>&1; then
        sysctl -n hw.ncpu 2>/dev/null || echo "1"
    else
        echo "1"
    fi
}

# 获取内存信息（MB）
gs_sys_memory() {
    case "$(gs_sys_os)" in
        macos)
            if command -v sysctl >/dev/null 2>&1; then
                local mem_bytes
                mem_bytes=$(sysctl -n hw.memsize 2>/dev/null || echo "0")
                echo $((mem_bytes / 1024 / 1024))
            else
                echo "0"
            fi
            ;;
        linux)
            if [[ -f /proc/meminfo ]]; then
                local mem_kb
                mem_kb=$(grep "MemTotal:" /proc/meminfo | awk '{print $2}' || echo "0")
                echo $((mem_kb / 1024))
            else
                echo "0"
            fi
            ;;
        *)
            echo "0"
            ;;
    esac
}

# 获取磁盘空间信息（MB）
gs_sys_disk_space() {
    local path="${1:-/}"
    
    if command -v df >/dev/null 2>&1; then
        local space_kb
        space_kb=$(df "$path" 2>/dev/null | awk 'NR==2 {print $4}' || echo "0")
        echo $((space_kb / 1024))
    else
        echo "0"
    fi
}

# 环境变量存在检查
gs_sys_env_exists() {
    local var="$1"
    [[ -n "${!var:-}" ]]
}

# 设置环境变量
gs_sys_env_set() {
    local var="$1"
    local value="$2"
    export "$var"="$value"
}

# 获取环境变量
gs_sys_env_get() {
    local var="$1"
    local default="${2:-}"
    echo "${!var:-$default}"
}

# ===============================
# 数组操作函数
# ===============================

# 数组包含检查
gs_array_contains() {
    local needle="$1"
    shift
    local item
    for item in "$@"; do
        [[ "$item" == "$needle" ]] && return 0
    done
    return 1
}

# 数组去重
gs_array_unique() {
    local -A seen
    local item
    for item in "$@"; do
        if [[ -z "${seen[$item]:-}" ]]; then
            printf '%s\n' "$item"
            seen["$item"]=1
        fi
    done
}

# 数组排序
gs_array_sort() {
    printf '%s\n' "$@" | sort
}

# 数组反转
gs_array_reverse() {
    local -a reversed
    local i
    for ((i = $# - 1; i >= 0; i--)); do
        reversed+=("${!i}")
    done
    printf '%s\n' "${reversed[@]}"
}

# ===============================
# 颜色输出函数
# ===============================

# 颜色代码定义
readonly _GS_COLOR_RED='\033[0;31m'
readonly _GS_COLOR_GREEN='\033[0;32m'
readonly _GS_COLOR_YELLOW='\033[1;33m'
readonly _GS_COLOR_BLUE='\033[0;34m'
readonly _GS_COLOR_PURPLE='\033[0;35m'
readonly _GS_COLOR_CYAN='\033[0;36m'
readonly _GS_COLOR_WHITE='\033[1;37m'
readonly _GS_COLOR_RESET='\033[0m'

# 检查终端是否支持颜色
gs_color_supported() {
    [[ -t 1 ]] && [[ "${TERM:-}" != "dumb" ]]
}

# 颜色输出函数
gs_color_print() {
    local color="$1"
    shift
    if gs_color_supported; then
        printf "${color}%s${_GS_COLOR_RESET}\\n" "$*"
    else
        printf "%s\\n" "$*"
    fi
}

gs_color_red() { gs_color_print "$_GS_COLOR_RED" "$@"; }
gs_color_green() { gs_color_print "$_GS_COLOR_GREEN" "$@"; }
gs_color_yellow() { gs_color_print "$_GS_COLOR_YELLOW" "$@"; }
gs_color_blue() { gs_color_print "$_GS_COLOR_BLUE" "$@"; }
gs_color_purple() { gs_color_print "$_GS_COLOR_PURPLE" "$@"; }
gs_color_cyan() { gs_color_print "$_GS_COLOR_CYAN" "$@"; }
gs_color_white() { gs_color_print "$_GS_COLOR_WHITE" "$@"; }

# ===============================
# 进度条函数
# ===============================

# 简单进度条
gs_progress_bar() {
    local current="$1"
    local total="$2"
    local width="${3:-50}"
    local char="${4:-█}"
    
    local percentage=$((current * 100 / total))
    local filled=$((current * width / total))
    local empty=$((width - filled))
    
    printf "\r["
    printf "%*s" "$filled" "" | tr ' ' "$char"
    printf "%*s" "$empty" ""
    printf "] %d%% (%d/%d)" "$percentage" "$current" "$total"
}

# 如果直接执行此脚本，运行测试
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
    echo "=== Global Scripts Utils Test ==="
    
    echo
    echo "1. 字符串处理测试:"
    echo "原字符串: '  Hello World  '"
    echo "去除空白: '$(gs_str_trim "  Hello World  ")'"
    echo "转大写: '$(gs_str_upper "hello world")'"
    echo "转小写: '$(gs_str_lower "HELLO WORLD")'"
    echo "字符串长度: $(gs_str_length "Hello World")"
    echo "包含检查: $(gs_str_contains "Hello World" "World" && echo "true" || echo "false")"
    
    echo
    echo "2. 文件操作测试:"
    test_file="$(gs_file_mktemp)"
    echo "创建临时文件: $test_file"
    echo "test content" > "$test_file"
    echo "文件大小: $(gs_file_size "$test_file") bytes"
    echo "文件行数: $(gs_file_lines "$test_file")"
    echo "文件扩展名: $(gs_file_extension "$test_file")"
    rm -f "$test_file"
    
    echo
    echo "3. 系统检测测试:"
    echo "操作系统: $(gs_sys_os)"
    echo "系统架构: $(gs_sys_arch)"
    echo "Shell类型: $(gs_sys_shell)"
    echo "Shell版本: $(gs_sys_shell_version)"
    echo "当前用户: $(gs_sys_username)"
    echo "CPU核心数: $(gs_sys_cpu_cores)"
    echo "内存大小: $(gs_sys_memory) MB"
    
    echo
    echo "4. 颜色输出测试:"
    gs_color_red "红色文本"
    gs_color_green "绿色文本"
    gs_color_yellow "黄色文本"
    gs_color_blue "蓝色文本"
    
    echo
    echo "5. 进度条测试:"
    for i in {0..10}; do
        gs_progress_bar "$i" 10
        sleep 0.1
    done
    echo
    
    echo
    echo "✓ Utils test completed"
fi