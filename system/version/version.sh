#!/bin/bash
# Global Scripts V3 - 版本信息管理
# 版本: 3.0.0
# 描述: 提供全面的版本信息查询功能，包括系统版本、组件版本、依赖信息等

# ============================================================================
# 版本信息管理 - 系统命令
# ============================================================================

# 主版本显示函数
gs_system_version() {
    # 功能描述: 显示版本信息
    # 参数: $1 - 选项 (字符串) [可选]
    # 返回值: 0 - 成功, 1 - 失败
    # 示例: gs-version, gs-version --json, gs-version --short

    local option="${1:-}"

    case "$option" in
        ""|"--full")
            _gs_version_show_full
            ;;
        "--short")
            _gs_version_show_short
            ;;
        "--json")
            _gs_version_show_json
            ;;
        "--components")
            _gs_version_show_components
            ;;
        "--dependencies")
            _gs_version_show_dependencies
            ;;
        "--build-info")
            _gs_version_show_build_info
            ;;
        "--git-info")
            _gs_version_show_git_info
            ;;
        "--system-info")
            _gs_version_show_system_info
            ;;
        "--help"|"-h")
            _gs_version_show_help
            ;;
        "--version"|"-v")
            echo "gs-version v3.0.0"
            ;;
        *)
            _gs_error "version" "未知选项: $option"
            _gs_info "version" "使用 'gs-version --help' 查看帮助"
            return 1
            ;;
    esac
}

# 显示完整版本信息
_gs_version_show_full() {
    local gs_version="${GS_VERSION:-unknown}"
    local build_time="$(_gs_get_build_time)"
    local git_commit="$(_gs_get_git_commit)"
    local shell_info="$(_gs_get_shell_info)"
    local system_info="$(_gs_get_system_info)"

    cat << EOF
Global Scripts V3 - 版本信息
============================
版本: $gs_version
构建时间: $build_time
Git提交: $git_commit
架构: .meta+函数检测架构
Shell: $shell_info
系统: $system_info

安装路径: ${GS_ROOT:-未知}
配置目录: ${GS_CONFIG_DIR:-未知}
EOF
}

# 显示简短版本
_gs_version_show_short() {
    echo "${GS_VERSION:-unknown}"
}

# 显示JSON格式版本信息
_gs_version_show_json() {
    local gs_version="${GS_VERSION:-unknown}"
    local build_time="$(_gs_get_build_time)"
    local git_commit="$(_gs_get_git_commit)"
    local shell_type="$(_gs_detect_shell_basic)"
    local shell_version="$(_gs_get_shell_version)"
    local system_os="$(_gs_get_os_name)"
    local system_version="$(_gs_get_os_version)"
    local core_modules="$(_gs_count_core_modules)"
    local system_commands="$(_gs_count_system_commands)"
    local plugins_loaded="$(_gs_count_loaded_plugins)"
    local startup_time="$(_gs_get_startup_time)"
    local memory_usage="$(_gs_get_memory_usage)"

    cat << EOF
{
  "version": "$gs_version",
  "build_time": "$build_time",
  "git_commit": "$git_commit",
  "architecture": "meta-function-detection",
  "shell": {
    "type": "$shell_type",
    "version": "$shell_version",
    "platform": "$(uname -m)-$(uname -s | tr '[:upper:]' '[:lower:]')"
  },
  "system": {
    "os": "$system_os",
    "version": "$system_version"
  },
  "components": {
    "core": "$gs_version",
    "plugins": "$gs_version",
    "tools": "$gs_version"
  },
  "installation": {
    "root_path": "${GS_ROOT:-unknown}",
    "config_dir": "${GS_CONFIG_DIR:-unknown}",
    "plugins_dir": "${GS_PLUGINS_DIR:-unknown}"
  },
  "statistics": {
    "core_modules": $core_modules,
    "system_commands": $system_commands,
    "plugins_loaded": $plugins_loaded
  },
  "performance": {
    "startup_time_ms": $startup_time,
    "memory_usage_mb": $memory_usage
  }
}
EOF
}

# 显示组件版本信息
_gs_version_show_components() {
    local gs_version="${GS_VERSION:-unknown}"
    
    echo "Global Scripts V3 - 组件版本"
    echo "=========================="
    echo "核心系统: $gs_version"
    echo "基础库: $gs_version (lib/base.sh)"
    echo "日志系统: $gs_version (core/logger.sh)"
    echo "缓存管理: $gs_version (core/cache_manager.sh)"
    echo "插件检测器: $gs_version (core/plugin_detector.sh)"
    echo "命令注册器: $gs_version (core/command_registry.sh)"
    echo "系统加载器: $gs_version (core/system_loader.sh)"
    echo "平台兼容层: $gs_version (core/platform_compat.sh)"
    echo
    echo "系统命令: $gs_version"
    echo "  gs-version: $gs_version"
    echo "  gs-status: $gs_version"
    echo "  gs-plugins: $gs_version"
    echo "  gs-help: $gs_version"
}

# 显示依赖信息
_gs_version_show_dependencies() {
    echo "Global Scripts V3 - 依赖信息"
    echo "=========================="
    echo "必需依赖:"
    echo "  bash: $(_gs_check_bash_version)"
    echo "  基础工具: $(_gs_check_basic_tools)"
    echo
    echo "可选依赖:"
    echo "  jq: $(_gs_check_jq_version)"
    echo "  git: $(_gs_check_git_version)"
    echo "  python3: $(_gs_check_python_version)"
    echo
    echo "系统要求:"
    echo "  最低Shell版本: bash 3.2+ 或 zsh 5.0+"
    echo "  支持系统: macOS 10.12+, Linux (Ubuntu 16.04+, CentOS 7+)"
}

# 显示构建信息
_gs_version_show_build_info() {
    local build_time="$(_gs_get_build_time)"
    local git_commit="$(_gs_get_git_commit)"
    local git_branch="$(_gs_get_git_branch)"
    local build_host="$(_gs_get_build_host)"
    
    echo "Global Scripts V3 - 构建信息"
    echo "=========================="
    echo "构建时间: $build_time"
    echo "Git提交: $git_commit"
    echo "Git分支: $git_branch"
    echo "构建主机: $build_host"
    echo "构建类型: 开发版本"
    echo "架构类型: .meta+函数检测架构"
}

# 显示Git信息
_gs_version_show_git_info() {
    if [[ ! -d "${GS_ROOT}/.git" ]]; then
        echo "Git信息不可用 (非Git仓库)"
        return 1
    fi
    
    echo "Global Scripts V3 - Git信息"
    echo "========================="
    echo "当前分支: $(_gs_get_git_branch)"
    echo "最新提交: $(_gs_get_git_commit)"
    echo "提交时间: $(_gs_get_git_commit_date)"
    echo "提交作者: $(_gs_get_git_author)"
    echo "仓库状态: $(_gs_get_git_status)"
    echo "远程仓库: $(_gs_get_git_remote)"
}

# 显示系统环境信息
_gs_version_show_system_info() {
    echo "Global Scripts V3 - 系统信息"
    echo "=========================="
    echo "操作系统: $(_gs_get_os_name) $(_gs_get_os_version)"
    echo "内核版本: $(uname -r)"
    echo "架构: $(uname -m)"
    echo "Shell类型: $(_gs_detect_shell_basic)"
    echo "Shell版本: $(_gs_get_shell_version)"
    echo "终端类型: ${TERM:-unknown}"
    echo "用户名: ${USER:-unknown}"
    echo "主目录: ${HOME:-unknown}"
    echo "当前目录: $(pwd)"
    echo "PATH: ${PATH}"
}

# ============================================================================
# 辅助函数
# ============================================================================

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

# 获取构建时间
_gs_get_build_time() {
    # 尝试从VERSION文件的修改时间获取
    if [[ -f "${GS_ROOT}/VERSION" ]]; then
        if command -v stat >/dev/null 2>&1; then
            # macOS和Linux的stat命令不同
            if [[ "$(uname)" == "Darwin" ]]; then
                stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "${GS_ROOT}/VERSION" 2>/dev/null || echo "unknown"
            else
                stat -c "%y" "${GS_ROOT}/VERSION" 2>/dev/null | cut -d'.' -f1 || echo "unknown"
            fi
        else
            echo "unknown"
        fi
    else
        echo "unknown"
    fi
}

# 获取Git提交信息
_gs_get_git_commit() {
    if [[ -d "${GS_ROOT}/.git" ]] && command -v git >/dev/null 2>&1; then
        (cd "$GS_ROOT" && git rev-parse --short HEAD 2>/dev/null) || echo "unknown"
    else
        echo "unknown"
    fi
}

# 获取Git分支
_gs_get_git_branch() {
    if [[ -d "${GS_ROOT}/.git" ]] && command -v git >/dev/null 2>&1; then
        (cd "$GS_ROOT" && git branch --show-current 2>/dev/null) || echo "unknown"
    else
        echo "unknown"
    fi
}

# 获取Git提交日期
_gs_get_git_commit_date() {
    if [[ -d "${GS_ROOT}/.git" ]] && command -v git >/dev/null 2>&1; then
        (cd "$GS_ROOT" && git log -1 --format="%ci" 2>/dev/null) || echo "unknown"
    else
        echo "unknown"
    fi
}

# 获取Git作者
_gs_get_git_author() {
    if [[ -d "${GS_ROOT}/.git" ]] && command -v git >/dev/null 2>&1; then
        (cd "$GS_ROOT" && git log -1 --format="%an <%ae>" 2>/dev/null) || echo "unknown"
    else
        echo "unknown"
    fi
}

# 获取Git状态
_gs_get_git_status() {
    if [[ -d "${GS_ROOT}/.git" ]] && command -v git >/dev/null 2>&1; then
        if (cd "$GS_ROOT" && git diff --quiet && git diff --staged --quiet 2>/dev/null); then
            echo "clean"
        else
            echo "modified"
        fi
    else
        echo "unknown"
    fi
}

# 获取Git远程仓库
_gs_get_git_remote() {
    if [[ -d "${GS_ROOT}/.git" ]] && command -v git >/dev/null 2>&1; then
        (cd "$GS_ROOT" && git remote get-url origin 2>/dev/null) || echo "unknown"
    else
        echo "unknown"
    fi
}

# 获取构建主机信息
_gs_get_build_host() {
    echo "$(hostname 2>/dev/null || echo 'unknown')@$(uname -s)"
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

# 统计核心模块数量
_gs_count_core_modules() {
    if [[ -d "${GS_CORE_DIR}" ]]; then
        find "${GS_CORE_DIR}" -name "*.sh" | wc -l | tr -d ' '
    else
        echo "0"
    fi
}

# 统计系统命令数量
_gs_count_system_commands() {
    if [[ -d "${GS_SYSTEM_DIR}" ]]; then
        find "${GS_SYSTEM_DIR}" -name "*.sh" | wc -l | tr -d ' '
    else
        echo "0"
    fi
}

# 统计已加载插件数量
_gs_count_loaded_plugins() {
    # 检查当前Shell中的gs_*函数数量作为近似值
    declare -F | grep -c "gs_" 2>/dev/null || echo "0"
}

# 获取启动时间（毫秒）
_gs_get_startup_time() {
    # 这是一个占位符，实际值应该在启动时测量
    echo "${_GS_STARTUP_TIME_MS:-unknown}"
}

# 获取内存使用情况（MB）
_gs_get_memory_usage() {
    # 尝试获取当前进程的内存使用情况
    if command -v ps >/dev/null 2>&1; then
        ps -o rss= -p $$ 2>/dev/null | awk '{print $1/1024}' 2>/dev/null | cut -d'.' -f1 || echo "unknown"
    else
        echo "unknown"
    fi
}

# 获取Shell信息
_gs_get_shell_info() {
    echo "$(_gs_detect_shell_basic) $(_gs_get_shell_version | cut -d' ' -f2)"
}

# 获取系统信息
_gs_get_system_info() {
    echo "$(_gs_get_os_name) $(_gs_get_os_version)"
}

# 检查依赖版本
_gs_check_bash_version() {
    if [[ -n "${BASH_VERSION:-}" ]]; then
        echo "✅ bash $BASH_VERSION"
    else
        echo "❌ 未安装或不是bash环境"
    fi
}

_gs_check_basic_tools() {
    local tools=(cat grep sed awk find)
    local missing=()
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing+=("$tool")
        fi
    done
    
    if [[ ${#missing[@]} -eq 0 ]]; then
        echo "✅ 所有基础工具可用"
    else
        echo "❌ 缺少: ${missing[*]}"
    fi
}

_gs_check_jq_version() {
    if command -v jq >/dev/null 2>&1; then
        echo "✅ $(jq --version 2>/dev/null)"
    else
        echo "❌ 未安装 (可选)"
    fi
}

_gs_check_git_version() {
    if command -v git >/dev/null 2>&1; then
        echo "✅ $(git --version 2>/dev/null)"
    else
        echo "❌ 未安装 (可选)"
    fi
}

_gs_check_python_version() {
    if command -v python3 >/dev/null 2>&1; then
        echo "✅ $(python3 --version 2>/dev/null)"
    else
        echo "❌ 未安装 (可选)"
    fi
}

# ============================================================================
# 帮助信息
# ============================================================================

_gs_version_show_help() {
    cat << 'HELP'
gs-version - 版本信息管理

功能描述:
  提供全面的版本信息查询功能，包括系统版本、组件版本、依赖信息等

用法:
  gs-version [选项]

基本选项:
  (无选项)            显示完整版本信息
  --short             显示简短版本号
  --json              JSON格式输出
  --components        显示组件版本信息
  --dependencies      显示依赖版本信息

高级选项:
  --build-info        显示构建信息
  --git-info          显示Git信息（如果可用）
  --system-info       显示系统环境信息

其他选项:
  --help, -h          显示此帮助信息
  --version, -v       显示命令版本

示例:
  gs-version                    # 显示完整版本信息
  gs-version --short           # 显示简短版本号
  gs-version --json            # JSON格式输出
  gs-version --components      # 显示组件版本
  gs-version --dependencies    # 显示依赖信息
  gs-version --git-info        # 显示Git信息

HELP
}

# ============================================================================
# 命令自检
# ============================================================================

_gs_system_version_selfcheck() {
    # 检查必需的环境变量
    if [[ -z "${GS_ROOT:-}" ]]; then
        _gs_error "version" "GS_ROOT环境变量未设置"
        return 1
    fi
    
    # 检查VERSION文件
    if [[ ! -f "${GS_ROOT}/VERSION" ]]; then
        _gs_error "version" "VERSION文件不存在: ${GS_ROOT}/VERSION"
        return 1
    fi
    
    return 0
}

# 执行自检
if ! _gs_system_version_selfcheck; then
    _gs_error "version" "系统命令自检失败"
    return 1
fi

_gs_debug "version" "gs-version系统命令加载完成"
