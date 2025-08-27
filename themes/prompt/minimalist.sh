#!/bin/bash
# ============================================================================
# Global Scripts Prompt 主题: Minimalist - 极简主义风格（重构版）
# 简洁明了，专注于核心信息，适合专业开发者
# ============================================================================

_gs_get_script_dir() {
    if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
        echo "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    elif [[ -n "${(%):-%x}" ]]; then
        echo "$(cd "$(dirname "${(%):-%x}")" && pwd)"
    elif [[ -n "$0" ]]; then
        echo "$(cd "$(dirname "$0")" && pwd)"
    else
        pwd
    fi
}

# 导入主题信息函数
source "$(_gs_get_script_dir)/gs_prompt_info.sh"

# ============================================================================
# 颜色配置
# ============================================================================
COLOR_USER=255      # 用户信息 (白色)
COLOR_PATH=250      # 路径信息 (亮灰)
COLOR_ENV=248       # 环境信息 (浅灰)
COLOR_GIT=034       # Git信息 (绿色)
COLOR_PROMPT=242    # 提示符 (中灰)

# ============================================================================
# 简化的颜色函数
# ============================================================================
_gs_color() {
    local color=$1
    local text=$2
    if [ -n "$ZSH_VERSION" ]; then
        echo "%F{$color}$text%f"
    else
        echo "\\[\\e[38;5;${color}m\\]$text\\[\\e[0m\\]"
    fi
}

# ============================================================================
# 主题组件
# ============================================================================

# 用户@主机
_gs_minimalist_user() {
    if [ -n "$ZSH_VERSION" ]; then
        local ip=$(_gs_theme_ip)
        _gs_color $COLOR_USER "%n@$ip"
    else
        _gs_color $COLOR_USER "\\u@$ip"
    fi
}


# 当前路径
_gs_minimalist_path() {
    if [ -n "$ZSH_VERSION" ]; then
        _gs_color $COLOR_PATH "%~"
    else
        _gs_color $COLOR_PATH "\\w"
    fi
}

# 环境信息
_gs_minimalist_env() {
    local env_info=$(_gs_theme_conda_or_py_info)
    if [[ "$env_info" != "no-py" ]]; then
        echo " $(_gs_color $COLOR_ENV "$env_info")"
    fi
}

# Git信息
_gs_minimalist_git() {
    local git_info=$(_gs_theme_git_info)
    if [ -n "$git_info" ]; then
        echo " $(_gs_color $COLOR_GIT "$git_info")"
    fi
}

# 提示符
_gs_minimalist_prompt() {
    _gs_color $COLOR_PROMPT ">"
}

# ============================================================================
# 提示符设置
# ============================================================================

if [ -n "$ZSH_VERSION" ]; then
    PROMPT='$(_gs_minimalist_user) $(_gs_minimalist_path)$(_gs_minimalist_env)$(_gs_minimalist_git)
$(_gs_minimalist_prompt) '
    setopt PROMPT_SUBST
else
    export PS1="$(_gs_minimalist_user) $(_gs_minimalist_path)$(_gs_minimalist_env)$(_gs_minimalist_git)
$(_gs_minimalist_prompt) "
fi
