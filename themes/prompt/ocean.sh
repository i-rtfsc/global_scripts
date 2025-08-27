#!/bin/bash
# ============================================================================
# Global Scripts Prompt 主题: Ocean - 海洋风格（重构版）
# 以蓝绿色调为主的清新主题，营造平静专注的编程环境
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
COLOR_WAVE=027      # 波浪符号 (深蓝)
COLOR_USER=081      # 用户信息 (青色)
COLOR_HOST=039      # 主机信息 (亮蓝)
COLOR_PATH=051      # 路径信息 (青绿)
COLOR_ENV=045       # 环境信息 (浅蓝)
COLOR_GIT=083       # Git信息 (青色)
COLOR_PROMPT=033    # 提示符 (蓝色)
COLOR_TIME=087      # 时间信息 (紫蓝)

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

# 波浪符号
_gs_ocean_wave() {
    _gs_color $COLOR_WAVE "~"
}

# 用户信息
_gs_ocean_user() {
    if [ -n "$ZSH_VERSION" ]; then
        _gs_color $COLOR_USER "%n"
    else
        _gs_color $COLOR_USER "\\u"
    fi
}

# 主机信息
_gs_ocean_host() {
    if [ -n "$ZSH_VERSION" ]; then
        local ip=$(_gs_theme_ip)
        _gs_color $COLOR_HOST "$ip"
    else
        _gs_color $COLOR_HOST "\\h"
    fi
}

# 路径信息
_gs_ocean_path() {
    if [ -n "$ZSH_VERSION" ]; then
        _gs_color $COLOR_PATH "%~"
    else
        _gs_color $COLOR_PATH "\\w"
    fi
}

# 环境信息
_gs_ocean_env() {
    local env_info=$(_gs_theme_conda_or_py_info)
    if [[ "$env_info" != "no-py" ]]; then
        echo " $(_gs_color $COLOR_ENV "$env_info")"
    fi
}

# Git信息
_gs_ocean_git() {
    local git_info=$(_gs_theme_git_info)
    if [ -n "$git_info" ]; then
        echo " $(_gs_color $COLOR_GIT "$git_info")"
    fi
}

# 提示符
_gs_ocean_prompt() {
    _gs_color $COLOR_PROMPT "$"
}

# 时间信息（右侧）
_gs_ocean_time() {
    if [ -n "$ZSH_VERSION" ]; then
        _gs_color $COLOR_TIME "%T"
    fi
}

# ============================================================================
# 提示符设置
# ============================================================================

if [ -n "$ZSH_VERSION" ]; then
    PROMPT='$(_gs_ocean_wave) $(_gs_ocean_user)@$(_gs_ocean_host) [$(_gs_ocean_path)]$(_gs_ocean_env)$(_gs_ocean_git)
$(_gs_ocean_prompt) '
    RPROMPT='$(_gs_ocean_time)'
    setopt PROMPT_SUBST
else
    export PS1="$(_gs_ocean_wave) $(_gs_ocean_user)@$(_gs_ocean_host) [$(_gs_ocean_path)]$(_gs_ocean_env)$(_gs_ocean_git)
$(_gs_ocean_prompt) "
fi