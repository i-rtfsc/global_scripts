#!/bin/bash
# ============================================================================
# Global Scripts Prompt 主题: Powerline - 强力线条风格（重构版）
# 分段显示信息，简洁的Powerline风格
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
COLOR_USER=024      # 用户信息 (深蓝)
COLOR_PATH=240      # 路径信息 (灰色)
COLOR_GIT=022       # Git信息 (深绿)
COLOR_ENV=208       # 环境信息 (橙色)
COLOR_PROMPT=036    # 提示符 (青色)

# ============================================================================
# 颜色函数
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

# 段落函数 - 带背景色
_gs_segment() {
    local bg_color=$1
    local fg_color=$2
    local text=$3
    if [ -n "$ZSH_VERSION" ]; then
        echo "%K{$bg_color}%F{$fg_color} $text %k%f"
    else
        echo "\\[\\e[48;5;${bg_color}m\\e[38;5;${fg_color}m\\] $text \\[\\e[0m\\]"
    fi
}

# ============================================================================
# 主题组件
# ============================================================================

# 用户信息段
_gs_powerline_user() {
    if [ -n "$ZSH_VERSION" ]; then
        local ip=$(_gs_theme_ip)
        _gs_segment $COLOR_USER 255 "%n@$ip"
    else
        _gs_segment $COLOR_USER 255 "\\u@\\h"
    fi
}

# 路径信息段
_gs_powerline_path() {
    if [ -n "$ZSH_VERSION" ]; then
        local path="%~"
        _gs_segment $COLOR_PATH 255 "$path"
    else
        _gs_segment $COLOR_PATH 255 "\\w"
    fi
}

# Git信息段
_gs_powerline_git() {
    local git_info=$(_gs_theme_git_info)
    if [ -n "$git_info" ]; then
        echo "$(_gs_powerline_sep) $(_gs_segment $COLOR_GIT 255 "$git_info")"
    fi
}

# 环境信息段
_gs_powerline_env() {
    local env_info=$(_gs_theme_conda_or_py_info)
    if [[ "$env_info" != "no-py" ]]; then
        echo "$(_gs_powerline_sep) $(_gs_segment $COLOR_ENV 16 "$env_info")"
    fi
}

# 分隔符
_gs_powerline_sep() {
    _gs_color $COLOR_PROMPT ">"
}

# 提示符
_gs_powerline_prompt() {
    _gs_color $COLOR_PROMPT "❯"
}

# ============================================================================
# 提示符设置
# ============================================================================

if [ -n "$ZSH_VERSION" ]; then
    PROMPT='$(_gs_powerline_user)$(_gs_powerline_sep) $(_gs_powerline_path)$(_gs_powerline_git)$(_gs_powerline_env)
$(_gs_powerline_prompt) '
    setopt PROMPT_SUBST
else
    export PS1="$(_gs_powerline_user)$(_gs_powerline_sep) $(_gs_powerline_path)$(_gs_powerline_git)$(_gs_powerline_env)
$(_gs_powerline_prompt) "
fi