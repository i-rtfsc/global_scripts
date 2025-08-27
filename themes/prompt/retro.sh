#!/bin/bash
# ============================================================================
# Global Scripts Prompt 主题: Retro - 复古风格
# 受经典终端和80年代美学启发的复古主题
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
# 颜色配置 - 复古绿色终端风格
# ============================================================================

COLOR_BORDER=040         # 边框颜色 (绿色)
COLOR_USER=046           # 用户信息 (亮绿)
COLOR_SYSTEM=082         # 系统信息 (浅绿)
COLOR_PATH=118           # 路径信息 (黄绿)
COLOR_TIME=154           # 时间信息 (粉绿)
COLOR_ENV=190            # 环境信息 (黄色)
COLOR_GIT=076            # Git信息 (深绿)
COLOR_PROMPT=148         # 提示符 (橄榄绿)
COLOR_ACCENT=226         # 强调色 (黄色)

# ============================================================================
# 符号配置 - 复古终端符号
# ============================================================================

SYMBOL_BORDER_H="-"                 # 水平边框
SYMBOL_BORDER_V="|"                 # 垂直边框
SYMBOL_CORNER_TL="+"                # 左上角
SYMBOL_CORNER_TR="+"                # 右上角
SYMBOL_CORNER_BL="+"                # 左下角
SYMBOL_CORNER_BR="+"                # 右下角
SYMBOL_JUNCTION_T="+"               # T型连接
SYMBOL_JUNCTION_L="+"               # 左连接
SYMBOL_JUNCTION_R="+"               # 右连接
SYMBOL_CPU="cpu:"                   # CPU符号
SYMBOL_MEMORY="py:"                 # 内存符号
SYMBOL_DISK="dir:"                  # 磁盘符号
SYMBOL_NETWORK="host:"              # 网络符号

# ============================================================================
# 复古终端辅助函数
# ============================================================================

# 带颜色的文本输出
function _gs_retro_color_text() {
    local code=$1
    local text=$2
    
    if [ -n "$ZSH_VERSION" ]; then
        echo "%F{${code}}${text}%f"
    else
        echo "\\[\\e[38;5;${code}m\\]${text}\\[\\033[0m\\]"
    fi
}

# 获取终端宽度（用于绘制边框）
function _gs_retro_terminal_width() {
    local width
    if command -v tput >/dev/null 2>&1; then
        width=$(tput cols 2>/dev/null)
    else
        width=${COLUMNS:-80}
    fi
    echo "${width:-80}"
}

# 系统信息显示
function _gs_retro_system_info() {
    local user_info
    local host_info
    
    if [ -n "$ZSH_VERSION" ]; then
        user_info="%n"
        host_info=$(_gs_theme_ip)
    else
        user_info="\\u"
        host_info="\\h"
    fi
    
    echo "$(_gs_retro_color_text $COLOR_USER "$SYMBOL_CPU $user_info") $(_gs_retro_color_text $COLOR_SYSTEM "$SYMBOL_NETWORK $host_info")"
}

# 路径信息
function _gs_retro_path_info() {
    local path_display
    if [ -n "$ZSH_VERSION" ]; then
        path_display="${PWD/#$HOME/~}"
        # 如果路径太长，智能截断
        if [[ ${#path_display} -gt 50 ]]; then
            local dir_name=$(basename "$path_display")
            local parent_dir=$(dirname "$path_display")
            if [[ ${#parent_dir} -gt 30 ]]; then
                path_display=".../${parent_dir: -20}/$dir_name"
            else
                path_display="$parent_dir/$dir_name"
            fi
        fi
    else
        path_display="\\w"
    fi
    
    echo "$(_gs_retro_color_text $COLOR_PATH "$SYMBOL_DISK $path_display")"
}

# 时间信息
function _gs_retro_time_info() {
    if [ -n "$ZSH_VERSION" ]; then
        local time_str=$(date '+%H:%M:%S')
        echo "$(_gs_retro_color_text $COLOR_TIME "[$time_str]")"
    else
        echo "$(_gs_retro_color_text $COLOR_TIME "[\\t]")"
    fi
}

# 环境信息
function _gs_retro_env_info() {
    local env_info=$(_gs_theme_conda_or_py_info)
    if [[ "$env_info" != "no-py" ]]; then
        if [ -n "$ZSH_VERSION" ]; then
            # 直接显示环境信息，不添加py:前缀
            echo " $(_gs_retro_color_text $COLOR_ENV "$env_info")"
        else
            echo " $(_gs_retro_color_text $COLOR_ENV "\$(_gs_theme_conda_or_py_info)")"
        fi
    fi
}

# Git信息
function _gs_retro_git_info() {
    local git_info=$(_gs_theme_git_info)
    if [ -n "$git_info" ]; then
        echo " $(_gs_retro_color_text $COLOR_GIT "[$git_info]")"
    fi
}

# 复古风格提示符
function _gs_retro_prompt() {
    _gs_retro_color_text $COLOR_PROMPT ">"
}

# ============================================================================
# 提示符设置
# ============================================================================

if [ -n "$ZSH_VERSION" ]; then
    PROMPT='$(_gs_retro_color_text $COLOR_BORDER "$SYMBOL_CORNER_TL$SYMBOL_BORDER_H") $(_gs_retro_system_info) $(_gs_retro_color_text $COLOR_BORDER "$SYMBOL_BORDER_H$SYMBOL_JUNCTION_T$SYMBOL_BORDER_H") $(_gs_retro_path_info)$(_gs_retro_env_info)$(_gs_retro_git_info)
$(_gs_retro_color_text $COLOR_BORDER "$SYMBOL_CORNER_BL$SYMBOL_BORDER_H")$(_gs_retro_prompt) '
    
    # 右侧显示时间
    RPROMPT='$(_gs_retro_time_info) $(_gs_retro_color_text $COLOR_BORDER "$SYMBOL_BORDER_H$SYMBOL_CORNER_TR")'
    
    setopt PROMPT_SUBST
else
    export PS1="$(_gs_retro_color_text $COLOR_BORDER "$SYMBOL_CORNER_TL$SYMBOL_BORDER_H") $(_gs_retro_system_info) $(_gs_retro_color_text $COLOR_BORDER "$SYMBOL_BORDER_H$SYMBOL_JUNCTION_T$SYMBOL_BORDER_H") $(_gs_retro_path_info)$(_gs_retro_env_info)$(_gs_retro_git_info)
$(_gs_retro_color_text $COLOR_BORDER "$SYMBOL_CORNER_BL$SYMBOL_BORDER_H")$(_gs_retro_prompt) "
fi