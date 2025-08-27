#!/bin/bash
# ============================================================================
# Global Scripts Prompt 主题配置 - 现代化终端提示符主题
# 基于V2版本增强，支持bash和zsh，美观实用的双行显示格式
# 显示系统信息、Git状态、Python环境等开发必需信息
# ============================================================================

_gs_get_script_dir() {
    if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
        # Bash环境
        echo "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    elif [[ -n "${(%):-%x}" ]]; then
        # Zsh环境
        echo "$(cd "$(dirname "${(%):-%x}")" && pwd)"
    elif [[ -n "$0" ]]; then
        # 备选方案
        echo "$(cd "$(dirname "$0")" && pwd)"
    else
        # 最后备选
        pwd
    fi
}

# 导入主题信息函数
source "$(_gs_get_script_dir)/gs_prompt_info.sh"

# ============================================================================
# 颜色配置 - 256色彩色方案，可自定义调整
# ============================================================================

# 主要颜色定义 (256色模式)
COLOR_PROMPT_HEAD=245    # 提示符边框颜色 (灰色)
COLOR_FG_SPLIT=003       # 分隔符颜色 (黄色)
COLOR_SYS_INFO=200       # 系统信息颜色 (粉红色)
COLOR_AT=226             # @ 符号颜色 (亮黄色)
COLOR_PATH=075           # 路径颜色 (蓝色)
COLOR_TIME=169           # 时间颜色 (紫色)
COLOR_ENV=069            # 环境信息颜色 (蓝绿色)
COLOR_GIT=110            # Git信息颜色 (绿色)
COLOR_SPILT=033          # 箭头分隔符颜色 (蓝色)
COLOR_FINAL1=214         # 结束符号颜色1 (橙色)
COLOR_FINAL2=199         # 结束符号颜色2 (粉色)
COLOR_FINAL3=033         # 结束符号颜色3 (蓝色)

# ============================================================================
# 符号配置 - 可自定义的显示符号
# ============================================================================

SYMBOL_SPLIT_LEFT="["                    # 左方括号
SYMBOL_SPLIT_RIGHT="]"                   # 右方括号
SYMBOL_SPLIT_PARENTHESES_LEFT="("        # 左圆括号
SYMBOL_SPLIT_PARENTHESES_RIGHT=")"       # 右圆括号
SYMBOL_SPLIT_AT="@"                      # @ 符号
SYMBOL_SPLIT_COLON=":"                   # 冒号
SYMBOL_SPLIT_ARROW="➬"                   # 箭头符号

# 根据操作系统选择不同的终结符号
if ${isMac} ; then
    SYMBOL_SPLIT_FINAL="⬡"  # macOS 使用六角形
else
    SYMBOL_SPLIT_FINAL="☺"  # Linux 使用笑脸
fi

# ============================================================================
# 提示符组件函数 - 各个显示组件的生成函数
# ============================================================================

# 第一行开始符号
function _gs_prompt_start_line1() {
    _gs_theme_color_text $COLOR_PROMPT_HEAD "╭─"
}

# 第二行开始符号
function _gs_prompt_start_line2() {
    _gs_theme_color_text $COLOR_PROMPT_HEAD "╰─"
}

# 左方括号
function _gs_prompt_symbol_split_left() {
    _gs_theme_color_text $COLOR_FG_SPLIT "${SYMBOL_SPLIT_LEFT}"
}

# 右方括号
function _gs_prompt_symbol_split_right() {
    _gs_theme_color_text $COLOR_FG_SPLIT "${SYMBOL_SPLIT_RIGHT}"
}

# 左圆括号
function _gs_prompt_symbol_split_parentheses_left() {
    _gs_theme_color_text $COLOR_FG_SPLIT "${SYMBOL_SPLIT_PARENTHESES_LEFT}"
}

# 右圆括号
function _gs_prompt_symbol_split_parentheses_right() {
    _gs_theme_color_text $COLOR_FG_SPLIT "${SYMBOL_SPLIT_PARENTHESES_RIGHT}"
}

# @ 符号
function _gs_prompt_symbol_at() {
    _gs_theme_color_text $COLOR_AT "${SYMBOL_SPLIT_AT}"
}

# 冒号符号
function _gs_prompt_symbol_split_colon() {
    _gs_theme_color_text $COLOR_AT "${SYMBOL_SPLIT_COLON}"
}

# 用户名
function _gs_prompt_name() {
    _gs_theme_color_text $COLOR_SYS_INFO "$(_gs_theme_user_name)"
}

# IP地址
function _gs_prompt_ip() {
    if [ -n "$ZSH_VERSION" ]; then
        _gs_theme_color_text $COLOR_SYS_INFO "$(_gs_theme_ip)"
    else
        _gs_theme_color_text $COLOR_SYS_INFO "\$(_gs_theme_ip)"
    fi
}

# 当前目录
function _gs_prompt_current_dir() {
    _gs_theme_color_text $COLOR_PATH "$(_gs_theme_current_dir)"
}

# 箭头分隔符（仅zsh显示）
function _gs_prompt_spilt_icon() {
    if [ -n "$ZSH_VERSION" ]; then
        local arrow_text=$(_gs_theme_color_text $COLOR_SPILT "${SYMBOL_SPLIT_ARROW}")
        if ${isMac} ; then
            echo "${arrow_text}"
        else
            echo " ${arrow_text} "
        fi
    else
        echo ""
    fi
}

# 时间显示
function _gs_prompt_time() {
    if [ -n "$ZSH_VERSION" ]; then
        _gs_theme_color_text $COLOR_TIME "$(_gs_theme_get_time)"
    else
        _gs_theme_color_text $COLOR_TIME "\$(_gs_theme_get_time)"
    fi
}

# 环境信息（Shell类型 + Python环境）
function _gs_prompt_env_info() {
    local shell_info=$(_gs_theme_shell_info)
    
    if [ -n "$ZSH_VERSION" ]; then
        local py_info=$(_gs_theme_conda_or_py_info)
        _gs_theme_color_text $COLOR_ENV "${shell_info}-${py_info}"
    else
        _gs_theme_color_text $COLOR_ENV "${shell_info}-\$(_gs_theme_conda_or_py_info)"
    fi
}

# 结束符号（彩色）
function _gs_prompt_smile() {
    local text1=$(_gs_theme_color_text $COLOR_FINAL1 "${SYMBOL_SPLIT_FINAL}")
    local text2=$(_gs_theme_color_text $COLOR_FINAL2 "${SYMBOL_SPLIT_FINAL}")
    local text3=$(_gs_theme_color_text $COLOR_FINAL3 "${SYMBOL_SPLIT_FINAL}")
    
    if ${isMac} ; then
        echo " ${text1}${text2}${text3} "
    else
        echo "${text1} ${text2} ${text3} "
    fi
}

# Git信息显示（右侧提示符）
function _gs_prompt_git_info() {
    local git_info=$(_gs_theme_git_info)
    if [ -n "${git_info}" ]; then
        _gs_theme_color_text $COLOR_GIT "${git_info}"
    fi
}

# ============================================================================
# 提示符设置 - 根据Shell类型设置不同的提示符
# ============================================================================

# zsh提示符设置
if [ -n "$ZSH_VERSION" ]; then
    # 主提示符（左侧，双行）
    PROMPT='$(_gs_prompt_start_line1)$(_gs_prompt_symbol_split_left)$(_gs_prompt_name)$(_gs_prompt_symbol_at)$(_gs_prompt_ip)$(_gs_prompt_symbol_split_colon)$(_gs_prompt_current_dir)$(_gs_prompt_symbol_split_right)$(_gs_prompt_spilt_icon)$(_gs_prompt_symbol_split_left)$(_gs_prompt_time)$(_gs_prompt_symbol_split_right)
$(_gs_prompt_start_line2)$(_gs_prompt_symbol_split_parentheses_left)$(_gs_prompt_env_info)$(_gs_prompt_symbol_split_parentheses_right)$(_gs_prompt_smile)'
    
    # 右侧提示符（Git信息）
    RPROMPT='$(_gs_prompt_git_info)'
    
    # 设置zsh选项
    setopt PROMPT_SUBST  # 允许提示符中的命令替换
    
# bash提示符设置
else
    # bash 主提示符
    export PS1="$(_gs_prompt_start_line1)$(_gs_prompt_symbol_split_left)$(_gs_prompt_name)$(_gs_prompt_symbol_at)$(_gs_prompt_ip)$(_gs_prompt_symbol_split_colon)$(_gs_prompt_current_dir)$(_gs_prompt_symbol_split_right)$(_gs_prompt_spilt_icon)$(_gs_prompt_symbol_split_left)$(_gs_prompt_time)$(_gs_prompt_symbol_split_right)
$(_gs_prompt_start_line2)$(_gs_prompt_symbol_split_parentheses_left)$(_gs_prompt_env_info)$(_gs_prompt_symbol_split_parentheses_right)$(_gs_prompt_smile)"
fi

# ============================================================================
# 使用说明和安装指南
# ============================================================================

# 主题效果预览：
# ╭─[用户名@192.168.1.100:~/项目路径]➬[2024-08-03 15:30:22]
# ╰─(zsh-conda_env) ⬡ ⬡ ⬡                                              git:main*

# 安装方法：
# 1. 手动安装：source /path/to/gs_theme.sh
# 2. 永久安装：将上述命令添加到 ~/.bashrc 或 ~/.zshrc
# 3. 通过配置系统：gs-config-install prompt

# 自定义颜色：
# 修改上面的 COLOR_* 变量来自定义颜色方案
# 256色对照表：https://jonasjacek.github.io/colors/

# 自定义符号：
# 修改 SYMBOL_* 变量来自定义显示符号
# 确保字体支持特殊Unicode字符

# Git信息说明：
# * = 有未提交的修改
# + = 有未跟踪的文件  
# ! = 有已暂存的更改

# 环境信息说明：
# zsh-conda_env = zsh shell + conda环境
# bash-py3.9 = bash shell + Python 3.9
# zsh-no-py = zsh shell + 无Python环境