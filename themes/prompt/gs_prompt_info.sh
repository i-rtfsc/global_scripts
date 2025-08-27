#!/bin/bash
# ============================================================================
# Global Scripts Prompt 主题信息函数库
# 提供各种系统信息获取功能，支持bash和zsh
# ============================================================================

# 检测操作系统类型
machine="$(uname -s)"
case "${machine}" in
    Linux*)     isMac=false;;
    Darwin*)    isMac=true;;
    *)          isMac=false;;
esac

# ============================================================================
# 系统信息获取函数
# ============================================================================

# 获取本机IP地址
function _gs_theme_ip() {
    local ip=""
    if ${isMac} ; then
        # macOS 优先获取en0，失败则尝试en1
        ip=$(ipconfig getifaddr en0 2>/dev/null)
        if [ -z "${ip}" ]; then
            ip=$(ipconfig getifaddr en1 2>/dev/null)
        fi
        # 如果都没有，尝试获取WiFi接口
        if [ -z "${ip}" ]; then
            ip=$(ipconfig getifaddr en2 2>/dev/null)
        fi
    else
        # Linux 通过默认路由接口获取IP
        local default_interface=$(route | grep default | awk 'NR==1{print $NF}' 2>/dev/null)
        if [ -n "${default_interface}" ]; then
            ip=$(ip addr show "${default_interface}" 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -f1 -d '/' | head -n1)
        fi
        # 备选方案：使用hostname命令
        if [ -z "${ip}" ]; then
            ip=$(hostname -I 2>/dev/null | awk '{print $1}')
        fi
    fi
    
    # 如果都获取不到，显示localhost
    if [ -z "${ip}" ]; then
        ip="localhost"
    fi
    
    echo "${ip}"
}

# 获取用户名（兼容bash和zsh）
function _gs_theme_user_name() {
    if [ -n "$ZSH_VERSION" ]; then
        echo "%n"  # zsh 格式
    else
        echo "\\u"  # bash 格式
    fi
}

# 获取当前目录（支持~缩写）
function _gs_theme_current_dir() {
    if [ -n "$ZSH_VERSION" ]; then
        # zsh 自动替换HOME为~
        echo "${PWD/#$HOME/~}"
    else
        # bash 使用\\w自动替换
        echo "\\w"
    fi
}

# 获取当前时间
function _gs_theme_get_time() {
    date "+%Y-%m-%d %H:%M:%S"
}

# 获取Python/Conda环境信息
function _gs_theme_conda_or_py_info() {
    local env_info=""
    
    # 优先显示Conda环境
    if [ -n "$CONDA_DEFAULT_ENV" ]; then
        env_info="$CONDA_DEFAULT_ENV"
    elif [ -n "$VIRTUAL_ENV" ]; then
        # 显示Python虚拟环境
        env_info=$(basename "$VIRTUAL_ENV")
    elif command -v python3 > /dev/null 2>&1; then
        # 显示Python版本
        local python_version=$(python3 -V 2>&1 | cut -d' ' -f2 | cut -d'.' -f1-2)
        env_info="py${python_version}"
    elif command -v python > /dev/null 2>&1; then
        local python_version=$(python -V 2>&1 | cut -d' ' -f2 | cut -d'.' -f1-2)
        env_info="py${python_version}"
    else
        env_info="no-py"
    fi
    
    echo "${env_info}"
}

# 获取当前shell类型
function _gs_theme_shell_info() {
    if [ -n "$ZSH_VERSION" ]; then
        echo "zsh"
    elif [ -n "$BASH_VERSION" ]; then
        echo "bash"
    else
        echo "sh"
    fi
}

# ============================================================================
# 颜色处理函数
# ============================================================================

# 带颜色的文本输出（兼容bash和zsh）
function _gs_theme_color_text() {
    local code=$1
    local text=$2
    
    if [ -n "$ZSH_VERSION" ]; then
        # zsh 颜色格式
        echo "%B%F{${code}}${text}%f%b"
    else
        # bash 颜色格式 (ANSI 256色)
        echo "\\[\\e[01;38;5;${code}m\\]${text}\\[\\033[0m\\]"
    fi
}

# ============================================================================
# Git信息获取函数
# ============================================================================

# 获取Git信息
function _gs_theme_git_info() {
    # 检查是否在Git仓库中
    if git rev-parse --git-dir > /dev/null 2>&1; then
        local branch=$(git symbolic-ref --short HEAD 2>/dev/null || git describe --tags --always 2>/dev/null)
        local git_status=""
        
        # 检查是否有未提交的更改
        if ! git diff --quiet 2>/dev/null; then
            git_status="${git_status}*"  # 有修改
        fi
        
        # 检查是否有未跟踪的文件
        if [ -n "$(git ls-files --others --exclude-standard 2>/dev/null)" ]; then
            git_status="${git_status}+"  # 有新文件
        fi
        
        # 检查是否有暂存的更改
        if ! git diff --cached --quiet 2>/dev/null; then
            git_status="${git_status}!"  # 有暂存
        fi
        
        if [ -n "${branch}" ]; then
            echo "git:${branch}${git_status}"
        fi
    fi
}