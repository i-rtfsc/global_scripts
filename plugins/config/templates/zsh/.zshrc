# ============================================================================
# Global Scripts Zsh 配置文件 - 现代化的 Zsh Shell 配置
# 基于最佳实践，提供高效的命令行体验
# 支持 Oh My Zsh 和 原生 Zsh 配置
# ============================================================================

# ============================================================================
# 环境变量配置 - 核心环境设置
# ============================================================================

# 默认编辑器
export EDITOR='vim'
export VISUAL='vim'

# 语言和编码设置
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

# 历史记录设置
export HISTSIZE=10000                # 内存中的历史记录条数
export SAVEHIST=10000               # 保存到文件的历史记录条数
export HISTFILE=~/.zsh_history      # 历史记录文件位置

# 路径配置
export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"

# 添加用户本地bin目录
if [[ -d "$HOME/.local/bin" ]]; then
    export PATH="$HOME/.local/bin:$PATH"
fi

# 添加Homebrew路径 (macOS)
if [[ -d "/opt/homebrew/bin" ]]; then
    export PATH="/opt/homebrew/bin:$PATH"
elif [[ -d "/usr/local/homebrew/bin" ]]; then
    export PATH="/usr/local/homebrew/bin:$PATH"
fi

# ============================================================================
# Zsh 核心配置选项
# ============================================================================

# 启用自动更正建议
setopt CORRECT
setopt CORRECT_ALL

# 历史记录配置
setopt HIST_EXPIRE_DUPS_FIRST    # 删除重复条目时优先删除旧的
setopt HIST_IGNORE_DUPS          # 忽略连续的重复命令
setopt HIST_IGNORE_ALL_DUPS      # 忽略所有重复命令
setopt HIST_FIND_NO_DUPS         # 查找时忽略重复
setopt HIST_IGNORE_SPACE         # 忽略以空格开头的命令
setopt HIST_SAVE_NO_DUPS         # 保存时忽略重复
setopt HIST_VERIFY               # 执行历史命令前确认
setopt SHARE_HISTORY             # 在多个会话间共享历史

# 目录导航配置
setopt AUTO_CD                   # 输入目录名直接进入
setopt AUTO_PUSHD                # 自动将目录推入栈
setopt PUSHD_IGNORE_DUPS         # 忽略栈中的重复目录
setopt PUSHD_SILENT              # 静默pushd操作

# 命令行编辑配置
setopt INTERACTIVE_COMMENTS      # 允许命令行注释
setopt NO_BEEP                   # 禁用蜂鸣声
setopt PROMPT_SUBST              # 允许提示符中的变量替换

# 文件匹配配置
setopt EXTENDED_GLOB             # 启用扩展的glob模式
setopt GLOB_DOTS                 # glob匹配以点开头的文件

# ============================================================================
# Oh My Zsh 配置 - 如果安装了 Oh My Zsh
# ============================================================================

# 检查 Oh My Zsh 是否安装
if [[ -d "$HOME/.oh-my-zsh" ]]; then
    # Oh My Zsh 安装路径
    export ZSH="$HOME/.oh-my-zsh"
    
    # 主题设置 (可选择: robbyrussell, agnoster, powerlevel10k, spaceship)
    ZSH_THEME="robbyrussell"
    
    # 插件配置 - 根据需要启用
    plugins=(
        git                    # Git 集成和别名
        docker                 # Docker 命令补全
        kubectl               # Kubernetes 命令补全
        npm                   # NPM 命令补全
        yarn                  # Yarn 命令补全
        pip                   # Pip 命令补全
        brew                  # Homebrew 命令补全
        golang                # Go 开发支持
        rust                  # Rust 开发支持
        python                # Python 开发支持
        node                  # Node.js 开发支持
        vscode                # VS Code 集成
        sudo                  # 双击ESC添加sudo
        extract               # 智能解压缩
        z                     # 智能目录跳转
        colored-man-pages     # 彩色man页面
        command-not-found     # 未找到命令时提供建议
        history-substring-search  # 历史子字符串搜索
        zsh-autosuggestions   # 自动建议 (需单独安装)
        zsh-syntax-highlighting  # 语法高亮 (需单独安装)
    )
    
    # 加载 Oh My Zsh
    source $ZSH/oh-my-zsh.sh
fi

# ============================================================================
# 自定义别名 - 提高命令行效率的快捷方式
# ============================================================================

# 基础命令增强
alias ll='ls -alF'               # 详细列表
alias la='ls -A'                 # 显示隐藏文件
alias l='ls -CF'                 # 简洁列表
alias ..='cd ..'                 # 上级目录
alias ...='cd ../..'             # 上两级目录
alias ....='cd ../../..'         # 上三级目录

# 安全别名 - 防止误操作
alias rm='rm -i'                 # 删除时确认
alias cp='cp -i'                 # 复制时确认覆盖
alias mv='mv -i'                 # 移动时确认覆盖

# 系统信息
alias df='df -h'                 # 友好的磁盘使用显示
alias du='du -h'                 # 友好的目录大小显示
alias free='free -h'             # 友好的内存显示 (Linux)
alias ps='ps aux'                # 详细进程列表

# 网络工具
alias ping='ping -c 5'           # 限制ping次数
alias wget='wget -c'             # 断点续传
alias curl='curl -L'             # 跟随重定向

# Git 别名 (如果没有使用Oh My Zsh的git插件)
if ! command -v gst &> /dev/null; then
    alias gst='git status'
    alias gco='git checkout'
    alias gcm='git commit -m'
    alias gaa='git add .'
    alias gp='git push'
    alias gl='git pull'
    alias gb='git branch'
    alias gd='git diff'
    alias glog='git log --oneline --graph --decorate'
fi

# 开发工具别名
alias py='python3'               # Python快捷方式
alias pip='pip3'                 # Pip快捷方式
alias serve='python3 -m http.server'  # 快速HTTP服务器
alias json='python3 -m json.tool'     # JSON格式化

# Docker 别名
alias d='docker'
alias dc='docker-compose'
alias dps='docker ps'
alias dimg='docker images'
alias dexec='docker exec -it'

# Kubernetes 别名
alias k='kubectl'
alias kgp='kubectl get pods'
alias kgs='kubectl get services'
alias kgd='kubectl get deployments'

# ============================================================================
# 自定义函数 - 实用的Shell函数
# ============================================================================

# 创建目录并进入
mkcd() {
    mkdir -p "$1" && cd "$1"
}

# 提取各种压缩文件
extract() {
    if [[ -f $1 ]]; then
        case $1 in
            *.tar.bz2)   tar xjf $1     ;;
            *.tar.gz)    tar xzf $1     ;;
            *.bz2)       bunzip2 $1     ;;
            *.rar)       unrar e $1     ;;
            *.gz)        gunzip $1      ;;
            *.tar)       tar xf $1      ;;
            *.tbz2)      tar xjf $1     ;;
            *.tgz)       tar xzf $1     ;;
            *.zip)       unzip $1       ;;
            *.Z)         uncompress $1  ;;
            *.7z)        7z x $1        ;;
            *)     echo "'$1' 无法被解压" ;;
        esac
    else
        echo "'$1' 不是有效文件"
    fi
}

# 查找文件
ff() {
    find . -name "*$1*" 2>/dev/null
}

# 查找并执行
fe() {
    find . -name "*$1*" -exec "${2:-ls -la}" {} \;
}

# 查看进程
psgrep() {
    ps aux | grep "$1" | grep -v grep
}

# 快速备份文件
backup() {
    cp "$1"{,.bak}
}

# 显示目录大小排序
dusort() {
    du -sh ${1:-.}/* | sort -hr
}

# ============================================================================
# 命令补全配置 - 增强的Tab补全
# ============================================================================

# 启用命令补全
autoload -Uz compinit
compinit

# 补全配置
zstyle ':completion:*' auto-description 'specify: %d'
zstyle ':completion:*' completer _expand _complete _correct _approximate
zstyle ':completion:*' format 'Completing %d'
zstyle ':completion:*' group-name ''
zstyle ':completion:*' menu select=2
zstyle ':completion:*:default' list-colors ${(s.:.)LS_COLORS}
zstyle ':completion:*' list-colors ''
zstyle ':completion:*' list-prompt %SAt %p: Hit TAB for more, or the character to insert%s
zstyle ':completion:*' matcher-list '' 'm:{a-z}={A-Z}' 'm:{a-zA-Z}={A-Za-z}' 'r:|[._-]=* r:|=* l:|=*'
zstyle ':completion:*' menu select=long
zstyle ':completion:*' select-prompt %SScrolling active: current selection at %p%s
zstyle ':completion:*' use-compctl false
zstyle ':completion:*' verbose true

# 进程补全
zstyle ':completion:*:processes' command 'ps -o pid,s,nice,stime,args'

# ============================================================================
# 按键绑定 - 自定义快捷键
# ============================================================================

# 使用 vim 模式
bindkey -v

# 历史搜索
bindkey '^R' history-incremental-search-backward
bindkey '^S' history-incremental-search-forward

# 单词移动
bindkey '^[[1;5C' forward-word    # Ctrl+Right
bindkey '^[[1;5D' backward-word   # Ctrl+Left

# 行编辑
bindkey '^A' beginning-of-line    # Ctrl+A
bindkey '^E' end-of-line          # Ctrl+E
bindkey '^K' kill-line            # Ctrl+K
bindkey '^U' backward-kill-line   # Ctrl+U

# ============================================================================
# 语言和工具特定配置
# ============================================================================

# Node.js 版本管理 (nvm)
if [[ -d "$HOME/.nvm" ]]; then
    export NVM_DIR="$HOME/.nvm"
    [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
    [ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"
fi

# Python 版本管理 (pyenv)
if command -v pyenv >/dev/null; then
    export PATH="$(pyenv root)/shims:$PATH"
    eval "$(pyenv init -)"
fi

# Ruby 版本管理 (rbenv)
if command -v rbenv >/dev/null; then
    eval "$(rbenv init -)"
fi

# Rust 环境
if [[ -f "$HOME/.cargo/env" ]]; then
    source "$HOME/.cargo/env"
fi

# Go 环境
if command -v go >/dev/null; then
    export GOPATH="$HOME/go"
    export PATH="$GOPATH/bin:$PATH"
fi

# Java 环境 (macOS)
if [[ -x /usr/libexec/java_home ]]; then
    export JAVA_HOME=$(/usr/libexec/java_home)
fi

# ============================================================================
# 自定义提示符 - 如果没有使用 Oh My Zsh 主题
# ============================================================================

if [[ -z "$ZSH_THEME" ]]; then
    # 简洁的提示符
    PROMPT='%F{cyan}%n@%m%f:%F{blue}%~%f%# '
    
    # Git 信息 (需要vcs_info)
    autoload -Uz vcs_info
    precmd() { vcs_info }
    zstyle ':vcs_info:git:*' formats ' (%b)'
    setopt PROMPT_SUBST
    RPROMPT='%F{yellow}${vcs_info_msg_0_}%f'
fi

# ============================================================================
# 性能优化配置
# ============================================================================

# 禁用流控制 (Ctrl+S/Ctrl+Q)
stty -ixon

# 设置合理的umask
umask 022

# ============================================================================
# 平台特定配置
# ============================================================================

# macOS 特定配置
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS 特有的别名
    alias showfiles="defaults write com.apple.finder AppleShowAllFiles -bool true && killall Finder"
    alias hidefiles="defaults write com.apple.finder AppleShowAllFiles -bool false && killall Finder"
    
    # Homebrew 配置
    if command -v brew >/dev/null; then
        # 添加 Homebrew 的 shell 补全
        FPATH=$(brew --prefix)/share/zsh/site-functions:$FPATH
    fi
fi

# Linux 特定配置
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux 特有的别名
    alias open='xdg-open'
    alias pbcopy='xclip -selection clipboard'
    alias pbpaste='xclip -selection clipboard -o'
fi

# ============================================================================
# 用户自定义配置 - 个人定制化设置
# ============================================================================

# 加载用户自定义配置 (如果存在)
if [[ -f "$HOME/.zshrc.local" ]]; then
    source "$HOME/.zshrc.local"
fi

# 加载工作相关配置 (如果存在)
if [[ -f "$HOME/.zshrc.work" ]]; then
    source "$HOME/.zshrc.work"
fi

# ============================================================================
# 启动时的欢迎信息
# ============================================================================

# 显示系统信息 (可选)
if command -v neofetch >/dev/null; then
    neofetch
elif command -v screenfetch >/dev/null; then
    screenfetch
else
    echo "Welcome to $(hostname)! 🚀"
    echo "Zsh $(zsh --version | cut -d' ' -f2) with Global Scripts configuration"
fi

# ============================================================================
# 配置完成
# ============================================================================

# 如果需要调试配置加载时间，取消注释下面的行
# echo "Zsh configuration loaded in ${SECONDS}s"