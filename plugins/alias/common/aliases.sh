#!/bin/bash
# -*- coding: utf-8 -*-
# Global Scripts v6 - Common Aliases
# 通用别名定义，适用于所有平台

# 基础 ls 别名
alias l='ls'
alias sl='ls'  # 打字错误修正

# 通用文件操作别名
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'
alias ~='cd ~'

# 增强的历史命令
alias h='history'
alias hgrep='history | grep'

# 快速编辑
alias vi='vim'

# 安全性别名（带确认）
alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'
alias ln='ln -i'

# 进程管理
alias psa='ps aux'
alias psg='ps aux | grep'

# 网络相关
alias ports='netstat -tulanp 2>/dev/null || lsof -i -P -n 2>/dev/null'

# Docker 常用别名
if command -v docker &>/dev/null; then
    alias dps='docker ps'
    alias dpsa='docker ps -a'
    alias dim='docker images'
    alias dex='docker exec -it'
    alias dlog='docker logs'
    alias dlogf='docker logs -f'
    alias dstop='docker stop'
    alias drm='docker rm'
    alias drmi='docker rmi'
    alias dprune='docker system prune'
fi

# Docker Compose 别名
if command -v docker-compose &>/dev/null; then
    alias dc='docker-compose'
    alias dcup='docker-compose up'
    alias dcupd='docker-compose up -d'
    alias dcdown='docker-compose down'
    alias dcbuild='docker-compose build'
    alias dcps='docker-compose ps'
    alias dclogs='docker-compose logs'
    alias dcexec='docker-compose exec'
fi

# 其他实用别名
alias now='date +"%Y-%m-%d %H:%M:%S"'
alias week='date +%V'
alias myip='curl -s https://api.ipify.org 2>/dev/null || echo "Network unavailable"'
alias reload='source ~/.bashrc 2>/dev/null || source ~/.zshrc 2>/dev/null'

# 磁盘使用
alias duh='du -h --max-depth=1 2>/dev/null || du -h -d1 2>/dev/null'
alias dfh='df -h'

# 创建目录并进入
mkcd() {
    mkdir -p "$1" && cd "$1"
}

# 解压任意格式
extract() {
    if [ -f "$1" ]; then
        case "$1" in
            *.tar.bz2)   tar xjf "$1"     ;;
            *.tar.gz)    tar xzf "$1"     ;;
            *.bz2)       bunzip2 "$1"     ;;
            *.rar)       unrar e "$1"     ;;
            *.gz)        gunzip "$1"      ;;
            *.tar)       tar xf "$1"      ;;
            *.tbz2)      tar xjf "$1"     ;;
            *.tgz)       tar xzf "$1"     ;;
            *.zip)       unzip "$1"       ;;
            *.Z)         uncompress "$1"  ;;
            *.7z)        7z x "$1"        ;;
            *)           echo "'$1' cannot be extracted" ;;
        esac
    else
        echo "'$1' is not a valid file"
    fi
}