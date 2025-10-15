#!/usr/bin/env fish
# -*- coding: utf-8 -*-
# Global Scripts v6 - Common Aliases (Fish Shell)
# 通用别名定义，适用于所有平台

# 基础 ls 别名
alias l='ls'
alias sl='ls'  # 打字错误修正

# 通用文件操作别名
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'
# Note: ~ already expands to home directory in fish, no alias needed

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
alias ports='netstat -tulanp 2>/dev/null; or lsof -i -P -n 2>/dev/null'

# Docker 常用别名
if command -v docker >/dev/null 2>&1
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
end

# Docker Compose 别名
if command -v docker-compose >/dev/null 2>&1
    alias dc='docker-compose'
    alias dcup='docker-compose up'
    alias dcupd='docker-compose up -d'
    alias dcdown='docker-compose down'
    alias dcbuild='docker-compose build'
    alias dcps='docker-compose ps'
    alias dclogs='docker-compose logs'
    alias dcexec='docker-compose exec'
end

# 其他实用别名
alias now='date +"%Y-%m-%d %H:%M:%S"'
alias week='date +%V'
alias myip='curl -s https://api.ipify.org 2>/dev/null; or echo "Network unavailable"'
alias reload='source ~/.config/fish/config.fish'

# 磁盘使用
alias duh='du -h --max-depth=1 2>/dev/null; or du -h -d1 2>/dev/null'
alias dfh='df -h'

# 创建目录并进入
function mkcd --description 'Create a directory and cd into it'
    mkdir -p $argv[1]
    and cd $argv[1]
end

# 解压任意格式
function extract --description 'Extract various archive formats'
    if test -f $argv[1]
        switch $argv[1]
            case '*.tar.bz2'
                tar xjf $argv[1]
            case '*.tar.gz'
                tar xzf $argv[1]
            case '*.bz2'
                bunzip2 $argv[1]
            case '*.rar'
                unrar e $argv[1]
            case '*.gz'
                gunzip $argv[1]
            case '*.tar'
                tar xf $argv[1]
            case '*.tbz2'
                tar xjf $argv[1]
            case '*.tgz'
                tar xzf $argv[1]
            case '*.zip'
                unzip $argv[1]
            case '*.Z'
                uncompress $argv[1]
            case '*.7z'
                7z x $argv[1]
            case '*'
                echo "'$argv[1]' cannot be extracted via extract()"
        end
    else
        echo "'$argv[1]' is not a valid file"
    end
end
