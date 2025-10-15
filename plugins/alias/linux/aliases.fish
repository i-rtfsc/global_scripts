#!/usr/bin/env fish
# -*- coding: utf-8 -*-
# Global Scripts v6 - Linux Specific Aliases (Fish Shell)

# Linux 特定的 ls 配置 - 使用 --color 选项启用颜色
alias ls='ls --color=auto'
alias ll='ls --color=auto -lah'
alias lh='ls --color=auto -lh'
alias la='ls --color=auto -la'
alias l='ls --color=auto -CF'

# 启用 GNU ls 的颜色支持
set -gx LS_COLORS 'di=1;36:ln=1;35:so=1;32:pi=33:ex=1;32:bd=34;46:cd=34;43:su=30;41:sg=30;46:tw=30;42:ow=30;43'

# 包管理器别名
if command -v apt >/dev/null 2>&1
    alias update='sudo apt update'
    alias upgrade='sudo apt upgrade'
    alias install='sudo apt install'
    alias remove='sudo apt remove'
    alias search='apt search'
    alias autoremove='sudo apt autoremove'
else if command -v yum >/dev/null 2>&1
    alias update='sudo yum update'
    alias install='sudo yum install'
    alias remove='sudo yum remove'
    alias search='yum search'
else if command -v dnf >/dev/null 2>&1
    alias update='sudo dnf update'
    alias install='sudo dnf install'
    alias remove='sudo dnf remove'
    alias search='dnf search'
else if command -v pacman >/dev/null 2>&1
    alias update='sudo pacman -Syu'
    alias install='sudo pacman -S'
    alias remove='sudo pacman -R'
    alias search='pacman -Ss'
end

# 系统服务管理 (systemd)
if command -v systemctl >/dev/null 2>&1
    alias sstart='sudo systemctl start'
    alias sstop='sudo systemctl stop'
    alias srestart='sudo systemctl restart'
    alias sstatus='sudo systemctl status'
    alias senable='sudo systemctl enable'
    alias sdisable='sudo systemctl disable'
end

# 防火墙管理 (UFW)
if command -v ufw >/dev/null 2>&1
    alias fwstatus='sudo ufw status'
    alias fwenable='sudo ufw enable'
    alias fwdisable='sudo ufw disable'
    alias fwallow='sudo ufw allow'
    alias fwdeny='sudo ufw deny'
end

# 剪贴板操作 (xclip)
if command -v xclip >/dev/null 2>&1
    alias cpwd='pwd | xclip -selection clipboard'
    alias paste='xclip -o -selection clipboard'
end

# 网络相关
alias ports='netstat -tulanp'
alias listening='netstat -tulanp | grep LISTEN'

# 进程管理
alias pstree='pstree -p'
alias meminfo='free -h'
alias cpuinfo='lscpu'

# 磁盘管理
alias diskspace='df -h'
alias diskusage='du -h --max-depth=1 | sort -h'

# 查看系统信息
alias sysinfo='uname -a'
alias distro='lsb_release -a 2>/dev/null; or cat /etc/os-release'

# 快速查找大文件
function findbig --description 'Find largest files in current directory'
    du -h | sort -rh | head -n 20
end

# 清理包缓存
function cleanpkg --description 'Clean package manager cache'
    if command -v apt >/dev/null 2>&1
        sudo apt clean
        and sudo apt autoremove
    else if command -v yum >/dev/null 2>&1
        sudo yum clean all
    else if command -v dnf >/dev/null 2>&1
        sudo dnf clean all
    else if command -v pacman >/dev/null 2>&1
        sudo pacman -Scc
    end
end
