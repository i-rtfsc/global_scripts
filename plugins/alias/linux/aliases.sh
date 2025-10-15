#!/bin/bash
# -*- coding: utf-8 -*-
# Global Scripts v6 - Linux Specific Aliases

# Linux 特定的 ls 配置 - 使用 --color=auto 选项
alias ls='ls --color=auto'
alias ll='ls --color=auto -alh'
alias lh='ls --color=auto -lh'
alias la='ls --color=auto -la'
alias l='ls --color=auto -CF'

# 增强的 grep 配置
alias grep='grep --color=auto'
alias fgrep='fgrep --color=auto'
alias egrep='egrep --color=auto'

# 启用 dircolors（如果存在）
if command -v dircolors >/dev/null 2>&1; then
    if [ -r ~/.dircolors ]; then
        eval "$(dircolors -b ~/.dircolors)"
    else
        eval "$(dircolors -b)"
    fi
fi

# Linux 包管理器相关
# APT (Debian/Ubuntu)
if command -v apt &>/dev/null; then
    alias aptup='sudo apt update && sudo apt upgrade'
    alias aptsearch='apt search'
    alias aptinstall='sudo apt install'
    alias aptremove='sudo apt remove'
    alias aptclean='sudo apt autoremove && sudo apt autoclean'
fi

# YUM/DNF (RHEL/CentOS/Fedora)
if command -v dnf &>/dev/null; then
    alias dnfup='sudo dnf update'
    alias dnfsearch='dnf search'
    alias dnfinstall='sudo dnf install'
    alias dnfremove='sudo dnf remove'
    alias dnfclean='sudo dnf clean all'
elif command -v yum &>/dev/null; then
    alias yumup='sudo yum update'
    alias yumsearch='yum search'
    alias yuminstall='sudo yum install'
    alias yumremove='sudo yum remove'
    alias yumclean='sudo yum clean all'
fi

# Pacman (Arch Linux)
if command -v pacman &>/dev/null; then
    alias pacup='sudo pacman -Syu'
    alias pacsearch='pacman -Ss'
    alias pacinstall='sudo pacman -S'
    alias pacremove='sudo pacman -R'
    alias pacclean='sudo pacman -Sc'
fi

# systemd 服务管理
if command -v systemctl &>/dev/null; then
    alias sysstart='sudo systemctl start'
    alias sysstop='sudo systemctl stop'
    alias sysrestart='sudo systemctl restart'
    alias sysstatus='systemctl status'
    alias sysenable='sudo systemctl enable'
    alias sysdisable='sudo systemctl disable'
    alias sysreload='sudo systemctl daemon-reload'
    alias syslist='systemctl list-units --type=service'
fi

# 日志查看
if command -v journalctl &>/dev/null; then
    alias jctl='journalctl'
    alias jctlf='journalctl -f'  # follow
    alias jctlu='journalctl -u'  # unit
fi

# 进程和系统监控
alias meminfo='free -m -l -t'
alias psmem='ps auxf | sort -nr -k 4'
alias pscpu='ps auxf | sort -nr -k 3'
alias cpuinfo='lscpu'
alias gpumeminfo='grep -i --color memory /var/log/Xorg.0.log'

# 网络相关
alias ports='netstat -tulanp'
alias listening='netstat -tulpn | grep LISTEN'
alias iptlist='sudo iptables -L -v -n --line-numbers'
alias firewall='sudo iptables -L -n -v'

# 文件系统
alias mount='mount | column -t'
alias diskspace='df -H'
alias foldersize='du -sh'
alias totalfoldersize='du -sh ./*'

# 快速编辑系统配置文件
alias nanorc='nano ~/.nanorc'
alias bashrc='nano ~/.bashrc'
alias zshrc='nano ~/.zshrc'
alias sshconfig='nano ~/.ssh/config'

# 权限相关
alias chmodx='chmod +x'
alias chmod755='chmod 755'
alias chmod644='chmod 644'

# 查找相关
alias findname='find . -name'
alias findtype='find . -type'
alias findrecent='find . -mtime -1'

# 显示当前分发版信息
if [ -f /etc/os-release ]; then
    alias osinfo='cat /etc/os-release'
elif [ -f /etc/lsb-release ]; then
    alias osinfo='cat /etc/lsb-release'
fi

# 硬件信息
alias hwinfo='sudo lshw -short'
alias cpufreq='watch -n 1 "cat /proc/cpuinfo | grep MHz"'

# SELinux 相关（如果存在）
if command -v getenforce &>/dev/null; then
    alias selinuxstatus='getenforce'
    alias selinuxoff='sudo setenforce 0'
    alias selinuxon='sudo setenforce 1'
fi

# 其他实用功能
alias path='echo -e ${PATH//:/\\n}'
alias now='timedatectl'
alias reboot='sudo reboot'
alias poweroff='sudo poweroff'