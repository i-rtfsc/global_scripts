#!/bin/bash
# -*- coding: utf-8 -*-
# Global Scripts v6 - Darwin (macOS) Specific Aliases

# macOS 特定的 ls 配置 - 使用 -G 选项启用颜色
alias ls='ls -G'
alias ll='ls -G -lah'
alias lh='ls -G -lh'
alias la='ls -G -la'
alias l='ls -G -CF'

# 启用 BSD ls 的颜色支持
export CLICOLOR=1
export LSCOLORS=GxFxCxDxBxegedabagaced

# macOS 特定命令
alias showfiles='defaults write com.apple.finder AppleShowAllFiles YES && killall Finder'
alias hidefiles='defaults write com.apple.finder AppleShowAllFiles NO && killall Finder'

# 清理 .DS_Store 文件
alias cleanupds='find . -type f -name "*.DS_Store" -ls -delete'

# 打开当前目录
alias finder='open -a Finder .'
alias o='open'
alias oo='open .'

# Homebrew 相关
if command -v brew &>/dev/null; then
    alias brewup='brew update && brew upgrade'
    alias brewinfo='brew info'
    alias brewsearch='brew search'
    alias brewclean='brew cleanup'
fi

# macOS 剪贴板操作
alias cpwd='pwd | pbcopy'
alias paste='pbpaste'

# 网络相关
alias flushdns='sudo dscacheutil -flushcache'
alias netinfo='netstat -nr'

# 进程管理
alias topmem='top -o mem'
alias topcpu='top -o cpu'

# 快速锁屏
alias lock='/System/Library/CoreServices/Menu\ Extras/User.menu/Contents/Resources/CGSession -suspend'

# 音量控制
alias mute='osascript -e "set volume output muted true"'
alias unmute='osascript -e "set volume output muted false"'

# WiFi 控制
alias wifion='networksetup -setairportpower en0 on'
alias wifioff='networksetup -setairportpower en0 off'
alias wifirestart='wifioff && wifion'

# 获取 macOS 版本信息
alias osversion='sw_vers'

# 清空废纸篓
alias emptytrash='sudo rm -rfv /Volumes/*/.Trashes; sudo rm -rfv ~/.Trash'

# 显示/隐藏桌面图标
alias showdesktop='defaults write com.apple.finder CreateDesktop true && killall Finder'
alias hidedesktop='defaults write com.apple.finder CreateDesktop false && killall Finder'

# 截图设置
alias screenshottype='defaults write com.apple.screencapture type'

# Spotlight 相关
alias spotoff='sudo mdutil -a -i off'
alias spoton='sudo mdutil -a -i on'

# 快速编辑 hosts 文件
alias hosts='sudo nano /etc/hosts'

# 显示所有进程的完整路径
alias psfull='ps aux | less'

# 查看正在监听的端口
alias listening='lsof -iTCP -sTCP:LISTEN -P -n'