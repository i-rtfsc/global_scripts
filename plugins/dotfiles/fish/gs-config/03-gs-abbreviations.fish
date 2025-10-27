#!/usr/bin/env fish
# ============================================
# Global Scripts - Fish Shell Configuration
# Command Abbreviations
# ============================================
# Generated automatically - do not edit manually
# Generated at: 2025-10-17 09:46:57
# Configuration source: /Users/solo/code/github/global_scripts
# File: 03-gs-abbreviations.fish
# ============================================

abbr -a -g c 'clear'
abbr -a -g h 'history'
abbr -a -g q 'exit'
abbr -a -g x 'exit'

# ============================================
# Navigation
# ============================================
abbr -a -g .. 'cd ..'
abbr -a -g ... 'cd ../..'
abbr -a -g .... 'cd ../../..'
abbr -a -g ..... 'cd ../../../..'
abbr -a -g ~ 'cd ~'
abbr -a -g - 'cd -'

# ============================================
# File Operations
# ============================================
# 注意：如果安装了 exa，这些会被 04-integrations.fish 覆盖
abbr -a -g la 'ls -A'
abbr -a -g l 'ls -CF'
abbr -a -g lt 'ls -lhtr'
abbr -a -g lsize 'ls -lhS'

# abbr -a -g cp 'cp -iv'
# abbr -a -g mv 'mv -iv'
# abbr -a -g rm 'rm -iv'
abbr -a -g mkdir 'mkdir -pv'

# ============================================
# Git Abbreviations
# ============================================
# 注意：避免使用 'gs' 以免与 Global Scripts 冲突
abbr -a -g g 'git'
abbr -a -g ga 'git add'
abbr -a -g gaa 'git add --all'
abbr -a -g gap 'git add --patch'

abbr -a -g gb 'git branch'
abbr -a -g gba 'git branch -a'
abbr -a -g gbd 'git branch -d'
abbr -a -g gbD 'git branch -D'

abbr -a -g gc 'git commit -v'
abbr -a -g gcm 'git commit -m'
abbr -a -g gca 'git commit -v -a'
abbr -a -g gcam 'git commit -a -m'
abbr -a -g gcamend 'git commit --amend'

abbr -a -g gco 'git checkout'
abbr -a -g gcob 'git checkout -b'
abbr -a -g gcom 'git checkout master'
abbr -a -g gcod 'git checkout develop'

abbr -a -g gd 'git diff'
abbr -a -g gds 'git diff --staged'
abbr -a -g gdw 'git diff --word-diff'

abbr -a -g gf 'git fetch'
abbr -a -g gfa 'git fetch --all'
abbr -a -g gfo 'git fetch origin'

abbr -a -g gl 'git pull'
abbr -a -g glog 'git log --oneline --decorate --graph'
abbr -a -g gloga 'git log --oneline --decorate --graph --all'
abbr -a -g glol 'git log --graph --pretty=format:"%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr) %C(bold blue)<%an>%Creset" --abbrev-commit'

abbr -a -g gm 'git merge'
abbr -a -g gma 'git merge --abort'

abbr -a -g gp 'git push'
abbr -a -g gpf 'git push --force-with-lease'
abbr -a -g gpu 'git push -u origin'

abbr -a -g gr 'git remote'
abbr -a -g gra 'git remote add'
abbr -a -g grv 'git remote -v'

abbr -a -g grb 'git rebase'
abbr -a -g grba 'git rebase --abort'
abbr -a -g grbc 'git rebase --continue'
abbr -a -g grbi 'git rebase -i'

abbr -a -g greset 'git reset'
abbr -a -g grhh 'git reset --hard'
abbr -a -g grh 'git reset --hard HEAD'

# 使用 gst 替代 gs，避免与 Global Scripts 冲突
abbr -a -g gst 'git status'
abbr -a -g gss 'git status -s'

abbr -a -g gsta 'git stash'
abbr -a -g gstaa 'git stash apply'
abbr -a -g gstd 'git stash drop'
abbr -a -g gstl 'git stash list'
abbr -a -g gstp 'git stash pop'

# ============================================
# System Operations
# ============================================
abbr -a -g ports 'netstat -tulanp'
abbr -a -g update 'sudo apt update && sudo apt upgrade'
abbr -a -g install 'sudo apt install'
abbr -a -g uninstall 'sudo apt remove'

# macOS specific
if test (uname) = Darwin
    abbr -a -g update 'brew update && brew upgrade'
    abbr -a -g install 'brew install'
    abbr -a -g uninstall 'brew uninstall'
    abbr -a -g cleanup 'brew cleanup'
end

# ============================================
# Docker Abbreviations
# ============================================
abbr -a -g d 'docker'
abbr -a -g dps 'docker ps'
abbr -a -g dpsa 'docker ps -a'
abbr -a -g di 'docker images'
abbr -a -g drmi 'docker rmi'
abbr -a -g drun 'docker run'
abbr -a -g dexec 'docker exec -it'
abbr -a -g dstop 'docker stop'
abbr -a -g dstart 'docker start'
abbr -a -g dlogs 'docker logs'
abbr -a -g dprune 'docker system prune -a'

abbr -a -g dc 'docker-compose'
abbr -a -g dcup 'docker-compose up -d'
abbr -a -g dcdown 'docker-compose down'
abbr -a -g dcrestart 'docker-compose restart'
abbr -a -g dclogs 'docker-compose logs -f'

# ============================================
# Python Abbreviations
# ============================================
abbr -a -g py 'python3'
abbr -a -g pip 'pip3'
abbr -a -g venv 'python3 -m venv'
abbr -a -g activate 'source venv/bin/activate.fish'
abbr -a -g freeze 'pip freeze > requirements.txt'

# ============================================
# Text Editing
# ============================================
if command -v nvim >/dev/null
    abbr -a -g vim 'nvim'
    abbr -a -g vi 'nvim'
end

abbr -a -g v '$EDITOR'
abbr -a -g nv 'nvim'

# ============================================
# Network
# ============================================
abbr -a -g myip 'curl ifconfig.me'
abbr -a -g localip 'get_ip'
abbr -a -g ping 'ping -c 5'
abbr -a -g wget 'wget -c'

# ============================================
# Miscellaneous
# ============================================
abbr -a -g reload 'source ~/.config/fish/config.fish'
abbr -a -g fishconfig 'nvim ~/.config/fish/config.fish'
abbr -a -g weather 'curl wttr.in'
abbr -a -g timer 'echo "Timer started. Stop with Ctrl-C" && date && time read'
