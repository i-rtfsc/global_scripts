#!/usr/bin/env fish
# ============================================
# Global Scripts - Fish Shell Configuration
# FZF Configuration
# ============================================
# Generated automatically - do not edit manually
# Generated at: 2025-10-17 09:46:57
# Configuration source: /Users/solo/code/github/global_scripts
# File: 02-gs-fzf.fish
# ============================================

set -gx FZF_DEFAULT_OPTS '
    --height 40%
    --layout=reverse
    --border
    --inline-info
    --preview-window=right:60%:wrap
    --color=fg:#d0d0d0,bg:#121212,hl:#5f87af
    --color=fg+:#d0d0d0,bg+:#262626,hl+:#5fd7ff
    --color=info:#afaf87,prompt:#d7005f,pointer:#af5fff
    --color=marker:#87ff00,spinner:#af5fff,header:#87afaf
'

# FZF default command (use fd if available, otherwise find)
if command -v fd >/dev/null
    set -gx FZF_DEFAULT_COMMAND 'fd --type f --hidden --follow --exclude .git'
    set -gx FZF_CTRL_T_COMMAND "$FZF_DEFAULT_COMMAND"
    set -gx FZF_ALT_C_COMMAND 'fd --type d --hidden --follow --exclude .git'
else
    set -gx FZF_DEFAULT_COMMAND 'find . -type f'
    set -gx FZF_CTRL_T_COMMAND "$FZF_DEFAULT_COMMAND"
    set -gx FZF_ALT_C_COMMAND 'find . -type d'
end

# FZF preview command (use bat if available, otherwise cat)
if command -v bat >/dev/null
    set -gx FZF_CTRL_T_OPTS "
        --preview 'bat --style=numbers --color=always --line-range :500 {}'
        --preview-window=right:60%:wrap
    "
else
    set -gx FZF_CTRL_T_OPTS "
        --preview 'cat {}'
        --preview-window=right:60%:wrap
    "
end

# FZF directory preview
if command -v tree >/dev/null
    set -gx FZF_ALT_C_OPTS "
        --preview 'tree -C {} | head -200'
        --preview-window=right:60%:wrap
    "
else if command -v ls >/dev/null
    set -gx FZF_ALT_C_OPTS "
        --preview 'ls -lah {}'
        --preview-window=right:60%:wrap
    "
end

# Enhanced file search with preview
function fcd -d 'Fuzzy find and cd to directory'
    set dir (fd --type d --hidden --follow --exclude .git | fzf --preview 'tree -C {} | head -200')
    if test -n "$dir"
        cd $dir
    end
end

# Fuzzy search and edit file
function fe -d 'Fuzzy find and edit file'
    set file (fzf --preview 'bat --style=numbers --color=always --line-range :500 {}')
    if test -n "$file"
        $EDITOR $file
    end
end

# Fuzzy search in command history
function fh -d 'Search command history with fzf'
    set cmd (history | fzf --tac --no-sort)
    if test -n "$cmd"
        commandline -r $cmd
    end
end

# Fuzzy git branch checkout
function fgb -d 'Fuzzy checkout git branch'
    set branch (git branch --all | grep -v HEAD | string trim | fzf)
    if test -n "$branch"
        git checkout (echo $branch | sed 's|remotes/origin/||')
    end
end

# Fuzzy git log viewer
function fgl -d 'Fuzzy git log viewer'
    git log --oneline --color=always | fzf --ansi --preview 'git show --color=always {1}'
end

# Fuzzy kill process
function fkill -d 'Fuzzy search and kill process'
    set process (ps aux | fzf --header='Select process to kill' | awk '{print $2}')
    if test -n "$process"
        echo "Killing process: $process"
        kill -9 $process
    end
end

# Fuzzy environment variable viewer
function fenv -d 'Fuzzy search environment variables'
    env | fzf --preview 'echo {}' | cut -d= -f1
end

# Fuzzy package search (for apt/brew/yum)
function fps -d 'Fuzzy search packages'
    if command -v brew >/dev/null
        brew search | fzf --preview 'brew info {}'
    else if command -v apt >/dev/null
        apt list 2>/dev/null | fzf --preview 'apt show {1}'
    else if command -v yum >/dev/null
        yum list available | fzf
    else
        echo "No supported package manager found"
    end
end
