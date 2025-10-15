#!/usr/bin/env bash
# Shared prompt helpers for Global Scripts v6

# Detect platform
machine="$(uname -s)"
case "$machine" in
    Linux*)     isMac=false;;
    Darwin*)    isMac=true;;
    *)          isMac=false;;
esac

_gs_prompt_ip() {
    if $GS_IS_MAC ; then
        local ip
        ip=$(ipconfig getifaddr en0 2>/dev/null)
        [[ -z "$ip" ]] && ip=$(ipconfig getifaddr en1 2>/dev/null)
        echo "$ip"
    else
        local dev ip
        dev=$(route | grep default | awk 'NR==1{print $NF}')
        ip=$(ip a | grep " ${dev}:" -A2 | tail -n1 | awk '{print $2}' | cut -f1 -d '/')
        echo "$ip"
    fi
}

_gs_prompt_user() {
    if [[ -n "$ZSH_VERSION" ]]; then
        echo "%n"
    else
        echo "\u"
    fi
}

_gs_prompt_pwd() {
    # Always show absolute path (user requested absolute, no ~ shortening)
    echo "$PWD"
}

_gs_prompt_time() {
    date "+%Y-%m-%d %H:%M:%S"
}

_gs_prompt_env() {
    if [[ -n "$ZSH_VERSION" ]]; then
        echo "zsh-"
    else
        echo "bash-"
    fi
}

_gs_prompt_conda_or_py() {
    local name=""
    if command -v python >/dev/null 2>&1; then
        if [[ -n "$CONDA_DEFAULT_ENV" ]]; then
            name="$CONDA_DEFAULT_ENV"
        else
            local ver
            ver="$(python -V 2>&1)"; ver=${ver/Python /Python}; ver=${ver/ */}
            name="$ver"
        fi
    fi
    echo "$name"
}

# 256-color text wrapper
_gs_theme_color_text() {
    local code="$1" text="$2"
    if [[ -n "$ZSH_VERSION" ]]; then
        echo "%B${FG[$code]}${text}%{$reset_color%}"
    else
        echo "\e[01;38;5;${code}m${text}\033[0m"
    fi
}

# Git prompt info
git_prompt_info() {
    if git rev-parse --git-dir >/dev/null 2>&1; then
        local branch
        branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
        [[ -n "$branch" ]] && echo " ($branch)"
    fi
}

# Alias for backward compatibility
_gs_prompt_color() { _gs_theme_color_text "$@"; }

# v2-compatible helper functions
_gs_theme_ip() { _gs_prompt_ip; }
_gs_theme_user_name() { _gs_prompt_user; }
_gs_theme_current_dir() { _gs_prompt_pwd; }
_gs_theme_get_time() { _gs_prompt_time; }
_gs_theme_conda_or_py_info() { _gs_prompt_conda_or_py; }

# Right prompt git info (if available via vcs/p10k/zsh-git-prompt)
_gs_prompt_git_info() {
    if type git_prompt_info >/dev/null 2>&1; then
        git_prompt_info
    else
        # very light fallback: current branch
        git rev-parse --abbrev-ref HEAD 2>/dev/null | sed 's/^/ /'
    fi
}
