#!/bin/bash

machine="$(uname -s)"
case "${machine}" in
    Linux*)     isMac=false;;
    Darwin*)    isMac=true;;
    *)          isMac=false;;
esac

function _gs_arrows() {
    local arrows=' %B%F{yellow}>%B%F{magenta}>%B%F{yellow}> '
    echo $arrows
}

function _gs_big_arrows() {
    local arrows=' %B%F{magenta}❯%B%F{yellow}❯%F{cyan}❯%B%F{magenta}❯%B%F{yellow}❯%F{cyan}❯ '
    echo $arrows
}

function _gs_get_machine_info() {
    local name="%n"
    if [[ "$USER" == 'root' ]]; then
        name="%{$highlight_bg%}%{$white_bold%}$name%{$reset_color%}"
    fi
    if $isMac ; then
        local ip=$(ipconfig getifaddr en0)
    else
        local ip=$(ip a | grep " `route | grep default | awk 'NR==1{print $NF}'`:" -A2 | tail -n1 | awk '{print $2}' | cut -f1 -d '/')
    fi
    local machine_info=%B%F{magenta}[%B%F{red}$name%B%F{yellow}@%B%F{red}$ip%B%F{magenta}]
    echo $machine_info
}

function _gs_get_current_dir() {
    local real_dir=${PWD/#$HOME/~}
    local dir=%B%F{magenta}[%B%F{cyan}$real_dir%B%F{magenta}]
    echo $dir
}

function _gs_get_time() {
    local time=%B%F{magenta}[%B%F{blue}$(date "+%Y-%m-%d %H:%M:%S")%B%F{magenta}]
    echo $time
}

# python version info
function _gs_conda_or_py_info() {
    if command -v python > /dev/null 2>&1; then
        python_version="$(python -V 2>&1)"
        python_version=${python_version/Python /Python}
        python_version=${python_version/ */}
        conda_or_py_name=''
        if [ -n "$CONDA_DEFAULT_ENV" ]; then
            conda_or_py_name="$CONDA_DEFAULT_ENV"
        else
            conda_or_py_name="$python_version"
        fi

        echo -n "%B%F{magenta}(%B%F{red}${conda_or_py_name}%B%F{magenta})"

    fi
}

function _gs_right_display() {
    local _right_display='%B%F{magenta}$(git_prompt_info)'
    echo $_right_display
}

PROMPT=$'%B%F{magenta}╭─%B%F{magenta}$(_gs_get_machine_info)$(_gs_arrows)$(_gs_get_current_dir)$(_gs_arrows)$(_gs_get_time)
%B%F{magenta}╰─$(_gs_conda_or_py_info)$(_gs_big_arrows)%{$reset_color%}'
RPROMPT=$(_gs_right_display)