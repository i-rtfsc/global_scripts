#!/bin/bash
# -*- coding: utf-8 -*-
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2022 anqi.huang@outlook.com
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


machine="$(uname -s)"
case "${machine}" in
    Linux*)     isMac=false;;
    Darwin*)    isMac=true;;
    *)          isMac=false;;
esac

_color_prompt_head=245
_color_fg_split=003
_color_sys_info=200
_color_at=226
_color_path=075
_color_time=169
_color_env=069
_color_git=110
_color_final=033
_color_final1=214
_color_final2=199
_color_final3=033

if [ -n "$ZSH_VERSION" ]; then
    COLOR_PROMPT_HEAD="%B$FG[${_color_prompt_head}]"
    COLOR_FG_SPLIT="%B$FG[${_color_fg_split}]"
    COLOR_SYS_INFO="%B$FG[${_color_sys_info}]"
    COLOR_AT="%B$FG[${_color_at}]"
    COLOR_PATH="%B$FG[${_color_path}]"
    COLOR_TIME="%B$FG[${_color_time}]"
    COLOR_ENV="%B$FG[${_color_env}]"
    COLOR_GIT="%B$FG[${_color_git}]"
    COLOR_SPILT="%B$FG[${_color_final}]"
    COLOR_FINAL1="%B$FG[${_color_final1}]"
    COLOR_FINAL2="%B$FG[${_color_final2}]"
    COLOR_FINAL3="%B$FG[${_color_final3}]"
    COLOR_WHITE='%B%F{white}'
else
    COLOR_PROMPT_HEAD="\e[01;38;5;${_color_prompt_head}m"
    COLOR_FG_SPLIT="\e[01;38;5;${_color_fg_split}m"
    COLOR_SYS_INFO="\033[01;38;5;${_color_sys_info}m"
    COLOR_AT="\e[01;38;5;${_color_at}m"
    COLOR_PATH="\e[01;38;5;${_color_path}m"
    COLOR_TIME="\e[01;38;5;${_color_time}m"
    COLOR_ENV="\e[01;38;5;${_color_env}m"
    COLOR_GIT="\e[01;38;5;${_color_git}m"
    COLOR_SPILT="\e[01;38;5;${_color_final}m"
    COLOR_FINAL1="\e[01;38;5;${_color_final1}m"
    COLOR_FINAL2="\e[01;38;5;${_color_final2}m"
    COLOR_FINAL3="\e[01;38;5;${_color_final3}m"
    COLOR_WHITE='\e[01;38;5;007m'
fi

SYMBOL_SPLIT_LEFT="["
SYMBOL_SPLIT_RIGHT="]"
SYMBOL_SPLIT_PARENTHESES_LEFT="("
SYMBOL_SPLIT_PARENTHESES_RIGHT=")"
SYMBOL_SPLIT_AT="@"
SYMBOL_SPLIT_COLON=":"
SYMBOL_SPLIT_FINAL="☺ "

if ${isMac} ; then
    SYMBOL_SPLIT_ARROW="➬"
else
    SYMBOL_SPLIT_ARROW=" ➬ "
fi

function _gs_spilt_icon() {
    echo "$COLOR_SPILT${SYMBOL_SPLIT_ARROW}"
}

function _gs_big_arrows() {
    local arrows="$COLOR_FINAL1${SYMBOL_SPLIT_FINAL}$COLOR_FINAL2${SYMBOL_SPLIT_FINAL}$COLOR_FINAL3${SYMBOL_SPLIT_FINAL}"
    echo " $arrows$COLOR_WHITE "
}

function _gs_get_machine_info_with_current_dir() {
    if ${isMac} ; then
        local ip=$(ipconfig getifaddr en0)
        if [ -z ${ip} ]; then
            ip=$(ipconfig getifaddr en1)
        fi
    else
        local ip=$(ip a | grep " `route | grep default | awk 'NR==1{print $NF}'`:" -A2 | tail -n1 | awk '{print $2}' | cut -f1 -d '/')
    fi

    if [ -n "$ZSH_VERSION" ]; then
        name="%n"
        real_dir=${PWD/#$HOME/~}
        echo $COLOR_FG_SPLIT${SYMBOL_SPLIT_LEFT}$COLOR_SYS_INFO${name}$COLOR_AT${SYMBOL_SPLIT_AT}$COLOR_SYS_INFO${ip}$COLOR_AT${SYMBOL_SPLIT_COLON}$COLOR_PATH${real_dir}$COLOR_FG_SPLIT${SYMBOL_SPLIT_RIGHT}
    else
        name="\u"
        echo $COLOR_FG_SPLIT${SYMBOL_SPLIT_LEFT}$COLOR_SYS_INFO${name}$COLOR_AT${SYMBOL_SPLIT_AT}$COLOR_SYS_INFO${ip}$COLOR_AT${SYMBOL_SPLIT_COLON}$COLOR_PATH'${PWD}'$COLOR_FG_SPLIT${SYMBOL_SPLIT_RIGHT}
    fi
}

function _gs_get_time() {
    if [ -n "$ZSH_VERSION" ]; then
        echo $COLOR_FG_SPLIT${SYMBOL_SPLIT_LEFT}$COLOR_TIME$(date "+%Y-%m-%d %H:%M:%S")$COLOR_FG_SPLIT${SYMBOL_SPLIT_RIGHT}
    else
        echo $COLOR_FG_SPLIT${SYMBOL_SPLIT_LEFT}$COLOR_TIME'$(date "+%Y-%m-%d %H:%M:%S")'$COLOR_FG_SPLIT${SYMBOL_SPLIT_RIGHT}
    fi
}

# conda env or python version info
function _gs_conda_or_py_info() {
    conda_or_py_name=''
    env="unknown"
    if command -v python > /dev/null 2>&1; then
        python_version="$(python -V 2>&1)"
        python_version=${python_version/Python /Python}
        python_version=${python_version/ */}
        if [ -n "$CONDA_DEFAULT_ENV" ]; then
            conda_or_py_name="$CONDA_DEFAULT_ENV"
        else
            conda_or_py_name="$python_version"
        fi
    fi

    if [ -n "$ZSH_VERSION" ]; then
       env="zsh"
    elif [ -n "$BASH_VERSION" ]; then
       env="bash"
    fi

    if [ -z ${conda_or_py_name} ]; then
        echo $COLOR_FG_SPLIT${SYMBOL_SPLIT_PARENTHESES_LEFT}$COLOR_SYS_INFO${env}$COLOR_FG_SPLIT${SYMBOL_SPLIT_PARENTHESES_RIGHT}
    else
        echo $COLOR_FG_SPLIT${SYMBOL_SPLIT_PARENTHESES_LEFT}$COLOR_SYS_INFO${env}$(_gs_spilt_icon)$COLOR_ENV${conda_or_py_name}$COLOR_FG_SPLIT${SYMBOL_SPLIT_PARENTHESES_RIGHT}
    fi
}

function _gs_right_display() {
    echo $COLOR_GIT$(git_prompt_info)
}

function _gs_prompt_start_line1() {
    echo $COLOR_PROMPT_HEAD"╭─"
}

function _gs_prompt_start_line2() {
    echo $COLOR_PROMPT_HEAD"╰─"
}


if [ -n "$ZSH_VERSION" ]; then
PROMPT=$'$(_gs_prompt_start_line1)$(_gs_get_machine_info_with_current_dir)$(_gs_spilt_icon)$(_gs_get_time)
$(_gs_prompt_start_line2)$(_gs_conda_or_py_info)$(_gs_big_arrows)'
RPROMPT=$'$(_gs_right_display)'
else
export PS1="$(_gs_prompt_start_line1)$(_gs_get_machine_info_with_current_dir)$(_gs_spilt_icon)$(_gs_get_time)
$(_gs_prompt_start_line2)$(_gs_conda_or_py_info)$(_gs_big_arrows)"
fi

#TMOUT=1
#
#TRAPALRM() {
#    zle reset-prompt
#}

## powerlevel10k
#source $HOME/.oh-my-zsh/custom/themes/powerlevel10k/powerlevel10k.zsh-theme
## To customize prompt, run `p10k configure` or edit ~/.p10k.zsh.
#[[ ! -f $HOME/.p10k.zsh ]] || source $HOME/.p10k.zsh
