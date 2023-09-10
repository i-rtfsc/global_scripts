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

# zsh theme colors
ZSH_COLOR_WHITE='%B%F{white}'    # White

#for code in {000..255}; do print -P -- "$code: $FG[$code]Color"; done
#for code in {000..255}; do print -P -- "$code: $BG[$code]Color"; done

ZSH_COLOR_FG_HEAD=172
ZSH_COLOR_FG_SPLIT=245
ZSH_COLOR_FG_SYS_INFO=163
ZSH_COLOR_FG_AT=190
ZSH_COLOR_FG_PATH=014
ZSH_COLOR_FG_TIME=069
ZSH_COLOR_FG_ENV=039
ZSH_COLOR_FG_GIT=213
ZSH_COLOR_FG_BIG_ARROW=015

ZSH_COLOR_FG_BIG_ARROW1=214
ZSH_COLOR_FG_BIG_ARROW2=199
ZSH_COLOR_FG_BIG_ARROW3=033

ZSH_COLOR_BG_SYS_INFO=045

machine="$(uname -s)"
case "${machine}" in
    Linux*)     isMac=false;;
    Darwin*)    isMac=true;;
    *)          isMac=false;;
esac

function _gs_spilt_icon() {
    echo "$FG[$ZSH_COLOR_FG_BIG_ARROW] ➤ "
}

function _gs_big_arrows() {
    local arrows="$FG[$ZSH_COLOR_FG_BIG_ARROW1]❯$FG[$ZSH_COLOR_FG_BIG_ARROW2]❯$FG[$ZSH_COLOR_FG_BIG_ARROW3]❯"
    echo " $arrows$arrows "
}

function _gs_get_machine_info_with_current_dir() {
    local name="%n"
    if $isMac ; then
        local ip=$(ipconfig getifaddr en0)
        if [ -z ${ip} ]; then
            ip=$(ipconfig getifaddr en1)
        fi
    else
        local ip=$(ip a | grep " `route | grep default | awk 'NR==1{print $NF}'`:" -A2 | tail -n1 | awk '{print $2}' | cut -f1 -d '/')
    fi
    local real_dir=${PWD/#$HOME/~}
    echo "%B$FG[$ZSH_COLOR_FG_SPLIT][$FG[$ZSH_COLOR_FG_SYS_INFO]$name$FG[$ZSH_COLOR_FG_AT]@$FG[$ZSH_COLOR_FG_SYS_INFO]$ip:$FG[$ZSH_COLOR_FG_PATH]$real_dir$FG[$ZSH_COLOR_FG_SPLIT]]"
}

function _gs_get_time() {
    echo "%B$FG[$ZSH_COLOR_FG_SPLIT][$FG[$ZSH_COLOR_FG_TIME]$(date "+%Y-%m-%d %H:%M:%S")$FG[$ZSH_COLOR_FG_SPLIT]]"
}


function _gs_system_cpu_men() {
    cpu_mem=$(ps -A -o %cpu,%mem | awk '{ cpu += $1; mem += $2} END {print "cpu : "cpu"%, memory : "mem"%"}')
#    cpu_mem=$(ps -A -o %cpu,%mem | awk '{ cpu += $1; mem += $2} END {print "cpu : "cpu" %" }')
    echo "%B$FG[$ZSH_COLOR_FG_SPLIT][%B$FG[$ZSH_COLOR_FG_SYS_INFO]${cpu_mem}%B$FG[$ZSH_COLOR_FG_SPLIT]]"
}


# conda env or python version info
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

        echo "%B$FG[$ZSH_COLOR_FG_SPLIT]($FG[$ZSH_COLOR_FG_ENV]${conda_or_py_name}$FG[$ZSH_COLOR_FG_SPLIT])"
    fi
}

function _gs_right_display() {
    echo '%B$FG[$ZSH_COLOR_FG_GIT]$(git_prompt_info)'
}

function _gs_prompt_start_line1() {
    echo "$FG[$ZSH_COLOR_FG_HEAD]╭─"
}

function _gs_prompt_start_line2() {
    echo "$FG[$ZSH_COLOR_FG_HEAD]╰─"
}

PROMPT=$'$(_gs_prompt_start_line1)$(_gs_get_machine_info_with_current_dir)$(_gs_spilt_icon)$(_gs_get_time)
$(_gs_prompt_start_line2)$(_gs_conda_or_py_info)$(_gs_big_arrows)${ZSH_COLOR_WHITE}'
RPROMPT=$(_gs_right_display)

#TMOUT=1
#
#TRAPALRM() {
#    zle reset-prompt
#}

## powerlevel10k
#source $HOME/.oh-my-zsh/custom/themes/powerlevel10k/powerlevel10k.zsh-theme
## To customize prompt, run `p10k configure` or edit ~/.p10k.zsh.
#[[ ! -f $HOME/.p10k.zsh ]] || source $HOME/.p10k.zsh