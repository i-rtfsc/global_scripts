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
ZSH_COLOR_BLACK='%B%F{black}'    # Black
ZSH_COLOR_RED='%B%F{red}'        # Red
ZSH_COLOR_GREEN='%B%F{green}'    # Green
ZSH_COLOR_YELLOW='%B%F{yellow}'  # Yellow
ZSH_COLOR_BLUE='%B%F{blue}'      # Blue
ZSH_COLOR_PURPLE='%B%F{magenta}' # Purple(magenta)
ZSH_COLOR_CYAN='%B%F{cyan}'      # Cyan
ZSH_COLOR_WHITE='%B%F{white}'    # White

machine="$(uname -s)"
case "${machine}" in
    Linux*)     isMac=false;;
    Darwin*)    isMac=true;;
    *)          isMac=false;;
esac

function _gs_spilt_icon() {
    echo " ${ZSH_COLOR_WHITE}➤ "
}

function _gs_big_arrows() {
    local arrows="${ZSH_COLOR_YELLOW}❯${ZSH_COLOR_PURPLE}❯${ZSH_COLOR_CYAN}❯"
    echo " $arrows$arrows "
}

function _gs_get_machine_info() {
    local name="%n"
    if $isMac ; then
        local ip=$(ipconfig getifaddr en0)
    else
        local ip=$(ip a | grep " `route | grep default | awk 'NR==1{print $NF}'`:" -A2 | tail -n1 | awk '{print $2}' | cut -f1 -d '/')
    fi
    echo "${ZSH_COLOR_PURPLE}[${ZSH_COLOR_RED}$name${ZSH_COLOR_YELLOW}@${ZSH_COLOR_RED}$ip${ZSH_COLOR_PURPLE}]"
}

function _gs_get_current_dir() {
    local real_dir=${PWD/#$HOME/~}
    echo "${ZSH_COLOR_PURPLE}[${ZSH_COLOR_CYAN}$real_dir${ZSH_COLOR_PURPLE}]"
}

function _gs_get_time() {
    echo "${ZSH_COLOR_PURPLE}[${ZSH_COLOR_BLUE}$(date "+%Y-%m-%d %H:%M:%S")${ZSH_COLOR_PURPLE}]"
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

        echo "${ZSH_COLOR_PURPLE}(${ZSH_COLOR_BLUE}${conda_or_py_name}${ZSH_COLOR_PURPLE})"
    fi
}

function _gs_right_display() {
    echo '${ZSH_COLOR_PURPLE}$(git_prompt_info)'
}

function gs_prompt_start_line1() {
    echo "${ZSH_COLOR_PURPLE}╭─"
}

function gs_prompt_start_line2() {
    echo "${ZSH_COLOR_PURPLE}╰─"
}

PROMPT=$'$(gs_prompt_start_line1)$(_gs_get_machine_info)$(_gs_spilt_icon)$(_gs_get_current_dir)$(_gs_spilt_icon)$(_gs_get_time)
$(gs_prompt_start_line2)$(_gs_conda_or_py_info)$(_gs_big_arrows)${ZSH_COLOR_WHITE}'
RPROMPT=$(_gs_right_display)
