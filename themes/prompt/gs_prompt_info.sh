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

function _gs_theme_ip() {
    if ${isMac} ; then
        local ip=$(ipconfig getifaddr en0)
        if [ -z ${ip} ]; then
            ip=$(ipconfig getifaddr en1)
        fi
    else
        local ip=$(ip a | grep " `route | grep default | awk 'NR==1{print $NF}'`:" -A2 | tail -n1 | awk '{print $2}' | cut -f1 -d '/')
    fi
    echo $ip
}

function _gs_theme_user_name() {
    if [ -n "$ZSH_VERSION" ]; then
        name="%n"
    else
        name="\u"
    fi

    echo $name
}

function _gs_theme_current_dir() {
    if [ -n "$ZSH_VERSION" ]; then
        real_dir=${PWD/#$HOME/~}
    else
        real_dir=${PWD}
    fi

    echo $real_dir
}

function _gs_theme_get_time() {
    echo $(date "+%Y-%m-%d %H:%M:%S")
}

# conda env or python version info
function _gs_theme_conda_or_py_info() {
    conda_or_py_name=''
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

    echo $conda_or_py_name
}

function _gs_theme_right_display() {
    echo $COLOR_GIT$(git_prompt_info)
}

function _gs_theme_start_line1() {
    echo "╭─"
}

function _gs_theme_start_line2() {
    echo "╰─"
}

function _gs_theme_color_text() {
    code=$1
    text=$2
    if [ -n "$ZSH_VERSION" ]; then
        echo "%B${FG[$code]}${text}%{$reset_color%}"
    else
        echo "\e[01;38;5;${code}m${text}\033[0m"
    fi
}
