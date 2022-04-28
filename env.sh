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

GS_ROOT_PATH="$HOME/code/github/global_scripts"

# global python env
function gs_init_env() {
    export PATH="$GS_ROOT_PATH:$PATH"

    export LC_ALL=en_US.UTF-8
    export LANG=en_US.UTF-8
}

function gs_conda_initialize() {
    # <<< conda initialize <<<
    _GS_CONDA_ROOT_DIR="$HOME/anaconda3"
    if [ ! -d ${_GS_CONDA_ROOT_DIR} ]; then
        _GS_CONDA_ROOT_DIR="$HOME/miniconda"
    fi

    if [ ! -d ${_GS_CONDA_ROOT_DIR} ]; then
        return 0
    fi

    __conda_setup="$('$_GS_CONDA_ROOT_DIR/bin/conda' 'shell.zsh' 'hook' 2> /dev/null)"
    if [ $? -eq 0 ]; then
        eval "$__conda_setup"
    else
        if [ -f "$_GS_CONDA_ROOT_DIR/etc/profile.d/conda.sh" ]; then
            . "$_GS_CONDA_ROOT_DIR/etc/profile.d/conda.sh"
        else
            export PATH="$_GS_CONDA_ROOT_DIR/bin:$PATH"
        fi
    fi
    unset __conda_setup
    # <<< conda initialize <<<

    conda config --set changeps1 False

    case `uname -s` in
        Darwin)
            conda activate py39tf2.x
            ;;
        *)
            conda activate py36tf1.15
            ;;
    esac

}

# gs update environment
function gs_update_env() {
    source ${GS_ROOT_PATH}/system.sh
    source ${GS_ROOT_PATH}/adb.sh
    source ${GS_ROOT_PATH}/android_build.sh
    source ${GS_ROOT_PATH}/android_grep.sh
    source ${GS_ROOT_PATH}/android_push.sh
    source ${GS_ROOT_PATH}/common_alias.sh
    source ${GS_ROOT_PATH}/private_alias.sh
    source ${GS_ROOT_PATH}/zsh_theme.sh
}

gs_init_env
gs_conda_initialize
gs_update_env
