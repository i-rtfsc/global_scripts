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

_GS_ROOT_PATH="$HOME/code/github/global_scripts"
_GS_CONFIG_PATH="${_GS_ROOT_PATH}/conf"

# global python env
function _gs_init_env() {
    export _GS_ROOT_PATH=$_GS_ROOT_PATH
    export PATH=$PATH:"$_GS_ROOT_PATH"
    export PATH=$PATH:"$_GS_ROOT_PATH/bin/"
    export PATH=$PATH:"$_GS_ROOT_PATH/git/"
    export PATH=$PATH:"$_GS_ROOT_PATH/.work/"
    export PATH=$PATH:"$_GS_ROOT_PATH/codestyle/"

    if [ -d "$HOME/Android/Sdk/platform-tools" ] ; then
        PATH="$HOME/Android/Sdk/platform-tools:$PATH"
    fi

    export LC_ALL=en_US.UTF-8
    export LANG=en_US.UTF-8
}

function _gs_conda_initialize() {
    # <<< conda initialize <<<
    _GS_CONDA_ROOT_DIR="$HOME/anaconda3"

    if [ ! -d ${_GS_CONDA_ROOT_DIR} ]; then
        _GS_CONDA_ROOT_DIR="$HOME/miniconda3"
    fi

    if [ ! -d ${_GS_CONDA_ROOT_DIR} ]; then
        _GS_CONDA_ROOT_DIR="$HOME/opt/miniconda3"
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

    conda activate py39tf2.x
}

function _gs_cargo_initialize() {
    # https://www.rust-lang.org/tools/install
    _GS_CARGO_DIR="$HOME/.cargo/env"
    if [ ! -d ${_GS_CARGO_DIR} ]; then
        return 0
    fi

    source ${_GS_CARGO_DIR}
}

function gs_init_git() {
    local gs_conf_dir=$HOME/bin/global_scripts/conf
    # check if the gs conf dir exists
    if [ ! -d ${gs_conf_dir} ]; then
        mkdir -p ${gs_conf_dir}
    fi

    local gs_conf_git_dir=$HOME/bin/global_scripts/conf/gs_git

    if [ "${_GS_CONFIG_PATH}/gs_git" = "$gs_conf_dir/gs_git" ]; then
        echo "don't need cp"
    else
        rm -rf $gs_conf_dir/gs_git
        cp -r ${_GS_CONFIG_PATH}/gs_git $gs_conf_git_dir
    fi

    mv $gs_conf_git_dir/.gitconfig $HOME/.gitconfig
}

function gs_init_ssh() {
    # conf or update ssh conf
   rm -rf $HOME/.ssh
   cp -r ${_GS_CONFIG_PATH}/gs_ssh $HOME/.ssh
   chmod 700 $HOME/.ssh/id_rsa
}

function gs_init_vim() {
    local gs_conf_dir=$HOME/bin/global_scripts/conf
    # check if the gs conf dir exists
    if [ ! -d ${gs_conf_dir} ]; then
        mkdir -p ${gs_conf_dir}
    fi

    local gs_conf_vim_dir=$HOME/bin/global_scripts/conf/gs_vim

    if [ "${_GS_CONFIG_PATH}/gs_vim" = "$gs_conf_dir/gs_vim" ]; then
        echo "don't need cp"
    else
        rm -rf $gs_conf_dir/gs_vim
        cp -r ${_GS_CONFIG_PATH}/gs_vim $gs_conf_vim_dir
    fi

    mv $gs_conf_vim_dir/.vimrc $HOME/.vimrc
    source $HOME/.vimrc
}

function gs_init_cargo() {
   cp  ${_GS_CONFIG_PATH}/cargo_config $HOME/.cargo/config
}

function gs_init_tmux() {
    cp ${_GS_CONFIG_PATH}/tmux/.tmux.conf $HOME/.tmux.conf
}

# gs update environment
function _gs_update_env() {
    source ${_GS_ROOT_PATH}/gs_adb.sh
    source ${_GS_ROOT_PATH}/gs_android_build.sh
    source ${_GS_ROOT_PATH}/gs_android_grep.sh
    source ${_GS_ROOT_PATH}/gs_android_push.sh
    source ${_GS_ROOT_PATH}/gs_common_alias.sh
    source ${_GS_ROOT_PATH}/gs_ext.sh
    source ${_GS_ROOT_PATH}/gs_private_alias.sh
    source ${_GS_ROOT_PATH}/gs_system.sh
    source ${_GS_ROOT_PATH}/gs_test.sh
    source ${_GS_ROOT_PATH}/gs_prompt_theme.sh
    # only for work
    source ${_GS_ROOT_PATH}/.work/gs_work.sh
    source ${_GS_ROOT_PATH}/frida/gs_android_frida.sh
    source ${_GS_ROOT_PATH}/clash/gs_system_clash.sh
}

function gs_init_all_config() {
#    cp ${_GS_CONFIG_PATH}/.zshrc $HOME/.zshrc
    gs_init_git
    gs_init_ssh
    gs_init_vim
    gs_init_cargo
}

_gs_init_env
# 我用 conda 我为了跑 py3.6以上，所以默认配置了py39tf2.x
# 公司 repo 、编译 qssi 都不支持高版本py
# 正好在 bash 情况下我没有用 conda 的需求，所以 bash 下不配置 conda
if [ -n "$ZSH_VERSION" ]; then
   _gs_conda_initialize
fi
_gs_cargo_initialize
_gs_update_env
