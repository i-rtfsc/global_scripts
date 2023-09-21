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

# step 1
# 初始化 _GS_ROOT_PATH、_GS_CONFIG_PATH 路径
#_GS_ROOT_PATH="$HOME/code/github/global_scripts"
if [ -n "$ZSH_VERSION" ]; then
    _GS_ROOT_PATH=`dirname ${(%):-%N}`
elif [ -n "$BASH_VERSION" ]; then
    _GS_ROOT_PATH=`dirname "$BASH_SOURCE"`
fi
_GS_CONFIG_PATH="${_GS_ROOT_PATH}/conf"


function _gs_init_path() {
    local gs_path=$1

    if [ ! -d ${gs_path} ]; then
        verbose_error "${gs_path} don't exists"
        return
    fi

    if [[ ${PATH} == *"${gs_path}"* ]]; then
        verbose_warn "has been export, ${gs_path}"
    else
        export PATH=$PATH:"${gs_path}"
    fi
}

# global python env
function _gs_init_global_env() {
    # step 2
    # 设置 _GS_ROOT_PATH、_GS_CONFIG_PATH 环境变量
    export _GS_ROOT_PATH=$_GS_ROOT_PATH
    export _GS_CONFIG_PATH=$_GS_CONFIG_PATH

    export LC_ALL=en_US.UTF-8
    export LANG=en_US.UTF-8

    # step 3
    # 加载 .gsrc 配置文件
    local gs_config=$HOME/.gsrc
    # check if the gs env exists
    if [ ! -f ${gs_config} ]; then
        source ${_GS_CONFIG_PATH}/.gsrc
    else
        source ${gs_config}
    fi

    # step 4
    # 加载 env 下的配置
    # 这个必须在 .gsrc 后接着马上加载，是因为里面配置了全局的颜色，func等
    # 别的配置需要依赖
    for file in ${_GS_ROOT_PATH}/env/gs_*.sh ; do
        if [ -f ${file} ]; then
            source $file
        fi
    done

    # step 5
    # 设置 PATH 环境变量
    _gs_init_path $_GS_ROOT_PATH/bin/
    _gs_init_path $_GS_ROOT_PATH/conf/
    _gs_init_path $_GS_ROOT_PATH/tools/codestyle/
    _gs_init_path $HOME/Android/Sdk/platform-tools/

    # step 6
    # 设置 zsh 特有的环境变量
    if [ -n "$ZSH_VERSION" ]; then
       for file in ${_GS_ROOT_PATH}/env/zsh_*.sh ; do
            if [ -f ${file} ]; then
                verbose_info ${file}
                source ${file}
            fi
        done
    fi

    # step 7
    # 根据 .gsrc 配置的插件加载对应的插件
    for plugin in ${plugins[@]}; do
        for file in ${_GS_ROOT_PATH}/plugins/${plugin}/gs_*.sh ; do
            if [ -f ${file} ]; then
                verbose_info ${file}
                source ${file}
            fi
        done
    done

    # step 8
    # 根据 .gsrc 加载工作配置
    if [[ "${gs_env_work}" == "1" ]]; then
        _gs_init_path $_GS_ROOT_PATH/.work/

        for file in ${_GS_ROOT_PATH}/.work/gs_*.sh ; do
            if [ -f ${file} ]; then
                verbose_info ${file}
                source ${file}
            fi
        done
    fi

    if [[ "${gs_env_debug}" == "1" ]]; then
        gs_env_version=`cat $_GS_ROOT_PATH/VERSION`
        verbose_warn "global scripts version = ${gs_env_version}"
    fi
}

_gs_init_global_env
