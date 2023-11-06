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
        verbose_info "export path = ${gs_path}"
        export PATH=$PATH:"${gs_path}"
    fi
}

function _gs_init_global_env() {
    # step 2
    # 设置 _GS_ROOT_PATH、_GS_CONFIG_PATH 环境变量
    export _GS_ROOT_PATH=${_GS_ROOT_PATH}
    export _GS_CONFIG_PATH=${_GS_CONFIG_PATH}

    export LC_ALL=en_US.UTF-8
    export LANG=en_US.UTF-8

    local gs_path_bin=${_GS_ROOT_PATH}/bin
    local gs_path_env=${_GS_ROOT_PATH}/env
    local gs_path_conf=${_GS_ROOT_PATH}/conf
    local gs_path_plugins=${_GS_ROOT_PATH}/plugins
    local gs_path_themes=${_GS_ROOT_PATH}/themes
    local gs_path_codestyle=${_GS_ROOT_PATH}/tools/codestyle
    local gs_path_custom_plugins=${_GS_ROOT_PATH}/custom

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
    for file in ${gs_path_env}/gs_*.sh ; do
        if [ -f ${file} ]; then
            source $file
        fi
    done

    # step 5
    # 设置 PATH 环境变量
    _gs_init_path ${gs_path_bin}
    _gs_init_path ${gs_path_conf}
    _gs_init_path ${gs_path_codestyle}
    # 设置 android sdk platform-tools
    platform="$(uname -s)"
    case "$platform" in
        Linux*)
            _gs_init_path $HOME/Android/Sdk/platform-tools
            ;;
        Darwin*)
            _gs_init_path $HOME/Library/Android/sdk/platform-tools
            ;;
        *)
            verbose_info "unknown platform"
    esac

    # step 6
    # 设置 zsh 特有的环境变量
    if [ -n "$ZSH_VERSION" ]; then
       for file in ${gs_path_env}/zsh_*.sh ; do
            if [ -f ${file} ]; then
                verbose_info ${file}
                source ${file}
            fi
        done
    fi

    # step 7
    # 根据 .gsrc 配置的插件加载对应的插件
    for plugin in ${gs_plugins[@]}; do
        if [ -z "$(find ${gs_path_plugins}/${plugin}/ -maxdepth 1 -type f)" ]; then
            verbose_error "${gs_path_plugins}/${plugin}/ has no files"
        else
            for file in ${gs_path_plugins}/${plugin}/gs_*.sh ; do
                if [ -f ${file} ]; then
                    verbose_info ${file}
                    source ${file}
                fi
            done
        fi

        if [ -d ${gs_path_plugins}/${plugin}/bin ]; then
            _gs_init_path ${gs_path_plugins}/${plugin}/bin
        fi
    done

    # step 8
    # 根据 .gsrc 配置的主题加载对应的主题
    if [ -z ${gs_themes_prompt} ]; then
        verbose_error "hasn't set prompt theme"
    else
        prompt_info_file=${gs_path_themes}/prompt/gs_prompt_info.sh
        if [ -f ${prompt_info_file} ]; then
            verbose_info ${prompt_info_file}
            source ${prompt_info_file}
        fi

        for file in ${gs_path_themes}/prompt/${gs_themes_prompt}/gs_*.sh ; do
            if [ -f ${file} ]; then
                verbose_info ${file}
                source ${file}
            fi
        done
    fi

    # step 9
    # 根据 .gsrc 配置的custom插件加载对应的插件
    for plugin in ${gs_custom_plugins[@]}; do
        if [ -z "$(find ${gs_path_custom_plugins}/${plugin}/ -maxdepth 1 -type f)" ]; then
            verbose_error "${gs_path_plugins}/${plugin}/ has no files"
        else
            for file in ${gs_path_custom_plugins}/${plugin}/*.sh ; do
                if [ -f ${file} ]; then
                    verbose_info ${file}
                    source ${file}
                fi
            done
        fi

        if [ -d ${gs_path_custom_plugins}/${plugin}/bin ]; then
            _gs_init_path ${gs_path_custom_plugins}/${plugin}/bin
        fi
    done

    if [[ "${gs_env_debug}" == "1" ]]; then
        gs_env_version=`cat ${_GS_ROOT_PATH}/VERSION`
        verbose_warn "global scripts version = ${gs_env_version}"
    fi
}

_gs_init_global_env
