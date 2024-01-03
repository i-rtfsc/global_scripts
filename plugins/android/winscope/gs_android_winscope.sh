#!/bin/bash
# -*- coding: utf-8 -*-
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2024 anqi.huang@outlook.com
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


function _gs_android_winscope_help() {
    echo "Usage:"
    echo "      -f: html 脚本（路径）。"
}

function _gs_android_winscope_parse_opts() {
    # 脚本文件
    js_file="winscope.html"

    while getopts 'f:h' opt;
    do
        case ${opt} in
            f)
                js_file="${OPTARG}"
                ;;
            h)
                gs_error=1
                ;;
            ?)
                gs_error=1
                ;;
        esac
    done

    # 脚本文件 不允许为空
    if [ -z ${js_file} ]; then
        gs_error=1
    else
        gs_error=0
    fi

    echo "${gs_error} ${js_file}"
}

# gs_android_winscope -f /home/solo/code/github/global_scripts/plugins/android/winscope/winscope.html
function gs_android_winscope {
    read gs_error js_file <<< $(_gs_android_winscope_parse_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == 1 ]] ; then
        _gs_android_winscope_help
        return
    fi

    # 如果js文件不存在，则设置默认的${_GS_ROOT_PATH}/plugins/android/winscope/路径
    if [ ! -f ${js_file} ]; then
        if [ -z ${_GS_ROOT_PATH} ]; then
            js_file=$(pwd)/${js_file}
        else
            js_file=${_GS_ROOT_PATH}/plugins/android/winscope/${js_file}
        fi
        echo "update js_file=${js_file}"
    fi

    # 再次检查文件，不存在则退出
    if [ ! -f ${js_file} ]; then
        echo "${js_file} does not exist."
        return
    fi

    xdg-open ${js_file}
    python3 ${_GS_ROOT_PATH}/plugins/android/winscope/winscope_proxy.py
}