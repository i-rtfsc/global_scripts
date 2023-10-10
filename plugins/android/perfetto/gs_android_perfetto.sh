#!/bin/bash
# -*- coding: utf-8 -*-
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2023 anqi.huang@outlook.com
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


function _gs_android_perfetto_help() {
    echo "Usage:"
    echo "      -f: 需要执行的脚本（路径）。"
}

function _gs_android_perfetto_parse_opts() {
    # 脚本文件
    config_file=""

    while getopts 'f:h' opt;
    do
        case ${opt} in
            f)
                config_file="${OPTARG}"
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
    if [ -z ${config_file} ]; then
        gs_error=1
    else
        gs_error=0
    fi

    echo "${gs_error} ${config_file}"
}

# gs_android_perfetto -f /home/solo/code/github/global_scripts/plugins/android/perfetto/config.pbtx
# 或者
# gs_android_perfetto -f config.pbtx
function gs_android_perfetto {
    read gs_error config_file <<< $(_gs_android_perfetto_parse_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == 1 ]] ; then
        _gs_android_perfetto_help
        return
    fi

    echo "config_file=${config_file}"

    # 如果配置文件不存在，则设置默认的${_GS_ROOT_PATH}/plugins/android/perfetto/路径
    if [ ! -f ${config_file} ]; then
        if [ -z ${_GS_ROOT_PATH} ]; then
            config_file=$(pwd)/${config_file}
        else
            config_file=${_GS_ROOT_PATH}/plugins/android/perfetto/${config_file}
        fi
        echo "update config_file=${config_file}"
    fi

    # 再次检查文件，不存在则退出
    if [ ! -f ${config_file} ]; then
        echo "${config_file} does not exist."
        return
    fi

    adb root
    adb remount

    cat ${config_file} | adb shell perfetto -c - --txt -o /data/misc/perfetto-traces/trace.perfetto-trace
    adb pull /data/misc/perfetto-traces/trace.perfetto-trace .

}

function gs_android_perfetto_default {
    adb root
    adb remount

    adb shell perfetto -o /data/misc/perfetto-traces/trace.perfetto-trace -t 20s sched freq idle am wm gfx view binder_driver hal dalvik camera input res memory
    adb pull /data/misc/perfetto-traces/trace.perfetto-trace .
}