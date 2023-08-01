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

function _gs_android_frida_help() {
    echo "Usage:"
    echo "      -p: 进程名字（包名），如 system_server。"
    echo "      -f: 需要执行的脚本（路径）。"
}

function _gs_android_frida_parse_opts() {
    # 设置的默认target
    process_name="system_server"

    # 脚本文件
    js_file=""

    while getopts 'p:f:h' opt;
    do
        case ${opt} in
            p)
                process_name="${OPTARG}"
                ;;
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

    # gs_module有可能为空, 所以必须放在最后面
    echo "${gs_error} ${process_name} ${js_file}"
}

# gs_android_frida -p system_server -f /home/solo/code/github/global_scripts/frida/hook3.js
function gs_android_frida {
    read gs_error process_name js_file <<< $(_gs_android_frida_parse_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == 1 ]] ; then
        _gs_android_frida_help
        return
    fi

    echo "process_name=${process_name}, js_file=${js_file}"

    file_name=`basename ${js_file}`
    echo "file_name=${file_name}"

    adb root
    adb remount

    if [[ `adb shell ls /data/local/frida/frida-inject 2> /dev/null` ]]; then
        echo "frida-inject exists"
        adb shell chmod a+x /data/local/frida/frida-inject
    else
        echo "frida-inject doesn't exist"
        if [ -z ${_GS_ROOT_PATH} ]; then
            root_dir=$(pwd)
        else
            root_dir=${_GS_ROOT_PATH}/frida
        fi

        adb push ${root_dir}/frida-inject /data/local/frida/frida-inject
        adb shell chmod a+x /data/local/frida/frida-inject
    fi

    adb push ${js_file} /data/local/frida/${file_name}
    adb shell /data/local/frida/frida-inject -p `adb shell pidof ${process_name}` -s /data/local/frida/${file_name}
}

# 在手机上运行frida-server服务
function gs_android_frida_server() {
    root_dir=$(pwd)
    echo ${root_dir}

    adb root
    adb remount

    if [[ `adb shell ls /data/local/frida/frida-server 2> /dev/null` ]]; then
        echo "frida-inject exists"
        adb shell chmod a+x /data/local/frida/frida-server
    else
        echo "frida-server doesn't exist"
        if [ -z ${_GS_ROOT_PATH} ]; then
            root_dir=$(pwd)
        else
            root_dir=${_GS_ROOT_PATH}/frida/frida-inject
        fi
        adb push ${root_dir}/frida-server /data/local/frida/frida-server
        adb shell chmod a+x /data/local/frida/frida-server
    fi

    adb shell "/data/local/frida/frida-server &"
}

function gs_android_frida_kill() {
    pids=($(adb shell ps | grep frida | awk '{print $2}'))
    for pid in ${pids}; do
        adb shell kill -9 $pid
    done
}