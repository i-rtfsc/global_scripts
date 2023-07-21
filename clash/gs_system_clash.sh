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

# 如果不用global_scripts刚才，单独使用clash目录，则需要配置_GS_ROOT_PATH
# 并且主动在这个文件里主动调用gs_system_clash，然后直接执行这个文件。
#_GS_ROOT_PATH="$HOME/code/github/global_scripts"

function _gs_system_clash_help() {
    echo "Usage:"
    echo "      -a: 动作（action），如启动（start）、关闭（shutdown）、重启（restart）；默认是启动"
    echo "      -c: 配置文件路径，不设置则为默认（clash/conf）。"
}

function _gs_system_clash_parse_opts() {
    # 动作
    action="start"

    # 配置文件路径
    config="${_GS_ROOT_PATH}/clash/conf"

    gs_error=0

    while getopts 'a:c:h' opt;
    do
        case ${opt} in
            a)
                action="${OPTARG}"
                ;;
            c)
                config="${OPTARG}"
                ;;
            ?)
                gs_error=1
                ;;
        esac
    done

    # gs_module有可能为空, 所以必须放在最后面
    echo "${gs_error} ${action} ${config}"
}

# 函数，判断命令是否正常执行
function _gs_clash_if_success() {
    local ReturnStatus=$1
    if [ $ReturnStatus -eq 0 ]; then
        echo "$2"
    else
        echo "$3"
    fi
}

## 关闭clash服务
function _gs_system_clash_shutdown() {
    # 查询并关闭程序进程
    pids=($(ps -ef | grep clash-linux | awk '{print $2}'))
    for pid in ${pids}; do
        kill -9 $pid
        _gs_clash_if_success $? "服务关闭成功！" "服务关闭失败！"
    done
}

function _gs_system_clash_start() {
    clash_bin=$1
    version=$2
    config=$3
    logs=$4

    ## 获取CPU架构
    if /bin/arch &>/dev/null; then
        cpu_arch=`/bin/arch`
    elif /usr/bin/arch &>/dev/null; then
        cpu_arch=`/usr/bin/arch`
    elif /bin/uname -m &>/dev/null; then
        cpu_arch=`/bin/uname -m`
    else
        echo -e "\033[31m\n[ERROR] Failed to obtain CPU architecture！\033[0m"
        exit 1
    fi
    echo "cpu = $cpu_arch"

    ## 重启启动clash服务
    start_success="服务启动成功！"
    start_failure="服务启动失败！"

    # 是否用nohup
    if [[ $cpu_arch =~ "x86_64" ]]; then
        cmd="$clash_bin/clash-linux-amd64$version -d $config | tee $logs 2>&1"
        eval $cmd
        _gs_clash_if_success $? $start_success $start_failure
    elif [[ $cpu_arch =~ "aarch64" ||  $CpuArch =~ "arm64" ]]; then
        cmd="$clash_bin/clash-linux-arm64$VERSION -d $config | tee $logs 2>&1"
        eval $cmd
        _gs_clash_if_success $? $start_success $start_failure
    elif [[ $cpu_arch =~ "armv7" ]]; then
        cmd="$clash_bin/clash-linux-armv7$VERSION -d $config | tee $logs 2>&1"
        eval $cmd
        _gs_clash_if_success $? $start_success $start_failure
    else
        echo -e "\033[31m\n[ERROR] Unsupported CPU Architecture！\033[0m"
        exit 1
    fi
}

function gs_system_clash {
    read gs_error action config <<< $(_gs_system_clash_parse_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == 1 ]] ; then
        _gs_system_clash_help
        return
    fi

    clash_bin="${_GS_ROOT_PATH}/clash/bin"
    version="-v1.17.0"
    logs="${_GS_ROOT_PATH}/clash/logs/logs.txt"

    echo "action=${action}, config=${config}, version=${version}, logs=${logs}"

    if [[ ${action} == "shutdown" ]]; then
        _gs_system_clash_shutdown
    elif [[ ${action} == "start" ]]; then
        _gs_system_clash_shutdown
        _gs_system_clash_start $clash_bin $version $config $logs
    elif [[ ${action} == "restart" ]]; then
        _gs_system_clash_shutdown
        _gs_system_clash_start $clash_bin $version $config $logs
    else
        echo "unknown"
    fi
}

