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

LUNCH_TARGET_DEFAULT="sdk_phone_x86_64"

function _gs_android_build_help() {
    echo "Usage:"
    echo "      -t: 编译的target，如 sdk_phone_x86_64、qssi。"
    echo "      -j: 编译线程数。"
    echo "      -m: 需要编译的模块，如framework。"
    echo "      -c: 是否启用ccache，1启用、0不启用；linux环境下默认使用。"
    echo "      -b: 飞书机器人token，编译完成后飞书通知。"
}

function _gs_android_build_parse_opts() {
    # 设置的默认target
    gs_target=$LUNCH_TARGET_DEFAULT

    # 编译的模块名
    gs_module=""

    case $(uname -s) in
    Darwin)
        # 编译线程数根据机器的核心数决定
        gs_build_thread=$(sysctl -n hw.logicalcpu)
        # 使用ccache
        gs_ccache="0"
        ;;
    *)
        # 编译线程数根据机器的核心数决定
        gs_build_thread=$(nproc)
        # 使用ccache
        gs_ccache="1"
        ;;
    esac

    # 飞书机器人
    local gs_bot="NONE"

    # error
    gs_error=0

    while getopts 't:j:m:c:b:h' opt;
    do
        case ${opt} in
            t)
                gs_target="${OPTARG}"
                ;;
            j)
                gs_build_thread="${OPTARG}"
                ;;
            c)
                gs_ccache="${OPTARG}"
                ;;
            b)
                gs_bot="${OPTARG}"
                ;;
            m)
                gs_module="${OPTARG}"
                ;;
            h)
                gs_error=1
#                通过read读取返回值，所以这里不能打印help
#                _gs_android_build_help
                ;;
            ?)
                gs_error=1
#                _gs_android_build_help
                ;;
        esac
    done

    # gs_module有可能为空, 所以必须放在最后面
    echo "${gs_error} ${gs_target} ${gs_build_thread} ${gs_ccache} ${gs_bot} ${gs_module}"
}

function _gs_android_build_echo_and_run() {
    echo "----------[$*]----------" ; "$@" ;
}

# remove colors
# https://stackoverflow.com/questions/17998978/removing-colors-from-output
function _gs_android_build_strip_escape_codes() {
    local _input="$1" _i _char _escape=0
    local -n _output="$2"
    _output=""
    for ((_i = 0; _i < ${#_input}; _i++)); do
        _char="${_input:_i:1}"
        if ((${_escape} == 1)); then
            if [[ "${_char}" == [a-zA-Z] ]]; then
                _escape=0
            fi
            continue
        fi
        if [[ "${_char}" == $'\e' ]]; then
            _escape=1
            continue
        fi
        _output+="${_char}"
    done
}

function _gs_android_build_bot() {
    gs_bot=$2
    # 检测脚本内部是否设置了机器人token
    if [ -z ${gs_bot} ]; then
        echo "android build script don't set im bot token"
        gs_bot=$_GS_BOT
    fi

    # 再次检测环境变量是否设置了机器人token
    if [ -z ${gs_bot} ]; then
        echo "environment don't set im bot token"
        # 没有都没有配置则无需通过机器人通知
        return 0
    fi

    build_log=$1
    if test -f "$build_log"; then
        info=$(tail -1 $build_log)

        if [ -z "$info" ]; then
            info=$(tail -2 $build_log)
        fi

        if [ -z "$info" ]; then
            info=$(tail -3 $build_log)
        fi
    fi

    if [ -z "$info" ]; then
        info="build finish"
    fi

    _gs_android_build_strip_escape_codes "${info}" info
#    echo $info
    curl -X POST https://open.feishu.cn/open-apis/bot/v2/hook/${gs_bot} -H "Content-Type: application/json" -d '{"msg_type":"text","content":{"text":"'"$info"'"}}'
    echo ""
    echo ""
}

function _gs_android_build_lunch() {
    TOP=$(pwd)
    # 创建log目录
    gs_build_log_dir=$TOP/out/build_log
    # check if the building log dir exists
    if [ ! -d ${gs_build_log_dir} ]; then
        _gs_android_build_echo_and_run mkdir -p ${gs_build_log_dir}
    fi
    _GS_BUILD_LOG_DIR=${gs_build_log_dir}

    # 如果TARGET_PRODUCT为空，则使用输入的gs_target参数
#    if [ -z ${TARGET_PRODUCT} ]; then
#        _GS_TARGET_PRODUCT=$1
#    else
#        _GS_TARGET_PRODUCT=${TARGET_PRODUCT}
#    fi
    # 这个改用自己export的_GS_TARGET_PRODUCT是因为有些公司改写了编译规则，
    # aosp使用TARGET_PRODUCT是没问题的。
    if [ "$1" = "$LUNCH_TARGET_DEFAULT" ]; then
        if [ -z ${_GS_TARGET_PRODUCT} ]; then
            _GS_TARGET_PRODUCT=$1
        else
            _GS_TARGET_PRODUCT=${_GS_TARGET_PRODUCT}
        fi
    else
        _GS_TARGET_PRODUCT=$1
    fi

    _gs_android_build_echo_and_run export _GS_TARGET_PRODUCT=${_GS_TARGET_PRODUCT}

    # CMakeLists.txt project file generation is enabled via environment variable:
    _gs_android_build_echo_and_run export SOONG_GEN_CMAKEFILES=1

    _gs_android_build_echo_and_run source build/envsetup.sh
    _gs_android_build_echo_and_run lunch ${_GS_TARGET_PRODUCT}
}

function _gs_android_build_with_ccache() {
    gs_ccache=$1
    gs_target_product=$2

    if [ "$gs_ccache" = "1" ]; then
        _gs_android_build_echo_and_run export USE_CCACHE=1
        _gs_android_build_echo_and_run export CCACHE_EXEC=/usr/bin/ccache

#        ccache_dir=$HOME/code/.ccache/$gs_target_product
        # 如果是qssi, 在只获取前面的字符串
        if [[ $gs_target_product =~ "qssi" ]]
        then
            ccache_dir=$HOME/code/.ccache/$(echo $gs_target_product | cut -d '-' -f1)
        else
            ccache_dir=$HOME/code/.ccache/$gs_target_product
        fi

        # check if the ccache dir exists
        if [ ! -d ${ccache_dir} ]; then
            _gs_android_build_echo_and_run mkdir -p ${ccache_dir}
        fi
        #set ccache dir
        _gs_android_build_echo_and_run export CCACHE_DIR=${ccache_dir}
        _gs_android_build_echo_and_run ccache --set-config=cache_dir=${ccache_dir}
        _gs_android_build_echo_and_run export CCACHE_CONFIGPATH=${ccache_dir}/ccache.conf
        _gs_android_build_echo_and_run ccache -M 100G
    fi
}

function _gs_android_build_modules() {
    local modules=(
        "framework"
        "framework-minus-apex"
        "services"
        "libandroid_servers"
        "libandroid_runtime"
        "libinputflinger"
        "libinputreader"
        "libinputservice"
        "selinux_policy"
        "surfaceflinger"
        "update_engine"
        "android.hardware.power-service"
        "libresourcemanagerservice"
        "libaudioflinger"
        "libcameraservice"
        "toolbox"
        "J007Service"
        "jos-framework"
        "jos-services"
        "watermark"
        "android.car"
        "car-frameworks-service"
        "CarService"
        "CarServiceUpdatable"
        "com.journeyOS.J007engine.hidl@1.0-service"
        "com.journeyOS.J007engine.hidl@1.0"
        "com.flyme.runtime"
    )
    for item in ${modules[@]}; do
        echo ${item}
    done
}

function _gs_android_build_show_and_choose_combo() {
#    unset _GS_BUILD_COMBO

    local user_input=$1
    local title=$2
    local choices=($(echo $3 | tr ',' ' '))

    local index=1
    local default_index=1
    if [ -n "$BASH_VERSION" ]; then
        index=0
        default_index=0
    fi

    if [ -z ${_GS_BUILD_COMBO} ]; then
        _GS_BUILD_COMBO=${choices[default_index]}
    fi

    local answer=${_GS_BUILD_COMBO}
    local selection=${_GS_BUILD_COMBO}

    if [ "${user_input}" ]; then
        answer=${user_input}
    else
        # print combo menu,
        for item in ${choices[@]}; do
            echo $index. ${item}
            index=$(($index + 1))
        done
        printf "Which would you like? [ %s ] " ${answer}
        read answer

        if [ -z "$answer" ]; then
            answer=${selection}
        fi
    fi

    if [ -z "$answer" ]; then
        echo "error: get null answer."
    elif (echo -n $answer | grep -q -e "^[0-9][0-9]*$"); then
        selection=${choices[answer]}
    else
        selection=${answer}
    fi

    _gs_android_build_echo_and_run export _GS_BUILD_COMBO=${selection}
}

function gs_android_build_ninja_clean() {
    _gs_android_build_echo_and_run time prebuilts/build-tools/linux-x86/bin/ninja -j ${_GS_BUILD_THREAD} -f out/combined-${TARGET_PRODUCT}.ninja -t clean
}

# ninja编译模块
function gs_android_build_ninja() {
    read gs_error gs_target gs_build_thread gs_ccache gs_bot gs_module <<< $(_gs_android_build_parse_opts $*)

    # 错误则打印help
    if [[ ${gs_error} == 1 ]] ; then
        _gs_android_build_help
        return
    fi

    echo "error=${gs_error}, target=${gs_target}, thread=${gs_build_thread}, ccache=${gs_ccache}, bot=${gs_bot}, module=${gs_module}"

    # lunch target
    _gs_android_build_lunch ${gs_target}
    # 校准target
    gs_target=${_GS_TARGET_PRODUCT}
    gs_build_log_dir=${_GS_BUILD_LOG_DIR}
    echo "update target=${gs_target}"

    # 设置ccache
    _gs_android_build_with_ccache ${gs_ccache} ${gs_target}

    # select module++++
    title="select modules(ninja)"
    modules=$(_gs_android_build_modules)
    _gs_android_build_show_and_choose_combo "${gs_module}" "${title}" "${modules}"
    selection=${_GS_BUILD_COMBO}

    # log file
    build_time=$(date "+%Y-%m-%d-%H-%M-%S")
    build_log=${gs_build_log_dir}/ninja_build_${selection}_${build_time}.log
    echo "selection = "${selection} ", building log =" ${build_log}

    # ninja build
    _gs_android_build_echo_and_run time prebuilts/build-tools/linux-x86/bin/ninja -j ${gs_build_thread} -f out/combined-${TARGET_PRODUCT}.ninja ${selection} | tee ${build_log}
    _gs_android_build_bot ${build_log} ${gs_bot}
}

# make编译模块
function gs_android_build_make() {
    read gs_error gs_target gs_build_thread gs_ccache gs_bot gs_module <<< $(_gs_android_build_parse_opts $*)

    # 错误则打印help
    if [[ ${gs_error} == 1 ]] ; then
        _gs_android_build_help
        return
    fi

    echo "error=${gs_error}, target=${gs_target}, thread=${gs_build_thread}, ccache=${gs_ccache}, bot=${gs_bot}, module=${gs_module}"

    # lunch target
    _gs_android_build_lunch ${gs_target}
    # 校准target
    gs_target=$_GS_TARGET_PRODUCT
    gs_build_log_dir=$_GS_BUILD_LOG_DIR
    echo "update target=${gs_target}"

    # 设置ccache
    _gs_android_build_with_ccache ${gs_ccache} ${gs_target}

    # select module++++
    title="select modules(make)"
    modules=$(_gs_android_build_modules)
    _gs_android_build_show_and_choose_combo "$gs_module" "${title}" "${modules}"
    selection=${_GS_BUILD_COMBO}

    # log file
    build_time=$(date "+%Y-%m-%d-%H-%M-%S")
    build_log=${gs_build_log_dir}/make_build_${selection}_${build_time}.log
    echo "selection = "${selection} ", building log =" ${build_log}

    # make build
    _gs_android_build_echo_and_run make ${selection} -j ${gs_build_thread} | tee ${build_log}
    _gs_android_build_bot ${build_log} ${gs_bot}
}

# 全编译
function gs_android_build() {
    read gs_error gs_target gs_build_thread gs_ccache gs_bot gs_module <<< $(_gs_android_build_parse_opts $*)

    # 错误则打印help
    if [[ ${gs_error} == 1 ]] ; then
        _gs_android_build_help
        return
    fi

    echo "error=${gs_error}, target=${gs_target}, thread=${gs_build_thread}, ccache=${gs_ccache}, bot=${gs_bot}, module=${gs_module}"

    # lunch target
    _gs_android_build_lunch ${gs_target}
    # 校准target
    gs_target=$_GS_TARGET_PRODUCT
    gs_build_log_dir=$_GS_BUILD_LOG_DIR
    echo "update target=${gs_target}"

    # 设置ccache
    _gs_android_build_with_ccache ${gs_ccache} ${gs_target}

    # log file
    build_time=$(date "+%Y-%m-%d-%H-%M-%S")
    build_log=${gs_build_log_dir}/build_full_${build_time}.log

    # full build
    _gs_android_build_echo_and_run m -j ${gs_build_thread} 2>&1 | tee ${build_log}
    _gs_android_build_bot ${build_log} ${gs_bot}
}

# 编译qssi(高通特有)
# 可以带上编译的 target ，否则从默认配置 _GS_BUILD_TARGET_DEFAULT 获取
function gs_android_build_qssi() {
    read gs_error gs_target gs_build_thread gs_ccache gs_bot gs_module <<< $(_gs_android_build_parse_opts $*)

    # 错误则打印help
    if [[ ${gs_error} == 1 ]] ; then
        _gs_android_build_help
        return
    fi

    echo "error=${gs_error}, target=${gs_target}, thread=${gs_build_thread}, ccache=${gs_ccache}, bot=${gs_bot}, module=${gs_module}"

    # lunch target
    _gs_android_build_lunch ${gs_target}
    # 校准target
    gs_target=$_GS_TARGET_PRODUCT
    gs_build_log_dir=$_GS_BUILD_LOG_DIR
    echo "update target=${gs_target}"

    # 设置ccache
    _gs_android_build_with_ccache ${gs_ccache} ${gs_target}

    # log file
    build_time=$(date "+%Y-%m-%d-%H-%M-%S")
    build_log=${gs_build_log_dir}/build_full_${build_time}.log

    # full build
    _gs_android_build_echo_and_run bash build.sh -j ${gs_build_thread} dist --qssi_only 2>&1 | tee ${build_log}
    _gs_android_build_bot ${build_log} ${gs_bot}
}

# 编译 vendor
# 可以带上编译的 target ，否则从默认配置 _GS_BUILD_TARGET_DEFAULT 获取
function gs_android_build_vendor() {
    read gs_error gs_target gs_build_thread gs_ccache gs_bot gs_module <<< $(_gs_android_build_parse_opts $*)

    # 错误则打印help
    if [[ ${gs_error} == 1 ]] ; then
        _gs_android_build_help
        return
    fi

    echo "error=${gs_error}, target=${gs_target}, thread=${gs_build_thread}, ccache=${gs_ccache}, bot=${gs_bot}, module=${gs_module}"

    # lunch target
    _gs_android_build_lunch ${gs_target}
    # 校准target
    gs_target=$_GS_TARGET_PRODUCT
    gs_build_log_dir=$_GS_BUILD_LOG_DIR
    echo "update target=${gs_target}"

    # 设置ccache
    _gs_android_build_with_ccache ${gs_ccache} ${gs_target}

    # log file
    build_time=$(date "+%Y-%m-%d-%H-%M-%S")
    build_log=${gs_build_log_dir}/build_vendor_${build_time}.log

    # build vendor
    _gs_android_build_echo_and_run bash build.sh -j ${gs_build_thread} dist --target_only 2>&1 | tee ${build_log}
    _gs_android_build_bot ${build_log} ${gs_bot}
}

# 非通用，后续可能删除掉
function gs_android_build_car() {
    read gs_error gs_target gs_build_thread gs_ccache gs_bot gs_module <<< $(_gs_android_build_parse_opts $*)

    # 错误则打印help
    if [[ ${gs_error} == 1 ]] ; then
        _gs_android_build_help
        return
    fi

    echo "error=${gs_error}, target=${gs_target}, thread=${gs_build_thread}, ccache=${gs_ccache}, bot=${gs_bot}, module=${gs_module}"

    # 设置环境变量
    export BUILD_MONKEY_VERSION=true

    # lunch target
    _gs_android_build_lunch ${gs_target}
    # 校准target
    gs_target=$_GS_TARGET_PRODUCT
    gs_build_log_dir=$_GS_BUILD_LOG_DIR
    echo "update target=${gs_target}"

    # 设置ccache
    _gs_android_build_with_ccache ${gs_ccache} ${gs_target}

    # log file
    build_time=$(date "+%Y-%m-%d-%H-%M-%S")
    build_log=${gs_build_log_dir}/build_full_${build_time}.log

    # 下载app
    _gs_android_build_echo_and_run python3 dependence -b master_p417_cn

    # full build
    _gs_android_build_echo_and_run make -j ${gs_build_thread} 2>&1 | tee ${build_log}
    _gs_android_build_bot ${build_log} ${gs_bot}
}
