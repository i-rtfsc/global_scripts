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

function _init_env() {
    # 编译线程数根据机器的核心数决定
    # 可根据需求自行更改
    case $(uname -s) in
    Darwin)
        _GS_BUILD_THREAD=$(sysctl -n hw.logicalcpu)
        ;;
    *)
        _GS_BUILD_THREAD=$(nproc)
        ;;
    esac

    # 设置的默认target
    _GS_BUILD_TARGET_DEFAULT="qssi-userdebug"
    #_GS_BUILD_TARGET_DEFAULT="sdk_phone_x86_64"

    # 飞书机器人
    _GS_BOT="93c6a139-2a53-44ec-9711-850dd3a1e6f4"

    # 使用ccache
    _GS_CCACHE=true
}

function _gs_android_build_with_ccache() {
    if $_GS_CCACHE; then
        export USE_CCACHE=1
        export CCACHE_EXEC=/usr/bin/ccache

        # get target product
        local gs_target_product=${TARGET_PRODUCT}
        if [ -z ${gs_target_product} ]; then
            gs_target_product=${_GS_BUILD_TARGET_DEFAULT}
        fi

        local ccache_dir=$HOME/.ccache/$gs_target_product
        # check if the ccache dir exists
        if [ ! -d ${ccache_dir} ]; then
            mkdir -p ${ccache_dir}
        fi
        #set ccache dir
        export CCACHE_DIR=${ccache_dir}
        ccache --set-config=cache_dir=${ccache_dir}
        export CCACHE_CONFIGPATH=${ccache_dir}/ccache.conf
        ccache -M 100G
    fi
}

# remove colors
# https://stackoverflow.com/questions/17998978/removing-colors-from-output
function _strip_escape_codes() {
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

function _gs_notify_bot() {
    if [ -z ${_GS_BOT} ]; then
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

    _strip_escape_codes "${info}" info
#    echo $info
    curl -X POST https://open.feishu.cn/open-apis/bot/v2/hook/${_GS_BOT} -H "Content-Type: application/json" -d '{"msg_type":"text","content":{"text":"'"$info"'"}}'
    echo ""
    echo ""
}

function _gs_print_info() {
    echo "------------------------------"
    # Android平台的版本号
    echo "Android platform version = $PLATFORM_VERSION"
    echo "build product = $TARGET_PRODUCT"
    echo "build variant = $TARGET_BUILD_VARIANT"
    echo "build type = $TARGET_BUILD_TYPE"
    echo "------------------------------"
}

function _gs_android_build_lunch() {
    TOP=$(pwd)
    local gs_build_log_dir=$TOP/out/build_log
    # check if the building log dir exists
    if [ ! -d ${gs_build_log_dir} ]; then
        mkdir -p ${gs_build_log_dir}
    fi
    _GS_BUILD_LOG_DIR=${gs_build_log_dir}

    local gs_target_product=$1
    if [ -z ${gs_target_product} ]; then
        gs_target_product=${TARGET_PRODUCT}
    fi

    if [ -z ${gs_target_product} ]; then
        gs_target_product=${_GS_BUILD_TARGET_DEFAULT}
    fi

    source build/envsetup.sh
    lunch ${gs_target_product}

    _gs_print_info
}

# 全编译
# 可以带上编译的 target ，否则从默认配置 _GS_BUILD_TARGET_DEFAULT 获取
function gs_android_build() {
    _init_env

    # lunch target
    _gs_android_build_lunch $1

    _gs_android_build_with_ccache

    # log file
    local build_time=$(date "+%Y-%m-%d-%H-%M-%S")
    local build_log=${_GS_BUILD_LOG_DIR}/build_full_${build_time}.log

    # full build
    m -j ${_GS_BUILD_THREAD} 2>&1 | tee ${build_log}
    _gs_notify_bot ${build_log}
}

# 全编译后在打ota包
# 可以带上编译的 target ，否则从默认配置 _GS_BUILD_TARGET_DEFAULT 获取
function gs_android_build_ota() {
    _init_env

    # lunch target
    _gs_android_build_lunch $1

    _gs_android_build_with_ccache

    # log file
    local build_time=$(date "+%Y-%m-%d-%H-%M-%S")
    local build_log=${_GS_BUILD_LOG_DIR}/build_full_${build_time}.log
    local build_ota_log=${_GS_BUILD_LOG_DIR}/build_ota_${build_time}.log

    # full build
    m -j ${_GS_BUILD_THREAD} 2>&1 | tee ${build_log}
    # make ota
    make otapackage -j ${_GS_BUILD_THREAD} 2>&1 | tee ${build_ota_log}
    _gs_notify_bot ${build_ota_log}
}

function _gs_android_build_system() {
    _init_env

    # lunch target
    _gs_android_build_lunch $2

    _gs_android_build_with_ccache

    local goals=$1

    # log file
    local build_time=$(date "+%Y-%m-%d-%H-%M-%S")
    local build_log=${_GS_BUILD_LOG_DIR}/build_${goals}_${build_time}.log

    # build
    m -j ${_GS_BUILD_THREAD} ${goals} 2>&1 | tee ${build_log}
    _gs_notify_bot ${build_log}
}

# 编译 system.img
# 可以带上编译的 target ，否则从默认配置 _GS_BUILD_TARGET_DEFAULT 获取
function gs_android_build_system() {
    _gs_android_build_system "snod" $1
}

# 编译 system_ext.img
# 可以带上编译的 target ，否则从默认配置 _GS_BUILD_TARGET_DEFAULT 获取
function gs_android_build_system_ext() {
    _gs_android_build_system "senod" $1
}

# 编译 vendor.img
# 可以带上编译的 target ，否则从默认配置 _GS_BUILD_TARGET_DEFAULT 获取
function gs_android_build_vendor() {
    _gs_android_build_system "vnod" $1
}

# 编译qssi(高通特有)
# 可以带上编译的 target ，否则从默认配置 _GS_BUILD_TARGET_DEFAULT 获取
function gs_android_build_qssi() {
    _init_env

    # lunch target
    _gs_android_build_lunch $1

    _gs_android_build_with_ccache

    # log file
    local build_time=$(date "+%Y-%m-%d-%H-%M-%S")
    local build_log=${_GS_BUILD_LOG_DIR}/build_full_${build_time}.log

    # full build
    bash build.sh -j ${_GS_BUILD_THREAD} dist --qssi_only 2>&1 | tee ${build_log}
    _gs_notify_bot ${build_log}
}

function _gs_modules() {
    local modules=(
        "framework"
        "framework-minus-apex"
        "services"
        "selinux_policy"
        "surfaceflinger"
        "update_engine"
        "android.hardware.power-service"
        "libresourcemanagerservice"
        "libaudioflinger"
        "libcameraservice"
        "com.journeyOS.J007engine.hidl@1.0-service"
        "com.journeyOS.J007engine.hidl@1.0"
        "J007Service"
        "jos-framework"
        "jos-services"
        "watermark"
        "xj-framework"
        "xj-services"
        "com.flyme.runtime"
    )
    #    echo $modules
    for item in ${modules[@]}; do
        echo ${item}
    done
}

function _gs_show_and_choose_combo() {
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

    export _GS_BUILD_COMBO=${selection}
}

function gs_android_build_ninja_clean() {
    _init_env

    time prebuilts/build-tools/linux-x86/bin/ninja -j ${_GS_BUILD_THREAD} -f out/combined-${TARGET_PRODUCT}.ninja -t clean
}

# ninja编译模块
# 可以带上模块名字，否则会有选择菜单
# 若需要编译的模块不在菜单里，也可以在选择菜单里输入模块名
function gs_android_build_ninja() {
    _init_env

    # lunch target
    _gs_android_build_lunch

    local title="select modules(ninja)"
    local modules=$(_gs_modules)

    # select module++++
    _gs_show_and_choose_combo "$1" "${title}" "${modules}"
    selection=${_GS_BUILD_COMBO}

    # log file
    local build_time=$(date "+%Y-%m-%d-%H-%M-%S")
    build_log=${_GS_BUILD_LOG_DIR}/ninja_build_${selection}_${build_time}.log
    echo "selection = "${selection} ", building log =" ${build_log}

    # ninja build
    time prebuilts/build-tools/linux-x86/bin/ninja -j ${_GS_BUILD_THREAD} -f out/combined-${TARGET_PRODUCT}.ninja ${selection} | tee ${build_log}
    _gs_notify_bot ${build_log}
}

# make编译模块
# 可以带上模块名字，否则会有选择菜单
# 若需要编译的模块不在菜单里，也可以在选择菜单里输入模块名
function gs_android_build_make() {
    _init_env

    # lunch target
    _gs_android_build_lunch

    local title="select modules(make)"
    local modules=$(_gs_modules)

    # select module
    _gs_show_and_choose_combo "$1" "${title}" "${modules}"
    selection=${_GS_BUILD_COMBO}

    # log file
    local build_time=$(date "+%Y-%m-%d-%H-%M-%S")
    build_log=${_GS_BUILD_LOG_DIR}/make_build_${selection}_${build_time}.log
    echo "selection = "${selection} ", building log =" ${build_log}

    # make build
    make ${selection} -j ${_GS_BUILD_THREAD} | tee ${build_log}
    _gs_notify_bot ${build_log}
}
