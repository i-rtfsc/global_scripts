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

# 编译线程数根据机器的核心数决定
# 可根据需求自行更改
case `uname -s` in
    Darwin)
        _GS_BUILD_THREAD=$(sysctl -n hw.logicalcpu)
        ;;
    *)
        _GS_BUILD_THREAD=$(nproc)
        ;;
esac

# target product
# 这么设置就要求在终端先lunch一次
# 如果没有lunch就是用默认target
_GS_BUILD_TARGET=${TARGET_PRODUCT}

# 设置的默认target（lineage_lemonadep-userdebug）
#_GS_BUILD_TARGET_DEFAULT="lineage_lemonadep-userdebug"
_GS_BUILD_TARGET_DEFAULT="sdk_phone_x86_64"

# 机器人地址
_GS_BOT="93c6a139-2a53-44ec-9711-850dd3a1e6f4"

# 使用ccache
_GS_CCACHE=false

function _gs_android_build_with_ccache() {
    if $_GS_CCACHE ; then
        export USE_CCACHE=1
        export CCACHE_EXEC=/usr/bin/ccache
        #set ccache dir
        # check if the ccache dir exists
        local ccache_dir=$HOME/$_GS_BUILD_TARGET_DEFAULT/.ccache
        if [ ! -d ${ccache_dir} ]; then
            mkdir -p ${ccache_dir}
        fi
        export CCACHE_DIR=${ccache_dir}
        ccache -M 50G
    fi
}

function _gs_notify_bot() {
    if [ -z ${_GS_BOT} ]; then
        return 0
    fi
    curl -X POST -H "Content-Type: application/json" -d '{"msg_type":"text","content":{"text":"build finish"}}' https://open.feishu.cn/open-apis/bot/v2/hook/${_GS_BOT}
}

function _gs_print_info() {
    echo "------------------------------"
    # Android平台的版本号
    echo "Android platform version = $PLATFORM_VERSION"
    echo "build product = $TARGET_PRODUCT"
    echo "build variant = $TARGET_BUILD_VARIANT"
    echo "build type = $TARGET_BUILD_TYPE"
    # 表示编译目标的CPU架构
    echo "build arch = $TARGET_ARCH"
    # 表示编译目标的CPU架构版本
    echo "build arch variant = $TARGET_ARCH_VARIANT"
    # 表示编译目标的CPU代号
    echo "build cpu variant = $TARGET_CPU_VARIANT"
    echo "BUILD_ID = $BUILD_ID"
    echo "OUT_DIR = $OUT_DIR"
    echo "------------------------------"
}

function _gs_android_build_lunch() {
    TOP=`pwd`
    local gs_build_log_dir=$TOP/out/build_log
    # check if the building log dir exists
    if [ ! -d ${gs_build_log_dir} ]; then
        mkdir -p ${gs_build_log_dir}
    fi
    export _GS_BUILD_LOG_DIR=${gs_build_log_dir}

    local gs_target_product=$1
    if [ -z ${gs_target_product} ]; then
        gs_target_product=${_GS_BUILD_TARGET}
    fi

    if [ -z ${target_product} ]; then
        gs_target_product=${_GS_BUILD_TARGET_DEFAULT}
    fi

    source build/envsetup.sh
    lunch ${gs_target_product}

    _gs_print_info
}

function gs_android_build() {
    _gs_android_build_with_ccache

    # lunch target
    _gs_android_build_lunch $1

    # log file
    local build_time=$(date "+%Y-%m-%d-%H-%M-%S")
    local build_log=${_GS_BUILD_LOG_DIR}/build_full_${build_time}.log

    # full build
    m -j ${_GS_BUILD_THREAD} 2>&1 | tee ${build_log}
    _gs_notify_bot
}

function gs_android_build_ota() {
    _gs_android_build_with_ccache

    # lunch target
    _gs_android_build_lunch $1

    # log file
    local build_time=$(date "+%Y-%m-%d-%H-%M-%S")
    local build_log=${_GS_BUILD_LOG_DIR}/build_full_${build_time}.log
    local build_ota_log=${_GS_BUILD_LOG_DIR}/build_ota_${build_time}.log

    # full build
    m -j ${_GS_BUILD_THREAD} 2>&1 | tee ${build_log}
    # make ota
    make otapackage -j ${_GS_BUILD_THREAD} 2>&1 | tee ${build_ota_log}
    _gs_notify_bot
}

function _gs_android_build_system() {
    #_gs_android_build_with_ccache

    # lunch target
    _gs_android_build_lunch

    local goals=$1

    # log file
    local build_time=$(date "+%Y-%m-%d-%H-%M-%S")
    local build_log=${_GS_BUILD_LOG_DIR}/build_${goals}_${build_time}.log

    # build
    m -j ${_GS_BUILD_THREAD} ${goals} 2>&1 | tee ${build_log}
    _gs_notify_bot
}

function gs_android_build_system() {
    _gs_android_build_system "snod"
}

function gs_android_build_system_ext() {
    _gs_android_build_system "senod"
}

function gs_android_build_vendor() {
    _gs_android_build_system "vnod"
}

function gs_lineage_build() {
    #_gs_android_build_with_ccache

    local LOCAL_TARGET_PRODUCT=
    if [ -z ${LOCAL_TARGET_PRODUCT} ]; then
        LOCAL_TARGET_PRODUCT=$1
    fi

    if [ -z ${LOCAL_TARGET_PRODUCT} ]; then
        LOCAL_TARGET_PRODUCT="lemonadep"
    fi

    source build/envsetup.sh
    breakfast ${LOCAL_TARGET_PRODUCT}

    TOP=`pwd`
    local build_log_dir=$TOP/out/build_log
    # check if the building log dir exists
    if [ ! -d ${build_log_dir} ]; then
        mkdir -p ${build_log_dir}
    fi

    # log file
    local build_time=$(date "+%Y-%m-%d-%H-%M-%S")
    local build_log=${build_log_dir}/build_lineage_${build_time}.log

    # lineage build
    brunch ${LOCAL_TARGET_PRODUCT} 2>&1 | tee ${build_log}
    _gs_notify_bot
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
                  "com.journeyOS.J007engine.hidl@1.0-service"
                  "com.journeyOS.J007engine.hidl@1.0"
                  "J007Service"
                  "jos-framework"
                  "jos-services"
                  "watermark"
                  "xj-framework"
                  "xj-services"
                  )
#    echo $modules
    for item in ${modules[@]}; do
        echo ${item}
    done
}

function _gs_show_and_choose_combo() {
    unset _GS_BUILD_COMBO

    local user_input=$1
    local title=$2
    local choices=(`echo $3 | tr ',' ' '` )

    local index=1
    local default_index=1

    if [ -z ${_GS_LAST_BUILD_COMBO} ]; then
        _GS_LAST_BUILD_COMBO=${choices[default_index]}
    fi

    local answer=${_GS_LAST_BUILD_COMBO}
    local selection=${_GS_LAST_BUILD_COMBO}

    if [ "${user_input}" ] ; then
        answer=${user_input}
    else
        # print combo menu,
        for item in ${choices[@]}; do
            echo $index.  ${item}
            index=$(($index+1))
        done
        printf "Which would you like? [ %s ] " ${answer}
        read answer

        if [ -z "$answer" ]; then
            answer=${selection}
        fi
    fi

    if [ -z "$answer" ] ; then
        echo "error: get null answer."
    elif (echo -n $answer | grep -q -e "^[0-9][0-9]*$") ; then
        selection=${choices[answer]}
    else
        selection=${answer}
    fi
    export _GS_BUILD_COMBO=${selection}
    export _GS_LAST_BUILD_COMBO=${_GS_BUILD_COMBO}
}

function gs_android_build_ninja_clean() {
    time prebuilts/build-tools/linux-x86/bin/ninja -j ${_GS_BUILD_THREAD} -f out/combined-${TARGET_PRODUCT}.ninja -t clean
}

function gs_android_build_ninja() {
    local title="select modules(ninja)"
    local modules=$(_gs_modules)

    # lunch target
    _gs_android_build_lunch

    # select module++++
    _gs_show_and_choose_combo "$1" "${title}" "${modules}"
    selection=${_GS_BUILD_COMBO}

    # log file
    local build_time=$(date "+%Y-%m-%d-%H-%M-%S")
    build_log=${_GS_BUILD_LOG_DIR}/ninja_build_${selection}_${build_time}.log
    echo "selection = "${selection} ", building log =" ${build_log}

    # ninja build
    time prebuilts/build-tools/linux-x86/bin/ninja -j ${_GS_BUILD_THREAD} -f out/combined-${TARGET_PRODUCT}.ninja ${selection} | tee ${build_log}
}

function gs_android_build_make() {
    local title="select modules(make)"
    local modules=$(_gs_modules)

    # lunch target
    _gs_android_build_lunch

    # select module
    _gs_show_and_choose_combo "$1" "${title}" "${modules}"
    selection=${_GS_BUILD_COMBO}

    # log file
    local build_time=$(date "+%Y-%m-%d-%H-%M-%S")
    build_log=${_GS_BUILD_LOG_DIR}/make_build_${selection}_${build_time}.log
    echo "selection = "${selection} ", building log =" ${build_log}

    # make build
    make ${selection} -j ${_GS_BUILD_THREAD} | tee ${build_log}
}
