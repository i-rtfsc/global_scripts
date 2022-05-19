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

function _gs_android_build_with_ccache() {
    export USE_CCACHE=1
    export CCACHE_EXEC=/usr/bin/ccache
    #set ccache dir
    export CCACHE_DIR=$HOME/ext-data/.ccache
    ccache -M 50G
}

function _gs_android_build_lunch() {
    TOP=`pwd`
    local building_log_dir=$TOP/out/build_log
    # check if the building log dir exists
    if [ ! -d ${building_log_dir} ]; then
        mkdir -p ${building_log_dir}
    fi
    export _GS_BUILD_LOG_DIR=${building_log_dir}

    local LOCAL_TARGET_PRODUCT=${TARGET_PRODUCT}
    if [ -z ${LOCAL_TARGET_PRODUCT} ]; then
        LOCAL_TARGET_PRODUCT=$1
    fi

    if [ -z ${LOCAL_TARGET_PRODUCT} ]; then
        LOCAL_TARGET_PRODUCT="lineage_lemonadep-userdebug"
    fi

    source build/envsetup.sh
    lunch ${LOCAL_TARGET_PRODUCT}
}

function gs_android_build() {
    #_gs_android_build_with_ccache

    # lunch target
    _gs_android_build_lunch

    # log file
    local building_time=$(date "+%Y-%m-%d-%H-%M-%S")
    local building_log=${_GS_BUILD_LOG_DIR}/build_full_${building_time}.log

    # full build
    m -j $(nproc) 2>&1 | tee ${building_log}
}

function gs_android_build_ota() {
    #_gs_android_build_with_ccache

    # lunch target
    _gs_android_build_lunch

    # log file
    local building_time=$(date "+%Y-%m-%d-%H-%M-%S")
    local building_log=${_GS_BUILD_LOG_DIR}/build_full_${building_time}.log
    local building_ota_log=${_GS_BUILD_LOG_DIR}/build_ota_${building_time}.log

    # full build
    m -j $(nproc) 2>&1 | tee ${building_log}
    # make ota
    make otapackage -j $(nproc) 2>&1 | tee ${building_ota_log}
}

function _gs_android_build_system() {
    #_gs_android_build_with_ccache

    # lunch target
    _gs_android_build_lunch

    local goals=$1

    # log file
    local building_time=$(date "+%Y-%m-%d-%H-%M-%S")
    local building_log=${_GS_BUILD_LOG_DIR}/build_${goals}_${building_time}.log

    # build
    m -j $(nproc) ${goals} 2>&1 | tee ${building_log}
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
    local building_log_dir=$TOP/out/build_log
    # check if the building log dir exists
    if [ ! -d ${building_log_dir} ]; then
        mkdir -p ${building_log_dir}
    fi

    # log file
    local building_time=$(date "+%Y-%m-%d-%H-%M-%S")
    local building_log=${building_log_dir}/build_lineage_${building_time}.log

    # lineage build
    brunch ${LOCAL_TARGET_PRODUCT} 2>&1 | tee ${building_log}
}

function _gs_modules() {
    local modules=(
                  "framework"
                  "services"
                  "surfaceflinger"
                  "update_engine"
                  "android.hardware.power-service"
                  "J007Service"
                  "jos-framework"
                  "com.journeyOS.J007engine.hidl@1.0-service"
                  "watermark"
                  "AiService"
                  "bx-framework"
                  "UMS"
                  "UMSTest"
                  "SystemUI"
                  "Settings"
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
    time prebuilts/build-tools/linux-x86/bin/ninja -j $(nproc) -f out/combined-${TARGET_PRODUCT}.ninja -t clean
}

function gs_android_build_ninja() {
    local title="select modules(ninja)"
    local modules=$(_gs_modules)

    # lunch target
    _gs_android_build_lunch

    # select module
    _gs_show_and_choose_combo "$1" "${title}" "${modules}"
    selection=${_GS_BUILD_COMBO}

    # log file
    local building_time=$(date "+%Y-%m-%d-%H-%M-%S")
    building_log=${_GS_BUILD_LOG_DIR}/ninja_build_${selection}_${building_time}.log
    echo "selection = "${selection} ", building log =" ${building_log}

    # ninja build
    time prebuilts/build-tools/linux-x86/bin/ninja -j $(nproc) -f out/combined-${TARGET_PRODUCT}.ninja ${selection} | tee ${building_log}
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
    local building_time=$(date "+%Y-%m-%d-%H-%M-%S")
    building_log=${_GS_BUILD_LOG_DIR}/make_build_${selection}_${building_time}.log
    echo "selection = "${selection} ", building log =" ${building_log}

    # make build
    make ${selection} -j $(nproc) | tee ${building_log}
}
