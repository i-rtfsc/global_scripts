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


function _gs_android_push_with_args() {
    adb root ; adb remount
    # 工程root dir名字
    # (如 flyme10)
    local target=$1
    # 需要push的模块名
    # (如 模块的目录system/framework)
    local module_dir=$2
    # (如 framework.jar)
    local module=$3
    # TARGET_PRODUCT
    # (如 qssi)
    local product=$4
    # 是否重启 android(仅上层)
    local resume=$5

    vm_dir=$HOME/code/work/vm
    vm_out_dir=$HOME/share/$target

    if [ ! -d $vm_dir ]; then
        adb push $vm_out_dir/out/target/product/$product/$module_dir/$module /$module_dir/$module
    else
        echo $vm_out_dir/out/target/product/$product/$module_dir/$module $vm_dir/$module
        cp $vm_out_dir/out/target/product/$product/$module_dir/$module $vm_dir/$module
        adb push $vm_dir/$module /$module_dir/$module
        rm $vm_dir/$module
    fi

    if [ "$resume" = "1" ]; then
        adb shell "stop && start"
    fi
}

function gs_android_push_framework {
    local target=$1
    if [ -z ${target} ]; then
        target=flyme10
    fi

    local resume=$2
    if [ -z ${resume} ]; then
        resume=1
    fi

    _gs_android_push_with_args $target system/framework framework.jar qssi $resume
}

function gs_android_push_services {
    local target=$1
    if [ -z ${target} ]; then
        target=flyme10
    fi

    local resume=$2
    if [ -z ${resume} ]; then
        resume=1
    fi

    _gs_android_push_with_args $target system/framework services.jar qssi $resume
}

function gs_android_push_fwk {
    local target=$1
    if [ -z ${target} ]; then
        target=flyme10
    fi

    local resume=$2
    if [ -z ${resume} ]; then
        resume=1
    fi

    _gs_android_push_with_args $target system/framework framework.jar qssi 0
    _gs_android_push_with_args $target system/framework services.jar qssi $resume
}

function gs_android_push_ext_framework {
    local target=$1
    if [ -z ${target} ]; then
        target=flyme10
    fi

    local resume=$2
    if [ -z ${resume} ]; then
        resume=1
    fi

    _gs_android_push_with_args $target system/framework xj-framework.jar qssi $resume
}

function gs_android_push_ext_services {
    local target=$1
    if [ -z ${target} ]; then
        target=flyme10
    fi

    local resume=$2
    if [ -z ${resume} ]; then
        resume=1
    fi

    _gs_android_push_with_args $target system/framework xj-services.jar qssi $resume
}

function gs_android_push_ext_fwk {
    local target=$1
    if [ -z ${target} ]; then
        target=flyme10
    fi

    local resume=$2
    if [ -z ${resume} ]; then
        resume=1
    fi

    _gs_android_push_with_args $target system/framework xj-framework.jar qssi 0
    _gs_android_push_with_args $target system/framework xj-services.jar qssi $resume
}

function gs_android_push_flyme_services {
    local target=$1
    if [ -z ${target} ]; then
        target=flyme10
    fi

    local resume=$2
    if [ -z ${resume} ]; then
        resume=1
    fi

    _gs_android_push_with_args $target system_ext/apex com.flyme.runtime.apex qssi 0
    adb reboot
#    _gs_android_push_with_args $target system_ext/apex/com.flyme.runtime/javalib framework-flyme.jar qssi 0
#    _gs_android_push_with_args $target system_ext/apex/com.flyme.runtime/javalib service-flyme.jar qssi 0
#    adb reboot
}

function gs_android_push_surfaceflinger {
    local target=$1
    if [ -z ${target} ]; then
        target=flyme10
    fi

    local resume=$2
    if [ -z ${resume} ]; then
        resume=1
    fi

    _gs_android_push_with_args $target system/bin surfaceflinger qssi $resume
}

function gs_android_push_framework_jni {
    local target=$1
    if [ -z ${target} ]; then
        target=flyme10
    fi

    local abi=$2
    if [ -z ${abi} ]; then
        abi=lib64
    fi

    local resume=$3
    if [ -z ${resume} ]; then
        resume=1
    fi

    _gs_android_push_with_args $target system/$abi libandroid_runtime.so qssi 0
    _gs_android_push_with_args $target system/$abi libandroid_servers.so qssi $resume
}

function gs_android_push_input {
    local target=$1
    if [ -z ${target} ]; then
        target=flyme10
    fi

    local abi=$2
    if [ -z ${abi} ]; then
        abi=lib64
    fi

    local resume=$3
    if [ -z ${resume} ]; then
        resume=1
    fi

    _gs_android_push_with_args $target system/$abi libinputreader.so qssi 0
    _gs_android_push_with_args $target system/$abi libinputflinger.so qssi 0
    _gs_android_push_with_args $target system/$abi libinputservice.so qssi 0
    _gs_android_push_with_args $target system/$abi libandroid_runtime.so qssi 0
    _gs_android_push_with_args $target system/$abi libandroid_servers.so qssi $resume
}

function gs_android_push_mediaserver {
    local target=$1
    if [ -z ${target} ]; then
        target=flyme10
    fi

    local abi=$2
    if [ -z ${abi} ]; then
        abi=lib64
    fi

    local resume=$3
    if [ -z ${resume} ]; then
        resume=1
    fi

    _gs_android_push_with_args $target system/$abi libmediadrm.so qssi 0
    _gs_android_push_with_args $target system/$abi libresourcemanagerservice.so qssi 0
    _gs_android_push_with_args $target system/$abi libmediaplayerservice.so qssi $resume
}

function gs_android_push_so {
    local so=$1
    if [ -z ${so} ]; then
        echo "error... need input so name"
        return 0
    fi

    local target=$2
    if [ -z ${target} ]; then
        target=flyme10
    fi

    local abi=$3
    if [ -z ${abi} ]; then
        abi=lib64
    fi

    local resume=$4
    if [ -z ${resume} ]; then
        resume=1
    fi

    _gs_android_push_with_args $target system/$abi $so qssi $resume
}
