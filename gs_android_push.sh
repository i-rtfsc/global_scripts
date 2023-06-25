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

function _gs_android_push_help() {
    echo "Usage:"
    echo "      -t: 工程root dir名字，如 aosp、miui、flyme。"
    echo "      -d: 需要push的模块的目录，如 模块的目录system/framework。"
    echo "      -m: 需要push的模块名，如 framework.jar。"
    echo "      -p: TARGET_PRODUCT，如 qssi。"
    echo "      -r: 是否重启 android(仅上层)，1重启，0不重启。"
}

function _gs_android_push_opts() {
    # 工程root dir名字
    # (如 aosp)
    local target=aosp
    # 需要push的模块名
    # (如 模块的目录system/framework)
    local module_dir=system/framework
    # (如 framework.jar)
    local module=framework.jar
    # TARGET_PRODUCT
    # (如 sdk_phone_x86_64)
    local product=sdk_phone_x86_64
    # 是否重启 android(仅上层)
    local resume="0"

    # error
    gs_error=0

    while getopts 't:d:m:p:r:h' opt;
    do
        case ${opt} in
            t)
                target="${OPTARG}"
                ;;
            d)
                module_dir="${OPTARG}"
                ;;
            m)
                module="${OPTARG}"
                ;;
            p)
                product="${OPTARG}"
                ;;
            r)
                resume="${OPTARG}"
                ;;
            h)
                gs_error=1
#                通过read读取返回值，所以这里不能打印help
#                _gs_android_push_help
                ;;
            ?)
                gs_error=1
#                通过read读取返回值，所以这里不能打印help
#                _gs_android_push_help
                ;;
        esac
    done

    echo "${gs_error} ${target} ${module_dir} ${module} ${product} ${resume}"
}

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
    read gs_error target module_dir module product resume <<< $(_gs_android_build_with_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == "1" ]] ; then
        _gs_android_push_help
        return
    fi

    ##### 强制改成 qssi 的 framework.jar #####
    module_dir=system/framework
    module=framework.jar
    product=qssi
    ##### 强制改成 qssi 的 framework.jar #####

    _gs_android_push_with_args $target $module_dir $module $product $resume
}

function gs_android_push_services {
    read gs_error target module_dir module product resume <<< $(_gs_android_build_with_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == "1" ]] ; then
        _gs_android_push_help
        return
    fi

    ##### 强制改成 qssi 的 services.jar #####
    module_dir=system/framework
    module=services.jar
    product=qssi
    ##### 强制改成 qssi 的 services.jar #####

    _gs_android_push_with_args $target $module_dir $module $product $resume
}

function gs_android_push_ext_framework {
    read gs_error target module_dir module product resume <<< $(_gs_android_build_with_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == "1" ]] ; then
        _gs_android_push_help
        return
    fi

    ##### 强制改成 qssi 的 xj-framework.jar #####
    module_dir=system/framework
    module=xj-framework.jar
    product=qssi
    ##### 强制改成 qssi 的 xj-framework.jar #####

    _gs_android_push_with_args $target $module_dir $module $product $resume
}

function gs_android_push_ext_services {
    read gs_error target module_dir module product resume <<< $(_gs_android_build_with_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == "1" ]] ; then
        _gs_android_push_help
        return
    fi

    ##### 强制改成 qssi 的 xj-services.jar #####
    module_dir=system/framework
    module=xj-services.jar
    product=qssi
    ##### 强制改成 qssi 的 xj-services.jar #####

    _gs_android_push_with_args $target $module_dir $module $product $resume
}

function gs_android_push_flyme_services {
    read gs_error target module_dir module product resume <<< $(_gs_android_build_with_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == "1" ]] ; then
        _gs_android_push_help
        return
    fi

    ##### 强制改成 qssi 的 com.flyme.runtime.apex #####
    module_dir=system_ext/apex
    module=com.flyme.runtime.apex
    product=qssi
    ##### 强制改成 qssi 的 com.flyme.runtime.apex #####

    _gs_android_push_with_args $target $module_dir $module $product $resume
    if [ "$resume" = "1" ]; then
        adb reboot
    fi
}

function gs_android_push_surfaceflinger {
    read gs_error target module_dir module product resume <<< $(_gs_android_build_with_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == "1" ]] ; then
        _gs_android_push_help
        return
    fi

    ##### 强制改成 qssi 的 surfaceflinger #####
    module_dir=system/bin
    module=surfaceflinger
    product=qssi
    ##### 强制改成 qssi 的 surfaceflinger #####

    _gs_android_push_with_args $target $module_dir $module $product $resume
}

function gs_android_push_framework_jni {
    read gs_error target module_dir module product resume <<< $(_gs_android_build_with_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == "1" ]] ; then
        _gs_android_push_help
        return
    fi

    ##### 强制改成 qssi 的 libandroid_runtime.so #####
    module_dir=system/lib64
    module=libandroid_runtime.so
    product=qssi
    ##### 强制改成 qssi 的 libandroid_runtime.so #####

    _gs_android_push_with_args $target $module_dir $module $product 0

    # 接着push libandroid_servers.so
    module=libandroid_servers.so
    _gs_android_push_with_args $target $module_dir $module $product $resume
}

function gs_android_push_input {
    read gs_error target module_dir module product resume <<< $(_gs_android_build_with_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == "1" ]] ; then
        _gs_android_push_help
        return
    fi

    ##### 强制改成 qssi 的 libinput.so #####
    module_dir=system/lib64
    module=libinput.so
    product=qssi
    ##### 强制改成 qssi 的 libinput.so #####

    _gs_android_push_with_args $target $module_dir $module $product 0

    # 接着push libinputreader.so
    module=libinputreader.so
    _gs_android_push_with_args $target $module_dir $module $product 0

    # 接着push libinputflinger.so
    module=libinputflinger.so
    _gs_android_push_with_args $target $module_dir $module $product 0

    # 接着push libinputservice.so
    module=libinputservice.so
    _gs_android_push_with_args $target $module_dir $module $product 0

    # 接着push libandroid_runtime.so
    module=libandroid_runtime.so
    _gs_android_push_with_args $target $module_dir $module $product 0

    # 接着push libandroid_servers.so
    module=libandroid_servers.so
    _gs_android_push_with_args $target $module_dir $module $product $resume
}

function gs_android_push_mediaserver {
    read gs_error target module_dir module product resume <<< $(_gs_android_build_with_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == "1" ]] ; then
        _gs_android_push_help
        return
    fi

    ##### 强制改成 qssi 的 libmediadrm.so #####
    module_dir=system/lib64
    module=libmediadrm.so
    product=qssi
    ##### 强制改成 qssi 的 libmediadrm.so #####

    _gs_android_push_with_args $target $module_dir $module $product 0

    # 接着push libresourcemanagerservice.so
    module=libresourcemanagerservice.so
    _gs_android_push_with_args $target $module_dir $module $product 0

    # 接着push libmediaplayerservice.so
    module=libmediaplayerservice.so
    _gs_android_push_with_args $target $module_dir $module $product $resume
}

function gs_android_push_so {
    read gs_error target module_dir module product resume <<< $(_gs_android_build_with_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == "1" ]] ; then
        _gs_android_push_help
        return
    fi

    ##### 强制改成 qssi 的 lib64 #####
    module_dir=system/lib64
    product=qssi
    ##### 强制改成 qssi 的 lib64 #####

    _gs_android_push_with_args $target $module_dir $module $product $resume
}

# 任何组合参数
function gs_android_push_with_args {
    read gs_error target module_dir module product resume <<< $(_gs_android_build_with_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == "1" ]] ; then
        _gs_android_push_help
        return
    fi

    _gs_android_push_with_args $target $module_dir $module $product $resume
}