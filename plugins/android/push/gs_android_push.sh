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

function _gs_android_push_parse_opts() {
    # 工程root dir名字
    # (如 aosp)
    local target=flyme10
    # 需要push的模块名
    # (如 模块的目录system/framework)
    local module_dir=system/framework
    # (如 framework.jar)
    local module=framework.jar
    # TARGET_PRODUCT
    # (如 sdk_phone_x86_64)
    local product=qssi
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

function _gs_android_push_impl() {
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

    echo $vm_out_dir/out/target/product/$product/$module_dir/$module /$module_dir/$module

    if [ ! -d $vm_dir ]; then
        adb push $vm_out_dir/out/target/product/$product/$module_dir/$module /$module_dir/$module
    else
        cp $vm_out_dir/out/target/product/$product/$module_dir/$module $vm_dir/$module
        adb push $vm_dir/$module /$module_dir/$module
        rm $vm_dir/$module
    fi

    if [ "$resume" = "1" ]; then
        adb shell "stop && start"
    fi
}

function _gs_android_push_delete_oat {
    oat=$1
    if [[ `adb shell ls $oat 2 > /dev/null` ]]; then
        adb shell rm -rf $oat
        echo 1
    else
        echo 0
    fi
}

function _gs_android_push_delete_fwk_ota {
    oat=system/framework/oat
    reboot=$(_gs_android_push_delete_oat $oat)
    if [ "$reboot" = "1" ]; then
        echo "[$oat] exists, delete it."
    fi

    arm=system/framework/arm
    if [ "$(_gs_android_push_delete_oat $arm)" = "1" ]; then
        reboot=1
        echo "[$arm] exists, delete it."
    fi

    arm64=system/framework/arm64
    if [ "$(_gs_android_push_delete_oat $arm64)" = "1" ]; then
        reboot=1
        echo "[$arm64] exists, delete it."
    fi

    if [ "$reboot" = "1" ]; then
        adb reboot
    fi
}

function gs_android_push_framework {
    read gs_error target module_dir module product resume <<< $(_gs_android_push_parse_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == 1 ]] ; then
        _gs_android_push_help
        return
    fi

    echo "target=${target}, module_dir=${module_dir}, module=${module}, product=${product}, resume=${resume}"

    ##### 强制改成 qssi 的 framework.jar #####
    module_dir=system/framework
    module=framework.jar
    ##### 强制改成 qssi 的 framework.jar #####
    echo "update module_dir=${module_dir}, module=${module}"

    _gs_android_push_impl $target $module_dir $module $product $resume

    _gs_android_push_delete_fwk_ota
}

function gs_android_push_services {
    read gs_error target module_dir module product resume <<< $(_gs_android_push_parse_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == 1 ]] ; then
        _gs_android_push_help
        return
    fi

    echo "target=${target}, module_dir=${module_dir}, module=${module}, product=${product}, resume=${resume}"

    ##### 强制改成 qssi 的 services.jar #####
    module_dir=system/framework
    module=services.jar
    ##### 强制改成 qssi 的 services.jar #####
    echo "update module_dir=${module_dir}, module=${module}"

    _gs_android_push_impl $target $module_dir $module $product $resume

    _gs_android_push_delete_fwk_ota
}

function gs_android_push_ext_framework {
    read gs_error target module_dir module product resume <<< $(_gs_android_push_parse_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == 1 ]] ; then
        _gs_android_push_help
        return
    fi

    echo "target=${target}, module_dir=${module_dir}, module=${module}, product=${product}, resume=${resume}"

    ##### 强制改成 qssi 的 xj-framework.jar #####
    module_dir=system/framework
    module=xj-framework.jar
    ##### 强制改成 qssi 的 xj-framework.jar #####
    echo "update module_dir=${module_dir}, module=${module}"

    _gs_android_push_impl $target $module_dir $module $product $resume

    _gs_android_push_delete_fwk_ota
}

function gs_android_push_ext_services {
    read gs_error target module_dir module product resume <<< $(_gs_android_push_parse_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == 1 ]] ; then
        _gs_android_push_help
        return
    fi

    echo "target=${target}, module_dir=${module_dir}, module=${module}, product=${product}, resume=${resume}"

    ##### 强制改成 qssi 的 xj-services.jar #####
    module_dir=system/framework
    module=xj-services.jar
    ##### 强制改成 qssi 的 xj-services.jar #####
    echo "update module_dir=${module_dir}, module=${module}"

    _gs_android_push_impl $target $module_dir $module $product $resume

    _gs_android_push_delete_fwk_ota
}

function gs_android_push_flyme_services {
    read gs_error target module_dir module product resume <<< $(_gs_android_push_parse_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == 1 ]] ; then
        _gs_android_push_help
        return
    fi
    echo "target=${target}, module_dir=${module_dir}, module=${module}, product=${product}, resume=${resume}"

    ##### 强制改成 qssi 的 com.flyme.runtime.apex #####
    module_dir=system_ext/apex
    module=com.flyme.runtime.apex
    ##### 强制改成 qssi 的 com.flyme.runtime.apex #####
    echo "update module_dir=${module_dir}, module=${module}"

    _gs_android_push_impl $target $module_dir $module $product $resume

    _gs_android_push_delete_fwk_ota

    if [ "$resume" = "1" ]; then
        adb reboot
    fi
}

function gs_android_push_surfaceflinger {
    read gs_error target module_dir module product resume <<< $(_gs_android_push_parse_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == 1 ]] ; then
        _gs_android_push_help
        return
    fi

    echo "target=${target}, module_dir=${module_dir}, module=${module}, product=${product}, resume=${resume}"

    ##### 强制改成 qssi 的 surfaceflinger #####
    module_dir=system/bin
    module=surfaceflinger
    ##### 强制改成 qssi 的 surfaceflinger #####
    echo "update module_dir=${module_dir}, module=${module}"

    _gs_android_push_impl $target $module_dir $module $product $resume
}

function gs_android_push_framework_jni {
    read gs_error target module_dir module product resume <<< $(_gs_android_push_parse_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == 1 ]] ; then
        _gs_android_push_help
        return
    fi

    echo "target=${target}, module_dir=${module_dir}, module=${module}, product=${product}, resume=${resume}"

    ##### 强制改成 qssi 的 libandroid_runtime.so #####
    module_dir=system/lib64
    module=libandroid_runtime.so
    ##### 强制改成 qssi 的 libandroid_runtime.so #####
    echo "update module_dir=${module_dir}, module=${module}"

    _gs_android_push_impl $target $module_dir $module $product 0

    # 接着push libandroid_servers.so
    module=libandroid_servers.so
    _gs_android_push_impl $target $module_dir $module $product $resume
}

function gs_android_push_input {
    read gs_error target module_dir module product resume <<< $(_gs_android_push_parse_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == 1 ]] ; then
        _gs_android_push_help
        return
    fi

    echo "target=${target}, module_dir=${module_dir}, module=${module}, product=${product}, resume=${resume}"

    ##### 强制改成 qssi 的 libinput.so #####
    module_dir=system/lib64
    module=libinput.so
    ##### 强制改成 qssi 的 libinput.so #####
    echo "update module_dir=${module_dir}"

    _gs_android_push_impl $target $module_dir $module $product 0

    # 接着push libinputreader.so
    module=libinputreader.so
    _gs_android_push_impl $target $module_dir $module $product 0

    # 接着push libinputflinger.so
    module=libinputflinger.so
    _gs_android_push_impl $target $module_dir $module $product 0

    # 接着push libinputservice.so
    module=libinputservice.so
    _gs_android_push_impl $target $module_dir $module $product 0

    # 接着push libandroid_runtime.so
    module=libandroid_runtime.so
    _gs_android_push_impl $target $module_dir $module $product 0

    # 接着push libandroid_servers.so
    module=libandroid_servers.so
    _gs_android_push_impl $target $module_dir $module $product $resume
}

function gs_android_push_mediaserver {
    read gs_error target module_dir module product resume <<< $(_gs_android_push_parse_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == 1 ]] ; then
        _gs_android_push_help
        return
    fi

    echo "target=${target}, module_dir=${module_dir}, module=${module}, product=${product}, resume=${resume}"

    ##### 强制改成 qssi 的 libmediadrm.so #####
    module_dir=system/lib64
    module=libmediadrm.so
    ##### 强制改成 qssi 的 libmediadrm.so #####
    echo "update module_dir=${module_dir}"

    _gs_android_push_impl $target $module_dir $module $product 0

    # 接着push libresourcemanagerservice.so
    module=libresourcemanagerservice.so
    _gs_android_push_impl $target $module_dir $module $product 0

    # 接着push libmediaplayerservice.so
    module=libmediaplayerservice.so
    _gs_android_push_impl $target $module_dir $module $product $resume
}

function gs_android_push_systemui {
    read gs_error target module_dir module product resume <<< $(_gs_android_push_parse_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == 1 ]] ; then
        _gs_android_push_help
        return
    fi

    echo "target=${target}, module_dir=${module_dir}, module=${module}, product=${product}, resume=${resume}"

    ##### 强制改成 SystemUI.apk #####
    module_dir=system_ext/priv-app/SystemUI
    module=SystemUI.apk
    ##### 强制改成 SystemUI.apk #####
    echo "update module_dir=${module_dir}, module=${module}"

    _gs_android_push_impl $target $module_dir $module $product $resume

    oat=system_ext/priv-app/SystemUI/oat
    reboot=$(_gs_android_push_delete_oat $oat)
    if [ "$reboot" = "1" ]; then
        echo "[$oat] exists, delete it."
        adb reboot
    fi
}

function gs_android_push_settings {
    read gs_error target module_dir module product resume <<< $(_gs_android_push_parse_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == 1 ]] ; then
        _gs_android_push_help
        return
    fi

    echo "target=${target}, module_dir=${module_dir}, module=${module}, product=${product}, resume=${resume}"

    ##### 强制改成 Settings.apk #####
    module_dir=system_ext/priv-app/Settings
    module=Settings.apk
    ##### 强制改成 Settings.apk #####
    echo "update module_dir=${module_dir}, module=${module}"

    _gs_android_push_impl $target $module_dir $module $product $resume

    oat=system_ext/priv-app/Settings/oat
    reboot=$(_gs_android_push_delete_oat $oat)
    if [ "$reboot" = "1" ]; then
        echo "[$oat] exists, delete it."
        adb reboot
    fi
}

function gs_android_push_so {
    read gs_error target module_dir module product resume <<< $(_gs_android_push_parse_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == 1 ]] ; then
        _gs_android_push_help
        return
    fi

    echo "target=${target}, module_dir=${module_dir}, module=${module}, product=${product}, resume=${resume}"

    ##### 强制改成 qssi 的 lib64 #####
    module_dir=system/lib64
    ##### 强制改成 qssi 的 lib64 #####
    echo "update module_dir=${module_dir}"

    _gs_android_push_impl $target $module_dir $module $product $resume
}

function gs_android_push_car_android-car {
    read gs_error target module_dir module product resume <<< $(_gs_android_push_parse_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == 1 ]] ; then
        _gs_android_push_help
        return
    fi

    echo "target=${target}, module_dir=${module_dir}, module=${module}, product=${product}, resume=${resume}"

    ##### 强制改成 car 的 android.car.jar #####
    module_dir=system/framework
    module=android.car.jar
    ##### 强制改成 car 的 android.car.jar #####
    echo "update module_dir=${module_dir}, module=${module}"

    _gs_android_push_impl $target $module_dir $module $product $resume
}

function gs_android_push_car_car-frameworks-service {
    read gs_error target module_dir module product resume <<< $(_gs_android_push_parse_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == 1 ]] ; then
        _gs_android_push_help
        return
    fi

    echo "target=${target}, module_dir=${module_dir}, module=${module}, product=${product}, resume=${resume}"

    ##### 强制改成 car 的 car-frameworks-service.jar #####
    module_dir=system/framework
    module=car-frameworks-service.jar
    ##### 强制改成 car 的 car-frameworks-service.jar #####
    echo "update module_dir=${module_dir}, module=${module}"

    _gs_android_push_impl $target $module_dir $module $product $resume
}

function gs_android_push_car_CarService {
    read gs_error target module_dir module product resume <<< $(_gs_android_push_parse_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == 1 ]] ; then
        _gs_android_push_help
        return
    fi

    echo "target=${target}, module_dir=${module_dir}, module=${module}, product=${product}, resume=${resume}"

    ##### 强制改成 car 的 CarService.apk #####
    module_dir=system/priv-app/CarService
    module=CarService.apk
    ##### 强制改成 car 的 CarService.apk #####
    echo "update module_dir=${module_dir}, module=${module}"

    _gs_android_push_impl $target $module_dir $module $product $resume
}

function gs_android_push_car_vehicle-service {
    read gs_error target module_dir module product resume <<< $(_gs_android_push_parse_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == 1 ]] ; then
        _gs_android_push_help
        return
    fi

    echo "target=${target}, module_dir=${module_dir}, module=${module}, product=${product}, resume=${resume}"

    ##### 强制改成 car 的 android.hardware.automotive.vehicle@2.0-service #####
    module_dir=vendor/bin/hw
    module=android.hardware.automotive.vehicle@2.0-service
    ##### 强制改成 car 的 android.hardware.automotive.vehicle@2.0-service #####
    echo "update module_dir=${module_dir}, module=${module}"

    _gs_android_push_impl $target $module_dir $module $product $resume
}

function gs_android_push_car_vehicle-service-ecarx {
    read gs_error target module_dir module product resume <<< $(_gs_android_push_parse_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == 1 ]] ; then
        _gs_android_push_help
        return
    fi

    echo "target=${target}, module_dir=${module_dir}, module=${module}, product=${product}, resume=${resume}"

    ##### 强制改成 car 的 vendor.ecarx.xma.automotive.vehicle@2.0-service #####
    module_dir=vendor/bin/hw
    module=vendor.ecarx.xma.automotive.vehicle@2.0-service
    echo "update module_dir=${module_dir}, module=${module}"
    _gs_android_push_impl $target $module_dir $module $product 0
    ##### 强制改成 car 的 vendor.ecarx.xma.automotive.vehicle@2.0-service #####

    ##### 强制改成 car 的 libvhal-scheduler.so #####
    module_dir=vendor/lib64
    module=libvhal-scheduler.so
    echo "update module_dir=${module_dir}, module=${module}"
    _gs_android_push_impl $target $module_dir $module $product 0
    ##### 强制改成 car 的 libvhal-scheduler.so #####

    ##### 强制改成 car 的 libvhal-property-impl.so #####
    module_dir=vendor/lib64
    module=libvhal-property-impl.so
    echo "update module_dir=${module_dir}, module=${module}"
    _gs_android_push_impl $target $module_dir $module $product $resume
    ##### 强制改成 car 的 libvhal-property-impl.so #####
}

# 任何组合参数
function gs_android_push_args {
    read gs_error target module_dir module product resume <<< $(_gs_android_push_parse_opts $*)
    # 错误则打印help
    if [[ ${gs_error} == 1 ]] ; then
        _gs_android_push_help
        return
    fi

    echo "target=${target}, module_dir=${module_dir}, module=${module}, product=${product}, resume=${resume}"

    _gs_android_push_impl $target $module_dir $module $product $resume
}
