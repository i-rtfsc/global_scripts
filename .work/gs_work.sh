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

alias vm-ssh-all='ssh anqi.huang@jumpserver.upuphone.com -p 2222'
alias vm-ssh='ssh solo@10.171.53.122'
alias vm-mount='sshfs solo@10.171.53.122:/home/solo/code/ $HOME/vm'
alias vm-umount='sudo diskutil umount force $HOME/vm'

alias ubuntu-ssh='ssh solo@10.88.161.172'
alias ubuntu-mount='sshfs solo@10.88.161.172:/home/solo/code/ $HOME/ubuntu'
alias ubuntu-umount='sudo diskutil umount force $HOME/ubuntu'

alias uos-ssh='ssh solo@10.88.159.103'
alias uos-mount='sshfs solo@10.88.159.103:/home/solo/code/ $HOME/uos'
alias uos-umount='sudo diskutil umount force $HOME/uos'

alias mz-ssh='ssh -oHostKeyAlgorithms=+ssh-dss x-huanganqi@fort-test.meizu.com'
function mz-share() {
    sudo mount -t cifs //172.16.204.113/share ~/share -o username=meizu,password=$1
}

alias gs_work_update_py2='sudo rm -rf /usr/bin/python; sudo ln -s /usr/bin/python2.7 /usr/bin/python'
alias gs_work_update_py3='sudo rm -rf /usr/bin/python; sudo ln -s /usr/bin/python3 /usr/bin/python'

function mz-repo() {
    export REPO_URL='ssh://x-huanganqi@review.rnd.meizu.com:29418/repo'
    export REPO_REV='master'
}

alias gs_work_fms_log='adb logcat --pid=`adb shell pidof com.flyme.mobileservice`'
alias gs_work_fms_kill='adb shell kill -9 `adb shell pidof com.flyme.mobileservice`'
alias gs_work_fms_version='adb shell dumpsys package com.flyme.mobileservice | grep -i version'
alias gs_work_fms_dump='adb shell dumpsys activity service com.flyme.mobileservice/.ltpo.VrrService'

alias gs_work_fms_ltpo_enable='adb shell dumpsys activity service com.flyme.mobileservice/.ltpo.VrrService put settings ltpo true bool'
alias gs_work_fms_ltpo_disable='adb shell dumpsys activity service com.flyme.mobileservice/.ltpo.VrrService put settings ltpo false bool'

alias gs_work_ltpo_note='adb shell "dmesg -w | grep -iE dsi"'

function gs_work_build_fms() {
    ./gradlew clean ; ./gradlew asR
    adb root ; adb remount
    adb push Apps/app-phone/build/outputs/apk/release/app-phone-universal-release.apk /system/app/FMS/FMS.apk
    adb shell kill -9 `adb shell pidof com.flyme.mobileservice`
}

function gs_work_copy_image() {
    abs_current_dir=$(pwd)
    current_dir_name=$(basename "$PWD")
    source_dir=$abs_current_dir/out/target/product/qssi
    image_dir=/data/share/image
    target_dir=$image_dir/$current_dir_name
    target_gz=$target_dir.tar.gz

    echo $abs_current_dir
    echo $source_dir
    echo $target_dir
    echo $target_gz

    ls $source_dir/system.img

    rm -rf $target_dir
    rm -rf $target_gz
    mkdir -p $target_dir

    cp $source_dir/system.img $target_dir
    cp $source_dir/system_ext.img $target_dir
    cp $source_dir/product.img $target_dir
    cp $source_dir/vbmeta_system.img $target_dir

#    tar -zcvf $target_gz $target_dir
    pushd $image_dir
    tar -zcvf $target_gz $current_dir_name
    popd
}

function gs_work_flash_qssi() {
    fastboot flash system system.img
    fastboot flash system_ext system_ext.img
    fastboot flash product product.img
    fastboot flash vbmeta_system vbmeta_system.img
    fastboot -w
    fastboot reboot
}

function gs_work_init_upuphone_env() {
    # init repo url
    unset REPO_URL
    export REPO_URL='http://gerrit.upuphone.com/repo'
    # init gitlab url
    unset GITLAB_URL
    export GITLAB_URL='git@gitlab.upuphone.com'
}
# init upuphone env
gs_work_init_upuphone_env

function gs_work_push_framework {
    adb push out/target/product/qssi/system/framework/framework.jar /system/framework/
}

function gs_work_push_services {
    adb push out/target/product/qssi/system/framework/services.jar /system/framework/
}

function gs_work_push_ext-framework {
    adb push out/target/product/qssi/system/framework/jos-framework.jar /system/framework/
}

function gs_work_push_ext-services {
    adb push out/target/product/qssi/system/framework/jos-services.jar /system/framework/
}

function _gs_code_git_copy() {
    local target=$1
    if [ -z ${target} ]; then
        target="vm"
    fi

    local source_dir=`pwd`
    local target_dir="${${source_dir}/code/${target}}"
    echo $target_dir

    if [ -z $1 ]; then
        files=($(git status --short --no-renames | awk '{print $(NF)}'))
    else
        files=($(git ls-files -m))
    fi

    for file in ${files}; do
        echo ${source_dir}/${file} ${target_dir}/${file}
        cp ${source_dir}/${file} ${target_dir}/${file}
    done
}

function _gs_work_git_copy() {
    local target=$1
    if [ -z ${target} ]; then
        target="vm"
    fi

    local source_dir=`pwd`
    local target_dir="${${source_dir}/work/${target}}"
    echo $target_dir

    if [ -z $1 ]; then
        files=($(git status --short --no-renames | awk '{print $(NF)}'))
    else
        files=($(git ls-files -m))
    fi

    for file in ${files}; do
        echo ${source_dir}/${file} ${target_dir}/${file}
        cp ${source_dir}/${file} ${target_dir}/${file}
    done
}

function gs_work_git_copy_vm() {
    _gs_work_git_copy "vm"
}

function gs_work_git_copy_uos() {
    _gs_work_git_copy "uos"
}

function gs_work_git_copy_mz() {
    _gs_code_git_copy "share"
}

function gs_work_qssi_git_copy() {
    local source_dir=`pwd`
    local remote='solo@10.171.53.122:'

    if [ -z $1 ]; then
        files=($(git status --short --no-renames | awk '{print $(NF)}'))
    else
        files=($(git ls-files -m))
    fi

    for file in ${files}; do
        source_file=${source_dir}/${file}
        target_file=${remote}${source_dir}/${file}

        case `uname -s` in
            Darwin)
                target_file="${${target_file}/Users/home}"
                ;;
        esac

        echo ${source_file} ${target_file}
        scp ${source_file} ${target_file}
    done
}

function gs_work_flash_qssi() {
#    adb reboot fastboot
    fastboot flash system system.img
    fastboot flash system_ext system_ext.img
    fastboot flash product product.img
    fastboot flash vbmeta_system vbmeta_system.img
    fastboot -w
    fastboot reboot
}

function gs_work_mars_copy() {
    local target=$1
    if [ -z ${target} ]; then
        target="/home/share/mars"
    fi

    local source_dir=`pwd`
    source="/home/solo/code/mfsc"
    local target_dir="${${source_dir}/${source}/${target}}"
    echo $target_dir

    if [ -z $1 ]; then
        files=($(git status --short --no-renames | awk '{print $(NF)}'))
    else
        files=($(git ls-files -m))
    fi

    for file in ${files}; do
        echo ${source_dir}/${file} ${target_dir}/${file}
        cp ${source_dir}/${file} ${target_dir}/${file}
    done
}