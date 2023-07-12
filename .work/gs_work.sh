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

alias gs_work_update_py2='sudo rm -rf /usr/bin/python; sudo ln -s /usr/bin/python2.7 /usr/bin/python'
alias gs_work_update_py3='sudo rm -rf /usr/bin/python; sudo ln -s /usr/bin/python3 /usr/bin/python'

alias ubuntu-ssh='ssh solo@10.88.30.174'
alias ubuntu-mount='sshfs solo@10.88.30.174:/home/solo/code/ $HOME/ubuntu'
alias ubuntu-umount='sudo diskutil umount force $HOME/ubuntu'

function flyme-ssh() {
    ssh -oHostKeyAlgorithms=+ssh-dss x-huanganqi@fort.meizu.com
}

function flyme-share() {
    sudo mount -t cifs //172.16.204.113/share ~/share -o username=meizu,password=$1
}

function gs_work_input_log_enabled() {
    adb shell setprop log.tag.InputDispatcherInboundEvent DEBUG
    adb shell setprop log.tag.InputDispatcherOutboundEvent DEBUG
    adb shell setprop log.tag.InputDispatcherDispatchCycle DEBUG
    adb shell setprop log.tag.InputDispatcherChannelCreation DEBUG
    adb shell setprop log.tag.InputDispatcherInjection DEBUG
    adb shell setprop log.tag.InputDispatcherFocus DEBUG
    adb shell setprop log.tag.InputDispatcherTouchMode DEBUG
    adb shell setprop log.tag.InputDispatcherTouchOcclusion DEBUG
    adb shell setprop log.tag.InputDispatcherAppSwitch DEBUG
    adb shell setprop log.tag.InputDispatcherHover DEBUG
    adb shell setprop sys.inputlog.enabled true
    adb shell "stop && start"
    # system_server起来进入桌面后
    # adb shell dumpsys input
}

function gs_work_flash_qssi() {
    fastboot flash system system.img
    fastboot flash system_ext system_ext.img
    fastboot flash product product.img
    fastboot flash vbmeta_system vbmeta_system.img
    fastboot -w
    fastboot reboot
}

function gs_work_copy_image() {
    target=$1
    if [ -z ${target} ]; then
        target=qssi
    fi

    abs_current_dir=$(pwd)
    current_dir_name=$(basename "$PWD")
    source_dir=$abs_current_dir/out/target/product/$target
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

    echo $image_dir
#    pushd $image_dir
    cd $image_dir
    tar -zcvf $target_gz $current_dir_name
#    popd
    cd -
}

function gs_work_git_copy() {
    local source_dir=`pwd`
    # code 改成 share
    local target_dir="${${source_dir}/code/share}"
    echo $target_dir

    local target=$1
    if [ -z ${target} ]; then
        echo "target was null"
        exit
    else
        # flyme 改成 $1
        target_dir="${${target_dir}/flyme/${target}}"
    fi
    echo $target_dir

    files=($(git status --short --no-renames | awk '{print $(NF)}'))
    #files=($(git ls-files -m))

    for file in ${files}; do
        echo ${source_dir}/${file} ${target_dir}/${file}
        sudo cp ${source_dir}/${file} ${target_dir}/${file}
    done
}

function gs_work_git_copy_mars() {
    gs_work_git_copy mars
}

function gs_work_git_copy_flyme10() {
    gs_work_git_copy flyme10
}

function gs_work_git_copy_flyme10-u() {
    gs_work_git_copy flyme10-u
}

