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

alias ubuntu-ssh='ssh solo@10.88.159.37'
alias ubuntu-mount='sshfs solo@10.88.159.37:/home/solo/code/ $HOME/ubuntu'
alias ubuntu-umount='sudo diskutil umount force $HOME/ubuntu'

alias uos-ssh='ssh solo@10.88.159.103'
alias uos-mount='sshfs solo@10.88.159.103:/home/solo/code/ $HOME/uos'
alias uos-umount='sudo diskutil umount force $HOME/uos'

alias mz-ssh='ssh x-huanganqi@fort-test.meizu.com'
function mz-share() {
    sudo mount -t cifs //172.16.204.113/share ~/share -o username=meizu,password=$1
}

alias gs_work_update_py2='sudo rm -rf /usr/bin/python; sudo ln -s /usr/bin/python2.7 /usr/bin/python'
alias gs_work_update_py3='sudo rm -rf /usr/bin/python; sudo ln -s /usr/bin/python3 /usr/bin/python'

function mz-repo() {
    export REPO_URL='ssh://x-huanganqi@review.rnd.meizu.com:29418/repo'
    export REPO_REV='master'
}

alias ums-log-pid='adb logcat --pid=`adb shell pidof com.upuphone.bxservice`'
alias ums-kill='adb shell kill -9 `adb shell pidof com.upuphone.bxservice`'
alias ums-version='adb shell dumpsys package com.upuphone.bxservice | grep -i version'
alias ums-version-test='adb shell dumpsys package com.upuphone.bxservicetest | grep -i version'

alias ai-log-pid='adb logcat --pid=`adb shell pidof com.upuphone.aiservice`'
alias ai-kill='adb shell kill -9 `adb shell pidof com.upuphone.aiservice`'
alias ai-version='adb shell dumpsys package com.upuphone.aiservice | grep -i version'
alias ai-dump='adb shell dumpsys activity service com.upuphone.aiservice/.service.AiService'
alias ai-push='adb push out/target/product/lemonadep/system_ext/priv-app/AiService/AiService.apk system_ext/priv-app/AiService/AiService.apk'

alias watermark-push='adb push out/target/product/lemonadep/system_ext/bin/watermark system_ext/bin/watermark'
alias watermark-kill='adb shell killall watermark'

function gs_work_build_ext_fwk() {
    ./gradlew clean ; ./gradlew asR
    adb root ; adb remount
    adb push test/build/ExtFwk.apk /system_ext/app/ExtFwk/
    adb shell kill -9 `adb shell pidof com.android.extfwk`
}

function gs_work_start_ext_fwk() {
    adb shell am start -n com.android.extfwk/com.android.extfwk.DebugActivity
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
    adb push out/target/product/lemonadep/system/framework/framework.jar /system/framework/
}

function gs_work_push_services {
    adb push out/target/product/lemonadep/system/framework/services.jar /system/framework/
}

function gs_work_push_bx-framework {
    adb push out/target/product/lemonadep/system/framework/bx-framework.jar /system/framework/
}

function _gs_code_git_copy() {
    local target=$1
    if [ -z ${target} ]; then
        target="vm"
    fi

    local source_dir=`pwd`
    local target_dir="${${source_dir}/code/${target}}"
    echo $target_dir

    #files=$(git ls-files -m)
    #要把结果转成arrry
    files=($(git ls-files -m))
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

    #files=$(git ls-files -m)
    #要把结果转成arrry
    files=($(git ls-files -m))
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

function gs_work_missing_change_id() {
    gitdir=$(git rev-parse --git-dir); scp -p -P 29418 anqi.huang@gerrit.upuphone.com:hooks/commit-msg ${gitdir}/hooks/
    git commit --amend --no-edit
}

function gs_work_test() {
    _gs_code_git_copy "share"
}