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
alias vm-ssh='ssh solo@10.164.118.252'
alias vm-mount='sshfs solo@10.164.118.252:/data/code/ $HOME/vm'
alias vm-umount='sudo diskutil umount force $HOME/vm'

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


function gs_init_upuphone_env() {
    # init repo url
    unset REPO_URL
    export REPO_URL='http://gerrit.upuphone.com/repo'

    # init gitlab url
    unset GITLAB_URL
    export GITLAB_URL='git@gitlab.upuphone.com'
}
# init upuphone env
gs_init_upuphone_env

function gs_android_push_bx-framework {
    adb push out/target/product/lemonadep/system/framework/bx-framework.jar /system/framework/
}

function gs_work_copy_git() {
    local source_dir=`pwd`
    local target_dir="${pwd/work/vm}"

    local modules=$(git ls-files -m)
    for item in ${modules[@]}; do
        echo ${source_dir}${item} ${target_dir}${item}
        cp ${source_dir}${item} ${target_dir}${item}
    done
}
