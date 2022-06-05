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

machine="$(uname -s)"
case "${machine}" in
    Linux*)     isMac=false;;
    Darwin*)    isMac=true;;
    *)          isMac=false;;
esac

# 启动pd vm
if $isMac ; then
    alias start-ubuntu='prlctl start ubuntu'
    alias start-deepin='prlctl start deepin'

    alias pd-ssh='ssh solo@10.211.55.13'
    alias pd-mount='sshfs solo@10.211.55.13:$HOME/code/ $HOME/pd/'
    alias pd-umount='sudo diskutil umount force $HOME/pd ; rm -rf $HOME/pd'
fi

####################################################################################################################
alias J007Engine-log-pid='adb logcat --pid=`com.journeyOS.J007engine.hidl@1.0-service`'
alias J007Engine-kill='adb shell killall com.journeyOS.J007engine.hidl@1.0-service'

alias J007Service-log-pid='adb logcat --pid=`adb shell pidof com.journeyOS.J007engine`'
alias J007Service-kill='adb shell killall com.journeyOS.J007engine'
alias J007Service-clear='adb shell pm clear com.journeyOS.J007engine'
alias J007Service-dump='adb shell dumpsys activity service com.journeyOS.J007engine/com.journeyOS.J007engine.service.J007EngineService'

alias J007Test-log-pid='adb logcat --pid=`adb shell pidof com.journeyOS.J007enginetest`'
alias J007Test-kill='adb shell killall com.journeyOS.J007enginetest'
alias J007Test-clear='adb shell pm clear com.journeyOS.J007enginetest'


alias I007-service-log-pid='adb logcat --pid=`adb shell pidof com.journeyOS.i007Service`'
alias I007-service-uninstall='adb uninstall com.journeyOS.i007Service'
alias I007-service-kill='adb shell killall com.journeyOS.i007Service'

alias I007-test-log-pid='adb logcat --pid=`adb shell pidof com.journeyOS.i007test`'
alias I007-test-uninstall='adb uninstall com.journeyOS.i007test'


####################################################################################################################

#if [ -f ~/global_scripts/environment.sh ]
#then
#    . ~/global_scripts/environment.sh
#fi
#[ -f ~/.vimrc ] || ln -s ~/global_scripts/.vimrc ~/
#[ -f ~/.gitconfig ] || ln -s ~/global_scripts/.gitconfig ~/
