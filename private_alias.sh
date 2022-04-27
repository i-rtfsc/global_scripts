#!/bin/bash

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

# boxing
alias update-git-global-name-upuphone='git config --global user.email anqi.huang@upuphone.com;git config --global user.name anqi.huang'
alias jumpserver-ssh-all='ssh anqi.huang@jumpserver.upuphone.com -p 2222'
alias jumpserver-ssh='ssh solo@10.164.118.252'
alias jumpserver-mount='sshfs solo@10.164.118.252:/data/lineage/ $HOME/jumpserver'
alias jumpserver-umount='sudo diskutil umount force $HOME/jumpserver ; rm -rf $HOME/jumpserver'

alias ums-log-pid='adb logcat --pid=`adb shell pidof com.upuphone.bxservice`'
alias ums-kill='adb shell kill -9 `adb shell pidof com.upuphone.bxservice`'
alias ums-version='adb shell dumpsys package com.upuphone.bxservice | grep -i version'
alias ums-version-test='adb shell dumpsys package com.upuphone.bxservicetest | grep -i version'

##########################################################solo##########################################################
alias update-git-global-name-private='git config --global user.email anqi.huang@outlook.com; git config --global user.name Solo'

alias J007Engine-log-pid='adb logcat --pid=`com.journeyOS.J007engine.hidl@1.0-service`'
alias J007Engine-kill='adb shell killall com.journeyOS.J007engine.hidl@1.0-service'
alias J007Service-log-pid='adb logcat --pid=`adb shell pidof com.journeyOS.J007engine`'
alias J007Service-kill='adb shell killall com.journeyOS.J007engine'
alias J007Service-clear='adb shell pm clear com.journeyOS.J007engine'
alias J007Service-dump='adb shell dumpsys activity service com.journeyOS.J007engine/com.journeyOS.J007engine.service.J007EngineService'

alias J007Test-log-pid='adb logcat --pid=`adb shell pidof com.journeyOS.J007enginetest`'
alias J007Test-kill='adb shell killall com.journeyOS.J007enginetest'
alias J007Test-clear='adb shell pm clear com.journeyOS.J007enginetest'
##########################################################solo##########################################################

#if [ -f ~/global_scripts/environment.sh ]
#then
#    . ~/global_scripts/environment.sh
#fi
#[ -f ~/.vimrc ] || ln -s ~/global_scripts/.vimrc ~/
#[ -f ~/.gitconfig ] || ln -s ~/global_scripts/.gitconfig ~/
