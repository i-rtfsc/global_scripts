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

function gs_adb_selinux() {
    adb shell "setenforce 0"
    adb shell "stop && start"
}

function gs_adb_hidden_api_enable {
    adb shell settings put global hidden_api_policy_pre_p_apps 1
    adb shell settings put global hidden_api_policy_p_apps 1
}

function gs_adb_hidden_api_disable {
    adb shell settings delete global hidden_api_policy_pre_p_apps
    adb shell settings delete global hidden_api_policy_p_apps
}

function gs_adb_show_3rd_app {
    adb shell pm list packages -f -3
}

function gs_adb_show_system_app {
    adb shell pm list packages -f -s
}

function gs_adb_ps_grep {
    adb shell ps | grep -v "$1:" | grep "$1"
}

function gs_adb_kill_grep {
    adb shell kill $(adb shell ps | grep $1 | awk '{print $2}')
}

function gs_adb_log_grep {
    # TODO
    #adb logcat -v time | grep $(adb shell ps | grep -v "$1:" |grep $1 | awk '{print $2}')
    adb logcat -v threadtime | grep -iE "$1"
}

function gs_adb_screencap {
    # alias dump-screencap='adb shell screencap -p /sdcard/screenshot.png ; adb pull /sdcard/screenshot.png'
    adb shell screencap -p /sdcard/"$1".png
    adb pull /sdcard/"$1".png
}

function gs_adb_dispaysync {
    adb shell dumpsys SurfaceFlinger --dispsync | grep mPeriod
}

function gs_adb_sf_set_refresh_rate() {
    adb shell service call SurfaceFlinger 1035 i32 $1
}

function gs_adb_sf_dump_refresh_rate() {
    adb shell dumpsys SurfaceFlinger | grep refresh
}

function gs_adb_vrr_set_refresh_rate() {
    adb shell dumpsys vrr $1 system 1
}

function gs_adb_systrace {
    if $isMac ; then
        python2 ~/Library/Android/sdk/platform-tools/systrace/systrace.py
    else
        # TODO
        python2 ~/Library/Android/sdk/platform-tools/systrace/systrace.py
    fi
}

function gs_adb_imei {
    adb shell "service call iphonesubinfo 1 | cut -c 52-66 | tr -d '.[:space:]'"
}

function gs_adb_key() {
    adb shell input keyevent "$1"
}

function gs_adb_key_home() {
    adb shell input keyevent 3
}

function gs_adb_key_back() {
    adb shell input keyevent 4
}

function gs_adb_key_menu() {
    adb shell input keyevent 82
}

####################################################################################################################
alias J007Engine-log-pid='adb logcat --pid=`com.journeyOS.J007engine.hidl@1.0-service`'
alias J007Engine-kill='adb shell killall com.journeyOS.J007engine.hidl@1.0-service'
####################################################################################################################
alias J007Service-log-pid='adb logcat --pid=`adb shell pidof com.journeyOS.J007engine`'
alias J007Service-kill='adb shell killall com.journeyOS.J007engine'
alias J007Service-clear='adb shell pm clear com.journeyOS.J007engine'
alias J007Service-dump='adb shell dumpsys activity service com.journeyOS.J007engine/com.journeyOS.J007engine.service.J007EngineService'
####################################################################################################################
alias J007Test-log-pid='adb logcat --pid=`adb shell pidof com.journeyOS.J007enginetest`'
alias J007Test-kill='adb shell killall com.journeyOS.J007enginetest'
alias J007Test-clear='adb shell pm clear com.journeyOS.J007enginetest'
####################################################################################################################
alias I007-service-log-pid='adb logcat --pid=`adb shell pidof com.journeyOS.i007Service`'
alias I007-service-uninstall='adb uninstall com.journeyOS.i007Service'
alias I007-service-kill='adb shell killall com.journeyOS.i007Service'
alias I007-service-version='adb shell dumpsys package com.journeyOS.i007Service | grep -i version'
####################################################################################################################
alias I007-test-log-pid='adb logcat --pid=`adb shell pidof com.journeyOS.i007test`'
alias I007-test-uninstall='adb uninstall com.journeyOS.i007test'
####################################################################################################################