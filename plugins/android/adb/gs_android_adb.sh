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

# https://github.com/mzlogin/awesome-adb

machine="$(uname -s)"
case "${machine}" in
    Linux*)     isMac=false;;
    Darwin*)    isMac=true;;
    *)          isMac=false;;
esac

function gs_android_adb_selinux_disable() {
    adb shell "setenforce 0"
    adb shell "stop && start"
}

function gs_android_adb_hidden_api_enable {
    adb shell settings put global hidden_api_policy_pre_p_apps 1
    adb shell settings put global hidden_api_policy_p_apps 1
}

function gs_android_adb_hidden_api_disable {
    adb shell settings delete global hidden_api_policy_pre_p_apps
    adb shell settings delete global hidden_api_policy_p_apps
}

function gs_android_adb_settings_provider() {
    # 查看 SettingsProvider 所有的配置
    # 比如不知道某个开关对应的数据库key，可以通过打开关闭抓两份结果对比值的变化
    adb shell dumpsys settings
}

function gs_android_adb_show_3rd_app {
    adb shell pm list packages -f -3
}

function gs_android_adb_show_system_app {
    adb shell pm list packages -f -s
}

function gs_android_adb_ps_grep {
    adb shell ps | grep -v "$1:" | grep "$1"
}

function gs_android_adb_kill_grep {
    adb shell kill $(adb shell ps | grep $1 | awk '{print $2}')
}

function gs_android_adb_log_grep {
    # TODO
    #adb logcat -v time | grep $(adb shell ps | grep -v "$1:" |grep $1 | awk '{print $2}')
    adb logcat -v threadtime | grep -iE "$1"
}

function gs_android_adb_screencap {
    # alias dump-screencap='adb shell screencap -p /sdcard/screenshot.png ; adb pull /sdcard/screenshot.png'
    adb shell screencap -p /sdcard/"$1".png
    adb pull /sdcard/"$1".png
}

function gs_android_adb_screenrecord {
    adb shell screenrecord /sdcard/"$1".mp4
    adb pull /sdcard/"$1".mp4
}

function gs_android_adb_sf_show_refresh_rate() {
    adb shell service call SurfaceFlinger 1034 i32 $1
}

function gs_android_adb_sf_set_refresh_rate() {
    adb shell service call SurfaceFlinger 1035 i32 $1
}

function gs_android_adb_sf_dump_refresh_rate() {
    adb shell dumpsys SurfaceFlinger | grep refresh
}

function gs_android_adb_systrace {
    if $isMac ; then
        python2 ~/Library/Android/sdk/platform-tools/systrace/systrace.py
    else
        # TODO
        python2 ~/bin/platform-tools/systrace/systrace.py
    fi
}

function gs_android_adb_imei {
    adb shell "service call iphonesubinfo 1 | cut -c 52-66 | tr -d '.[:space:]'"
}

function gs_android_adb_input_disable() {
    adb shell settings put system touch_event 0
    adb shell setprop sys.inputlog.enabled false
    adb shell setprop sys.input.TouchFilterEnable false
    adb shell dumpsys input
}

function gs_android_adb_input_enable {
    adb shell settings put system touch_event 1
    adb shell setprop sys.inputlog.enabled true
    adb shell setprop sys.input.TouchFilterEnable false
    adb shell dumpsys input
}

function gs_android_adb_key() {
    adb shell input keyevent "$1"
}

function gs_android_adb_key_home() {
    adb shell input keyevent 3
}

function gs_android_adb_key_back() {
    adb shell input keyevent 4
}

function gs_android_adb_key_menu() {
    adb shell input keyevent 82
}

# https://stackoverflow.com/questions/20155376/android-stop-emulator-from-command-line
function gs_android_adb_shutdown_emulator() {
    adb emu kill
}

function gs_android_adb_rm_dex2oat() {
    adb root
    adb remount
    adb shell rm -rf system/framework/oat
    adb shell rm -rf system/framework/arm
    adb shell rm -rf system/framework/arm64
    adb reboot
}

#输入包名
function gs_android_adb_dump_version() {
    if [ -z $1 ]; then
        echo "input package name"
        return
    fi
    adb shell dumpsys package $1 | grep -i version
}

#输入包名
function gs_android_adb_show_log() {
    if [ -z $1 ]; then
        echo "input package name"
        return
    fi
    adb logcat --pid=`adb shell pidof  $1`
}

#输入包名
function gs_android_adb_kill_package() {
    if [ -z $1 ]; then
        echo "input package name"
        return
    fi
    adb shell killall $1
#    adb shell kill -9 `adb shell pidof $1`
}

#输入包名
function gs_android_adb_clear_package() {
    if [ -z $1 ]; then
        echo "input package name"
        return
    fi
    adb shell pm clear $1
}

function gs_android_adb_dump_version_settings() {
    gs_android_adb_dump_version com.android.settings
}

function gs_android_adb_abx2xml() {
    # https://blog.csdn.net/q1165328963/article/details/125007694
    # adb shell cat /data/system/packages.xml | adb shell abx2xml - -
    # usage: abx2xml [-i] input [output]
    # usage: xml2abx [-i] input [output]
    adb shell cat $1 | adb shell abx2xml - -
}

function gs_android_adb_connect() {
    adb tcpip 5555
    adb connect $1
}

function gs_android_adb_j007engine_kill() {
    gs_android_adb_kill_package com.journeyOS.J007engine.hidl@1.0-service
}

function gs_android_adb_j007engine_log() {
    gs_android_adb_show_log com.journeyOS.J007engine.hidl@1.0-service
}

function gs_android_adb_j007service_kill() {
    gs_android_adb_kill_package com.journeyOS.J007engine
}

function gs_android_adb_j007service_log() {
    gs_android_adb_show_log com.journeyOS.J007engine
}

function gs_android_adb_j007service_clear() {
    gs_android_adb_clear_package com.journeyOS.J007engine
}

function gs_android_adb_j007service_version() {
    gs_android_adb_dump_version com.journeyOS.J007engine
}

function gs_android_adb_i007service_kill() {
    gs_android_adb_kill_package com.journeyOS.i007Service
}

function gs_android_adb_i007service_log() {
    gs_android_adb_show_log com.journeyOS.i007Service
}

function gs_android_adb_i007service_clear() {
    gs_android_adb_clear_package com.journeyOS.i007Service
}

function gs_android_adb_i007service_version() {
    gs_android_adb_dump_version com.journeyOS.i007Service
}