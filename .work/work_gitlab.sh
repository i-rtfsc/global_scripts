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

function git_pull_android_app_eco() {
    local root_dir="gitlab/app/eco"
    local modules=(
                  "Account"
                  "appmarket"
                  "Browser"
                  "Cloud"
                  "GameCenter"
                  )
    mkdir -p ${root_dir}
    for item in ${modules[@]}; do
        echo ${item}
        git clone -b dev ${GITLAB_URL}:android/app/eco/${item}.git ${root_dir}/${item}
    done
}

function git_pull_android_app_sys() {
    local root_dir="gitlab/app/sys"
    local modules=(
                  "Alarm"
#                  "BoxingMover"
                  "Calculator"
                  "Calendar"
                  "Camera"
                  "FeedBack"
                  "FileManager"
                  "FOTA"
                  "Fuyiping"
                  "Gallery"
                  "GameAssistant"
                  "Launcher"
                  "LogCenter"
                  "Message"
                  "Note"
                  "PermissionController"
                  "Phone"
                  "PhoneButler"
                  "PrivacyManager"
                  "ScanCode"
                  "SetupWizard"
                  "StarChat"
                  "SysPermissionController"
                  "Theme"
                  "Wallpaper"
                  "Weather"
                  )
    mkdir -p ${root_dir}
    for item in ${modules[@]}; do
        echo ${item}
        git clone -b dev ${GITLAB_URL}:android/app/sysapps/${item}.git ${root_dir}/${item}
    done
}

function git_pull_android_common_biz_eco() {
    local root_dir="gitlab/common/biz/eco"
    local modules=(
                  "ApkDiff"
                  "PackageInstallerLib"
                  "Push"
                  )
    mkdir -p ${root_dir}
    for item in ${modules[@]}; do
        echo ${item}
        git clone -b dev ${GITLAB_URL}:android/common/biz/eco/${item}.git ${root_dir}/${item}
    done
}

function git_pull_android_common_biz_system() {
    local root_dir="gitlab/common/biz/system"
    local modules=(
                  "ProxyService"
                  )
    mkdir -p ${root_dir}
    for item in ${modules[@]}; do
        echo ${item}
        git clone -b dev ${GITLAB_URL}:android/common/biz/system/${item}.git ${root_dir}/${item}
    done
}

function git_pull_android_core() {
    local root_dir="gitlab/common/core"
    local modules=(
                  "CommonExt"
                  "DataTracker"
                  "FileDownloader"
                  "GradlePlugins"
                  "IndicatorView"
                  "KVLib"
                  "LiveDataBus"
                  "Logger"
                  "OAID"
                  "PermissionRequester"
                  "Sentry"
                  "uupimageloader"
                  "USkinLoader"
                  "XUI-Lib"
#                  "XUI-Lib-Compose"
                  )
    mkdir -p ${root_dir}
    for item in ${modules[@]}; do
        echo ${item}
        git clone -b dev ${GITLAB_URL}:android/common/base/${item}.git ${root_dir}/${item}
    done

    git clone -b feature-lx-init ${GITLAB_URL}:android/common/base/xui-lib-compose.git ${root_dir}/xui-lib-compose
}

function git_pull_android_common_apptemplate() {
    local root_dir="gitlab/common"
    local modules=(
                  "AppTemplate"
                  )
    mkdir -p ${root_dir}
    for item in ${modules[@]}; do
        echo ${item}
        git clone -b dev ${GITLAB_URL}:android/common/${item}.git ${root_dir}/${item}
    done
}

function git_pull_android_tool() {
    local root_dir="gitlab/tool"
    local modules=(
                  "ezenv-shell"
                  )
    mkdir -p ${root_dir}
    for item in ${modules[@]}; do
        echo ${item}
        git clone ${GITLAB_URL}:android/tool/${item}.git ${root_dir}/${item}
    done
}

function main() {
    git_pull_android_app_eco
    git_pull_android_app_sys
    git_pull_android_common_biz_eco
    git_pull_android_common_biz_system
    git_pull_android_core
    git_pull_android_common_apptemplate
    git_pull_android_tool
}

main