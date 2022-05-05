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

function gs_system_cpu_men() {
    cpu_mem=$(ps -A -o %cpu,%mem | awk '{ cpu += $1; mem += $2} END {print "cpu="cpu"%\nmem="mem"%"}')
    echo "${cpu_mem}"
}

function gs_repo_url_update_google() {
    unset REPO_URL
    export REPO_URL='https://gerrit.googlesource.com/git-repo'
}

function gs_repo_url_update_intel() {
    unset REPO_URL
    export REPO_URL='https://gerrit.intel.com/git-repo'
}

function gs_repo_url_update_tsinghua() {
    unset REPO_URL
    export REPO_URL='https://mirrors.tuna.tsinghua.edu.cn/git/git-repo'
}

function gs_repo_url_update_upuphone() {
    unset REPO_URL
    export REPO_URL='http://gerrit.upuphone.com/repo'
}

function gs_init_config() {
    local _gs_config_path="$HOME/code/github/global_scripts/config"
    cp ${_gs_config_path}/.zshrc $HOME/.zshrc
    cp ${_gs_config_path}/.editorconfig $HOME/.editorconfig
    cp ${_gs_config_path}/.gitconfig $HOME/.gitconfig
    cp ${_gs_config_path}/.gitprivate $HOME/.gitprivate
    cp ${_gs_config_path}/.gitwork $HOME/.gitwork
    cp ${_gs_config_path}/.gitignore $HOME/.gitignore
    cp ${_gs_config_path}/.gitattributes $HOME/.gitattributes

    cp -r ${_gs_config_path}/.ssh $HOME/.ssh
    chmod 700 $HOME/.ssh/id_rsa
}

# init repo url
gs_repo_url_update_upuphone