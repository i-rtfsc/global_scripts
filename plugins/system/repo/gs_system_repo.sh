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


function gs_system_repo_url_update_google() {
    unset REPO_URL
    export REPO_URL='https://gerrit.googlesource.com/git-repo'
}

function gs_system_repo_url_update_intel() {
    unset REPO_URL
    export REPO_URL='https://gerrit.intel.com/git-repo'
}

function gs_system_repo_url_update_tsinghua() {
    unset REPO_URL
    export REPO_URL='https://mirrors.tuna.tsinghua.edu.cn/git/git-repo'
}
