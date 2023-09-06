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

function gs_test() {
    if [ -n "$ZSH_VERSION" ]; then
       echo "zsh"
    elif [ -n "$BASH_VERSION" ]; then
       echo "bash"
    fi
}

function gs_git_copy() {
    local source_dir=`pwd`
    local target_dir=`pwd`

    files=($(git status --short --no-renames | awk '{print $(NF)}'))
    #files=($(git ls-files -m))

    for file in ${files}; do
        echo ${source_dir}/${file} ${target_dir}/${file}
        scp ${source_dir}/${file} solo@10.88.221.244:${target_dir}/${file}
    done
}