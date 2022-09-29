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

    local search_dir=`pwd`
    files=($(find $search_dir -type f))
    for file in ${files}; do
#        dir_name=$(dirname $file)
#        file_name=$(basename $file)
#        file_name_suffix="${file##*.}"

        target_file="${${file}/8550/8550_back}"_back

        if [ ! -d ${target_dir_name} ]; then
            mkdir -p ${target_dir_name}
        fi
#        cat $file > $target_file
        echo $target_file
    done

#    local search_dir=`pwd`
#    files=($(find $search_dir -type f))
#    for file in ${files}; do
#        dir_name=$(dirname $file)
#        file_name=$(basename $file)
#        file_name_suffix="${file##*.}"
#
#        new_file_name_suffix="${${file}/_back/""}"
#
#        if [ ! -d ${target_dir_name} ]; then
#            mkdir -p ${target_dir_name}
#        fi
##        cat $file > $target_file
#        new_file=$new_file_name_suffix
#        mv $file $new_file
#        echo $new_file
#    done

}