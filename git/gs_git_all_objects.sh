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

find .git/objects -type f | \
while read file; do
    if echo $file | egrep -q '\.idx$'; then
        git show-index < $file | awk '{print $2}'
    elif echo $file | egrep -q '[0-9a-f]{38}$'; then
        echo $(basename $(dirname $file))$(basename $file)
    fi
done | \
while read hash; do
    if [ "$(git cat-file -t $hash)" = commit ]; then
        echo $hash
    fi
done
