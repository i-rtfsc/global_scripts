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

set -e
shopt -s nullglob extglob

cd "`git rev-parse --git-path objects`"

# packed objects
for p in pack/pack-*([0-9a-f]).idx ; do
    git show-index < $p | cut -f 2 -d ' '
done

# loose objects
for o in [0-9a-f][0-9a-f]/*([0-9a-f]) ; do
    echo ${o/\/}
done