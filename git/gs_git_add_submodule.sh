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

# This script makes it much easier to add new submodules
GIT_DIR=$(git rev-parse --git-dir)

PROJ_DIR=$(dirname "$GIT_DIR")
PROJ_DIR=$(abspath "$PROJ_DIR")
PROJ_RE=$(echo "$PROJ_DIR/" | sed 's/\//\\\//g')

for dir in "$@"; do
    SUBDIR=$(abspath "$dir")
    SUBDIR=$(echo $SUBDIR | sed s/$PROJ_RE//)

    repo=$(echo $(grep "url = " "$dir/.git/config") | \
        sed 's/.*url = //' | \
        sed 's/git@github.com:\([^\/]*\)\//git:\/\/github.com\/\1\//' )

    (cd "$PROJ_DIR" && \
     git submodule add "$repo" "$SUBDIR" && \
     git commit -m "Added submodule $SUBDIR")
done
