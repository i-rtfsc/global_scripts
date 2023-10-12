#!/bin/bash
# -*- coding: utf-8 -*-
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2023 anqi.huang@outlook.com
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

function gs_git_add_remove() {
    git add -A
    git ls-files --deleted -z | while read file; do
        git rm "$file"
    done
}

function gs_git_add_submodule() {
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
}

function gs_git_all_commits() {
    cd "`git rev-parse --git-path objects`"

    # packed objects
    for p in pack/pack-*([0-9a-f]).idx ; do
        git show-index < $p | cut -f 2 -d ' '
    done

    # loose objects
    for o in [0-9a-f][0-9a-f]/*([0-9a-f]) ; do
        echo ${o/\/}
    done
}

function gs_git_all_objects() {
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
}

function gs_git_already_merged() {
    for branch in $(git branch -r --merged | grep -v HEAD)
    do
        echo -e $(git show --format="%ci %cr %an" $branch | head -n 1) \\t$branch
    done | sort -r
}

function gs_git_current_branch() {
    git rev-parse --abbrev-ref HEAD
}

function gs_git_delete_branch() {
    git rev-parse --abbrev-ref HEAD
}

function gs_git_delete_tag() {
    git tag -d $1
    git push origin :refs/tags/$1
}

function gs_git_whoami() {
    git config --get user.email
    git config --get user.name
}

function gs_git_author_commits_number() {
    git shortlog -s -n
}

function gs_git_commits_number() {
    git rev-list HEAD --count
}

function gs_git_upload_current_branch() {
    branch=$(git rev-parse --abbrev-ref HEAD)
    echo "push to ${branch}"
    git push -u origin HEAD:${branch}
}