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

code=$HOME/code
githuh=$HOME/code/github

function gs_goto_house() {
    cd ${githuh}/house
}

function gs_goto_global_scripts(){
    cd ${githuh}/global_scripts
}

function gs_goto_as-aosp(){
    cd ${githuh}/as-aosp
}

function gs_goto_aosp(){
    cd ${code}/aosp
}

function gs_goto_lineage(){
    cd ${code}/lineage
}

function gs_goto_flyme(){
    cd ${code}/flyme
}

function gs_goto_miui(){
   cd ${code}/miui
}

function gs_goto_oppo(){
   cd ${code}/oppo
}

function gs_goto_vivo(){
   cd ${code}/vivo
}