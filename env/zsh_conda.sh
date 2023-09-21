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


# <<< conda initialize <<<
gs_conda_dir="$HOME/anaconda3"

if [ ! -d ${gs_conda_dir} ]; then
    gs_conda_dir="$HOME/miniconda3"
fi

if [ ! -d ${gs_conda_dir} ]; then
    gs_conda_dir="$HOME/opt/miniconda3"
fi

if [ ! -d ${gs_conda_dir} ]; then
    return 0
fi

__conda_setup="$('$gs_conda_dir/bin/conda' 'shell.zsh' 'hook' 2> /dev/null)"
if [ $? -eq 0 ]; then
    eval "$__conda_setup"
else
    if [ -f "$gs_conda_dir/etc/profile.d/conda.sh" ]; then
        . "$gs_conda_dir/etc/profile.d/conda.sh"
    else
        export PATH="$gs_conda_dir/bin:$PATH"
    fi
fi
unset __conda_setup
# <<< conda initialize <<<

conda config --set changeps1 False

conda activate py39tf2.x