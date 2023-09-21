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



function gs_system_brew_remote() {
    # brew.git镜像源
    git -C "$(brew --repo)" remote -v
    # homebrew-core.git镜像源
    git -C "$(brew --repo homebrew/core)" remote -v
    # homebrew-cask.git镜像源
    git -C "$(brew --repo homebrew/cask)" remote -v
}

function gs_system_brew_ustc() {
    git -C "$(brew --repo)" remote set-url origin https://mirrors.ustc.edu.cn/brew.git
    git -C "$(brew --repo homebrew/core)" remote set-url origin https://mirrors.ustc.edu.cn/homebrew-core.git
    git -C "$(brew --repo homebrew/cask)" remote set-url origin https://mirrors.ustc.edu.cn/homebrew-cask.git
    export HOMEBREW_BOTTLE_DOMAIN=https://mirrors.ustc.edu.cn/homebrew-bottles
    brew update
}

function gs_system_brew_tsinghua() {
    git -C "$(brew --repo)" remote set-url origin https://mirrors.tuna.tsinghua.edu.cn/git/homebrew/brew.git
    git -C "$(brew --repo homebrew/core)" remote set-url origin https://mirrors.tuna.tsinghua.edu.cn/git/homebrew/homebrew-core.git
    git -C "$(brew --repo homebrew/cask)" remote set-url origin https://mirrors.tuna.tsinghua.edu.cn/git/homebrew/homebrew-cask.git
    export HOMEBREW_BOTTLE_DOMAIN=https://mirrors.tuna.tsinghua.edu.cn/git/homebrew/homebrew-bottles
    brew update
}

function gs_system_brew_aliyun() {
    git -C "$(brew --repo)" remote set-url origin https://mirrors.aliyun.com/homebrew//brew.git
    git -C "$(brew --repo homebrew/core)" remote set-url origin https://mirrors.aliyun.com/homebrew//homebrew-core.git
    git -C "$(brew --repo homebrew/cask)" remote set-url origin https://mirrors.aliyun.com/homebrew//homebrew-cask.git
    export HOMEBREW_BOTTLE_DOMAIN=https://mirrors.aliyun.com/homebrew/homebrew-bottles
    brew update
}

function gs_system_brew_github() {
    git -C "$(brew --repo)" remote set-url origin https://github.com/Homebrew/brew.git
    git -C "$(brew --repo homebrew/core)" remote set-url origin https://github.com/Homebrew/homebrew-core.git
    git -C "$(brew --repo homebrew/cask)" remote set-url origin https://github.com/Homebrew/homebrew-cask.git
    brew update
}
