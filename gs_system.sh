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

function gs_system_cpu_men() {
    cpu_mem=$(ps -A -o %cpu,%mem | awk '{ cpu += $1; mem += $2} END {print "cpu="cpu"%\nmem="mem"%"}')
    echo "${cpu_mem}"
}

function gs_repo_url_update_google() {
    unset REPO_URL
    export REPO_URL='https://gerrit.googlesource.com/git-repo'
}

function gs_repo_url_update_intel() {
    unset REPO_URL
    export REPO_URL='https://gerrit.intel.com/git-repo'
}

function gs_repo_url_update_tsinghua() {
    unset REPO_URL
    export REPO_URL='https://mirrors.tuna.tsinghua.edu.cn/git/git-repo'
}

function gs_brew_remote() {
    # brew.git镜像源
    git -C "$(brew --repo)" remote -v
    # homebrew-core.git镜像源
    git -C "$(brew --repo homebrew/core)" remote -v
    # homebrew-cask.git镜像源
    git -C "$(brew --repo homebrew/cask)" remote -v
}

function gs_brew_ustc() {
    git -C "$(brew --repo)" remote set-url origin https://mirrors.ustc.edu.cn/brew.git
    git -C "$(brew --repo homebrew/core)" remote set-url origin https://mirrors.ustc.edu.cn/homebrew-core.git
    git -C "$(brew --repo homebrew/cask)" remote set-url origin https://mirrors.ustc.edu.cn/homebrew-cask.git
    export HOMEBREW_BOTTLE_DOMAIN=https://mirrors.ustc.edu.cn/homebrew-bottles
    brew update
}

function gs_brew_tsinghua() {
    git -C "$(brew --repo)" remote set-url origin https://mirrors.tuna.tsinghua.edu.cn/git/homebrew/brew.git
    git -C "$(brew --repo homebrew/core)" remote set-url origin https://mirrors.tuna.tsinghua.edu.cn/git/homebrew/homebrew-core.git
    git -C "$(brew --repo homebrew/cask)" remote set-url origin https://mirrors.tuna.tsinghua.edu.cn/git/homebrew/homebrew-cask.git
    export HOMEBREW_BOTTLE_DOMAIN=https://mirrors.tuna.tsinghua.edu.cn/git/homebrew/homebrew-bottles
    brew update
}

function gs_brew_aliyun() {
    git -C "$(brew --repo)" remote set-url origin https://mirrors.aliyun.com/homebrew//brew.git
    git -C "$(brew --repo homebrew/core)" remote set-url origin https://mirrors.aliyun.com/homebrew//homebrew-core.git
    git -C "$(brew --repo homebrew/cask)" remote set-url origin https://mirrors.aliyun.com/homebrew//homebrew-cask.git
    export HOMEBREW_BOTTLE_DOMAIN=https://mirrors.aliyun.com/homebrew/homebrew-bottles
    brew update
}

function gs_brew_github() {
    git -C "$(brew --repo)" remote set-url origin https://github.com/Homebrew/brew.git
    git -C "$(brew --repo homebrew/core)" remote set-url origin https://github.com/Homebrew/homebrew-core.git
    git -C "$(brew --repo homebrew/cask)" remote set-url origin https://github.com/Homebrew/homebrew-cask.git
    brew update
}

_GS_CONFIG_PATH="$HOME/code/github/global_scripts/conf"

function gs_init_git() {
    # conf or update git conf
    rm -rf $HOME/.gs_git
    cp -r ${_GS_CONFIG_PATH}/.gs_git $HOME/.gs_git
    mv $HOME/.gs_git/.gitconfig $HOME/.gitconfig
}

function gs_init_ssh() {
    # conf or update ssh conf
   rm -rf $HOME/.ssh
   cp -r ${_GS_CONFIG_PATH}/.gs_ssh $HOME/.ssh
   chmod 700 $HOME/.ssh/id_rsa
}

function gs_init_vim() {
    # conf or update ssh conf
    rm -rf $HOME/.gs_vim
    cp -r ${_GS_CONFIG_PATH}/.gs_vim $HOME/
    mv $HOME/.gs_vim/.vimrc $HOME/.vimrc
}

function gs_init_cargo() {
   cp  ${_GS_CONFIG_PATH}/.cargo_config $HOME/.cargo/config
}

function gs_init_all_config() {
    cp ${_GS_CONFIG_PATH}/.zshrc $HOME/.zshrc
    gs_init_git
    gs_init_ssh
    gs_init_vim
    gs_init_cargo
}

function gs_repo_upload() {
    git push -u origin HEAD:$1
}
