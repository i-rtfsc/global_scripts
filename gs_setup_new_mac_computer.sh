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


function mac_install_brew() {
    ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
}

function mac_install_utilities() {
    brew install bash
    brew install bash-completion
    brew install zsh
    brew install zsh-completions
    sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
    brew install scrcpy
}

# https://formulae.brew.sh/cask/android-studio
function mac_install_apps() {
    brew install --cask android-platform-tools
    brew install --cask miniconda
    brew install --cask iterm2
    brew install --cask sublime-text
    brew install --cask google-chrome
    brew install --cask android-studio
    brew install --cask clion
    brew install --cask pycharm
    brew install --cask db-browser-for-sqlite
#    brew install --cask webstorm
#    brew install --cask visual-studio-code"
}

function mac_install_for_build_aosp() {
    # sudo ln -sfn $(brew --prefix)/opt/openjdk@11/libexec/openjdk.jdk /Library/Java/JavaVirtualMachines/openjdk-11.jdk
    brew install openjdk@11
    # For the system Java wrappers to find this JDK, symlink it with
    # sudo ln -sfn /usr/local/opt/openjdk@11/libexec/openjdk.jdk /Library/Java/JavaVirtualMachines/openjdk-11.jdk

    # openjdk@11 is keg-only, which means it was not symlinked into /usr/local,
    # because this is an alternate version of another formula.

    # If you need to have openjdk@11 first in your PATH, run:
    # echo 'export PATH="/usr/local/opt/openjdk@11/bin:$PATH"' >> ~/.zshrc

    # For compilers to find openjdk@11 you may need to set:
    # export CPPFLAGS="-I/usr/local/opt/openjdk@11/include"

    # ==> Summary
    # 🍺  /usr/local/Cellar/openjdk@11/11.0.15: 678 files, 299.3MB
    # ==> Running `brew cleanup openjdk@11`...
    # Disable this behaviour by setting HOMEBREW_NO_INSTALL_CLEANUP.
    # Hide these hints with HOMEBREW_NO_ENV_HINTS (see `man brew`).
    brew install bc bison build-essential ccache curl flex g++-multilib gcc-multilib git gnupg gperf imagemagick lib32ncurses5-dev lib32readline-dev lib32z1-dev liblz4-tool libncurses5 libncurses5-dev libsdl1.2-dev libssl-dev libxml2 libxml2-utils lzop pngcrush rsync schedtool squashfs-tools xsltproc zip zlib1g-dev -y
}
