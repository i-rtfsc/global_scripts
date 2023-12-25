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

machine="$(uname -s)"
case "${machine}" in
    Linux*)     isMac=false;;
    Darwin*)    isMac=true;;
    *)          isMac=false;;
esac

COLOR_PROMPT_HEAD=245
COLOR_FG_SPLIT=003
COLOR_SYS_INFO=200
COLOR_AT=226
COLOR_PATH=075
COLOR_TIME=169
COLOR_ENV=069
COLOR_GIT=110
COLOR_SPILT=033
COLOR_FINAL1=214
COLOR_FINAL2=199
COLOR_FINAL3=033

SYMBOL_SPLIT_LEFT="["
SYMBOL_SPLIT_RIGHT="]"
SYMBOL_SPLIT_PARENTHESES_LEFT="("
SYMBOL_SPLIT_PARENTHESES_RIGHT=")"
SYMBOL_SPLIT_AT="@"
SYMBOL_SPLIT_COLON=":"
SYMBOL_SPLIT_ARROW="➬"

if ${isMac} ; then
    SYMBOL_SPLIT_FINAL="⬡"
else
    SYMBOL_SPLIT_FINAL="☺"
fi

function _gs_prompt_start_line1() {
    _gs_theme_color_text $COLOR_PROMPT_HEAD "╭─"
}

function _gs_prompt_start_line2() {
    _gs_theme_color_text $COLOR_PROMPT_HEAD "╰─"
}

function _gs_prompt_symbol_split_left() {
    _gs_theme_color_text $COLOR_FG_SPLIT ${SYMBOL_SPLIT_LEFT}
}

function _gs_prompt_symbol_split_right() {
    _gs_theme_color_text $COLOR_FG_SPLIT ${SYMBOL_SPLIT_RIGHT}
}

function _gs_prompt_symbol_split_parentheses_left() {
    _gs_theme_color_text $COLOR_FG_SPLIT ${SYMBOL_SPLIT_PARENTHESES_LEFT}
}

function _gs_prompt_symbol_split_parentheses_right() {
    _gs_theme_color_text $COLOR_FG_SPLIT ${SYMBOL_SPLIT_PARENTHESES_RIGHT}
}

function _gs_prompt_symbol_at() {
    _gs_theme_color_text $COLOR_AT ${SYMBOL_SPLIT_AT}
}

function _gs_prompt_symbol_split_colon() {
    _gs_theme_color_text $COLOR_AT ${SYMBOL_SPLIT_COLON}
}

function _gs_prompt_name() {
    _gs_theme_color_text $COLOR_SYS_INFO $(_gs_theme_user_name)
}

function _gs_prompt_ip() {
    _gs_theme_color_text $COLOR_SYS_INFO $(_gs_theme_ip)
}

function _gs_prompt_current_dir() {
    if [ -n "$ZSH_VERSION" ]; then
        _gs_theme_color_text $COLOR_PATH "$(_gs_theme_current_dir)"
    else
        _gs_theme_color_text $COLOR_PATH '$(_gs_theme_current_dir)'
    fi
}

function _gs_prompt_spilt_icon() {
    if [ -n "$ZSH_VERSION" ]; then
        text=$(_gs_theme_color_text $COLOR_SPILT ${SYMBOL_SPLIT_ARROW})

        if ${isMac} ; then
            echo "$text"
        else
            echo " $text "
        fi
    else
        echo ""
    fi
}

function _gs_prompt_time() {
    if [ -n "$ZSH_VERSION" ]; then
        _gs_theme_color_text $COLOR_TIME "$(_gs_theme_get_time)"
    else
        _gs_theme_color_text $COLOR_TIME '$(_gs_theme_get_time)'
    fi
}

function _gs_prompt_conda_or_py_info() {
    _gs_theme_color_text $COLOR_ENV $(_gs_theme_conda_or_py_info)
}

function _gs_prompt_env() {
    text=bash-
    if [ -n "$ZSH_VERSION" ]; then
        text=zsh-
    fi
    _gs_theme_color_text $COLOR_ENV $text
}

function _gs_prompt_smile() {
    text1=$(_gs_theme_color_text $COLOR_FINAL1 ${SYMBOL_SPLIT_FINAL})
    text2=$(_gs_theme_color_text $COLOR_FINAL2 ${SYMBOL_SPLIT_FINAL})
    text3=$(_gs_theme_color_text $COLOR_FINAL3 ${SYMBOL_SPLIT_FINAL})

    if ${isMac} ; then
        echo " $text1$text2$text3 "
    else
        echo "$text1 $text2 $text3 "
    fi
}

function _gs_prompt_right_display() {
    _gs_theme_color_text $COLOR_GIT $(git_prompt_info)
}

if [ -n "$ZSH_VERSION" ]; then
PROMPT=$'$(_gs_prompt_start_line1)$(_gs_prompt_symbol_split_left)$(_gs_prompt_name)$(_gs_prompt_symbol_at)$(_gs_prompt_ip)$(_gs_prompt_symbol_split_colon)$(_gs_prompt_current_dir)$(_gs_prompt_symbol_split_right)$(_gs_prompt_spilt_icon)$(_gs_prompt_symbol_split_left)$(_gs_prompt_time)$(_gs_prompt_symbol_split_right)
$(_gs_prompt_start_line2)$(_gs_prompt_symbol_split_parentheses_left)$(_gs_prompt_env)$(_gs_prompt_conda_or_py_info)$(_gs_prompt_symbol_split_parentheses_right)$(_gs_prompt_smile)'
RPROMPT=$'$(_gs_prompt_right_display)'
else
export PS1="$(_gs_prompt_start_line1)$(_gs_prompt_symbol_split_left)$(_gs_prompt_name)$(_gs_prompt_symbol_at)$(_gs_prompt_ip)$(_gs_prompt_symbol_split_colon)$(_gs_prompt_current_dir)$(_gs_prompt_symbol_split_right)$(_gs_prompt_spilt_icon)$(_gs_prompt_symbol_split_left)$(_gs_prompt_time)$(_gs_prompt_symbol_split_right)
$(_gs_prompt_start_line2)$(_gs_prompt_symbol_split_parentheses_left)$(_gs_prompt_env)$(_gs_prompt_conda_or_py_info)$(_gs_prompt_symbol_split_parentheses_right)$(_gs_prompt_smile)"
fi