#!/usr/bin/env bash
# Remote-style prompt (exact copy from v2)

source "${GS_ROOT:-$PWD}/themes/prompt/_lib.sh" 2>/dev/null || true

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
    _gs_theme_color_text $COLOR_SYS_INFO $(_gs_prompt_user)
}

## Colored IP segment (avoid name collision with _lib.sh _gs_prompt_ip)
function _gs_prompt_ip_segment() {
    # Use compatibility alias _gs_theme_ip defined in _lib.sh
    _gs_theme_color_text $COLOR_SYS_INFO "$(_gs_theme_ip)"
}

function _gs_prompt_current_dir() {
    if [ -n "$ZSH_VERSION" ]; then
        _gs_theme_color_text $COLOR_PATH "$(_gs_prompt_pwd)"
    else
        _gs_theme_color_text $COLOR_PATH '$(_gs_prompt_pwd)'
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

## Colored time segment with late evaluation for bash
function _gs_prompt_time_segment() {
    if [ -n "$ZSH_VERSION" ]; then
        # Direct evaluation each prompt render in zsh
        _gs_theme_color_text $COLOR_TIME "$(_gs_theme_get_time)"
    else
        # For bash, embed a literal command substitution so PS1 updates each prompt
        _gs_theme_color_text $COLOR_TIME '$(_gs_theme_get_time)'
    fi
}

function _gs_prompt_conda_or_py_info() {
    _gs_theme_color_text $COLOR_ENV $(_gs_prompt_conda_or_py)
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
PROMPT=$'$(_gs_prompt_start_line1)$(_gs_prompt_symbol_split_left)$(_gs_prompt_name)$(_gs_prompt_symbol_at)$(_gs_prompt_ip_segment)$(_gs_prompt_symbol_split_colon)$(_gs_prompt_current_dir)$(_gs_prompt_symbol_split_right)$(_gs_prompt_spilt_icon)$(_gs_prompt_symbol_split_left)$(_gs_prompt_time_segment)$(_gs_prompt_symbol_split_right)
$(_gs_prompt_start_line2)$(_gs_prompt_symbol_split_parentheses_left)$(_gs_prompt_env)$(_gs_prompt_conda_or_py_info)$(_gs_prompt_symbol_split_parentheses_right)$(_gs_prompt_smile)'
RPROMPT=$'$(_gs_prompt_right_display)'
else
export PS1="$(_gs_prompt_start_line1)$(_gs_prompt_symbol_split_left)$(_gs_prompt_name)$(_gs_prompt_symbol_at)$(_gs_prompt_ip_segment)$(_gs_prompt_symbol_split_colon)$(_gs_prompt_current_dir)$(_gs_prompt_symbol_split_right)$(_gs_prompt_spilt_icon)$(_gs_prompt_symbol_split_left)$(_gs_prompt_time_segment)$(_gs_prompt_symbol_split_right)
$(_gs_prompt_start_line2)$(_gs_prompt_symbol_split_parentheses_left)$(_gs_prompt_env)$(_gs_prompt_conda_or_py_info)$(_gs_prompt_symbol_split_parentheses_right)$(_gs_prompt_smile)"
fi
