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


if [[ -x `which tput` ]] && [[ "${use_tput:-}" ]]; then
	tput init
	BG_BLACK="$(tput setab 0)"
	BG_RED="$(tput setab 1)"
	BG_GREEN="$(tput setab 2)"
	BG_BROWN="$(tput setab 3)"
	BG_BLUE="$(tput setab 4)"
	BG_MAGENTA="$(tput setab 5)"
	BG_CYAN="$(tput setab 6)"
	BG_LIGHT_GRAY="$(tput setab 7)"

	# Only define colors if not already set (avoid conflicts with gs_common.sh)
	[[ -z "${BLACK:-}" ]] && BLACK="$(tput sgr0; tput setaf 0)"
	[[ -z "${DARK_GRAY:-}" ]] && DARK_GRAY="$(tput bold; tput setaf 0)"
	[[ -z "${RED:-}" ]] && RED="$(tput sgr0; tput setaf 1)"
	[[ -z "${LIGHT_RED:-}" ]] && LIGHT_RED="$(tput bold; tput setaf 1)"
	[[ -z "${GREEN:-}" ]] && GREEN="$(tput sgr0; tput setaf 2)"
	[[ -z "${LIGHT_GREEN:-}" ]] && LIGHT_GREEN="$(tput bold; tput setaf 2)"
	[[ -z "${BROWN:-}" ]] && BROWN="$(tput sgr0; tput setaf 3)"
	[[ -z "${YELLOW:-}" ]] && YELLOW="$(tput bold; tput setaf 3)"
	[[ -z "${BLUE:-}" ]] && BLUE="$(tput sgr0; tput setaf 4)"
	[[ -z "${LIGHT_BLUE:-}" ]] && LIGHT_BLUE="$(tput bold; tput setaf 4)"
	[[ -z "${MAGENTA:-}" ]] && MAGENTA="$(tput sgr0; tput setaf 5)"
	[[ -z "${LIGHT_MAGENTA:-}" ]] && LIGHT_MAGENTA="$(tput bold; tput setaf 5)"
	[[ -z "${CYAN:-}" ]] && CYAN="$(tput sgr0; tput setaf 6)"
	[[ -z "${LIGHT_CYAN:-}" ]] && LIGHT_CYAN="$(tput bold; tput setaf 6)"
	[[ -z "${LIGHT_GRAY:-}" ]] && LIGHT_GRAY="$(tput sgr0; tput setaf 7)"
	[[ -z "${WHITE:-}" ]] && WHITE="$(tput bold; tput setaf 7)"
	[[ -z "${NO_COLOR:-}" ]] && NO_COLOR="$(tput sgr0)"
else
	BG_BLACK="\033[0;40m"
	BG_RED="\033[0;41m"
	BG_GREEN="\033[0;42m"
	BG_BROWN="\033[0;43m"
	BG_BLUE="\033[0;44m"
	BG_MAGENTA="\033[0;45m"
	BG_CYAN="\033[0;46m"
	BG_LIGHT_GRAY="\033[0;47m"

	# Only define colors if not already set (avoid conflicts with gs_common.sh)
	[[ -z "${BLACK:-}" ]] && BLACK="\033[0;30m"
	[[ -z "${DARK_GRAY:-}" ]] && DARK_GRAY="\033[1;30m"
	[[ -z "${RED:-}" ]] && RED="\033[0;31m"
	[[ -z "${LIGHT_RED:-}" ]] && LIGHT_RED="\033[1;31m"
	[[ -z "${GREEN:-}" ]] && GREEN="\033[0;32m"
	[[ -z "${LIGHT_GREEN:-}" ]] && LIGHT_GREEN="\033[1;32m"
	[[ -z "${BROWN:-}" ]] && BROWN="\033[0;33m"
	[[ -z "${YELLOW:-}" ]] && YELLOW="\033[1;33m"
	[[ -z "${BLUE:-}" ]] && BLUE="\033[0;34m"
	[[ -z "${LIGHT_BLUE:-}" ]] && LIGHT_BLUE="\033[1;34m"
	[[ -z "${MAGENTA:-}" ]] && MAGENTA="\033[0;35m"
	[[ -z "${LIGHT_MAGENTA:-}" ]] && LIGHT_MAGENTA="\033[1;35m"
	[[ -z "${CYAN:-}" ]] && CYAN="\033[0;36m"
	[[ -z "${LIGHT_CYAN:-}" ]] && LIGHT_CYAN="\033[1;36m"
	[[ -z "${LIGHT_GRAY:-}" ]] && LIGHT_GRAY="\033[0;37m"
	[[ -z "${WHITE:-}" ]] && WHITE="\033[1;37m"
	[[ -z "${NO_COLOR:-}" ]] && NO_COLOR="\033[0m"
fi

NORMAL=$NO_COLOR
INFO=$LIGHT_GREEN
WARN=$YELLOW
ERROR=$LIGHT_RED

echo_info() {
  echo -e "${INFO}$@${NORMAL}"
  return 0
}

echo_warn() {
  echo -e "${WARN}$@${NORMAL}"
  return 0
}

echo_error() {
  echo -e "${ERROR}$@${NORMAL}"
  return 0
}

verbose_info() {
	if [[ "$gs_env_debug" == "1" ]]; then
	  echo_info $@
	fi
}

verbose_warn() {
	if [[ "$gs_env_debug" == "1" ]]; then
	  echo_warn $@
	fi
}

verbose_error() {
	if [[ "$gs_env_debug" == "1" ]]; then
	  echo_error $@
	fi
}