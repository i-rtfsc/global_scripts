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

# Global Scripts Common Library
# This file contains common functions used across all plugins

# Error handling (safe for interactive shell)
# Removed 'set -e' to prevent script exit in interactive mode

# Color definitions (only if not already defined)
if [[ -z "${RED:-}" ]]; then
    readonly RED='\033[0;31m'
    readonly GREEN='\033[0;32m'
    readonly YELLOW='\033[1;33m'
    readonly BLUE='\033[0;34m'
    readonly PURPLE='\033[0;35m'
    readonly CYAN='\033[0;36m'
    readonly WHITE='\033[1;37m'
    readonly NC='\033[0m' # No Color
fi

# Error codes (only if not already defined)
if [[ -z "${GS_SUCCESS:-}" ]]; then
    readonly GS_SUCCESS=0
    readonly GS_ERROR_GENERAL=1
    readonly GS_ERROR_INVALID_ARGS=2
    readonly GS_ERROR_MISSING_DEPENDENCY=3
    readonly GS_ERROR_PERMISSION_DENIED=4
    readonly GS_ERROR_FILE_NOT_FOUND=5
    readonly GS_ERROR_NETWORK=6
    readonly GS_ERROR_TIMEOUT=7
fi

# Error handling functions
function gs_error() {
    local message="$1"
    local exit_code="${2:-$GS_ERROR_GENERAL}"
    echo -e "${RED}[ERROR]${NC} $message" >&2
    
    # Don't exit in interactive shell to prevent terminal closure
    if [[ $- == *i* ]]; then
        echo -e "${RED}[ERROR]${NC} Function aborted with exit code $exit_code" >&2
        return "$exit_code"
    else
        exit "$exit_code"
    fi
}

function gs_warn() {
    local message="$1"
    echo -e "${YELLOW}[WARN]${NC} $message" >&2
}

function gs_info() {
    local message="$1"
    echo -e "${BLUE}[INFO]${NC} $message"
}

function gs_success() {
    local message="$1"
    echo -e "${GREEN}[SUCCESS]${NC} $message"
}

function gs_debug() {
    local message="$1"
    if [[ "${gs_env_debug:-0}" == "1" ]]; then
        echo -e "${PURPLE}[DEBUG]${NC} $message" >&2
    fi
}

# Dependency checking
function gs_require_command() {
    local command="$1"
    local install_hint="${2:-}"
    
    if ! command -v "$command" >/dev/null 2>&1; then
        local msg="Required command '$command' not found"
        if [[ -n "$install_hint" ]]; then
            msg="$msg. Install with: $install_hint"
        fi
        gs_error "$msg" "$GS_ERROR_MISSING_DEPENDENCY"
    fi
}

function gs_require_file() {
    local file="$1"
    local description="${2:-file}"
    
    if [[ ! -f "$file" ]]; then
        gs_error "Required $description not found: $file" "$GS_ERROR_FILE_NOT_FOUND"
    fi
}

function gs_require_dir() {
    local dir="$1"
    local description="${2:-directory}"
    
    if [[ ! -d "$dir" ]]; then
        gs_error "Required $description not found: $dir" "$GS_ERROR_FILE_NOT_FOUND"
    fi
}

# Input validation
function gs_validate_not_empty() {
    local value="$1"
    local name="$2"
    
    if [[ -z "$value" ]]; then
        gs_error "Parameter '$name' cannot be empty" "$GS_ERROR_INVALID_ARGS"
    fi
}

function gs_validate_number() {
    local value="$1"
    local name="$2"
    
    if ! [[ "$value" =~ ^[0-9]+$ ]]; then
        gs_error "Parameter '$name' must be a number, got: $value" "$GS_ERROR_INVALID_ARGS"
    fi
}

function gs_validate_choice() {
    local value="$1"
    local name="$2"
    shift 2
    local choices=("$@")
    
    local valid=false
    for choice in "${choices[@]}"; do
        if [[ "$value" == "$choice" ]]; then
            valid=true
            break
        fi
    done
    
    if [[ "$valid" == false ]]; then
        local choices_str=$(IFS="|"; echo "${choices[*]}")
        gs_error "Parameter '$name' must be one of: $choices_str, got: $value" "$GS_ERROR_INVALID_ARGS"
    fi
}

# File operations with error handling
function gs_create_dir() {
    local dir="$1"
    local mode="${2:-755}"
    
    if [[ ! -d "$dir" ]]; then
        if ! mkdir -p "$dir" 2>/dev/null; then
            gs_error "Failed to create directory: $dir" "$GS_ERROR_PERMISSION_DENIED"
        fi
        chmod "$mode" "$dir" 2>/dev/null || gs_warn "Failed to set permissions for: $dir"
        gs_debug "Created directory: $dir"
    fi
}

function gs_copy_file() {
    local src="$1"
    local dst="$2"
    local mode="${3:-644}"
    
    gs_require_file "$src" "source file"
    
    if ! cp "$src" "$dst" 2>/dev/null; then
        gs_error "Failed to copy file: $src -> $dst" "$GS_ERROR_PERMISSION_DENIED"
    fi
    
    chmod "$mode" "$dst" 2>/dev/null || gs_warn "Failed to set permissions for: $dst"
    gs_debug "Copied file: $src -> $dst"
}

# Network operations with error handling
function gs_download_file() {
    local url="$1"
    local output="$2"
    local timeout="${3:-30}"
    
    gs_require_command "curl" "curl"
    
    if ! curl -L --max-time "$timeout" --output "$output" "$url" 2>/dev/null; then
        gs_error "Failed to download file from: $url" "$GS_ERROR_NETWORK"
    fi
    
    gs_debug "Downloaded file: $url -> $output"
}

# Process operations with error handling
function gs_run_with_timeout() {
    local timeout="$1"
    local command="$2"
    shift 2
    local args=("$@")
    
    if ! timeout "$timeout" "$command" "${args[@]}" 2>/dev/null; then
        gs_error "Command timed out after ${timeout}s: $command" "$GS_ERROR_TIMEOUT"
    fi
}

# Platform detection
function gs_get_platform() {
    case "$(uname -s)" in
        Linux*)     echo "linux";;
        Darwin*)    echo "macos";;
        CYGWIN*)    echo "windows";;
        MINGW*)     echo "windows";;
        *)          echo "unknown";;
    esac
}

# Android specific checks
function gs_check_adb() {
    gs_require_command "adb" "Android SDK platform-tools"
    
    if ! adb devices >/dev/null 2>&1; then
        gs_error "ADB server not running or no devices connected" "$GS_ERROR_GENERAL"
    fi
}

function gs_check_device_connected() {
    local device_count
    device_count=$(adb devices -l | grep -c "device$" || echo "0")
    
    if [[ "$device_count" -eq 0 ]]; then
        gs_error "No Android devices connected" "$GS_ERROR_GENERAL"
    fi
    
    if [[ "$device_count" -gt 1 ]]; then
        gs_warn "Multiple devices connected, using first available"
    fi
}

# Git operations with error handling
function gs_check_git_repo() {
    local dir="${1:-.}"
    
    if ! git -C "$dir" rev-parse --git-dir >/dev/null 2>&1; then
        gs_error "Not a git repository: $dir" "$GS_ERROR_GENERAL"
    fi
}

# Cleanup functions
function gs_cleanup_temp() {
    local temp_dir="$1"
    
    if [[ -d "$temp_dir" ]]; then
        rm -rf "$temp_dir" 2>/dev/null || gs_warn "Failed to cleanup temp directory: $temp_dir"
        gs_debug "Cleaned up temp directory: $temp_dir"
    fi
}

# Signal handling
function gs_setup_signal_handlers() {
    trap 'gs_error "Script interrupted by user" 130' INT
    trap 'gs_error "Script terminated" 143' TERM
}

# Help function template
function gs_show_help() {
    local script_name="$1"
    local description="$2"
    shift 2
    local options=("$@")
    
    echo "Usage: $script_name [OPTIONS]"
    echo
    echo "$description"
    echo
    echo "Options:"
    for option in "${options[@]}"; do
        echo "  $option"
    done
    echo "  -h, --help    Show this help message"
    echo
}

# Version information
function gs_show_version() {
    local script_name="$1"
    local version="${2:-unknown}"
    
    echo "$script_name version $version"
    echo "Part of Global Scripts project"
    echo "Copyright (c) 2023 anqi.huang@outlook.com"
}

# Initialize common environment
function gs_init_common() {
    # Set up signal handlers
    gs_setup_signal_handlers
    
    # Validate environment
    gs_require_dir "$_GS_ROOT_PATH" "Global Scripts root directory"
    gs_require_file "$_GS_ROOT_PATH/VERSION" "version file"
    
    # Set default debug mode if not set
    gs_env_debug="${gs_env_debug:-0}"
    
    gs_debug "Common library initialized"
}

# Auto-initialize when sourced
if [[ -n "${ZSH_VERSION:-}" ]]; then
    # In zsh, check if sourced vs executed
    if [[ "${(%):-%N}" != "${0}" ]]; then
        # Only initialize if _GS_ROOT_PATH is set (sourced from gs_env.sh)
        if [[ -n "${_GS_ROOT_PATH:-}" ]]; then
            gs_init_common
        fi
    fi
elif [[ -n "${BASH_VERSION:-}" ]]; then
    # In bash, use BASH_SOURCE
    if [[ "${BASH_SOURCE[0]:-}" != "${0}" ]]; then
        # Only initialize if _GS_ROOT_PATH is set (sourced from gs_env.sh)
        if [[ -n "${_GS_ROOT_PATH:-}" ]]; then
            gs_init_common
        fi
    fi
fi