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

# Global Scripts Arguments Validation Library
# Provides common argument parsing and validation functions

# Source common library
if [[ -f "${_GS_ROOT_PATH}/env/gs_common.sh" ]]; then
    source "${_GS_ROOT_PATH}/env/gs_common.sh"
fi

# Confirmation utilities
function gs_confirm() {
    local message="$1"
    local default="${2:-n}"
    local response
    
    if [[ "${options[force]:-false}" == "true" ]]; then
        gs_debug "Force mode enabled, auto-confirming: $message"
        return 0
    fi
    
    while true; do
        if [[ "$default" == "y" ]]; then
            read -p "$message [Y/n]: " response
            response=${response:-y}
        else
            read -p "$message [y/N]: " response
            response=${response:-n}
        fi
        
        case $response in
            [Yy]|[Yy][Ee][Ss])
                return 0
                ;;
            [Nn]|[Nn][Oo])
                return 1
                ;;
            *)
                echo "Please answer yes or no."
                ;;
        esac
    done
}

# Progress indicators
function gs_progress_start() {
    local message="$1"
    if [[ "${options[quiet]:-false}" != "true" ]]; then
        echo -n "$message... "
    fi
}

function gs_progress_end() {
    local status="$1"
    if [[ "${options[quiet]:-false}" != "true" ]]; then
        if [[ "$status" == "ok" ]]; then
            echo -e "${GREEN}OK${NC}"
        elif [[ "$status" == "warn" ]]; then
            echo -e "${YELLOW}WARN${NC}"
        else
            echo -e "${RED}FAIL${NC}"
        fi
    fi
}

# Spinner for long operations
function gs_spinner() {
    local pid=$1
    local message="${2:-Processing}"
    local spin='-\|/'
    local i=0
    
    if [[ "${options[quiet]:-false}" == "true" ]]; then
        wait $pid
        return $?
    fi
    
    echo -n "$message "
    while kill -0 $pid 2>/dev/null; do
        i=$(( (i+1) %4 ))
        printf "\r$message ${spin:$i:1}"
        sleep .1
    done
    
    wait $pid
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        printf "\r$message ${GREEN}✓${NC}\n"
    else
        printf "\r$message ${RED}✗${NC}\n"
    fi
    
    return $exit_code
}

# Multi-choice selection
function gs_select() {
    local prompt="$1"
    shift
    local choices=("$@")
    local choice
    
    echo "$prompt"
    for i in "${!choices[@]}"; do
        echo "  $((i+1)). ${choices[i]}"
    done
    
    while true; do
        read -p "Select [1-${#choices[@]}]: " choice
        
        if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le "${#choices[@]}" ]]; then
            echo "${choices[$((choice-1))]}"
            return 0
        else
            echo "Invalid selection. Please choose 1-${#choices[@]}."
        fi
    done
}

# Package management detection
function gs_detect_package_manager() {
    if command -v brew >/dev/null 2>&1; then
        echo "brew"
    elif command -v apt-get >/dev/null 2>&1; then
        echo "apt"
    elif command -v yum >/dev/null 2>&1; then
        echo "yum"
    elif command -v dnf >/dev/null 2>&1; then
        echo "dnf"
    elif command -v pacman >/dev/null 2>&1; then
        echo "pacman"
    else
        echo "unknown"
    fi
}

# Package installation wrapper
function gs_install_package() {
    local package="$1"
    local pm=$(gs_detect_package_manager)
    
    gs_info "Installing package: $package using $pm"
    
    case "$pm" in
        brew)
            brew install "$package"
            ;;
        apt)
            sudo apt-get update && sudo apt-get install -y "$package"
            ;;
        yum)
            sudo yum install -y "$package"
            ;;
        dnf)
            sudo dnf install -y "$package"
            ;;
        pacman)
            sudo pacman -S --noconfirm "$package"
            ;;
        *)
            gs_error "Unknown package manager. Please install $package manually."
            ;;
    esac
}

# File backup utilities
function gs_backup_file() {
    local file="$1"
    local backup_dir="${2:-$HOME/.gs_backups}"
    
    if [[ ! -f "$file" ]]; then
        gs_debug "File does not exist, no backup needed: $file"
        return 0
    fi
    
    gs_create_dir "$backup_dir"
    
    local backup_name="$(basename "$file").$(date +%Y%m%d_%H%M%S).bak"
    local backup_path="$backup_dir/$backup_name"
    
    if gs_copy_file "$file" "$backup_path"; then
        gs_info "Backed up: $file -> $backup_path"
        echo "$backup_path"
    else
        gs_error "Failed to backup file: $file"
    fi
}

# Configuration merging
function gs_merge_config() {
    local user_config="$1"
    local default_config="$2"
    local output_config="$3"
    
    if [[ -f "$user_config" ]]; then
        gs_debug "Using existing user config: $user_config"
        cp "$user_config" "$output_config"
    elif [[ -f "$default_config" ]]; then
        gs_debug "Using default config: $default_config"
        cp "$default_config" "$output_config"
    else
        gs_error "Neither user nor default config found"
    fi
}

# URL validation
function gs_validate_url() {
    local url="$1"
    local name="${2:-URL}"
    
    if [[ ! "$url" =~ ^https?://[[:alnum:].-]+[[:alnum:]]+(:[0-9]+)?(/.*)?$ ]]; then
        gs_error "Invalid $name: $url"
    fi
}

# Port validation
function gs_validate_port() {
    local port="$1"
    local name="${2:-port}"
    
    if [[ ! "$port" =~ ^[0-9]+$ ]] || [[ "$port" -lt 1 ]] || [[ "$port" -gt 65535 ]]; then
        gs_error "Invalid $name: $port (must be 1-65535)"
    fi
}

# Email validation
function gs_validate_email() {
    local email="$1"
    local name="${2:-email}"
    
    if [[ ! "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        gs_error "Invalid $name: $email"
    fi
}

# Path validation
function gs_validate_path() {
    local path="$1"
    local name="${2:-path}"
    local must_exist="${3:-false}"
    
    if [[ "$must_exist" == "true" ]] && [[ ! -e "$path" ]]; then
        gs_error "$name does not exist: $path"
    fi
    
    if [[ ! "$path" =~ ^/ ]] && [[ ! "$path" =~ ^~ ]]; then
        gs_warn "$name is not absolute: $path"
    fi
}

# Initialize args module - shell compatible
if [[ -n "$ZSH_VERSION" ]]; then
    typeset -A options 2>/dev/null || true
    typeset -a args 2>/dev/null || true
else
    declare -A options 2>/dev/null || true
    declare -a args 2>/dev/null || true
fi

# Auto-initialize common options if sourced
if [[ -n "${ZSH_VERSION:-}" ]]; then
    # In zsh, check if sourced vs executed
    if [[ "${(%):-%N}" != "${0}" ]]; then
        gs_debug "Arguments library loaded (zsh)"
    fi
elif [[ -n "${BASH_VERSION:-}" ]]; then
    # In bash, use BASH_SOURCE
    if [[ "${BASH_SOURCE[0]:-}" != "${0}" ]]; then
        gs_debug "Arguments library loaded (bash)"
    fi
fi