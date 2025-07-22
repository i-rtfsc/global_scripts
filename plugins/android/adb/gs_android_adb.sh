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

# https://github.com/mzlogin/awesome-adb

# Source common library functions
# shellcheck source=../../../env/gs_common.sh
if [[ -f "${_GS_ROOT_PATH}/env/gs_common.sh" ]]; then
    source "${_GS_ROOT_PATH}/env/gs_common.sh"
fi

# Platform detection using common library
readonly IS_MAC=$(gs_get_platform)

# ADB Functions with error handling

function gs_android_adb_selinux_disable() {
    gs_info "Disabling SELinux..."
    gs_check_adb
    gs_check_device_connected
    
    if ! adb shell "setenforce 0" 2>/dev/null; then
        gs_error "Failed to disable SELinux. Check device permissions."
    fi
    
    gs_info "Restarting Android..."
    if ! adb shell "stop && start" 2>/dev/null; then
        gs_warn "Failed to restart Android services"
    fi
    
    gs_success "SELinux disabled"
}

function gs_android_adb_hidden_api_enable() {
    gs_info "Enabling hidden API access..."
    gs_check_adb
    gs_check_device_connected
    
    if ! adb shell settings put global hidden_api_policy_pre_p_apps 1; then
        gs_error "Failed to enable hidden API for pre-P apps"
    fi
    
    if ! adb shell settings put global hidden_api_policy_p_apps 1; then
        gs_error "Failed to enable hidden API for P apps"
    fi
    
    gs_success "Hidden API access enabled"
}

function gs_android_adb_hidden_api_disable() {
    gs_info "Disabling hidden API access..."
    gs_check_adb
    gs_check_device_connected
    
    adb shell settings delete global hidden_api_policy_pre_p_apps 2>/dev/null || true
    adb shell settings delete global hidden_api_policy_p_apps 2>/dev/null || true
    
    gs_success "Hidden API access disabled"
}

function gs_android_adb_input_disable() {
    gs_info "Disabling touch input..."
    gs_check_adb
    gs_check_device_connected
    
    if ! adb shell input keyevent --longpress POWER 2>/dev/null; then
        gs_warn "Failed to simulate power button"
    fi
    
    # Alternative method using settings
    adb shell settings put system accelerometer_rotation 0 2>/dev/null || true
    gs_success "Input controls disabled"
}

function gs_android_adb_input_enable() {
    gs_info "Enabling touch input..."
    gs_check_adb
    gs_check_device_connected
    
    adb shell settings put system accelerometer_rotation 1 2>/dev/null || true
    gs_success "Input controls enabled"
}

function gs_android_adb_key_home() {
    gs_check_adb
    gs_check_device_connected
    adb shell input keyevent KEYCODE_HOME
}

function gs_android_adb_key_back() {
    gs_check_adb
    gs_check_device_connected
    adb shell input keyevent KEYCODE_BACK
}

function gs_android_adb_key_menu() {
    gs_check_adb
    gs_check_device_connected
    adb shell input keyevent KEYCODE_MENU
}

function gs_android_adb_screencap() {
    local filename="${1:-screenshot_$(date +%Y%m%d_%H%M%S).png}"
    local local_path="${2:-./}"
    
    gs_info "Taking screenshot..."
    gs_check_adb
    gs_check_device_connected
    
    local device_path="/sdcard/${filename}"
    
    if ! adb shell screencap -p "${device_path}"; then
        gs_error "Failed to capture screenshot"
    fi
    
    if ! adb pull "${device_path}" "${local_path}${filename}"; then
        gs_error "Failed to pull screenshot from device"
    fi
    
    # Cleanup device file
    adb shell rm "${device_path}" 2>/dev/null || true
    
    gs_success "Screenshot saved: ${local_path}${filename}"
}

function gs_android_adb_screenrecord() {
    local filename="${1:-recording_$(date +%Y%m%d_%H%M%S).mp4}"
    local duration="${2:-30}"
    local local_path="${3:-./}"
    
    gs_info "Starting screen recording for ${duration} seconds..."
    gs_check_adb
    gs_check_device_connected
    gs_validate_number "$duration" "duration"
    
    local device_path="/sdcard/${filename}"
    
    gs_info "Recording... Press Ctrl+C to stop early"
    if ! adb shell screenrecord --time-limit "${duration}" "${device_path}"; then
        gs_error "Failed to record screen"
    fi
    
    if ! adb pull "${device_path}" "${local_path}${filename}"; then
        gs_error "Failed to pull recording from device"
    fi
    
    # Cleanup device file
    adb shell rm "${device_path}" 2>/dev/null || true
    
    gs_success "Recording saved: ${local_path}${filename}"
}

# Log filtering functions with package-based filtering
function gs_android_adb_log_am_proc_start() {
    local package="${1:-}"
    gs_check_adb
    gs_check_device_connected
    
    if [[ -n "$package" ]]; then
        gs_info "Filtering am_proc_start logs for package: $package"
        adb logcat -v time | grep "am_proc_start" | grep "$package"
    else
        gs_info "Showing all am_proc_start logs"
        adb logcat -v time | grep "am_proc_start"
    fi
}

function gs_android_adb_log_am_proc_died() {
    local package="${1:-}"
    gs_check_adb
    gs_check_device_connected
    
    if [[ -n "$package" ]]; then
        gs_info "Filtering am_proc_died logs for package: $package"
        adb logcat -v time | grep "am_proc_died" | grep "$package"
    else
        gs_info "Showing all am_proc_died logs"
        adb logcat -v time | grep "am_proc_died"
    fi
}

function gs_android_adb_log_am_kill() {
    local package="${1:-}"
    gs_check_adb
    gs_check_device_connected
    
    if [[ -n "$package" ]]; then
        gs_info "Filtering am_kill logs for package: $package"
        adb logcat -v time | grep "am_kill" | grep "$package"
    else
        gs_info "Showing all am_kill logs"
        adb logcat -v time | grep "am_kill"
    fi
}

function gs_android_adb_log_am_anr() {
    local package="${1:-}"
    gs_check_adb
    gs_check_device_connected
    
    if [[ -n "$package" ]]; then
        gs_info "Filtering am_anr logs for package: $package"
        adb logcat -v time | grep "am_anr" | grep "$package"
    else
        gs_info "Showing all am_anr logs"
        adb logcat -v time | grep "am_anr"
    fi
}

function gs_android_adb_show_log() {
    local tag="${1:-}"
    local level="${2:-V}"
    
    gs_check_adb
    gs_check_device_connected
    gs_validate_choice "$level" "log level" "V" "D" "I" "W" "E" "F"
    
    if [[ -n "$tag" ]]; then
        gs_info "Showing logs for tag: $tag, level: $level"
        adb logcat -s "${tag}:${level}"
    else
        gs_info "Showing all logs with level: $level"
        adb logcat "*:${level}"
    fi
}

function gs_android_adb_clear_logcat() {
    gs_info "Clearing logcat buffer..."
    gs_check_adb
    gs_check_device_connected
    
    if ! adb logcat -c; then
        gs_error "Failed to clear logcat buffer"
    fi
    
    gs_success "Logcat buffer cleared"
}

function gs_android_adb_dump_version() {
    gs_info "Dumping Android version information..."
    gs_check_adb
    gs_check_device_connected
    
    echo "=== Android Version Information ==="
    echo "Build version: $(adb shell getprop ro.build.version.release 2>/dev/null || echo 'unknown')"
    echo "Build ID: $(adb shell getprop ro.build.id 2>/dev/null || echo 'unknown')"
    echo "SDK version: $(adb shell getprop ro.build.version.sdk 2>/dev/null || echo 'unknown')"
    echo "Device model: $(adb shell getprop ro.product.model 2>/dev/null || echo 'unknown')"
    echo "Device brand: $(adb shell getprop ro.product.brand 2>/dev/null || echo 'unknown')"
    echo "Device name: $(adb shell getprop ro.product.name 2>/dev/null || echo 'unknown')"
    echo "CPU ABI: $(adb shell getprop ro.product.cpu.abi 2>/dev/null || echo 'unknown')"
    echo "================================="
}

function gs_android_adb_settings_provider() {
    gs_info "Dumping SettingsProvider configuration..."
    gs_check_adb
    gs_check_device_connected
    
    adb shell dumpsys settings
}

function gs_android_adb_package_info() {
    local package="${1:-}"
    
    if [[ -z "$package" ]]; then
        echo "Usage: gs_android_adb_package_info <package_name>"
        echo "Example: gs_android_adb_package_info com.android.settings"
        return 1
    fi
    
    gs_info "Getting package information for: $package"
    gs_check_adb
    gs_check_device_connected
    
    echo "=== Package Information ==="
    echo "Package: $package"
    echo
    
    # Check if package is installed
    if ! adb shell pm list packages | grep -q "$package"; then
        gs_error "Package '$package' not found on device"
        return 1
    fi
    
    echo "Package details:"
    adb shell dumpsys package "$package" | head -20
    
    echo
    echo "Activities:"
    adb shell pm list packages -f | grep "$package"
    
    echo
    echo "Permissions:"
    adb shell pm dump "$package" | grep -A 5 "declared permissions"
}

function gs_android_adb_kill_package() {
    local package="${1:-}"
    
    if [[ -z "$package" ]]; then
        echo "Usage: gs_android_adb_kill_package <package_name>"
        return 1
    fi
    
    gs_info "Killing package: $package"
    gs_check_adb
    gs_check_device_connected
    
    if adb shell am force-stop "$package"; then
        gs_success "Package '$package' killed"
    else
        gs_error "Failed to kill package '$package'"
    fi
}

function gs_android_adb_clear_package() {
    local package="${1:-}"
    
    if [[ -z "$package" ]]; then
        echo "Usage: gs_android_adb_clear_package <package_name>"
        return 1
    fi
    
    gs_info "Clearing package data: $package"
    gs_check_adb
    gs_check_device_connected
    
    if gs_confirm "Clear all data for package '$package'?" "n"; then
        if adb shell pm clear "$package"; then
            gs_success "Package '$package' data cleared"
        else
            gs_error "Failed to clear package '$package' data"
        fi
    else
        gs_info "Operation cancelled"
    fi
}

function gs_android_adb_show_3rd_app() {
    gs_info "Listing third-party applications..."
    gs_check_adb
    gs_check_device_connected
    
    echo "=== Third-party Applications ==="
    adb shell pm list packages -3 | sed 's/package://' | sort
}

function gs_android_adb_show_system_app() {
    gs_info "Listing system applications..."
    gs_check_adb
    gs_check_device_connected
    
    echo "=== System Applications ==="
    adb shell pm list packages -s | sed 's/package://' | sort
}

function gs_android_adb_ps_grep() {
    local pattern="${1:-}"
    
    if [[ -z "$pattern" ]]; then
        echo "Usage: gs_android_adb_ps_grep <pattern>"
        echo "Show running processes matching pattern"
        return 1
    fi
    
    gs_info "Searching processes for: $pattern"
    gs_check_adb
    gs_check_device_connected
    
    echo "=== Process List (matching: $pattern) ==="
    adb shell ps | head -1  # Show header
    adb shell ps | grep -i "$pattern"
}

function gs_android_adb_kill_grep() {
    local pattern="${1:-}"
    
    if [[ -z "$pattern" ]]; then
        echo "Usage: gs_android_adb_kill_grep <pattern>"
        echo "Kill processes matching pattern"
        return 1
    fi
    
    gs_info "Finding processes matching: $pattern"
    gs_check_adb
    gs_check_device_connected
    
    local pids=($(adb shell ps | grep -i "$pattern" | awk '{print $2}' | grep -E '^[0-9]+$'))
    
    if [[ ${#pids[@]} -eq 0 ]]; then
        gs_warn "No processes found matching: $pattern"
        return 0
    fi
    
    echo "Found ${#pids[@]} processes:"
    adb shell ps | head -1
    adb shell ps | grep -i "$pattern"
    
    if gs_confirm "Kill these ${#pids[@]} processes?" "n"; then
        for pid in "${pids[@]}"; do
            gs_info "Killing PID: $pid"
            adb shell kill "$pid" 2>/dev/null || gs_warn "Failed to kill PID: $pid"
        done
        gs_success "Kill commands sent"
    else
        gs_info "Operation cancelled"
    fi
}

function gs_android_adb_imei() {
    gs_info "Getting device IMEI..."
    gs_check_adb
    gs_check_device_connected
    
    echo "=== Device IMEI Information ==="
    adb shell service call iphonesubinfo 1 2>/dev/null | \
    cut -d "'" -f2 | grep -E '^[0-9]{15}$' || \
    echo "IMEI not available or permission denied"
}

function gs_android_adb_connect() {
    local ip_port="${1:-}"
    
    if [[ -z "$ip_port" ]]; then
        echo "Usage: gs_android_adb_connect <ip:port>"
        echo "Example: gs_android_adb_connect 192.168.1.100:5555"
        return 1
    fi
    
    gs_info "Connecting to ADB over TCP: $ip_port"
    
    if adb connect "$ip_port"; then
        gs_success "Connected to $ip_port"
        echo
        gs_info "Connected devices:"
        adb devices
    else
        gs_error "Failed to connect to $ip_port"
    fi
}

function gs_android_adb_disconnect() {
    local ip_port="${1:-}"
    
    gs_info "Disconnecting ADB..."
    
    if [[ -n "$ip_port" ]]; then
        adb disconnect "$ip_port"
    else
        adb disconnect
    fi
    
    gs_success "ADB disconnected"
    echo
    gs_info "Remaining devices:"
    adb devices
}

# Surface Flinger refresh rate functions
function gs_android_adb_sf_show_refresh_rate() {
    gs_info "Getting current refresh rate..."
    gs_check_adb
    gs_check_device_connected
    
    echo "=== Display Refresh Rate ==="
    adb shell dumpsys SurfaceFlinger | grep -i refresh || \
    adb shell dumpsys display | grep -i refresh || \
    echo "Refresh rate information not available"
}

function gs_android_adb_sf_set_refresh_rate() {
    local rate="${1:-}"
    
    if [[ -z "$rate" ]]; then
        echo "Usage: gs_android_adb_sf_set_refresh_rate <rate>"
        echo "Example: gs_android_adb_sf_set_refresh_rate 60"
        return 1
    fi
    
    gs_validate_number "$rate" "refresh rate"
    
    gs_info "Setting refresh rate to: ${rate}Hz"
    gs_check_adb
    gs_check_device_connected
    
    # Try different methods based on Android version
    if adb shell cmd display set-forced-display-density "$rate" 2>/dev/null; then
        gs_success "Refresh rate set to ${rate}Hz"
    elif adb shell service call SurfaceFlinger 1035 i32 "$rate" 2>/dev/null; then
        gs_success "Refresh rate set to ${rate}Hz (via SurfaceFlinger)"
    else
        gs_warn "Unable to set refresh rate. May require root access."
    fi
}

function gs_android_adb_sf_dump_refresh_rate() {
    gs_info "Dumping detailed refresh rate information..."
    gs_check_adb
    gs_check_device_connected
    
    echo "=== SurfaceFlinger Refresh Rate Details ==="
    adb shell dumpsys SurfaceFlinger | grep -A 10 -B 10 -i "refresh\|vsync\|fps"
}



# Legacy helper functions for specific services (kept for backward compatibility)
function gs_android_adb_i007service_start() {
    gs_info "Starting I007Service..."
    gs_check_adb
    gs_check_device_connected
    adb shell am start-service com.journeyOS.i007Service/.I007Service
}

function gs_android_adb_i007service_dump() {
    gs_info "Dumping I007Service state..."
    gs_check_adb
    gs_check_device_connected
    adb shell dumpsys activity service com.journeyOS.i007Service
}