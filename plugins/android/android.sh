#!/bin/bash
# -*- coding: utf-8 -*-
# -*- encoding: utf-8 -*-
#
# Android Plugin Main Entry
# Copyright (c) 2024 Solo
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

# =============================================================================
# 公共设备管理函数 - 供所有子模块使用
# =============================================================================

_gs_android_check_adb() {
    if ! command -v adb >/dev/null 2>&1; then
        echo "错误: 缺少必需命令: adb" >&2
        echo "建议: 请安装Android SDK Platform Tools" >&2
        return 1
    fi
    return 0
}

_gs_android_check_device() {
    local device_count=$(adb devices | grep -c "device$")
    if [[ $device_count -eq 0 ]]; then
        echo "错误: 没有连接的设备" >&2
        echo "建议: 请连接设备并启用USB调试" >&2
        return 1
    fi
    return 0
}

_gs_android_cache_device() {
    local device_id="$1"
    local cache_file="${HOME}/.gs_android_device_cache"
    
    if [[ -n "$device_id" ]]; then
        echo "$device_id" > "$cache_file"
    fi
}

_gs_android_get_cached_device() {
    local cache_file="${HOME}/.gs_android_device_cache"
    
    if [[ -f "$cache_file" ]]; then
        cat "$cache_file"
    fi
}

_gs_android_get_default_device() {
    local first_device
    first_device=$(adb devices 2>/dev/null | grep -E "device$" | head -1 | awk '{print $1}')
    
    if [[ -n "$first_device" ]]; then
        echo "$first_device"
    else
        echo "No devices found" >&2
        return 1
    fi
}

_gs_android_resolve_device() {
    local input_device_id="${1:-}"
    local resolved_device_id=""
    
    if [[ -n "$input_device_id" ]]; then
        resolved_device_id="$input_device_id"
        _gs_android_cache_device "$resolved_device_id"
    else
        local cached_device
        cached_device=$(_gs_android_get_cached_device)
        
        if [[ -n "$cached_device" ]] && adb devices | grep -q "$cached_device.*device$"; then
            resolved_device_id="$cached_device"
        else
            resolved_device_id=$(_gs_android_get_default_device)
            if [[ -n "$resolved_device_id" ]]; then
                _gs_android_cache_device "$resolved_device_id"
            fi
        fi
    fi
    
    echo "$resolved_device_id"
}

_gs_android_validate_device() {
    local device_id="${1:-}"
    local resolved_device_id
    
    resolved_device_id=$(_gs_android_resolve_device "$device_id")
    
    if [[ -z "$resolved_device_id" ]]; then
        echo "错误: 没有连接的设备" >&2
        echo "建议: 请连接设备并启用USB调试" >&2
        return 1
    fi
    
    if ! adb devices | grep -q "$resolved_device_id.*device$"; then
        echo "错误: 设备 '$resolved_device_id' 未连接或状态异常" >&2
        echo "建议: 使用 'gs-android-devices' 查看设备状态" >&2
        return 1
    fi
    
    echo "$resolved_device_id"
    return 0
}

_gs_android_execute() {
    local device_id="$1"
    shift
    
    if [[ -n "$device_id" ]]; then
        adb -s "$device_id" "$@"
    else
        adb "$@"
    fi
}

# =============================================================================
# 主插件功能函数
# =============================================================================

gs_android_devices() {
    if [[ "$1" == "--help" || "$1" == "-h" ]]; then
        _show_android_devices_help
        return 0
    fi
    
    _gs_android_check_adb || return 2
    
    echo "已连接的Android设备:"
    adb devices -l
    return 0
}

_show_android_devices_help() {
    cat << 'EOF'
gs_android_devices - 显示已连接的Android设备

功能描述:
  显示所有通过ADB连接的Android设备列表，包括设备ID和状态信息

使用方式:
  gs-android-devices [选项]

选项:
  --help, -h     显示此帮助信息

示例:
  gs-android-devices
  gs-android-devices --help

依赖:
  系统命令: adb
  插件依赖: system

注意事项:
  - 需要启用USB调试模式
  - 确保设备已通过USB连接或网络连接
EOF
}

gs_android_connect() {
    local device_ip="${1:-}"
    local port="${2:-5555}"
    
    if [[ "$device_ip" == "--help" || "$device_ip" == "-h" ]]; then
        _show_android_connect_help
        return 0
    fi
    
    if [[ $# -eq 0 ]]; then
        echo "错误: 缺少必需参数" >&2
        echo "使用方式: gs-android-connect <设备IP> [端口]" >&2
        echo "使用 'gs-android-connect --help' 查看详细帮助" >&2
        return 1
    fi
    
    _gs_android_check_adb || return 2
    
    echo "正在连接到设备: $device_ip:$port"
    
    if adb connect "$device_ip:$port"; then
        echo "设备连接成功"
        return 0
    else
        echo "错误: 设备连接失败" >&2
        echo "建议: 检查设备IP地址和网络连接" >&2
        return 2
    fi
}

_show_android_connect_help() {
    cat << 'EOF'
gs_android_connect - 通过网络连接Android设备

功能描述:
  使用TCP/IP方式连接Android设备，适用于无线调试场景

使用方式:
  gs-android-connect <设备IP> [端口]

参数:
  设备IP         目标设备的IP地址（必需）
  端口           连接端口，默认5555（可选）

选项:
  --help, -h     显示此帮助信息

示例:
  gs-android-connect 192.168.1.100
  gs-android-connect 192.168.1.100 5555
  gs-android-connect --help

依赖:
  系统命令: adb
  插件依赖: system

注意事项:
  - 设备需要先通过USB启用网络调试
  - 确保设备和主机在同一网络
  - 首次连接可能需要在设备上确认
EOF
}

gs_android_info() {
    local device_id="${1:-}"
    
    if [[ "$device_id" == "--help" || "$device_id" == "-h" ]]; then
        _show_android_info_help
        return 0
    fi
    
    _gs_android_check_adb || return 2
    _gs_android_check_device || return 1
    
    local resolved_device_id
    resolved_device_id=$(_gs_android_resolve_device "$device_id")
    
    echo "=== Android设备信息 ==="
    echo "设备型号: $(_gs_android_execute "$resolved_device_id" shell getprop ro.product.model)"
    echo "制造商: $(_gs_android_execute "$resolved_device_id" shell getprop ro.product.manufacturer)"
    echo "Android版本: $(_gs_android_execute "$resolved_device_id" shell getprop ro.build.version.release)"
    echo "API级别: $(_gs_android_execute "$resolved_device_id" shell getprop ro.build.version.sdk)"
    echo "设备ID: $(_gs_android_execute "$resolved_device_id" shell getprop ro.serialno)"
    echo "CPU架构: $(_gs_android_execute "$resolved_device_id" shell getprop ro.product.cpu.abi)"
    echo "设备名称: $(_gs_android_execute "$resolved_device_id" shell getprop ro.product.device)"
    
    return 0
}

_show_android_info_help() {
    cat << 'EOF'
gs_android_info - 显示Android设备详细信息

功能描述:
  显示连接设备的详细系统信息，包括型号、版本、制造商等

使用方式:
  gs-android-info [设备ID]

参数:
  设备ID         指定设备ID，留空则使用默认设备（可选）

选项:
  --help, -h     显示此帮助信息

示例:
  gs-android-info
  gs-android-info emulator-5554
  gs-android-info --help

依赖:
  系统命令: adb
  插件依赖: system

注意事项:
  - 设备必须已连接并授权
  - 如有多个设备，建议指定设备ID
EOF
}

gs_android_shell() {
    local device_id=""
    local shell_cmd=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_android_shell_help
                return 0
                ;;
            -d|--device)
                device_id="$2"
                shift 2
                ;;
            *)
                shell_cmd="$*"
                break
                ;;
        esac
    done
    
    _gs_android_check_adb || return 2
    _gs_android_check_device || return 1
    
    local resolved_device_id
    resolved_device_id=$(_gs_android_resolve_device "$device_id")
    
    if [[ -n "$shell_cmd" ]]; then
        _gs_android_execute "$resolved_device_id" shell "$shell_cmd"
    else
        _gs_android_execute "$resolved_device_id" shell
    fi
    
    return 0
}

_show_android_shell_help() {
    cat << 'EOF'
gs_android_shell - 执行Android设备shell命令

功能描述:
  在Android设备上执行shell命令或进入交互式shell

使用方式:
  gs-android-shell [-d 设备ID] [命令]

参数:
  命令           要执行的shell命令（可选）

选项:
  -d, --device   指定设备ID
  --help, -h     显示此帮助信息

示例:
  gs-android-shell
  gs-android-shell "ls -la /system"
  gs-android-shell -d emulator-5554 "ps aux"
  gs-android-shell --help

依赖:
  系统命令: adb
  插件依赖: system

注意事项:
  - 设备必须已连接并授权
  - 某些命令可能需要root权限
  - 交互式shell用exit退出
EOF
}