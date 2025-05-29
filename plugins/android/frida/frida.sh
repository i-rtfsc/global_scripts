#!/bin/bash
# -*- coding: utf-8 -*-
# -*- encoding: utf-8 -*-
#
# Android Frida Submodule
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

_gs_android_frida_check_python() {
    if ! command -v python3 >/dev/null 2>&1; then
        echo "错误: 缺少必需命令: python3" >&2
        echo "建议: 请安装Python 3" >&2
        return 1
    fi
    return 0
}

_gs_android_frida_get_device_arch() {
    local arch=$(adb shell getprop ro.product.cpu.abi | tr -d '\r')
    echo "$arch"
}

gs_android_frida_inject() {
    local process_name="${1:-system_server}"
    local script_file="${2:-}"
    local device_id="${3:-}"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_android_frida_inject_help
                return 0
                ;;
            -p|--process)
                process_name="$2"
                shift 2
                ;;
            -f|--file)
                script_file="$2"
                shift 2
                ;;
            -d|--device)
                device_id="$2"
                shift 2
                ;;
            *)
                if [[ -z "$script_file" ]]; then
                    script_file="$1"
                fi
                shift
                ;;
        esac
    done
    
    if [[ -z "$script_file" ]]; then
        echo "错误: 缺少必需参数" >&2
        echo "使用方式: gs-android-frida-inject [-p 进程名] -f <脚本文件>" >&2
        echo "使用 'gs-android-frida-inject --help' 查看详细帮助" >&2
        return 1
    fi
    
    _gs_android_check_adb || return 2
    _gs_android_frida_check_python || return 2
    _gs_android_check_device || return 1
    
    # 如果脚本文件不存在，尝试从插件目录查找
    if [[ ! -f "$script_file" ]]; then
        local script_dir
        if [[ -n "$_GS_ROOT_PATH" ]]; then
            script_dir="$_GS_ROOT_PATH/plugins/android/frida"
        else
            script_dir="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" 
        fi
        
        local alt_script="${script_dir}/${script_file}"
        if [[ -f "$alt_script" ]]; then
            script_file="$alt_script"
        else
            echo "错误: 脚本文件不存在: $script_file" >&2
            return 1
        fi
    fi
    
    local resolved_device_id
    resolved_device_id=$(_gs_android_resolve_device "$device_id")
    
    local pid
    pid=$(_gs_android_execute "$resolved_device_id" shell pidof "$process_name" 2>/dev/null | tr -d '\r')
    
    if [[ -z "$pid" ]]; then
        echo "错误: 进程 '$process_name' 未找到" >&2
        echo "建议: 检查进程名是否正确或进程是否正在运行" >&2
        return 1
    fi
    
    echo "目标进程: $process_name (PID: $pid)"
    echo "脚本文件: $script_file"
    
    # 检查并安装frida-inject
    if ! _gs_android_execute "$resolved_device_id" shell "ls /data/local/frida/frida-inject" >/dev/null 2>&1; then
        echo "frida-inject不存在，正在安装..."
        
        local script_dir
        if [[ -n "$_GS_ROOT_PATH" ]]; then
            script_dir="$_GS_ROOT_PATH/plugins/android/frida"
        else
            script_dir="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
        fi
        
        local frida_inject="${script_dir}/frida-inject"
        if [[ ! -f "$frida_inject" ]]; then
            echo "错误: frida-inject二进制文件不存在: $frida_inject" >&2
            return 2
        fi
        
        _gs_android_execute "$resolved_device_id" root && _gs_android_execute "$resolved_device_id" remount
        _gs_android_execute "$resolved_device_id" shell "mkdir -p /data/local/frida"
        
        if _gs_android_execute "$resolved_device_id" push "$frida_inject" "/data/local/frida/frida-inject"; then
            _gs_android_execute "$resolved_device_id" shell "chmod a+x /data/local/frida/frida-inject"
            echo "frida-inject安装成功"
        else
            echo "错误: frida-inject安装失败" >&2
            return 2
        fi
    else
        echo "frida-inject已存在"
        _gs_android_execute "$resolved_device_id" shell "chmod a+x /data/local/frida/frida-inject"
    fi
    
    local remote_script="/data/local/frida/$(basename "$script_file")"
    
    if _gs_android_execute "$resolved_device_id" push "$script_file" "$remote_script"; then
        echo "脚本上传成功，开始注入..."
        
        if _gs_android_execute "$resolved_device_id" shell "/data/local/frida/frida-inject -p $pid -s $remote_script"; then
            echo "Frida注入完成"
            return 0
        else
            echo "错误: Frida注入失败" >&2
            return 2
        fi
    else
        echo "错误: 脚本上传失败" >&2
        return 2
    fi
}

_show_android_frida_inject_help() {
    cat << 'EOF'
gs_android_frida_inject - Android Frida脚本注入

功能描述:
  将Frida JavaScript脚本注入到Android设备的指定进程中

使用方式:
  gs-android-frida-inject [-p 进程名] -f <脚本文件> [-d 设备ID]

参数:
  脚本文件       要注入的Frida JavaScript文件（必需）

选项:
  -p, --process  目标进程名，默认system_server
  -f, --file     指定脚本文件路径
  -d, --device   指定设备ID
  --help, -h     显示此帮助信息

示例:
  gs-android-frida-inject -f hook.js
  gs-android-frida-inject -p com.example.app -f trace.js
  gs-android-frida-inject -p system_server -f monitor.js -d emulator-5554
  gs-android-frida-inject --help

依赖:
  系统命令: adb, python3
  插件依赖: android
  设备工具: frida-inject

注意事项:
  - 需要在设备上安装frida-inject
  - 目标进程必须正在运行
  - 某些系统进程可能需要root权限
EOF
}

gs_android_frida_server() {
    local action="${1:-start}"
    local device_id="${2:-}"
    
    if [[ "$action" == "--help" || "$action" == "-h" ]]; then
        _show_android_frida_server_help
        return 0
    fi
    
    _gs_android_frida_check_deps || return 2
    _gs_android_frida_check_device || return 1
    
    local adb_cmd="adb"
    if [[ -n "$device_id" ]]; then
        adb_cmd="adb -s $device_id"
    fi
    
    case "$action" in
        "start")
            echo "启动Frida Server..."
            
            if $adb_cmd shell "ps | grep frida-server" >/dev/null 2>&1; then
                echo "Frida Server已在运行"
                return 0
            fi
            
            $adb_cmd root && $adb_cmd remount
            
            # 检查并安装frida-server
            if ! $adb_cmd shell "ls /data/local/frida/frida-server" >/dev/null 2>&1; then
                echo "frida-server不存在，正在安装..."
                
                local script_dir
                if [[ -n "$_GS_ROOT_PATH" ]]; then
                    script_dir="$_GS_ROOT_PATH/plugins/android/frida"
                else
                    script_dir="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
                fi
                
                # 注意：这里原始代码有问题，尝试修复
                local frida_server="${script_dir}/frida-server"
                if [[ ! -f "$frida_server" ]]; then
                    # 如果没有frida-server，提示用户手动下载
                    echo "错误: frida-server二进制文件不存在: $frida_server" >&2
                    echo "建议: 请从https://github.com/frida/frida/releases下载frida-server" >&2
                    return 2
                fi
                
                $adb_cmd shell "mkdir -p /data/local/frida"
                
                if $adb_cmd push "$frida_server" "/data/local/frida/frida-server"; then
                    $adb_cmd shell "chmod a+x /data/local/frida/frida-server"
                    echo "frida-server安装成功"
                else
                    echo "错误: frida-server安装失败" >&2
                    return 2
                fi
            else
                echo "frida-server已存在"
                $adb_cmd shell "chmod a+x /data/local/frida/frida-server"
            fi
            
            if $adb_cmd shell "/data/local/frida/frida-server &" ; then
                sleep 2
                if $adb_cmd shell "ps | grep frida-server" >/dev/null 2>&1; then
                    echo "Frida Server启动成功"
                    return 0
                else
                    echo "错误: Frida Server启动失败" >&2
                    return 2
                fi
            else
                echo "错误: 无法启动Frida Server" >&2
                return 2
            fi
            ;;
        "stop")
            echo "停止Frida Server..."
            local pids
            pids=($($adb_cmd shell "ps | grep frida-server | awk '{print \$2}'" | tr -d '\r'))
            
            if [[ ${#pids[@]} -eq 0 ]]; then
                echo "Frida Server未运行"
                return 0
            fi
            
            for pid in "${pids[@]}"; do
                if [[ -n "$pid" ]]; then
                    $adb_cmd shell "kill -9 $pid"
                fi
            done
            
            echo "Frida Server已停止"
            return 0
            ;;
        "status")
            echo "检查Frida Server状态..."
            if $adb_cmd shell "ps | grep frida-server" >/dev/null 2>&1; then
                echo "Frida Server: 运行中"
                $adb_cmd shell "ps | grep frida-server"
                return 0
            else
                echo "Frida Server: 未运行"
                return 1
            fi
            ;;
        *)
            echo "错误: 不支持的操作: $action" >&2
            echo "支持的操作: start, stop, status" >&2
            return 1
            ;;
    esac
}

_show_android_frida_server_help() {
    cat << 'EOF'
gs_android_frida_server - 管理Android设备上的Frida Server

功能描述:
  启动、停止或检查Android设备上Frida Server的运行状态

使用方式:
  gs-android-frida-server [操作] [设备ID]

参数:
  操作           start(启动), stop(停止), status(状态)，默认start（可选）

选项:
  设备ID         指定设备ID，多设备时必需（可选）
  --help, -h     显示此帮助信息

示例:
  gs-android-frida-server start
  gs-android-frida-server stop
  gs-android-frida-server status
  gs-android-frida-server start emulator-5554
  gs-android-frida-server --help

依赖:
  系统命令: adb
  插件依赖: android
  设备工具: frida-server

注意事项:
  - 需要在设备上安装frida-server
  - 启动需要root权限
  - Server运行在后台，占用端口27042
EOF
}

gs_android_frida_ps() {
    local device_id="${1:-}"
    
    if [[ "$device_id" == "--help" || "$device_id" == "-h" ]]; then
        _show_android_frida_ps_help
        return 0
    fi
    
    _gs_android_frida_check_deps || return 2
    _gs_android_frida_check_device || return 1
    
    if ! command -v frida-ps >/dev/null 2>&1; then
        echo "错误: 缺少frida-ps命令" >&2
        echo "建议: 请安装Frida工具集 (pip install frida-tools)" >&2
        return 2
    fi
    
    local frida_cmd="frida-ps -U"
    if [[ -n "$device_id" ]]; then
        frida_cmd="frida-ps -D $device_id"
    fi
    
    echo "获取设备进程列表..."
    
    if $frida_cmd; then
        return 0
    else
        echo "错误: 无法获取进程列表" >&2
        echo "建议: 检查Frida Server是否正在运行" >&2
        return 2
    fi
}

_show_android_frida_ps_help() {
    cat << 'EOF'
gs_android_frida_ps - 显示Android设备进程列表

功能描述:
  通过Frida获取Android设备的进程列表，包括应用名称和PID

使用方式:
  gs-android-frida-ps [设备ID]

参数:
  设备ID         指定设备ID，默认使用USB设备（可选）

选项:
  --help, -h     显示此帮助信息

示例:
  gs-android-frida-ps
  gs-android-frida-ps emulator-5554
  gs-android-frida-ps --help

依赖:
  系统命令: frida-ps
  插件依赖: android, frida-tools
  设备工具: frida-server

注意事项:
  - 需要Frida Server在设备上运行
  - 需要安装frida-tools Python包
  - 显示可hook的进程信息
EOF
}

gs_android_frida_trace() {
    local package_name="${1:-}"
    local trace_pattern="${2:-*}"
    local device_id="${3:-}"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_android_frida_trace_help
                return 0
                ;;
            -p|--package)
                package_name="$2"
                shift 2
                ;;
            -t|--trace)
                trace_pattern="$2"
                shift 2
                ;;
            -d|--device)
                device_id="$2"
                shift 2
                ;;
            *)
                if [[ -z "$package_name" ]]; then
                    package_name="$1"
                fi
                shift
                ;;
        esac
    done
    
    if [[ -z "$package_name" ]]; then
        echo "错误: 缺少必需参数" >&2
        echo "使用方式: gs-android-frida-trace <包名> [选项]" >&2
        echo "使用 'gs-android-frida-trace --help' 查看详细帮助" >&2
        return 1
    fi
    
    _gs_android_frida_check_deps || return 2
    _gs_android_frida_check_device || return 1
    
    if ! command -v frida-trace >/dev/null 2>&1; then
        echo "错误: 缺少frida-trace命令" >&2
        echo "建议: 请安装Frida工具集 (pip install frida-tools)" >&2
        return 2
    fi
    
    local frida_cmd="frida-trace -U"
    if [[ -n "$device_id" ]]; then
        frida_cmd="frida-trace -D $device_id"
    fi
    
    echo "开始跟踪应用: $package_name"
    echo "跟踪模式: $trace_pattern"
    echo "按Ctrl+C停止跟踪"
    
    if $frida_cmd -f "$package_name" -i "$trace_pattern"; then
        return 0
    else
        echo "错误: 跟踪失败" >&2
        echo "建议: 检查应用是否存在和Frida Server状态" >&2
        return 2
    fi
}

gs_android_frida_kill() {
    local device_id="${1:-}"
    
    if [[ "$device_id" == "--help" || "$device_id" == "-h" ]]; then
        _show_android_frida_kill_help
        return 0
    fi
    
    _gs_android_frida_check_deps || return 2
    _gs_android_frida_check_device || return 1
    
    local adb_cmd="adb"
    if [[ -n "$device_id" ]]; then
        adb_cmd="adb -s $device_id"
    fi
    
    echo "终止所有Frida进程..."
    local pids
    pids=($($adb_cmd shell "ps | grep frida | awk '{print \$2}'" | tr -d '\r'))
    
    if [[ ${#pids[@]} -eq 0 ]]; then
        echo "没有运行的Frida进程"
        return 0
    fi
    
    for pid in "${pids[@]}"; do
        if [[ -n "$pid" ]]; then
            $adb_cmd shell "kill -9 $pid"
            echo "已终止PID: $pid"
        fi
    done
    
    echo "所有Frida进程已终止"
    return 0
}

_show_android_frida_kill_help() {
    cat << 'EOF'
gs_android_frida_kill - 终止Android设备上的Frida进程

功能描述:
  终止Android设备上所有运行的Frida相关进程

使用方式:
  gs-android-frida-kill [设备ID]

参数:
  设备ID         指定设备ID，多设备时必需（可选）

选项:
  --help, -h     显示此帮助信息

示例:
  gs-android-frida-kill
  gs-android-frida-kill emulator-5554
  gs-android-frida-kill --help

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - 会终止所有Frida相关进程
  - 包括frida-server和frida-inject
  - 用于清理Frida环境
EOF
}

gs_android_frida_template() {
    local template_name="${1:-android-template}"
    local device_id="${2:-}"
    
    if [[ "$template_name" == "--help" || "$template_name" == "-h" ]]; then
        _show_android_frida_template_help
        return 0
    fi
    
    _gs_android_frida_check_deps || return 2
    
    local script_dir
    if [[ -n "$_GS_ROOT_PATH" ]]; then
        script_dir="$_GS_ROOT_PATH/plugins/android/frida"
    else
        script_dir="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" 
    fi
    
    local template_file="${script_dir}/${template_name}.js"
    
    if [[ ! -f "$template_file" ]]; then
        echo "错误: 模板文件不存在: $template_file" >&2
        echo "可用模板:"
        ls "$script_dir"/*.js 2>/dev/null | xargs -n1 basename | sed 's/\.js$//' | sed 's/^/  /'
        return 1
    fi
    
    echo "使用模板: $template_name"
    echo "模板路径: $template_file"
    
    gs_android_frida_inject "system_server" "$template_file" "$device_id"
}

_show_android_frida_template_help() {
    cat << 'EOF'
gs_android_frida_template - 使用预定义Frida模板脚本

功能描述:
  快速使用预定义的Frida JavaScript模板进行常见的hook操作

使用方式:
  gs-android-frida-template [模板名] [设备ID]

参数:
  模板名         要使用的模板名称，默认android-template（可选）
  设备ID         指定设备ID，多设备时必需（可选）

选项:
  --help, -h     显示此帮助信息

可用模板:
  android-template          - 基础模板和工具函数
  android-app-info         - 应用信息获取
  android-broadcast        - 广播监控
  android-click            - 点击事件监控
  android-database         - 数据库操作监控
  android-settings-provider - Settings Provider监控
  android-system-property  - 系统属性监控
  android-trace            - 方法调用跟踪
  android-ui               - UI相关监控
  android-binder-transactions - Binder事务监控

示例:
  gs-android-frida-template
  gs-android-frida-template android-app-info
  gs-android-frida-template android-trace emulator-5554
  gs-android-frida-template --help

依赖:
  系统命令: adb
  插件依赖: android
  设备工具: frida-inject

注意事项:
  - 模板文件位于frida子模块目录
  - 默认注入到system_server进程
  - 可配合其他frida命令使用
EOF
}

_show_android_frida_trace_help() {
    cat << 'EOF'
gs_android_frida_trace - Android应用函数跟踪

功能描述:
  使用Frida跟踪Android应用的函数调用，实时显示调用信息

使用方式:
  gs-android-frida-trace <包名> [选项]

参数:
  包名           要跟踪的应用包名（必需）

选项:
  -t, --trace    跟踪模式，支持通配符，默认*
  -d, --device   指定设备ID
  --help, -h     显示此帮助信息

示例:
  gs-android-frida-trace com.example.app
  gs-android-frida-trace com.example.app -t "java.io.*"
  gs-android-frida-trace com.example.app -t "open*" -d emulator-5554
  gs-android-frida-trace --help

依赖:
  系统命令: frida-trace
  插件依赖: android, frida-tools
  设备工具: frida-server

注意事项:
  - 需要Frida Server在设备上运行
  - 会自动启动目标应用
  - 按Ctrl+C停止跟踪
  - 支持Java和Native函数跟踪
EOF
}