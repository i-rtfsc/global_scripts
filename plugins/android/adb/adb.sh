#!/bin/bash
# -*- coding: utf-8 -*-
# -*- encoding: utf-8 -*-
#
# Android ADB Submodule
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

gs_android_adb_screenshot() {
    local filename="${1:-screenshot}"
    local device_id="${2:-}"
    
    if [[ "$filename" == "--help" || "$filename" == "-h" ]]; then
        _show_android_adb_screenshot_help
        return 0
    fi
    
    _gs_android_check_adb || return 2
    _gs_android_check_device || return 1
    
    local resolved_device_id
    resolved_device_id=$(_gs_android_validate_device "$device_id")
    if [[ $? -ne 0 ]]; then
        return 1
    fi
    
    local remote_path="/sdcard/${filename}.png"
    local local_path="${filename}.png"
    
    echo "正在截屏到: $local_path (设备: $resolved_device_id)"
    
    if _gs_android_execute "$resolved_device_id" shell screencap -p "$remote_path" && \
       _gs_android_execute "$resolved_device_id" pull "$remote_path" "$local_path"; then
        _gs_android_execute "$resolved_device_id" shell rm "$remote_path"
        echo "截屏成功: $local_path"
        return 0
    else
        echo "错误: 截屏失败" >&2
        return 2
    fi
}

_show_android_adb_screenshot_help() {
    cat << 'EOF'
gs_android_adb_screenshot - Android设备截屏

功能描述:
  对Android设备进行截屏，并将截图保存到本地

使用方式:
  gs-android-adb-screenshot [文件名] [设备ID]

参数:
  文件名         截图文件名，不需要扩展名，默认screenshot（可选）
  设备ID         指定设备ID，多设备时必需（可选）

选项:
  --help, -h     显示此帮助信息

示例:
  gs-android-adb-screenshot
  gs-android-adb-screenshot myscreen
  gs-android-adb-screenshot myscreen emulator-5554
  gs-android-adb-screenshot --help

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - 设备必须已连接并授权
  - 会自动清理设备上的临时文件
  - 截图保存为PNG格式
EOF
}

gs_android_adb_screenrecord() {
    local filename="${1:-screenrecord}"
    local duration="${2:-30}"
    local device_id="${3:-}"
    
    if [[ "$filename" == "--help" || "$filename" == "-h" ]]; then
        _show_android_adb_screenrecord_help
        return 0
    fi
    
    if ! command -v adb >/dev/null 2>&1; then
        echo "错误: 缺少必需命令: adb" >&2
        return 2
    fi
    
    _gs_android_check_device || return 1
    
    local resolved_device_id
    resolved_device_id=$(_gs_android_resolve_device "$device_id")
    
    local remote_path="/sdcard/${filename}.mp4"
    local local_path="${filename}.mp4"
    
    echo "开始录屏，时长: ${duration}秒"
    echo "录制中... (按Ctrl+C提前停止)"
    
    if _gs_android_adb_execute "$device_id" shell screenrecord --time-limit "$duration" "$remote_path"; then
        echo "录屏完成，正在传输..."
        if _gs_android_adb_execute "$device_id" pull "$remote_path" "$local_path"; then
            _gs_android_adb_execute "$device_id" shell rm "$remote_path"
            echo "录屏成功: $local_path"
            return 0
        fi
    fi
    
    echo "错误: 录屏失败" >&2
    return 2
}

_show_android_adb_screenrecord_help() {
    cat << 'EOF'
gs_android_adb_screenrecord - Android设备录屏

功能描述:
  对Android设备进行录屏，并将视频保存到本地

使用方式:
  gs-android-adb-screenrecord [文件名] [时长] [设备ID]

参数:
  文件名         录屏文件名，不需要扩展名，默认screenrecord（可选）
  时长           录制时长（秒），默认30秒（可选）
  设备ID         指定设备ID，多设备时必需（可选）

选项:
  --help, -h     显示此帮助信息

示例:
  gs-android-adb-screenrecord
  gs-android-adb-screenrecord demo 60
  gs-android-adb-screenrecord demo 60 emulator-5554
  gs-android-adb-screenrecord --help

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - 设备必须已连接并授权
  - 需要Android 4.4+支持
  - 录制期间设备保持唤醒
  - 可以按Ctrl+C提前停止录制
EOF
}

gs_android_adb_logcat() {
    local package_name="${1:-}"
    local device_id="${2:-}"
    local filter_level="V"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_android_adb_logcat_help
                return 0
                ;;
            -p|--package)
                package_name="$2"
                shift 2
                ;;
            -d|--device)  
                device_id="$2"
                shift 2
                ;;
            -l|--level)
                filter_level="$2"
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
    
    if ! command -v adb >/dev/null 2>&1; then
        echo "错误: 缺少必需命令: adb" >&2
        return 2
    fi
    
    _gs_android_check_device || return 1
    
    local resolved_device_id
    resolved_device_id=$(_gs_android_resolve_device "$device_id")
    
    if [[ -n "$package_name" ]]; then
        local pid
        pid=$(_gs_android_execute "$resolved_device_id" shell pidof "$package_name" 2>/dev/null)
        if [[ -n "$pid" ]]; then
            echo "正在监控应用日志: $package_name (PID: $pid)"
            _gs_android_execute "$resolved_device_id" logcat --pid="$pid"
        else
            echo "正在监控应用日志: $package_name (使用grep过滤)"
            _gs_android_execute "$resolved_device_id" logcat -v threadtime | grep -i "$package_name"
        fi
    else
        echo "正在监控系统日志 (过滤级别: $filter_level)"
        _gs_android_execute "$resolved_device_id" logcat -v threadtime "*:$filter_level"
    fi
    
    return 0
}

_show_android_adb_logcat_help() {
    cat << 'EOF'
gs_android_adb_logcat - Android日志监控

功能描述:
  实时监控Android设备的日志输出，支持应用过滤和级别过滤

使用方式:
  gs-android-adb-logcat [-p 包名] [-l 级别] [-d 设备ID]
  gs-android-adb-logcat [包名] [设备ID]

参数:
  包名           要监控的应用包名（可选）

选项:
  -p, --package  指定应用包名
  -l, --level    日志级别(V|D|I|W|E)，默认V
  -d, --device   指定设备ID
  --help, -h     显示此帮助信息

示例:
  gs-android-adb-logcat
  gs-android-adb-logcat com.example.app
  gs-android-adb-logcat -p com.example.app -l I
  gs-android-adb-logcat -d emulator-5554
  gs-android-adb-logcat --help

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - 按Ctrl+C停止监控
  - 日志级别: V(详细) D(调试) I(信息) W(警告) E(错误)
  - 指定包名时优先使用PID过滤
EOF
}

gs_android_adb_install() {
    local apk_path="${1:-}"
    local device_id="${2:-}"
    local install_flags="-r"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_android_adb_install_help
                return 0
                ;;
            -d|--device)
                device_id="$2"
                shift 2
                ;;
            -f|--force)
                install_flags="-r -d"
                shift
                ;;
            --test)
                install_flags="-r -t"
                shift
                ;;
            *)
                if [[ -z "$apk_path" ]]; then
                    apk_path="$1"
                fi
                shift
                ;;
        esac
    done
    
    if [[ -z "$apk_path" ]]; then
        echo "错误: 缺少必需参数" >&2
        echo "使用方式: gs-android-adb-install <APK路径> [选项]" >&2
        echo "使用 'gs-android-adb-install --help' 查看详细帮助" >&2
        return 1
    fi
    
    if [[ ! -f "$apk_path" ]]; then
        echo "错误: APK文件不存在: $apk_path" >&2
        return 1
    fi
    
    if ! command -v adb >/dev/null 2>&1; then
        echo "错误: 缺少必需命令: adb" >&2
        return 2
    fi
    
    _gs_android_check_device || return 1
    
    local resolved_device_id
    resolved_device_id=$(_gs_android_resolve_device "$device_id")
    
    echo "正在安装APK: $apk_path"
    echo "安装选项: $install_flags"
    
    if _gs_android_execute "$resolved_device_id" install $install_flags "$apk_path"; then
        echo "APK安装成功"
        return 0
    else
        echo "错误: APK安装失败" >&2
        echo "建议: 检查APK文件完整性或设备存储空间" >&2
        return 2
    fi
}

_show_android_adb_install_help() {
    cat << 'EOF'
gs_android_adb_install - 安装Android应用

功能描述:
  在Android设备上安装APK应用包

使用方式:
  gs-android-adb-install <APK路径> [选项]

参数:
  APK路径        要安装的APK文件路径（必需）

选项:
  -d, --device   指定设备ID
  -f, --force    强制安装（覆盖降级）
  --test         允许安装测试APK
  --help, -h     显示此帮助信息

示例:
  gs-android-adb-install app.apk
  gs-android-adb-install app.apk -f
  gs-android-adb-install app.apk --test
  gs-android-adb-install app.apk -d emulator-5554
  gs-android-adb-install --help

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - 需要启用"未知来源"或开发者选项
  - 强制安装可能覆盖已有应用
  - 确保设备有足够存储空间
EOF
}

gs_android_adb_uninstall() {
    local package_name="${1:-}"
    local device_id="${2:-}"
    local keep_data=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_android_adb_uninstall_help
                return 0
                ;;
            -d|--device)
                device_id="$2"
                shift 2
                ;;
            -k|--keep-data)
                keep_data=true
                shift
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
        echo "使用方式: gs-android-adb-uninstall <包名> [选项]" >&2
        echo "使用 'gs-android-adb-uninstall --help' 查看详细帮助" >&2
        return 1
    fi
    
    if ! command -v adb >/dev/null 2>&1; then
        echo "错误: 缺少必需命令: adb" >&2
        return 2
    fi
    
    _gs_android_check_device || return 1
    
    local resolved_device_id
    resolved_device_id=$(_gs_android_resolve_device "$device_id")
    
    local uninstall_flags=""
    if $keep_data; then
        uninstall_flags="-k"
    fi
    
    echo "正在卸载应用: $package_name"
    
    if _gs_android_execute "$resolved_device_id" uninstall $uninstall_flags "$package_name"; then
        echo "应用卸载成功"
        return 0
    else
        echo "错误: 应用卸载失败" >&2
        echo "建议: 检查包名是否正确或应用是否为系统应用" >&2
        return 2
    fi
}

_show_android_adb_uninstall_help() {
    cat << 'EOF'
gs_android_adb_uninstall - 卸载Android应用

功能描述:
  从Android设备上卸载指定的应用包

使用方式:
  gs-android-adb-uninstall <包名> [选项]

参数:
  包名           要卸载的应用包名（必需）

选项:
  -d, --device   指定设备ID
  -k, --keep-data 保留应用数据和缓存
  --help, -h     显示此帮助信息

示例:
  gs-android-adb-uninstall com.example.app
  gs-android-adb-uninstall com.example.app -k
  gs-android-adb-uninstall com.example.app -d emulator-5554
  gs-android-adb-uninstall --help

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - 系统应用可能无法卸载
  - 保留数据选项适用于重新安装场景
  - 卸载后应用快捷方式会自动移除
EOF
}

gs_android_adb_clear() {
    local package_name="${1:-}"
    local device_id="${2:-}"
    
    if [[ "$package_name" == "--help" || "$package_name" == "-h" ]]; then
        _show_android_adb_clear_help
        return 0
    fi
    
    if [[ -z "$package_name" ]]; then
        echo "错误: 缺少必需参数" >&2
        echo "使用方式: gs-android-adb-clear <包名> [设备ID]" >&2
        echo "使用 'gs-android-adb-clear --help' 查看详细帮助" >&2
        return 1
    fi
    
    if ! command -v adb >/dev/null 2>&1; then
        echo "错误: 缺少必需命令: adb" >&2
        return 2
    fi
    
    _gs_android_check_device || return 1
    
    local resolved_device_id
    resolved_device_id=$(_gs_android_resolve_device "$device_id")
    
    echo "正在清除应用数据: $package_name"
    
    if _gs_android_execute "$resolved_device_id" shell pm clear "$package_name"; then
        echo "应用数据清除成功"
        return 0
    else
        echo "错误: 应用数据清除失败" >&2
        echo "建议: 检查包名是否正确或应用是否存在" >&2
        return 2
    fi
}

_show_android_adb_clear_help() {
    cat << 'EOF'
gs_android_adb_clear - 清除Android应用数据

功能描述:
  清除指定应用的所有数据和缓存，相当于恢复应用初始状态

使用方式:
  gs-android-adb-clear <包名> [设备ID]

参数:
  包名           要清除数据的应用包名（必需）
  设备ID         指定设备ID，多设备时必需（可选）

选项:
  --help, -h     显示此帮助信息

示例:
  gs-android-adb-clear com.example.app
  gs-android-adb-clear com.example.app emulator-5554
  gs-android-adb-clear --help

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - 会清除应用的所有数据，不可恢复
  - 清除后应用将恢复到初始安装状态
  - 某些系统应用可能无法清除数据
EOF
}

gs_android_adb_start() {
    local package_name="${1:-}"
    local activity_name="${2:-}"
    local device_id="${3:-}"
    
    if [[ "$package_name" == "--help" || "$package_name" == "-h" ]]; then
        _show_android_adb_start_help
        return 0
    fi
    
    if [[ -z "$package_name" ]]; then
        echo "错误: 缺少必需参数" >&2
        echo "使用方式: gs-android-adb-start <包名> [Activity] [设备ID]" >&2
        echo "使用 'gs-android-adb-start --help' 查看详细帮助" >&2
        return 1
    fi
    
    if ! command -v adb >/dev/null 2>&1; then
        echo "错误: 缺少必需命令: adb" >&2
        return 2
    fi
    
    _gs_android_check_device || return 1
    
    local resolved_device_id
    resolved_device_id=$(_gs_android_resolve_device "$device_id")
    
    local launch_intent
    if [[ -n "$activity_name" ]]; then
        launch_intent="$package_name/$activity_name"
    else
        launch_intent="$package_name"
    fi
    
    echo "正在启动应用: $launch_intent"
    
    if _gs_android_execute "$resolved_device_id" shell monkey -p "$package_name" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1; then
        echo "应用启动成功"
        return 0
    else
        echo "错误: 应用启动失败" >&2
        echo "建议: 检查包名是否正确或应用是否已安装" >&2
        return 2
    fi
}

_show_android_adb_start_help() {
    cat << 'EOF'
gs_android_adb_start - 启动Android应用

功能描述:
  启动指定的Android应用，可指定特定Activity

使用方式:
  gs-android-adb-start <包名> [Activity] [设备ID]

参数:
  包名           要启动的应用包名（必需）
  Activity       指定Activity名称（可选）
  设备ID         指定设备ID，多设备时必需（可选）

选项:
  --help, -h     显示此帮助信息

示例:
  gs-android-adb-start com.example.app
  gs-android-adb-start com.example.app .MainActivity
  gs-android-adb-start com.example.app .MainActivity emulator-5554
  gs-android-adb-start --help

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - 应用必须已安装在设备上
  - 不指定Activity时启动默认启动页
  - Activity名称通常以.开头
EOF
}

gs_android_adb_kill() {
    local package_name="${1:-}"
    local device_id="${2:-}"
    
    if [[ "$package_name" == "--help" || "$package_name" == "-h" ]]; then
        _show_android_adb_kill_help
        return 0
    fi
    
    if [[ -z "$package_name" ]]; then
        echo "错误: 缺少必需参数" >&2
        echo "使用方式: gs-android-adb-kill <包名> [设备ID]" >&2
        echo "使用 'gs-android-adb-kill --help' 查看详细帮助" >&2
        return 1
    fi
    
    if ! command -v adb >/dev/null 2>&1; then
        echo "错误: 缺少必需命令: adb" >&2
        return 2
    fi
    
    _gs_android_check_device || return 1
    
    local resolved_device_id
    resolved_device_id=$(_gs_android_resolve_device "$device_id")
    
    echo "正在强制停止应用: $package_name"
    
    if _gs_android_execute "$resolved_device_id" shell am force-stop "$package_name"; then
        echo "应用已强制停止"
        return 0
    else
        echo "错误: 应用停止失败" >&2
        echo "建议: 检查包名是否正确" >&2
        return 2
    fi
}

_show_android_adb_kill_help() {
    cat << 'EOF'
gs_android_adb_kill - 强制停止Android应用

功能描述:
  强制停止指定的Android应用进程

使用方式:
  gs-android-adb-kill <包名> [设备ID]

参数:
  包名           要停止的应用包名（必需）
  设备ID         指定设备ID，多设备时必需（可选）

选项:
  --help, -h     显示此帮助信息

示例:
  gs-android-adb-kill com.example.app
  gs-android-adb-kill com.example.app emulator-5554
  gs-android-adb-kill --help

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - 强制停止会终止应用的所有进程
  - 应用的所有后台任务也会被停止
  - 系统应用可能无法强制停止
EOF
}

# 平台检测
machine="$(uname -s)"
case "${machine}" in
    Linux*)     isMac=false;;
    Darwin*)    isMac=true;;
    *)          isMac=false;;
esac

gs_android_adb_selinux_disable() {
    local device_id="${1:-}"
    
    if [[ "$device_id" == "--help" || "$device_id" == "-h" ]]; then
        _show_android_adb_selinux_disable_help
        return 0
    fi
    
    if ! command -v adb >/dev/null 2>&1; then
        echo "错误: 缺少必需命令: adb" >&2
        return 2
    fi
    
    _gs_android_check_device || return 1
    
    local resolved_device_id
    resolved_device_id=$(_gs_android_resolve_device "$device_id")
    
    echo "禁用SELinux (设备: $resolved_device_id)"
    
    if _gs_android_execute "$resolved_device_id" shell "setenforce 0" && \
       _gs_android_execute "$resolved_device_id" shell "stop && start"; then
        echo "SELinux已禁用并重启框架"
        return 0
    else
        echo "错误: SELinux禁用失败" >&2
        echo "建议: 检查设备是否有root权限" >&2
        return 2
    fi
}

_show_android_adb_selinux_disable_help() {
    cat << 'EOF'
gs_android_adb_selinux_disable - 禁用Android SELinux

功能描述:
  禁用Android设备的SELinux安全策略并重启框架

使用方式:
  gs-android-adb-selinux-disable [设备ID]

参数:
  设备ID         指定设备ID，多设备时必需（可选）

选项:
  --help, -h     显示此帮助信息

示例:
  gs-android-adb-selinux-disable
  gs-android-adb-selinux-disable emulator-5554
  gs-android-adb-selinux-disable --help

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - 需要root权限
  - 会重启Android框架
  - 用于开发调试，降低安全限制
EOF
}

gs_android_adb_hidden_api_enable() {
    local device_id="${1:-}"
    
    if [[ "$device_id" == "--help" || "$device_id" == "-h" ]]; then
        _show_android_adb_hidden_api_enable_help
        return 0
    fi
    
    if ! command -v adb >/dev/null 2>&1; then
        echo "错误: 缺少必需命令: adb" >&2
        return 2
    fi
    
    _gs_android_check_device || return 1
    
    local resolved_device_id
    resolved_device_id=$(_gs_android_resolve_device "$device_id")
    
    echo "启用Hidden API访问 (设备: $resolved_device_id)"
    
    if _gs_android_execute "$resolved_device_id" shell "settings put global hidden_api_policy_pre_p_apps 1" && \
       _gs_android_execute "$resolved_device_id" shell "settings put global hidden_api_policy_p_apps 1"; then
        echo "Hidden API访问已启用"
        return 0
    else
        echo "错误: Hidden API设置失败" >&2
        return 2
    fi
}

_show_android_adb_hidden_api_enable_help() {
    cat << 'EOF'
gs_android_adb_hidden_api_enable - 启用Hidden API访问

功能描述:
  启用Android Hidden API访问，允许应用调用系统隐藏接口

使用方式:
  gs-android-adb-hidden-api-enable [设备ID]

参数:
  设备ID         指定设备ID，多设备时必需（可选）

选项:
  --help, -h     显示此帮助信息

示例:
  gs-android-adb-hidden-api-enable
  gs-android-adb-hidden-api-enable emulator-5554
  gs-android-adb-hidden-api-enable --help

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - 用于开发调试
  - 允许访问系统内部API
  - 可能影响应用兼容性
EOF
}

gs_android_adb_hidden_api_disable() {
    local device_id="${1:-}"
    
    if [[ "$device_id" == "--help" || "$device_id" == "-h" ]]; then
        _show_android_adb_hidden_api_disable_help
        return 0
    fi
    
    if ! command -v adb >/dev/null 2>&1; then
        echo "错误: 缺少必需命令: adb" >&2
        return 2
    fi
    
    _gs_android_check_device || return 1
    
    local resolved_device_id
    resolved_device_id=$(_gs_android_resolve_device "$device_id")
    
    echo "禁用Hidden API访问 (设备: $resolved_device_id)"
    
    if _gs_android_execute "$resolved_device_id" shell "settings delete global hidden_api_policy_pre_p_apps" && \
       _gs_android_execute "$resolved_device_id" shell "settings delete global hidden_api_policy_p_apps"; then
        echo "Hidden API访问已禁用"
        return 0
    else
        echo "错误: Hidden API设置失败" >&2
        return 2
    fi
}

_show_android_adb_hidden_api_disable_help() {
    cat << 'EOF'
gs_android_adb_hidden_api_disable - 禁用Hidden API访问

功能描述:
  禁用Android Hidden API访问，恢复系统默认安全策略

使用方式:
  gs-android-adb-hidden-api-disable [设备ID]

参数:
  设备ID         指定设备ID，多设备时必需（可选）

选项:
  --help, -h     显示此帮助信息

示例:
  gs-android-adb-hidden-api-disable
  gs-android-adb-hidden-api-disable emulator-5554
  gs-android-adb-hidden-api-disable --help

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - 恢复系统默认策略
  - 提高系统安全性
  - 可能影响某些调试功能
EOF
}

gs_android_adb_connect_tcp() {
    local device_ip="${1:-}"
    local port="${2:-5555}"
    
    if [[ "$device_ip" == "--help" || "$device_ip" == "-h" ]]; then
        _show_android_adb_connect_tcp_help
        return 0
    fi
    
    if [[ -z "$device_ip" ]]; then
        echo "错误: 缺少必需参数" >&2
        echo "使用方式: gs-android-adb-connect-tcp <设备IP> [端口]" >&2
        echo "使用 'gs-android-adb-connect-tcp --help' 查看详细帮助" >&2
        return 1
    fi
    
    if ! command -v adb >/dev/null 2>&1; then
        echo "错误: 缺少必需命令: adb" >&2
        return 2
    fi
    
    echo "启用TCP模式并连接到: $device_ip:$port"
    
    # 先启用tcpip模式
    if adb tcpip "$port"; then
        echo "TCP模式已启用，端口: $port"
        sleep 2
        
        # 连接网络设备
        if adb connect "$device_ip:$port"; then
            echo "设备连接成功: $device_ip:$port"
            echo "当前连接的设备:"
            adb devices
            return 0
        else
            echo "错误: 设备连接失败" >&2
            return 2
        fi
    else
        echo "错误: TCP模式启用失败" >&2
        echo "建议: 检查设备是否通过USB连接" >&2
        return 2
    fi
}

gs_android_adb_devices() {
    if [[ "$1" == "--help" || "$1" == "-h" ]]; then
        _show_android_adb_devices_help
        return 0
    fi
    
    if ! command -v adb >/dev/null 2>&1; then
        echo "错误: 缺少必需命令: adb" >&2
        return 2
    fi
    
    echo "获取已连接设备列表..."
    adb devices -l
    return 0
}

gs_android_adb_info() {
    local device_id="${1:-}"
    
    if [[ "$device_id" == "--help" || "$device_id" == "-h" ]]; then
        _show_android_adb_info_help
        return 0
    fi
    
    if ! command -v adb >/dev/null 2>&1; then
        echo "错误: 缺少必需命令: adb" >&2
        return 2
    fi
    
    _gs_android_check_device || return 1
    
    local resolved_device_id
    resolved_device_id=$(_gs_android_resolve_device "$device_id")
    
    echo "设备信息 (设备: $resolved_device_id)"
    echo "==============================="
    
    echo "基本信息:"
    echo "  品牌: $(_gs_android_execute "$resolved_device_id" shell getprop ro.product.brand)"
    echo "  型号: $(_gs_android_execute "$resolved_device_id" shell getprop ro.product.model)"
    echo "  制造商: $(_gs_android_execute "$resolved_device_id" shell getprop ro.product.manufacturer)"
    echo "  设备名: $(_gs_android_execute "$resolved_device_id" shell getprop ro.product.device)"
    
    echo "
Android版本:"
    echo "  版本: $(_gs_android_execute "$resolved_device_id" shell getprop ro.build.version.release)"
    echo "  API级别: $(_gs_android_execute "$resolved_device_id" shell getprop ro.build.version.sdk)"
    echo "  构建号: $(_gs_android_execute "$resolved_device_id" shell getprop ro.build.display.id)"
    
    echo "
CPU信息:"
    echo "  架构: $(_gs_android_execute "$resolved_device_id" shell getprop ro.product.cpu.abi)"
    echo "  支持架构: $(_gs_android_execute "$resolved_device_id" shell getprop ro.product.cpu.abilist)"
    
    echo "
屏幕信息:"
    local density
    density=$(_gs_android_execute "$resolved_device_id" shell wm density | cut -d: -f2 | tr -d ' ')
    echo "  密度: ${density}dpi"
    
    local size
    size=$(_gs_android_execute "$resolved_device_id" shell wm size | cut -d: -f2 | tr -d ' ')
    echo "  分辨率: $size"
    
    echo "
存储信息:"
    _gs_android_execute "$resolved_device_id" shell df -h /data | tail -n 1 | awk '{print "  内部存储: " $2 " 总计, " $3 " 已用, " $4 " 可用"}'
    
    echo "
网络信息:"
    local ip
    ip=$(_gs_android_execute "$resolved_device_id" shell ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || echo "未连接")
    echo "  IP地址: $ip"
    
    return 0
}

gs_android_adb_packages() {
    local filter="${1:-}"
    local device_id="${2:-}"
    local show_system=false
    local show_enabled_only=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_android_adb_packages_help
                return 0
                ;;
            -s|--system)
                show_system=true
                shift
                ;;
            -e|--enabled)
                show_enabled_only=true
                shift
                ;;
            -d|--device)
                device_id="$2"
                shift 2
                ;;
            *)
                if [[ -z "$filter" ]]; then
                    filter="$1"
                fi
                shift
                ;;
        esac
    done
    
    if ! command -v adb >/dev/null 2>&1; then
        echo "错误: 缺少必需命令: adb" >&2
        return 2
    fi
    
    _gs_android_check_device || return 1
    
    local resolved_device_id
    resolved_device_id=$(_gs_android_resolve_device "$device_id")
    
    local pm_flags=""
    if $show_system; then
        pm_flags="-s"
    else
        pm_flags="-3"  # 第三方应用
    fi
    
    if $show_enabled_only; then
        pm_flags="$pm_flags -e"
    fi
    
    echo "获取应用包列表..."
    
    if [[ -n "$filter" ]]; then
        echo "过滤条件: $filter"
    fi
    
    local packages
    packages=$(_gs_android_execute "$resolved_device_id" shell pm list packages $pm_flags)
    
    if [[ -n "$filter" ]]; then
        packages=$(echo "$packages" | grep -i "$filter")
    fi
    
    echo "$packages" | sed 's/package://' | sort
    
    local count
    count=$(echo "$packages" | wc -l)
    echo "
找到 $count 个应用包"
    
    return 0
}

gs_android_adb_dumpsys() {
    local service="${1:-}"
    local device_id="${2:-}"
    local output_file=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_android_adb_dumpsys_help
                return 0
                ;;
            -o|--output)
                output_file="$2"
                shift 2
                ;;
            -d|--device)
                device_id="$2"
                shift 2
                ;;
            *)
                if [[ -z "$service" ]]; then
                    service="$1"
                fi
                shift
                ;;
        esac
    done
    
    if [[ -z "$service" ]]; then
        echo "错误: 缺少必需参数" >&2
        echo "使用方式: gs-android-adb-dumpsys <服务名> [选项]" >&2
        echo "使用 'gs-android-adb-dumpsys --help' 查看详细帮助" >&2
        return 1
    fi
    
    if ! command -v adb >/dev/null 2>&1; then
        echo "错误: 缺少必需命令: adb" >&2
        return 2
    fi
    
    _gs_android_check_device || return 1
    
    local resolved_device_id
    resolved_device_id=$(_gs_android_resolve_device "$device_id")
    
    echo "获取系统服务信息: $service"
    
    if [[ -n "$output_file" ]]; then
        echo "输出到文件: $output_file"
        _gs_android_execute "$resolved_device_id" shell dumpsys "$service" > "$output_file"
        echo "服务信息已保存到: $output_file"
    else
        _gs_android_execute "$resolved_device_id" shell dumpsys "$service"
    fi
    
    return 0
}

gs_android_adb_monkey() {
    local package_name="${1:-}"
    local event_count="${2:-100}"
    local device_id="${3:-}"
    local throttle="100"
    local seed=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_android_adb_monkey_help
                return 0
                ;;
            -c|--count)
                event_count="$2"
                shift 2
                ;;
            -t|--throttle)
                throttle="$2"
                shift 2
                ;;
            -s|--seed)
                seed="$2"
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
        echo "使用方式: gs-android-adb-monkey <包名> [事件数] [选项]" >&2
        echo "使用 'gs-android-adb-monkey --help' 查看详细帮助" >&2
        return 1
    fi
    
    if ! command -v adb >/dev/null 2>&1; then
        echo "错误: 缺少必需命令: adb" >&2
        return 2
    fi
    
    _gs_android_check_device || return 1
    
    local resolved_device_id
    resolved_device_id=$(_gs_android_resolve_device "$device_id")
    
    local monkey_cmd="monkey -p $package_name --throttle $throttle"
    
    if [[ -n "$seed" ]]; then
        monkey_cmd="$monkey_cmd -s $seed"
    fi
    
    monkey_cmd="$monkey_cmd $event_count"
    
    echo "启动Monkey测试..."
    echo "目标应用: $package_name"
    echo "事件数量: $event_count"
    echo "事件间隔: ${throttle}ms"
    if [[ -n "$seed" ]]; then
        echo "随机种子: $seed"
    fi
    echo "按Ctrl+C停止测试"
    
    _gs_android_execute "$resolved_device_id" shell "$monkey_cmd"
    
    return 0
}

gs_android_adb_input() {
    local input_type="${1:-}"
    local device_id=""
    
    case "$input_type" in
        text)
            local text="${2:-}"
            device_id="${3:-}"
            
            if [[ -z "$text" ]]; then
                echo "错误: 缺少文本内容" >&2
                return 1
            fi
            
            if ! command -v adb >/dev/null 2>&1; then
                echo "错误: 缺少必需命令: adb" >&2
                return 2
            fi
            
            _gs_android_check_device || return 1
            
            local resolved_device_id
            resolved_device_id=$(_gs_android_resolve_device "$device_id")
            
            echo "输入文本: $text"
            # 转义特殊字符
            text=$(echo "$text" | sed 's/ /\%s/g')
            _gs_android_execute "$resolved_device_id" shell input text "$text"
            ;;
        tap)
            local x="${2:-}"
            local y="${3:-}"
            device_id="${4:-}"
            
            if [[ -z "$x" || -z "$y" ]]; then
                echo "错误: 缺少坐标参数" >&2
                return 1
            fi
            
            if ! command -v adb >/dev/null 2>&1; then
                echo "错误: 缺少必需命令: adb" >&2
                return 2
            fi
            
            _gs_android_check_device || return 1
            
            local resolved_device_id
            resolved_device_id=$(_gs_android_resolve_device "$device_id")
            
            echo "点击坐标: ($x, $y)"
            _gs_android_execute "$resolved_device_id" shell input tap "$x" "$y"
            ;;
        swipe)
            local x1="${2:-}"
            local y1="${3:-}"
            local x2="${4:-}"
            local y2="${5:-}"
            local duration="${6:-300}"
            device_id="${7:-}"
            
            if [[ -z "$x1" || -z "$y1" || -z "$x2" || -z "$y2" ]]; then
                echo "错误: 缺少坐标参数" >&2
                return 1
            fi
            
            if ! command -v adb >/dev/null 2>&1; then
                echo "错误: 缺少必需命令: adb" >&2
                return 2
            fi
            
            _gs_android_check_device || return 1
            
            local resolved_device_id
            resolved_device_id=$(_gs_android_resolve_device "$device_id")
            
            echo "滑动: ($x1, $y1) -> ($x2, $y2), 时长: ${duration}ms"
            _gs_android_execute "$resolved_device_id" shell input swipe "$x1" "$y1" "$x2" "$y2" "$duration"
            ;;
        keyevent)
            local keycode="${2:-}"
            device_id="${3:-}"
            
            if [[ -z "$keycode" ]]; then
                echo "错误: 缺少按键代码" >&2
                return 1
            fi
            
            if ! command -v adb >/dev/null 2>&1; then
                echo "错误: 缺少必需命令: adb" >&2
                return 2
            fi
            
            _gs_android_check_device || return 1
            
            local resolved_device_id
            resolved_device_id=$(_gs_android_resolve_device "$device_id")
            
            echo "发送按键事件: $keycode"
            _gs_android_execute "$resolved_device_id" shell input keyevent "$keycode"
            ;;
        --help|-h)
            _show_android_adb_input_help
            return 0
            ;;
        *)
            echo "错误: 不支持的输入类型: $input_type" >&2
            echo "支持的类型: text, tap, swipe, keyevent" >&2
            echo "使用 'gs-android-adb-input --help' 查看详细帮助" >&2
            return 1
            ;;
    esac
    
    return 0
}

gs_android_adb_backup() {
    local package_name="${1:-}"
    local backup_file="${2:-backup.ab}"
    local device_id="${3:-}"
    local include_apk=false
    local include_shared=false
    local include_system=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_android_adb_backup_help
                return 0
                ;;
            --apk)
                include_apk=true
                shift
                ;;
            --shared)
                include_shared=true
                shift
                ;;
            --system)
                include_system=true
                shift
                ;;
            -f|--file)
                backup_file="$2"
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
    
    if ! command -v adb >/dev/null 2>&1; then
        echo "错误: 缺少必需命令: adb" >&2
        return 2
    fi
    
    _gs_android_check_device || return 1
    
    local resolved_device_id
    resolved_device_id=$(_gs_android_resolve_device "$device_id")
    
    local backup_cmd="backup"
    
    if $include_apk; then
        backup_cmd="$backup_cmd -apk"
    else
        backup_cmd="$backup_cmd -noapk"
    fi
    
    if $include_shared; then
        backup_cmd="$backup_cmd -shared"
    fi
    
    if $include_system; then
        backup_cmd="$backup_cmd -system"
    fi
    
    backup_cmd="$backup_cmd -f $backup_file"
    
    if [[ -n "$package_name" ]]; then
        backup_cmd="$backup_cmd $package_name"
        echo "开始备份应用: $package_name"
    else
        backup_cmd="$backup_cmd -all"
        echo "开始备份所有应用数据"
    fi
    
    echo "备份文件: $backup_file"
    echo "请在设备上确认备份操作..."
    
    _gs_android_execute "$resolved_device_id" $backup_cmd
    
    if [[ -f "$backup_file" ]]; then
        echo "备份完成: $backup_file"
        return 0
    else
        echo "错误: 备份失败" >&2
        return 2
    fi
}

gs_android_adb_restore() {
    local backup_file="${1:-}"
    local device_id="${2:-}"
    
    if [[ "$backup_file" == "--help" || "$backup_file" == "-h" ]]; then
        _show_android_adb_restore_help
        return 0
    fi
    
    if [[ -z "$backup_file" ]]; then
        echo "错误: 缺少必需参数" >&2
        echo "使用方式: gs-android-adb-restore <备份文件> [设备ID]" >&2
        echo "使用 'gs-android-adb-restore --help' 查看详细帮助" >&2
        return 1
    fi
    
    if [[ ! -f "$backup_file" ]]; then
        echo "错误: 备份文件不存在: $backup_file" >&2
        return 1
    fi
    
    if ! command -v adb >/dev/null 2>&1; then
        echo "错误: 缺少必需命令: adb" >&2
        return 2
    fi
    
    _gs_android_check_device || return 1
    
    local resolved_device_id
    resolved_device_id=$(_gs_android_resolve_device "$device_id")
    
    echo "开始恢复备份: $backup_file"
    echo "请在设备上确认恢复操作..."
    
    _gs_android_execute "$resolved_device_id" restore "$backup_file"
    
    echo "恢复完成"
    return 0
}

_show_android_adb_connect_tcp_help() {
    cat << 'EOF'
gs_android_adb_connect_tcp - TCP网络连接设备

功能描述:
  启用ADB TCP模式并连接网络设备，实现无线调试

使用方式:
  gs-android-adb-connect-tcp <设备IP> [端口]

参数:
  设备IP         目标设备的IP地址（必需）
  端口           TCP端口，默认5555（可选）

选项:
  --help, -h     显示此帮助信息

示例:
  gs-android-adb-connect-tcp 192.168.1.100
  gs-android-adb-connect-tcp 192.168.1.100 5555
  gs-android-adb-connect-tcp --help

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - 首次需要USB连接启用TCP模式
  - 设备和主机需在同一网络
  - 连接后可拔掉USB线
EOF
}

_show_android_adb_devices_help() {
    cat << 'EOF'
gs_android_adb_devices - 获取已连接设备列表

功能描述:
  显示所有已连接的Android设备和模拟器列表

使用方式:
  gs-android-adb-devices

选项:
  --help, -h     显示此帮助信息

示例:
  gs-android-adb-devices
  gs-android-adb-devices --help

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - 显示设备ID、状态和详细信息
  - 支持USB和TCP连接的设备
EOF
}

_show_android_adb_info_help() {
    cat << 'EOF'
gs_android_adb_info - 获取设备详细信息

功能描述:
  获取Android设备的详细信息，包括硬件、系统、网络等

使用方式:
  gs-android-adb-info [设备ID]

参数:
  设备ID         指定设备ID，多设备时必需（可选）

选项:
  --help, -h     显示此帮助信息

示例:
  gs-android-adb-info
  gs-android-adb-info emulator-5554
  gs-android-adb-info --help

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - 显示品牌、型号、Android版本等信息
  - 包括CPU架构、屏幕尺寸、存储空间等
EOF
}

_show_android_adb_packages_help() {
    cat << 'EOF'
gs_android_adb_packages - 获取应用包列表

功能描述:
  获取Android设备上的应用包列表，支持过滤和分类

使用方式:
  gs-android-adb-packages [过滤条件] [选项]

参数:
  过滤条件       包名过滤关键词（可选）

选项:
  -s, --system   显示系统应用
  -e, --enabled  仅显示已启用的应用
  -d, --device   指定设备ID
  --help, -h     显示此帮助信息

示例:
  gs-android-adb-packages
  gs-android-adb-packages com.google
  gs-android-adb-packages -s
  gs-android-adb-packages -e chrome
  gs-android-adb-packages --help

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - 默认仅显示递三方应用
  - 支持大小写不敏感的过滤
  - 统计显示找到的应用数量
EOF
}

_show_android_adb_dumpsys_help() {
    cat << 'EOF'
gs_android_adb_dumpsys - 获取系统服务信息

功能描述:
  获取Android系统服务的详细信息，用于调试和分析

使用方式:
  gs-android-adb-dumpsys <服务名> [选项]

参数:
  服务名         系统服务名称（必需）

选项:
  -o, --output   输出到文件
  -d, --device   指定设备ID
  --help, -h     显示此帮助信息

常用服务:
  activity           - Activity Manager
  window             - Window Manager
  package            - Package Manager
  power              - Power Manager
  battery            - 电池信息
  wifi               - WiFi服务
  connectivity       - 连接管理
  telephony          - 电话服务
  location           - 位置服务
  notification       - 通知服务

示例:
  gs-android-adb-dumpsys activity
  gs-android-adb-dumpsys battery -o battery.txt
  gs-android-adb-dumpsys window -d emulator-5554
  gs-android-adb-dumpsys --help

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - 输出信息量很大，建议使用输出到文件
  - 不同服务提供不同的信息内容
EOF
}

_show_android_adb_monkey_help() {
    cat << 'EOF'
gs_android_adb_monkey - Monkey压力测试

功能描述:
  使用Monkey工具对Android应用进行随机事件压力测试

使用方式:
  gs-android-adb-monkey <包名> [事件数] [选项]

参数:
  包名           目标应用的包名（必需）
  事件数         生成的事件数量，默认100（可选）

选项:
  -c, --count    指定事件数量
  -t, --throttle 事件间隔（毫秒），默认100ms
  -s, --seed     随机种子，用于重现测试
  -d, --device   指定设备ID
  --help, -h     显示此帮助信息

示例:
  gs-android-adb-monkey com.example.app
  gs-android-adb-monkey com.example.app 500
  gs-android-adb-monkey com.example.app -c 1000 -t 50
  gs-android-adb-monkey com.example.app -s 12345
  gs-android-adb-monkey --help

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - 测试期间会随机操作应用
  - 可能触发应用崩溃或ANR
  - 使用相同种子可重现测试过程
EOF
}

_show_android_adb_input_help() {
    cat << 'EOF'
gs_android_adb_input - 模拟输入事件

功能描述:
  模拟各种输入事件，包括文本输入、点击、滑动和按键

使用方式:
  gs-android-adb-input text <文本> [设备ID]
  gs-android-adb-input tap <X> <Y> [设备ID]
  gs-android-adb-input swipe <X1> <Y1> <X2> <Y2> [时长] [设备ID]
  gs-android-adb-input keyevent <按键代码> [设备ID]

命令类型:
  text           输入文本内容
  tap            点击指定坐标
  swipe          从起始坐标滑动到结束坐标
  keyevent       发送按键事件

常用按键代码:
  3  - HOME键
  4  - BACK键
  82 - MENU键
  84 - 搜索键
  85 - 播放/暂停
  24 - 音量加
  25 - 音量减
  26 - 电源键

示例:
  gs-android-adb-input text "Hello World"
  gs-android-adb-input tap 500 1000
  gs-android-adb-input swipe 300 1000 300 500 500
  gs-android-adb-input keyevent 4
  gs-android-adb-input --help

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - 文本中的空格会自动转义
  - 坐标是绝对坐标，左上角为(0,0)
  - 滑动时长单位为毫秒
EOF
}

_show_android_adb_backup_help() {
    cat << 'EOF'
gs_android_adb_backup - 应用数据备份

功能描述:
  备份Android应用数据到本地文件，支持单个应用或所有应用

使用方式:
  gs-android-adb-backup [包名] [选项]

参数:
  包名           要备份的应用包名，不指定则备份所有（可选）

选项:
  -f, --file     备份文件名，默认backup.ab
  --apk          包拫APK文件
  --shared       包拫共享存储
  --system       包拫系统应用
  -d, --device   指定设备ID
  --help, -h     显示此帮助信息

示例:
  gs-android-adb-backup com.example.app
  gs-android-adb-backup --apk -f myapp.ab com.example.app
  gs-android-adb-backup --system
  gs-android-adb-backup --help

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - 需在设备上确认备份操作
  - 备份文件为Android专用格式
  - 支持密码保护
EOF
}

_show_android_adb_restore_help() {
    cat << 'EOF'
gs_android_adb_restore - 恢复应用数据

功能描述:
  从备份文件恢复Android应用数据

使用方式:
  gs-android-adb-restore <备份文件> [设备ID]

参数:
  备份文件       要恢复的备份文件路径（必需）
  设备ID         指定设备ID，多设备时必需（可选）

选项:
  --help, -h     显示此帮助信息

示例:
  gs-android-adb-restore backup.ab
  gs-android-adb-restore myapp.ab emulator-5554
  gs-android-adb-restore --help

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - 需在设备上确认恢复操作
  - 恢复前应卸载相关应用
  - 支持密码保护的备份文件
EOF
}