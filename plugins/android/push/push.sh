#!/bin/bash
# -*- coding: utf-8 -*-
# -*- encoding: utf-8 -*-
#
# Android Push Submodule
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

_gs_android_push_ensure_writable() {
    local device_id="$1"
    
    echo "获取root权限并重新挂载系统分区..."
    
    if _gs_android_execute "$device_id" root && _gs_android_execute "$device_id" remount; then
        return 0
    else
        echo "警告: 无法获取root权限或重新挂载分区" >&2
        echo "建议: 检查设备是否支持root或使用eng/userdebug版本" >&2
        return 1
    fi
}

_gs_android_push_cleanup_oat() {
    local device_id="$1"
    local target_dir="$2"
    
    local oat_dirs=("${target_dir}/oat" "${target_dir}/arm" "${target_dir}/arm64")
    local need_reboot=false
    
    for oat_dir in "${oat_dirs[@]}"; do
        if _gs_android_execute "$device_id" shell "test -d $oat_dir" >/dev/null 2>&1; then
            echo "清理OAT缓存: $oat_dir"
            _gs_android_execute "$device_id" shell "rm -rf $oat_dir"
            need_reboot=true
        fi
    done
    
    if $need_reboot; then
        echo "检测到OAT缓存清理，需要重启以生效"
        return 1
    fi
    
    return 0
}

gs_android_push_file() {
    local local_file="${1:-}"
    local remote_path="${2:-}"
    local device_id="${3:-}"
    local auto_restart=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_android_push_file_help
                return 0
                ;;
            --restart|-r)
                auto_restart=true
                shift
                ;;
            -d|--device)
                device_id="$2"
                shift 2
                ;;
            *)
                if [[ -z "$local_file" ]]; then
                    local_file="$1"
                elif [[ -z "$remote_path" ]]; then
                    remote_path="$1"
                fi
                shift
                ;;
        esac
    done
    
    if [[ -z "$local_file" || -z "$remote_path" ]]; then
        echo "错误: 缺少必需参数" >&2
        echo "使用方式: gs-android-push-file <本地文件> <远程路径> [选项]" >&2
        echo "使用 'gs-android-push-file --help' 查看详细帮助" >&2
        return 1
    fi
    
    if [[ ! -f "$local_file" ]]; then
        echo "错误: 本地文件不存在: $local_file" >&2
        return 1
    fi
    
    _gs_android_check_adb || return 2
    _gs_android_check_device || return 1
    
    local resolved_device_id
    resolved_device_id=$(_gs_android_resolve_device "$device_id")
    
    _gs_android_push_ensure_writable "$resolved_device_id"
    
    echo "推送文件: $local_file -> $remote_path"
    
    if _gs_android_execute "$resolved_device_id" push "$local_file" "$remote_path"; then
        echo "文件推送成功"
        
        if $auto_restart; then
            echo "重启Android框架..."
            _gs_android_execute "$resolved_device_id" shell "stop && start"
            echo "重启完成"
        fi
        
        return 0
    else
        echo "错误: 文件推送失败" >&2
        return 2
    fi
}

_show_android_push_file_help() {
    cat << 'EOF'
gs_android_push_file - 推送文件到Android设备

功能描述:
  将本地文件推送到Android设备的指定路径

使用方式:
  gs-android-push-file <本地文件> <远程路径> [选项]

参数:
  本地文件       要推送的本地文件路径（必需）
  远程路径       设备上的目标路径（必需）

选项:
  -r, --restart  推送后重启Android框架
  -d, --device   指定设备ID
  --help, -h     显示此帮助信息

示例:
  gs-android-push-file app.apk /system/app/MyApp/MyApp.apk
  gs-android-push-file framework.jar /system/framework/framework.jar --restart
  gs-android-push-file lib.so /system/lib64/lib.so -d emulator-5554
  gs-android-push-file --help

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - 推送系统文件需要root权限
  - 推送框架文件后建议重启
  - 确保目标目录存在且可写
EOF
}

gs_android_push_framework() {
    local build_out_dir="${1:-out/target/product}"
    local target_product="${2:-}"
    local device_id="${3:-}"
    local auto_restart=true
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_android_push_framework_help
                return 0
                ;;
            --no-restart)
                auto_restart=false
                shift
                ;;
            -o|--out)
                build_out_dir="$2"
                shift 2
                ;;
            -t|--target)
                target_product="$2"
                shift 2
                ;;
            -d|--device)
                device_id="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done
    
    _gs_android_push_check_deps || return 2
    _gs_android_push_check_device || return 1
    
    if [[ -z "$target_product" ]]; then
        target_product="$TARGET_PRODUCT"
        if [[ -z "$target_product" ]]; then
            echo "错误: 未指定构建目标" >&2
            echo "建议: 设置TARGET_PRODUCT环境变量或使用-t选项" >&2
            return 1
        fi
    fi
    
    local framework_path="$build_out_dir/$target_product/system/framework/framework.jar"
    
    if [[ ! -f "$framework_path" ]]; then
        echo "错误: Framework文件不存在: $framework_path" >&2
        echo "建议: 检查构建输出目录和目标产品名称" >&2
        return 1
    fi
    
    local adb_cmd="adb"
    if [[ -n "$device_id" ]]; then
        adb_cmd="adb -s $device_id"
    fi
    
    _gs_android_push_ensure_writable "$device_id"
    
    echo "推送Framework: $framework_path"
    
    if $adb_cmd push "$framework_path" "/system/framework/framework.jar"; then
        echo "Framework推送成功"
        
        _gs_android_push_cleanup_oat "$device_id" "/system/framework"
        local need_reboot=$?
        
        if $auto_restart || [[ $need_reboot -eq 1 ]]; then
            echo "重启设备以生效..."
            $adb_cmd reboot
            echo "设备正在重启，请等待..."
        fi
        
        return 0
    else
        echo "错误: Framework推送失败" >&2
        return 2
    fi
}

_show_android_push_framework_help() {
    cat << 'EOF'
gs_android_push_framework - 推送Android Framework

功能描述:
  将编译好的framework.jar推送到Android设备并处理相关缓存

使用方式:
  gs-android-push-framework [选项]

选项:
  -o, --out      构建输出目录，默认out/target/product
  -t, --target   目标产品名称，默认使用TARGET_PRODUCT
  --no-restart   推送后不自动重启
  -d, --device   指定设备ID
  --help, -h     显示此帮助信息

示例:
  gs-android-push-framework
  gs-android-push-framework -t sdk_phone_x86_64
  gs-android-push-framework --no-restart
  gs-android-push-framework -o ~/build/out -t myproduct
  gs-android-push-framework --help

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - 需要root权限和可写系统分区
  - 会自动清理OAT缓存
  - 通常需要重启设备以生效
  - 确保framework.jar已正确编译
EOF
}

gs_android_push_services() {
    local build_out_dir="${1:-out/target/product}"
    local target_product="${2:-}"
    local device_id="${3:-}"
    local auto_restart=true
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_android_push_services_help
                return 0
                ;;
            --no-restart)
                auto_restart=false
                shift
                ;;
            -o|--out)
                build_out_dir="$2"
                shift 2
                ;;
            -t|--target)
                target_product="$2"
                shift 2
                ;;
            -d|--device)
                device_id="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done
    
    _gs_android_push_check_deps || return 2
    _gs_android_push_check_device || return 1
    
    if [[ -z "$target_product" ]]; then
        target_product="$TARGET_PRODUCT"
        if [[ -z "$target_product" ]]; then
            echo "错误: 未指定构建目标" >&2
            echo "建议: 设置TARGET_PRODUCT环境变量或使用-t选项" >&2
            return 1
        fi
    fi
    
    local services_path="$build_out_dir/$target_product/system/framework/services.jar"
    
    if [[ ! -f "$services_path" ]]; then
        echo "错误: Services文件不存在: $services_path" >&2
        echo "建议: 检查构建输出目录和目标产品名称" >&2
        return 1
    fi
    
    local adb_cmd="adb"
    if [[ -n "$device_id" ]]; then
        adb_cmd="adb -s $device_id"
    fi
    
    _gs_android_push_ensure_writable "$device_id"
    
    echo "推送Services: $services_path"
    
    if $adb_cmd push "$services_path" "/system/framework/services.jar"; then
        echo "Services推送成功"
        
        _gs_android_push_cleanup_oat "$device_id" "/system/framework"
        local need_reboot=$?
        
        if $auto_restart || [[ $need_reboot -eq 1 ]]; then
            echo "重启Android框架..."
            $adb_cmd shell "stop && start"
            echo "重启完成"
        fi
        
        return 0
    else
        echo "错误: Services推送失败" >&2
        return 2
    fi
}

_show_android_push_services_help() {
    cat << 'EOF'
gs_android_push_services - 推送Android Services

功能描述:
  将编译好的services.jar推送到Android设备并处理相关缓存

使用方式:
  gs-android-push-services [选项]

选项:
  -o, --out      构建输出目录，默认out/target/product
  -t, --target   目标产品名称，默认使用TARGET_PRODUCT
  --no-restart   推送后不自动重启框架
  -d, --device   指定设备ID
  --help, -h     显示此帮助信息

示例:
  gs-android-push-services
  gs-android-push-services -t sdk_phone_x86_64
  gs-android-push-services --no-restart
  gs-android-push-services -o ~/build/out -t myproduct
  gs-android-push-services --help

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - 需要root权限和可写系统分区
  - 会自动清理OAT缓存
  - 通常只需重启Android框架
  - Services包含系统核心服务
EOF
}

gs_android_push_apk() {
    local apk_path="${1:-}"
    local package_name="${2:-}"
    local device_id="${3:-}"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_android_push_apk_help
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
        echo "使用方式: gs-android-push-apk <APK路径> [选项]" >&2
        echo "使用 'gs-android-push-apk --help' 查看详细帮助" >&2
        return 1
    fi
    
    if [[ ! -f "$apk_path" ]]; then
        echo "错误: APK文件不存在: $apk_path" >&2
        return 1
    fi
    
    _gs_android_push_check_deps || return 2
    _gs_android_push_check_device || return 1
    
    local adb_cmd="adb"
    if [[ -n "$device_id" ]]; then
        adb_cmd="adb -s $device_id"
    fi
    
    if [[ -z "$package_name" ]]; then
        echo "获取APK包名..."
        if command -v aapt >/dev/null 2>&1; then
            package_name=$(aapt dump badging "$apk_path" 2>/dev/null | grep "package:" | awk -F "'" '{print $2}')
        else
            echo "警告: 未找到aapt工具，无法自动获取包名" >&2
            echo "建议: 使用-p选项手动指定包名" >&2
        fi
    fi
    
    if [[ -n "$package_name" ]]; then
        echo "目标应用: $package_name"
        
        echo "停止应用..."
        $adb_cmd shell am force-stop "$package_name" 2>/dev/null
    fi
    
    echo "推送APK: $apk_path"
    
    if $adb_cmd install -r "$apk_path"; then
        echo "APK推送成功"
        
        if [[ -n "$package_name" ]]; then
            echo "启动应用..."
            $adb_cmd shell monkey -p "$package_name" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
        fi
        
        return 0
    else
        echo "错误: APK推送失败" >&2
        return 2
    fi
}

_show_android_push_apk_help() {
    cat << 'EOF'
gs_android_push_apk - 推送APK到Android设备

功能描述:
  将APK文件推送安装到Android设备，支持覆盖安装和自动启动

使用方式:
  gs-android-push-apk <APK路径> [选项]

参数:
  APK路径        要推送的APK文件路径（必需）

选项:
  -p, --package  指定包名，用于停止和启动应用
  -d, --device   指定设备ID
  --help, -h     显示此帮助信息

示例:
  gs-android-push-apk app.apk
  gs-android-push-apk app.apk -p com.example.app
  gs-android-push-apk app.apk -d emulator-5554
  gs-android-push-apk --help

依赖:
  系统命令: adb, aapt(可选)
  插件依赖: android

注意事项:
  - 自动覆盖安装现有应用
  - 可自动获取包名并重启应用
  - 需要启用"未知来源"安装权限
EOF
}

gs_android_push_systemui() {
    local build_out_dir="${1:-out/target/product}"
    local target_product="${2:-}"
    local device_id="${3:-}"
    local auto_restart=true
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_android_push_systemui_help
                return 0
                ;;
            --no-restart)
                auto_restart=false
                shift
                ;;
            -o|--out)
                build_out_dir="$2"
                shift 2
                ;;
            -t|--target)
                target_product="$2"
                shift 2
                ;;
            -d|--device)
                device_id="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done
    
    _gs_android_push_check_deps || return 2
    _gs_android_push_check_device || return 1
    
    if [[ -z "$target_product" ]]; then
        target_product="$TARGET_PRODUCT"
        if [[ -z "$target_product" ]]; then
            echo "错误: 未指定构建目标" >&2
            echo "建议: 设置TARGET_PRODUCT环境变量或使用-t选项" >&2
            return 1
        fi
    fi
    
    local systemui_path="$build_out_dir/$target_product/system_ext/priv-app/SystemUI/SystemUI.apk"
    
    if [[ ! -f "$systemui_path" ]]; then
        echo "错误: SystemUI文件不存在: $systemui_path" >&2
        echo "建议: 检查构建输出目录和目标产品名称" >&2
        return 1
    fi
    
    local adb_cmd="adb"
    if [[ -n "$device_id" ]]; then
        adb_cmd="adb -s $device_id"
    fi
    
    _gs_android_push_ensure_writable "$device_id"
    
    echo "推送SystemUI: $systemui_path"
    
    if $adb_cmd push "$systemui_path" "/system_ext/priv-app/SystemUI/SystemUI.apk"; then
        echo "SystemUI推送成功"
        
        _gs_android_push_cleanup_oat "$device_id" "/system_ext/priv-app/SystemUI"
        local need_reboot=$?
        
        if $auto_restart || [[ $need_reboot -eq 1 ]]; then
            echo "重启设备以生效..."
            $adb_cmd reboot
            echo "设备正在重启，请等待..."
        fi
        
        return 0
    else
        echo "错误: SystemUI推送失败" >&2
        return 2
    fi
}

_show_android_push_systemui_help() {
    cat << 'EOF'
gs_android_push_systemui - 推送Android SystemUI

功能描述:
  将编译好的SystemUI.apk推送到Android设备

使用方式:
  gs-android-push-systemui [选项]

选项:
  -o, --out      构建输出目录，默认out/target/product
  -t, --target   目标产品名称，默认使用TARGET_PRODUCT
  --no-restart   推送后不自动重启
  -d, --device   指定设备ID
  --help, -h     显示此帮助信息

示例:
  gs-android-push-systemui
  gs-android-push-systemui -t sdk_phone_x86_64
  gs-android-push-systemui --no-restart
  gs-android-push-systemui --help

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - 需要root权限和可写系统分区
  - 通常需要重启设备以生效
  - SystemUI是系统界面核心组件
EOF
}

gs_android_push_settings() {
    local build_out_dir="${1:-out/target/product}"
    local target_product="${2:-}"
    local device_id="${3:-}"
    local auto_restart=true
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_android_push_settings_help
                return 0
                ;;
            --no-restart)
                auto_restart=false
                shift
                ;;
            -o|--out)
                build_out_dir="$2"
                shift 2
                ;;
            -t|--target)
                target_product="$2"
                shift 2
                ;;
            -d|--device)
                device_id="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done
    
    _gs_android_push_check_deps || return 2
    _gs_android_push_check_device || return 1
    
    if [[ -z "$target_product" ]]; then
        target_product="$TARGET_PRODUCT"
        if [[ -z "$target_product" ]]; then
            echo "错误: 未指定构建目标" >&2
            echo "建议: 设置TARGET_PRODUCT环境变量或使用-t选项" >&2
            return 1
        fi
    fi
    
    local settings_path="$build_out_dir/$target_product/system_ext/priv-app/Settings/Settings.apk"
    
    if [[ ! -f "$settings_path" ]]; then
        echo "错误: Settings文件不存在: $settings_path" >&2
        echo "建议: 检查构建输出目录和目标产品名称" >&2
        return 1
    fi
    
    local adb_cmd="adb"
    if [[ -n "$device_id" ]]; then
        adb_cmd="adb -s $device_id"
    fi
    
    _gs_android_push_ensure_writable "$device_id"
    
    echo "推送Settings: $settings_path"
    
    if $adb_cmd push "$settings_path" "/system_ext/priv-app/Settings/Settings.apk"; then
        echo "Settings推送成功"
        
        _gs_android_push_cleanup_oat "$device_id" "/system_ext/priv-app/Settings"
        local need_reboot=$?
        
        if $auto_restart || [[ $need_reboot -eq 1 ]]; then
            echo "重启设备以生效..."
            $adb_cmd reboot
            echo "设备正在重启，请等待..."
        fi
        
        return 0
    else
        echo "错误: Settings推送失败" >&2
        return 2
    fi
}

_show_android_push_settings_help() {
    cat << 'EOF'
gs_android_push_settings - 推送Android Settings

功能描述:
  将编译好的Settings.apk推送到Android设备

使用方式:
  gs-android-push-settings [选项]

选项:
  -o, --out      构建输出目录，默认out/target/product
  -t, --target   目标产品名称，默认使用TARGET_PRODUCT
  --no-restart   推送后不自动重启
  -d, --device   指定设备ID
  --help, -h     显示此帮助信息

示例:
  gs-android-push-settings
  gs-android-push-settings -t sdk_phone_x86_64
  gs-android-push-settings --no-restart
  gs-android-push-settings --help

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - 需要root权限和可写系统分区
  - 通常需要重启设备以生效
  - Settings是系统设置应用
EOF
}

gs_android_push_native_lib() {
    local lib_path="${1:-}"
    local lib_name="${2:-}"
    local target_arch="${3:-lib64}"
    local device_id="${4:-}"
    local auto_restart=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_android_push_native_lib_help
                return 0
                ;;
            --restart|-r)
                auto_restart=true
                shift
                ;;
            --arch|-a)
                target_arch="$2"
                shift 2
                ;;
            -d|--device)
                device_id="$2"
                shift 2
                ;;
            *)
                if [[ -z "$lib_path" ]]; then
                    lib_path="$1"
                elif [[ -z "$lib_name" ]]; then
                    lib_name="$1"
                fi
                shift
                ;;
        esac
    done
    
    if [[ -z "$lib_path" ]]; then
        echo "错误: 缺少必需参数" >&2
        echo "使用方式: gs-android-push-native-lib <库文件路径> [库名] [选项]" >&2
        echo "使用 'gs-android-push-native-lib --help' 查看详细帮助" >&2
        return 1
    fi
    
    if [[ ! -f "$lib_path" ]]; then
        echo "错误: 库文件不存在: $lib_path" >&2
        return 1
    fi
    
    if [[ -z "$lib_name" ]]; then
        lib_name=$(basename "$lib_path")
    fi
    
    _gs_android_push_check_deps || return 2
    _gs_android_push_check_device || return 1
    
    local adb_cmd="adb"
    if [[ -n "$device_id" ]]; then
        adb_cmd="adb -s $device_id"
    fi
    
    _gs_android_push_ensure_writable "$device_id"
    
    local remote_path="/system/$target_arch/$lib_name"
    
    echo "推送Native库: $lib_path -> $remote_path"
    
    if $adb_cmd push "$lib_path" "$remote_path"; then
        echo "Native库推送成功"
        $adb_cmd shell "chmod 644 $remote_path"
        
        if $auto_restart; then
            echo "重启Android框架..."
            $adb_cmd shell "stop && start"
            echo "重启完成"
        fi
        
        return 0
    else
        echo "错误: Native库推送失败" >&2
        return 2
    fi
}

_show_android_push_native_lib_help() {
    cat << 'EOF'
gs_android_push_native_lib - 推送Native库到Android设备

功能描述:
  将编译好的.so库文件推送到Android设备的系统库目录

使用方式:
  gs-android-push-native-lib <库文件路径> [库名] [选项]

参数:
  库文件路径     要推送的.so文件路径（必需）
  库名           目标库名，默认使用文件名（可选）

选项:
  --arch, -a     目标架构目录，默认lib64(lib/lib64)
  -r, --restart  推送后重启Android框架
  -d, --device   指定设备ID
  --help, -h     显示此帮助信息

示例:
  gs-android-push-native-lib libtest.so
  gs-android-push-native-lib libtest.so --arch lib
  gs-android-push-native-lib libtest.so libtest_new.so --restart
  gs-android-push-native-lib --help

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - 需要root权限和可写系统分区
  - 推送后可能需要重启框架或设备
  - 确保库文件与目标架构匹配
EOF
}

gs_android_push_surfaceflinger() {
    local build_out_dir="${1:-out/target/product}"
    local target_product="${2:-}"
    local device_id="${3:-}"
    local auto_restart=true
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_android_push_surfaceflinger_help
                return 0
                ;;
            --no-restart)
                auto_restart=false
                shift
                ;;
            -o|--out)
                build_out_dir="$2"
                shift 2
                ;;
            -t|--target)
                target_product="$2"
                shift 2
                ;;
            -d|--device)
                device_id="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done
    
    _gs_android_push_check_deps || return 2
    _gs_android_push_check_device || return 1
    
    local resolved_device_id
    resolved_device_id=$(_gs_android_resolve_device "$device_id")
    
    if [[ -z "$target_product" ]]; then
        target_product="$TARGET_PRODUCT"
        if [[ -z "$target_product" ]]; then
            echo "错误: 未指定构建目标" >&2
            echo "建议: 设置TARGET_PRODUCT环境变量或使用-t选项" >&2
            return 1
        fi
    fi
    
    local sf_path="$build_out_dir/$target_product/system/bin/surfaceflinger"
    
    if [[ ! -f "$sf_path" ]]; then
        echo "错误: SurfaceFlinger文件不存在: $sf_path" >&2
        echo "建议: 检查构建输出目录和目标产品名称" >&2
        return 1
    fi
    
    _gs_android_push_ensure_writable "$resolved_device_id"
    
    echo "推送SurfaceFlinger: $sf_path"
    
    if _gs_android_execute "$resolved_device_id" push "$sf_path" "/system/bin/surfaceflinger"; then
        echo "SurfaceFlinger推送成功"
        _gs_android_execute "$resolved_device_id" shell "chmod 755 /system/bin/surfaceflinger"
        
        if $auto_restart; then
            echo "重启Android框架..."
            _gs_android_execute "$resolved_device_id" shell "stop && start"
            echo "重启完成"
        fi
        
        return 0
    else
        echo "错误: SurfaceFlinger推送失败" >&2
        return 2
    fi
}

gs_android_push_bootimage() {
    local boot_img="${1:-}"
    local device_id="${2:-}"
    local partition="boot"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_android_push_bootimage_help
                return 0
                ;;
            -p|--partition)
                partition="$2"
                shift 2
                ;;
            -d|--device)
                device_id="$2"
                shift 2
                ;;
            *)
                if [[ -z "$boot_img" ]]; then
                    boot_img="$1"
                fi
                shift
                ;;
        esac
    done
    
    if [[ -z "$boot_img" ]]; then
        echo "错误: 缺少必需参数" >&2
        echo "使用方式: gs-android-push-bootimage <启动镜像> [选项]" >&2
        echo "使用 'gs-android-push-bootimage --help' 查看详细帮助" >&2
        return 1
    fi
    
    if [[ ! -f "$boot_img" ]]; then
        echo "错误: 启动镜像文件不存在: $boot_img" >&2
        return 1
    fi
    
    _gs_android_push_check_deps || return 2
    _gs_android_push_check_device || return 1
    
    local resolved_device_id
    resolved_device_id=$(_gs_android_resolve_device "$device_id")
    
    echo "警告: 刷写启动分区具有风险，可能导致设备无法启动！"
    echo "推送启动镜像: $boot_img -> $partition"
    echo "请确认继续 (y/N):"
    read -r confirm
    
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "操作已取消"
        return 0
    fi
    
    # 检查是否支持fastboot
    if ! command -v fastboot >/dev/null 2>&1; then
        echo "错误: 缺少必需命令: fastboot" >&2
        echo "建议: 安装Android SDK Platform Tools" >&2
        return 2
    fi
    
    # 重启到bootloader模式
    echo "重启到bootloader模式..."
    _gs_android_execute "$resolved_device_id" reboot bootloader
    
    echo "等待设备进入fastboot模式..."
    sleep 5
    
    # 刷写启动镜像
    if fastboot flash "$partition" "$boot_img"; then
        echo "启动镜像刷写成功"
        
        echo "重启设备..."
        fastboot reboot
        
        echo "设备正在重启，请等待..."
        return 0
    else
        echo "错误: 启动镜像刷写失败" >&2
        echo "尝试重启设备..."
        fastboot reboot
        return 2
    fi
}

gs_android_push_recovery() {
    local recovery_img="${1:-}"
    local device_id="${2:-}"
    local flash_recovery=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_android_push_recovery_help
                return 0
                ;;
            --flash)
                flash_recovery=true
                shift
                ;;
            -d|--device)
                device_id="$2"
                shift 2
                ;;
            *)
                if [[ -z "$recovery_img" ]]; then
                    recovery_img="$1"
                fi
                shift
                ;;
        esac
    done
    
    if [[ -z "$recovery_img" ]]; then
        echo "错误: 缺少必需参数" >&2
        echo "使用方式: gs-android-push-recovery <恢复镜像> [选项]" >&2
        echo "使用 'gs-android-push-recovery --help' 查看详细帮助" >&2
        return 1
    fi
    
    if [[ ! -f "$recovery_img" ]]; then
        echo "错误: 恢复镜像文件不存在: $recovery_img" >&2
        return 1
    fi
    
    _gs_android_push_check_deps || return 2
    _gs_android_push_check_device || return 1
    
    local resolved_device_id
    resolved_device_id=$(_gs_android_resolve_device "$device_id")
    
    if $flash_recovery; then
        echo "警告: 刷写恢复分区具有风险，可能影响系统恢复功能！"
        echo "刷写恢复镜像: $recovery_img"
        echo "请确认继续 (y/N):"
        read -r confirm
        
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            echo "操作已取消"
            return 0
        fi
        
        # 检查是否支持fastboot
        if ! command -v fastboot >/dev/null 2>&1; then
            echo "错误: 缺少必需命令: fastboot" >&2
            echo "建议: 安装Android SDK Platform Tools" >&2
            return 2
        fi
        
        # 重启到bootloader模式
        echo "重启到bootloader模式..."
        _gs_android_execute "$resolved_device_id" reboot bootloader
        
        echo "等待设备进入fastboot模式..."
        sleep 5
        
        # 刷写恢复镜像
        if fastboot flash recovery "$recovery_img"; then
            echo "恢复镜像刷写成功"
            fastboot reboot
            return 0
        else
            echo "错误: 恢复镜像刷写失败" >&2
            fastboot reboot
            return 2
        fi
    else
        # 临时启动恢复镜像
        echo "临时启动恢复镜像: $recovery_img"
        
        # 检查是否支持fastboot
        if ! command -v fastboot >/dev/null 2>&1; then
            echo "错误: 缺少必需命令: fastboot" >&2
            echo "建议: 安装Android SDK Platform Tools" >&2
            return 2
        fi
        
        # 重启到bootloader模式
        echo "重启到bootloader模式..."
        _gs_android_execute "$resolved_device_id" reboot bootloader
        
        echo "等待设备进入fastboot模式..."
        sleep 5
        
        # 临时启动恢复镜像
        if fastboot boot "$recovery_img"; then
            echo "恢复镜像临时启动成功"
            return 0
        else
            echo "错误: 恢复镜像启动失败" >&2
            return 2
        fi
    fi
}

gs_android_push_vbmeta() {
    local vbmeta_img="${1:-}"
    local device_id="${2:-}"
    local disable_verification=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_android_push_vbmeta_help
                return 0
                ;;
            --disable-verification)
                disable_verification=true
                shift
                ;;
            -d|--device)
                device_id="$2"
                shift 2
                ;;
            *)
                if [[ -z "$vbmeta_img" ]]; then
                    vbmeta_img="$1"
                fi
                shift
                ;;
        esac
    done
    
    if [[ -z "$vbmeta_img" ]]; then
        echo "错误: 缺少必需参数" >&2
        echo "使用方式: gs-android-push-vbmeta <vbmeta镜像> [选项]" >&2
        echo "使用 'gs-android-push-vbmeta --help' 查看详细帮助" >&2
        return 1
    fi
    
    if [[ ! -f "$vbmeta_img" ]]; then
        echo "错误: vbmeta镜像文件不存在: $vbmeta_img" >&2
        return 1
    fi
    
    _gs_android_push_check_deps || return 2
    _gs_android_push_check_device || return 1
    
    local resolved_device_id
    resolved_device_id=$(_gs_android_resolve_device "$device_id")
    
    echo "警告: 刷写vbmeta分区具有风险，可能影响系统启动验证！"
    echo "刷写vbmeta镜像: $vbmeta_img"
    if $disable_verification; then
        echo "将禁用启动验证 (--disable-verity --disable-verification)"
    fi
    echo "请确认继续 (y/N):"
    read -r confirm
    
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "操作已取消"
        return 0
    fi
    
    # 检查是否支持fastboot
    if ! command -v fastboot >/dev/null 2>&1; then
        echo "错误: 缺少必需命令: fastboot" >&2
        echo "建议: 安装Android SDK Platform Tools" >&2
        return 2
    fi
    
    # 重启到bootloader模式
    echo "重启到bootloader模式..."
    _gs_android_execute "$resolved_device_id" reboot bootloader
    
    echo "等待设备进入fastboot模式..."
    sleep 5
    
    # 禁用验证（如果需要）
    if $disable_verification; then
        echo "禁用启动验证..."
        fastboot --disable-verity --disable-verification flash vbmeta "$vbmeta_img"
    else
        # 刷写vbmeta镜像
        fastboot flash vbmeta "$vbmeta_img"
    fi
    
    if [[ $? -eq 0 ]]; then
        echo "vbmeta镜像刷写成功"
        
        echo "重启设备..."
        fastboot reboot
        
        echo "设备正在重启，请等待..."
        return 0
    else
        echo "错误: vbmeta镜像刷写失败" >&2
        echo "尝试重启设备..."
        fastboot reboot
        return 2
    fi
}

gs_android_push_magisk() {
    local magisk_apk="${1:-}"
    local device_id="${2:-}"
    local install_method="patch"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_android_push_magisk_help
                return 0
                ;;
            --method)
                install_method="$2"
                shift 2
                ;;
            -d|--device)
                device_id="$2"
                shift 2
                ;;
            *)
                if [[ -z "$magisk_apk" ]]; then
                    magisk_apk="$1"
                fi
                shift
                ;;
        esac
    done
    
    if [[ -z "$magisk_apk" ]]; then
        echo "错误: 缺少必需参数" >&2
        echo "使用方式: gs-android-push-magisk <Magisk APK> [选项]" >&2
        echo "使用 'gs-android-push-magisk --help' 查看详细帮助" >&2
        return 1
    fi
    
    if [[ ! -f "$magisk_apk" ]]; then
        echo "错误: Magisk APK文件不存在: $magisk_apk" >&2
        return 1
    fi
    
    _gs_android_push_check_deps || return 2
    _gs_android_push_check_device || return 1
    
    local resolved_device_id
    resolved_device_id=$(_gs_android_resolve_device "$device_id")
    
    echo "警告: 安装Magisk将修改系统分区，可能影响系统稳定性！"
    echo "安装Magisk: $magisk_apk"
    echo "安装方式: $install_method"
    echo "请确认继续 (y/N):"
    read -r confirm
    
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "操作已取消"
        return 0
    fi
    
    case "$install_method" in
        "patch")
            echo "使用补丁方式安装Magisk..."
            
            # 安装Magisk APK
            echo "安装Magisk APK..."
            if ! _gs_android_execute "$resolved_device_id" install -r "$magisk_apk"; then
                echo "错误: Magisk APK安装失败" >&2
                return 2
            fi
            
            echo "Magisk APK安装成功"
            echo "请手动打开Magisk应用并完成初始化设置"
            echo "然后使用Magisk的补丁功能对boot.img进行修改"
            ;;
        "direct")
            echo "使用直接安装方式..."
            echo "注意: 这种方式需要预先补丁的boot.img"
            
            # 安装Magisk APK
            echo "安装Magisk APK..."
            if ! _gs_android_execute "$resolved_device_id" install -r "$magisk_apk"; then
                echo "错误: Magisk APK安装失败" >&2
                return 2
            fi
            
            echo "Magisk APK安装成功"
            echo "请手动使用fastboot刷写已补丁的boot.img"
            ;;
        *)
            echo "错误: 不支持的安装方式: $install_method" >&2
            echo "支持的方式: patch, direct" >&2
            return 1
            ;;
    esac
    
    return 0
}

gs_android_push_module() {
    local module_type="${1:-}"
    local module_file="${2:-}"
    local device_id="${3:-}"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_android_push_module_help
                return 0
                ;;
            -d|--device)
                device_id="$2"
                shift 2
                ;;
            *)
                if [[ -z "$module_type" ]]; then
                    module_type="$1"
                elif [[ -z "$module_file" ]]; then
                    module_file="$1"
                fi
                shift
                ;;
        esac
    done
    
    if [[ -z "$module_type" || -z "$module_file" ]]; then
        echo "错误: 缺少必需参数" >&2
        echo "使用方式: gs-android-push-module <模块类型> <模块文件> [选项]" >&2
        echo "使用 'gs-android-push-module --help' 查看详细帮助" >&2
        return 1
    fi
    
    if [[ ! -f "$module_file" ]]; then
        echo "错误: 模块文件不存在: $module_file" >&2
        return 1
    fi
    
    _gs_android_push_check_deps || return 2
    _gs_android_push_check_device || return 1
    
    local resolved_device_id
    resolved_device_id=$(_gs_android_resolve_device "$device_id")
    
    case "$module_type" in
        "xposed")
            echo "安装Xposed模块: $module_file"
            
            # 安装APK
            if _gs_android_execute "$resolved_device_id" install -r "$module_file"; then
                echo "Xposed模块安装成功"
                echo "请在Xposed Installer中激活模块并重启"
                return 0
            else
                echo "错误: Xposed模块安装失败" >&2
                return 2
            fi
            ;;
        "magisk")
            echo "安装Magisk模块: $module_file"
            
            # 推送到设备
            local remote_path="/sdcard/Download/$(basename "$module_file")"
            if _gs_android_execute "$resolved_device_id" push "$module_file" "$remote_path"; then
                echo "Magisk模块已推送到: $remote_path"
                echo "请在Magisk应用中手动安装模块"
                return 0
            else
                echo "错误: Magisk模块推送失败" >&2
                return 2
            fi
            ;;
        "edxposed")
            echo "安装EdXposed模块: $module_file"
            
            # 安装APK
            if _gs_android_execute "$resolved_device_id" install -r "$module_file"; then
                echo "EdXposed模块安装成功"
                echo "请在EdXposed Manager中激活模块并重启"
                return 0
            else
                echo "错误: EdXposed模块安装失败" >&2
                return 2
            fi
            ;;
        *)
            echo "错误: 不支持的模块类型: $module_type" >&2
            echo "支持的类型: xposed, magisk, edxposed" >&2
            return 1
            ;;
    esac
}

_show_android_push_surfaceflinger_help() {
    cat << 'EOF'
gs_android_push_surfaceflinger - 推送SurfaceFlinger到Android设备

功能描述:
  将编译好的surfaceflinger二进制文件推送到Android设备

使用方式:
  gs-android-push-surfaceflinger [选项]

选项:
  -o, --out      构建输出目录，默认out/target/product
  -t, --target   目标产品名称，默认使用TARGET_PRODUCT
  --no-restart   推送后不自动重启框架
  -d, --device   指定设备ID
  --help, -h     显示此帮助信息

示例:
  gs-android-push-surfaceflinger
  gs-android-push-surfaceflinger -t sdk_phone_x86_64
  gs-android-push-surfaceflinger --no-restart
  gs-android-push-surfaceflinger --help

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - 需要root权限和可写系统分区
  - SurfaceFlinger是显示系统核心服务
  - 通常需要重启框架以生效
EOF
}

_show_android_push_bootimage_help() {
    cat << 'EOF'
gs_android_push_bootimage - 刷写启动镜像

功能描述:
  将boot.img刷写到Android设备的启动分区

使用方式:
  gs-android-push-bootimage <启动镜像> [选项]

参数:
  启动镜像       要刷写的boot.img文件路径（必需）

选项:
  -p, --partition 目标分区名，默认boot
  -d, --device   指定设备ID
  --help, -h     显示此帮助信息

示例:
  gs-android-push-bootimage boot.img
  gs-android-push-bootimage boot.img -p boot_a
  gs-android-push-bootimage patched_boot.img
  gs-android-push-bootimage --help

依赖:
  系统命令: adb, fastboot
  插件依赖: android

注意事项:
  - 需要解锁bootloader
  - 刷写错误可能导致设备无法启动
  - 会自动重启到fastboot模式
  - 支持A/B分区系统
EOF
}

_show_android_push_recovery_help() {
    cat << 'EOF'
gs_android_push_recovery - 推送/启动Recovery镜像

功能描述:
  刷写或临时启动自定义Recovery镜像

使用方式:
  gs-android-push-recovery <Recovery镜像> [选项]

参数:
  Recovery镜像   要使用的recovery.img文件路径（必需）

选项:
  --flash        永久刷写到recovery分区
  -d, --device   指定设备ID
  --help, -h     显示此帮助信息

示例:
  gs-android-push-recovery twrp.img
  gs-android-push-recovery twrp.img --flash
  gs-android-push-recovery custom_recovery.img
  gs-android-push-recovery --help

依赖:
  系统命令: adb, fastboot
  插件依赖: android

注意事项:
  - 需要解锁bootloader
  - 默认为临时启动，不会永久替换
  - 使用--flash选项永久刷写
  - 会自动重启到fastboot模式
EOF
}

_show_android_push_vbmeta_help() {
    cat << 'EOF'
gs_android_push_vbmeta - 刷写VBMeta镜像

功能描述:
  刷写vbmeta.img到设备，用于管理验证启动

使用方式:
  gs-android-push-vbmeta <vbmeta镜像> [选项]

参数:
  vbmeta镜像     要刷写的vbmeta.img文件路径（必需）

选项:
  --disable-verification 禁用启动验证
  -d, --device   指定设备ID
  --help, -h     显示此帮助信息

示例:
  gs-android-push-vbmeta vbmeta.img
  gs-android-push-vbmeta vbmeta.img --disable-verification
  gs-android-push-vbmeta custom_vbmeta.img
  gs-android-push-vbmeta --help

依赖:
  系统命令: adb, fastboot
  插件依赖: android

注意事项:
  - 需要解锁bootloader
  - 影响系统验证启动功能
  - 禁用验证可能降低安全性
  - 会自动重启到fastboot模式
EOF
}

_show_android_push_magisk_help() {
    cat << 'EOF'
gs_android_push_magisk - 安装Magisk Root管理器

功能描述:
  安装Magisk APK并提供Root安装指导

使用方式:
  gs-android-push-magisk <Magisk APK> [选项]

参数:
  Magisk APK     Magisk应用安装包（必需）

选项:
  --method       安装方式：patch(补丁), direct(直接)
  -d, --device   指定设备ID
  --help, -h     显示此帮助信息

安装方式:
  patch          安装APK后手动使用补丁功能
  direct         直接刷写预补丁的boot.img

示例:
  gs-android-push-magisk Magisk-v24.3.apk
  gs-android-push-magisk Magisk.apk --method patch
  gs-android-push-magisk Magisk.apk --method direct
  gs-android-push-magisk --help  

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - 需要解锁bootloader
  - Root会修改系统安全机制
  - 可能影响某些应用运行
  - 建议备份重要数据
EOF
}

_show_android_push_module_help() {
    cat << 'EOF'
gs_android_push_module - 安装系统模块

功能描述:
  安装各种类型的Android系统增强模块

使用方式:
  gs-android-push-module <模块类型> <模块文件> [选项]

参数:
  模块类型       支持的模块类型（必需）
  模块文件       模块安装包文件路径（必需）

模块类型:
  xposed         Xposed框架模块
  magisk         Magisk模块
  edxposed       EdXposed框架模块

选项:
  -d, --device   指定设备ID
  --help, -h     显示此帮助信息

示例:
  gs-android-push-module xposed GravityBox.apk
  gs-android-push-module magisk module.zip
  gs-android-push-module edxposed XPrivacyLua.apk
  gs-android-push-module --help

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - Xposed/EdXposed模块需要对应框架支持
  - Magisk模块需要Magisk环境
  - 安装后需要在对应管理器中激活
  - 某些模块可能需要重启生效
EOF
}