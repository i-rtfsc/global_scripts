#!/bin/bash
# -*- coding: utf-8 -*-
# -*- encoding: utf-8 -*-
#
# Android Perfetto Submodule
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

_gs_android_perfetto_check_deps() {
    _gs_android_check_adb || return 2
    return 0
}

_gs_android_perfetto_check_device() {
    _gs_android_check_device || return 1
    return 0
}

_gs_android_perfetto_setup_device() {
    local device_id="$1"
    
    echo "设置设备权限..."
    _gs_android_execute "$device_id" root && _gs_android_execute "$device_id" remount
    
    # 确保跟踪目录存在
    _gs_android_execute "$device_id" shell "mkdir -p /data/misc/perfetto-traces"
    _gs_android_execute "$device_id" shell "chmod 755 /data/misc/perfetto-traces"
    
    return 0
}

gs_android_perfetto_trace() {
    local config_file="${1:-}"
    local output_file="${2:-trace.perfetto-trace}"
    local device_id="${3:-}"
    local duration="20s"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_android_perfetto_trace_help
                return 0
                ;;
            -c|--config)
                config_file="$2"
                shift 2
                ;;
            -o|--output)
                output_file="$2"
                shift 2
                ;;
            -t|--time)
                duration="$2"
                shift 2
                ;;
            -d|--device)
                device_id="$2"
                shift 2
                ;;
            *)
                if [[ -z "$config_file" ]]; then
                    config_file="$1"
                fi
                shift
                ;;
        esac
    done
    
    if [[ -z "$config_file" ]]; then
        echo "错误: 缺少必需参数" >&2
        echo "使用方式: gs-android-perfetto-trace <配置文件> [选项]" >&2
        echo "使用 'gs-android-perfetto-trace --help' 查看详细帮助" >&2
        return 1
    fi
    
    _gs_android_perfetto_check_deps || return 2
    _gs_android_perfetto_check_device || return 1
    
    # 检查配置文件是否存在，如果不存在尝试从插件目录查找
    if [[ ! -f "$config_file" ]]; then
        local script_dir
        if [[ -n "$_GS_ROOT_PATH" ]]; then
            script_dir="$_GS_ROOT_PATH/plugins/android/perfetto"
        else
            script_dir="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
        fi
        
        local alt_config="${script_dir}/${config_file}"
        if [[ -f "$alt_config" ]]; then
            config_file="$alt_config"
        else
            echo "错误: 配置文件不存在: $config_file" >&2
            echo "建议: 检查文件路径或使用默认配置" >&2
            return 1
        fi
    fi
    
    local adb_cmd="adb"
    if [[ -n "$device_id" ]]; then
        adb_cmd="adb -s $device_id"
    fi
    
    _gs_android_perfetto_setup_device "$resolved_device_id"
    
    local remote_trace="/data/misc/perfetto-traces/trace.perfetto-trace"
    
    echo "开始Perfetto性能跟踪..."
    echo "配置文件: $config_file"
    echo "输出文件: $output_file"
    echo "跟踪时长: $duration"
    
    if cat "$config_file" | _gs_android_execute "$resolved_device_id" shell "perfetto -c - --txt -o $remote_trace"; then
        echo "跟踪完成，正在下载..."
        
        if _gs_android_execute "$resolved_device_id" pull "$remote_trace" "$output_file"; then
            echo "跟踪文件已保存: $output_file"
            echo "可以使用Perfetto UI查看: https://ui.perfetto.dev"
            
            # 清理设备上的临时文件
            _gs_android_execute "$resolved_device_id" shell "rm -f $remote_trace"
            return 0
        else
            echo "错误: 跟踪文件下载失败" >&2
            return 2
        fi
    else
        echo "错误: Perfetto跟踪失败" >&2
        echo "建议: 检查设备是否支持Perfetto或配置文件格式" >&2
        return 2
    fi
}

_show_android_perfetto_trace_help() {
    cat << 'EOF'
gs_android_perfetto_trace - Android Perfetto性能跟踪

功能描述:
  使用Perfetto进行Android系统性能跟踪，支持自定义配置

使用方式:
  gs-android-perfetto-trace <配置文件> [选项]

参数:
  配置文件       Perfetto配置文件(.pbtx格式)（必需）

选项:
  -o, --output   输出文件名，默认trace.perfetto-trace
  -t, --time     跟踪时长，默认20s
  -d, --device   指定设备ID
  --help, -h     显示此帮助信息

示例:
  gs-android-perfetto-trace config.pbtx
  gs-android-perfetto-trace config.pbtx -o my_trace.perfetto-trace
  gs-android-perfetto-trace config.pbtx -t 30s -d emulator-5554
  gs-android-perfetto-trace --help

依赖:
  系统命令: adb
  插件依赖: android
  设备工具: perfetto

注意事项:
  - 需要Android 9+支持
  - 跟踪期间会占用设备资源
  - 使用https://ui.perfetto.dev查看跟踪结果
  - 配置文件格式为protobuf text format
EOF
}

gs_android_perfetto_quick() {
    local categories="${1:-sched freq idle am wm gfx view binder_driver hal dalvik camera input res memory}"
    local duration="${2:-20s}"
    local output_file="${3:-trace.perfetto-trace}"
    local device_id="${4:-}"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_android_perfetto_quick_help
                return 0
                ;;
            -c|--categories)
                categories="$2"
                shift 2
                ;;
            -t|--time)
                duration="$2"
                shift 2
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
                shift
                ;;
        esac
    done
    
    _gs_android_perfetto_check_deps || return 2
    _gs_android_perfetto_check_device || return 1
    
    local resolved_device_id
    resolved_device_id=$(_gs_android_resolve_device "$device_id")
    
    _gs_android_perfetto_setup_device "$resolved_device_id"
    
    local remote_trace="/data/misc/perfetto-traces/trace.perfetto-trace"
    
    echo "开始快速Perfetto跟踪..."
    echo "跟踪类别: $categories"
    echo "跟踪时长: $duration"
    echo "输出文件: $output_file"
    
    if _gs_android_execute "$resolved_device_id" shell "perfetto -o $remote_trace -t $duration $categories"; then
        echo "跟踪完成，正在下载..."
        
        if _gs_android_execute "$resolved_device_id" pull "$remote_trace" "$output_file"; then
            echo "跟踪文件已保存: $output_file"
            echo "可以使用Perfetto UI查看: https://ui.perfetto.dev"
            
            # 清理设备上的临时文件
            _gs_android_execute "$resolved_device_id" shell "rm -f $remote_trace"
            return 0
        else
            echo "错误: 跟踪文件下载失败" >&2
            return 2
        fi
    else
        echo "错误: Perfetto跟踪失败" >&2
        return 2
    fi
}

_show_android_perfetto_quick_help() {
    cat << 'EOF'
gs_android_perfetto_quick - 快速Perfetto性能跟踪

功能描述:
  使用预定义类别进行快速的Android性能跟踪

使用方式:
  gs-android-perfetto-quick [选项]

选项:
  -c, --categories  跟踪类别，默认常用系统类别
  -t, --time        跟踪时长，默认20s
  -o, --output      输出文件名，默认trace.perfetto-trace
  -d, --device      指定设备ID
  --help, -h        显示此帮助信息

常用跟踪类别:
  sched            - 调度器事件
  freq             - CPU频率变化
  idle             - CPU空闲状态
  am               - Activity Manager
  wm               - Window Manager
  gfx              - 图形系统
  view             - View系统
  binder_driver    - Binder驱动
  hal              - HAL层
  dalvik           - Dalvik虚拟机
  camera           - 相机子系统
  input            - 输入系统
  res              - 资源管理
  memory           - 内存管理

示例:
  gs-android-perfetto-quick
  gs-android-perfetto-quick -t 30s
  gs-android-perfetto-quick -c "sched freq gfx"
  gs-android-perfetto-quick -c "memory dalvik" -t 60s
  gs-android-perfetto-quick --help

依赖:
  系统命令: adb
  插件依赖: android
  设备工具: perfetto

注意事项:
  - 适合快速性能分析
  - 自动选择常用跟踪类别
  - 结果文件可用Perfetto UI分析
EOF
}

gs_android_perfetto_ui() {
    local trace_file="${1:-}"
    
    if [[ "$trace_file" == "--help" || "$trace_file" == "-h" ]]; then
        _show_android_perfetto_ui_help
        return 0
    fi
    
    if [[ -n "$trace_file" && ! -f "$trace_file" ]]; then
        echo "错误: 跟踪文件不存在: $trace_file" >&2
        return 1
    fi
    
    echo "打开Perfetto UI..."
    echo "Perfetto UI: https://ui.perfetto.dev"
    
    if [[ -n "$trace_file" ]]; then
        echo "请在浏览器中打开上述链接，然后拖拽文件: $trace_file"
    else
        echo "请在浏览器中打开上述链接，然后拖拽您的.perfetto-trace文件"
    fi
    
    # 尝试自动打开浏览器
    if command -v open >/dev/null 2>&1; then
        open "https://ui.perfetto.dev"
    elif command -v xdg-open >/dev/null 2>&1; then
        xdg-open "https://ui.perfetto.dev"
    else
        echo "请手动在浏览器中打开上述链接"
    fi
    
    return 0
}

_show_android_perfetto_ui_help() {
    cat << 'EOF'
gs_android_perfetto_ui - 打开Perfetto分析界面

功能描述:
  打开Perfetto Web UI用于分析跟踪文件

使用方式:
  gs-android-perfetto-ui [跟踪文件]

参数:
  跟踪文件       要分析的.perfetto-trace文件（可选）

选项:
  --help, -h     显示此帮助信息

示例:
  gs-android-perfetto-ui
  gs-android-perfetto-ui trace.perfetto-trace
  gs-android-perfetto-ui --help

依赖:
  系统命令: open(macOS) 或 xdg-open(Linux)

注意事项:
  - 会自动尝试打开默认浏览器
  - Perfetto UI运行在浏览器中
  - 支持拖拽文件进行分析
  - 提供丰富的性能分析功能
EOF
}