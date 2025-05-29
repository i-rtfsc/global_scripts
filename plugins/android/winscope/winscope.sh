#!/bin/bash
# -*- coding: utf-8 -*-
# -*- encoding: utf-8 -*-
#
# Android Winscope Submodule
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

_gs_android_winscope_check_deps() {
    _gs_android_check_adb || return 2
    _gs_android_winscope_check_python || return 2
    return 0
}

_gs_android_winscope_check_device() {
    _gs_android_check_device || return 1
    return 0
}

gs_android_winscope_trace() {
    local duration="${1:-10}"
    local output_dir="${2:-winscope_traces}"
    local device_id="${3:-}"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_android_winscope_trace_help
                return 0
                ;;
            -t|--time)
                duration="$2"
                shift 2
                ;;
            -o|--output)
                output_dir="$2"
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
    
    _gs_android_winscope_check_deps || return 2
    _gs_android_winscope_check_device || return 1
    
    local resolved_device_id
    resolved_device_id=$(_gs_android_resolve_device "$device_id")
    
    # 创建输出目录
    mkdir -p "$output_dir"
    
    echo "开始Winscope跟踪收集..."
    echo "跟踪时长: ${duration}秒"
    echo "输出目录: $output_dir"
    
    # 启用跟踪
    echo "启用Window Manager跟踪..."
    _gs_android_execute "$resolved_device_id" shell "service call window 1 i32 1"
    
    echo "启用Surface Flinger跟踪..."
    _gs_android_execute "$resolved_device_id" shell "service call SurfaceFlinger 1020 i32 1"
    
    echo "收集跟踪数据 ${duration}秒..."
    sleep "$duration"
    
    echo "停止跟踪并收集数据..."
    
    # 停止跟踪
    _gs_android_execute "$resolved_device_id" shell "service call window 1 i32 0"
    _gs_android_execute "$resolved_device_id" shell "service call SurfaceFlinger 1020 i32 0"
    
    # 收集Window Manager跟踪
    echo "收集Window Manager跟踪..."
    if _gs_android_execute "$resolved_device_id" shell "dumpsys window --proto WindowManager" > "$output_dir/wm_trace.pb"; then
        echo "Window Manager跟踪已保存: $output_dir/wm_trace.pb"
    else
        echo "警告: Window Manager跟踪收集失败" >&2
    fi
    
    # 收集Surface Flinger跟踪
    echo "收集Surface Flinger跟踪..."
    if _gs_android_execute "$resolved_device_id" shell "dumpsys SurfaceFlinger --proto" > "$output_dir/sf_trace.pb"; then
        echo "Surface Flinger跟踪已保存: $output_dir/sf_trace.pb"
    else
        echo "警告: Surface Flinger跟踪收集失败" >&2
    fi
    
    # 收集层级转储
    echo "收集层级转储..."
    if _gs_android_execute "$resolved_device_id" shell "dumpsys window --proto windows" > "$output_dir/wm_dump.pb"; then
        echo "Window层级转储已保存: $output_dir/wm_dump.pb"
    fi
    
    if _gs_android_execute "$resolved_device_id" shell "dumpsys SurfaceFlinger --proto dump" > "$output_dir/sf_dump.pb"; then
        echo "Surface层级转储已保存: $output_dir/sf_dump.pb"
    fi
    
    echo "Winscope跟踪收集完成！"
    echo "使用 'gs-android-winscope-ui $output_dir' 查看结果"
    
    return 0
}

_show_android_winscope_trace_help() {
    cat << 'EOF'
gs_android_winscope_trace - 收集Winscope跟踪数据

功能描述:
  收集Android Window Manager和Surface Flinger的跟踪数据用于Winscope分析

使用方式:
  gs-android-winscope-trace [选项]

选项:
  -t, --time     跟踪时长（秒），默认10秒
  -o, --output   输出目录，默认winscope_traces
  -d, --device   指定设备ID
  --help, -h     显示此帮助信息

示例:
  gs-android-winscope-trace
  gs-android-winscope-trace -t 20
  gs-android-winscope-trace -o my_traces -t 30
  gs-android-winscope-trace -d emulator-5554
  gs-android-winscope-trace --help

输出文件:
  wm_trace.pb    - Window Manager跟踪数据
  sf_trace.pb    - Surface Flinger跟踪数据
  wm_dump.pb     - Window层级转储
  sf_dump.pb     - Surface层级转储

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - 跟踪期间请进行要分析的操作
  - 跟踪会影响设备性能
  - 生成的文件可用Winscope分析
EOF
}

gs_android_winscope_ui() {
    local html_file="${1:-winscope.html}"
    local device_id="${2:-}"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_android_winscope_ui_help
                return 0
                ;;
            -f|--file)
                html_file="$2"
                shift 2
                ;;
            -d|--device)
                device_id="$2"
                shift 2
                ;;
            *)
                if [[ -z "$html_file" || "$html_file" == "winscope.html" ]]; then
                    html_file="$1"
                fi
                shift
                ;;
        esac
    done
    
    _gs_android_winscope_check_deps || return 2
    
    # 检查HTML文件是否存在，如果不存在尝试从插件目录查找
    if [[ ! -f "$html_file" ]]; then
        local script_dir
        if [[ -n "$_GS_ROOT_PATH" ]]; then
            script_dir="$_GS_ROOT_PATH/plugins/android/winscope"
        else
            script_dir="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
        fi
        
        local alt_html="${script_dir}/${html_file}"
        if [[ -f "$alt_html" ]]; then
            html_file="$alt_html"
        else
            echo "错误: HTML文件不存在: $html_file" >&2
            echo "可用文件:"
            ls "$script_dir"/*.html 2>/dev/null | xargs -n1 basename | sed 's/^/  /'
            return 1
        fi
    fi
    
    echo "启动Winscope UI..."
    echo "HTML文件: $html_file"
    
    # 启动代理服务器
    local script_dir
    if [[ -n "$_GS_ROOT_PATH" ]]; then
        script_dir="$_GS_ROOT_PATH/plugins/android/winscope"
    else
        script_dir="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
    fi
    
    local proxy_script="${script_dir}/winscope_proxy.py"
    
    if [[ ! -f "$proxy_script" ]]; then
        echo "警告: 代理脚本不存在: $proxy_script" >&2
        echo "将直接打开HTML文件"
    fi
    
    # 尝试打开HTML文件
    if command -v open >/dev/null 2>&1; then
        open "$html_file"
    elif command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$html_file"
    else
        echo "请手动在浏览器中打开: $html_file"
    fi
    
    # 启动代理服务器（如果存在）
    if [[ -f "$proxy_script" ]]; then
        echo "启动Winscope代理服务器..."
        echo "代理运行在 http://localhost:8080"
        python3 "$proxy_script"
    fi
    
    return 0
}

_show_android_winscope_ui_help() {
    cat << 'EOF'
gs_android_winscope_ui - 启动Winscope分析界面

功能描述:
  启动Winscope Web界面用于分析Window Manager和Surface Flinger跟踪数据

使用方式:
  gs-android-winscope-ui [HTML文件] [选项]

参数:
  HTML文件      Winscope HTML界面文件，默认winscope.html（可选）

选项:
  -f, --file    指定HTML文件
  -d, --device  指定设备ID（预留）
  --help, -h    显示此帮助信息

可用HTML文件:
  winscope.html       - 标准Winscope界面
  winscope-aosp.html  - AOSP版本Winscope界面

示例:
  gs-android-winscope-ui
  gs-android-winscope-ui winscope-aosp.html
  gs-android-winscope-ui -f winscope.html
  gs-android-winscope-ui --help

依赖:
  系统命令: python3, open(macOS) 或 xdg-open(Linux)
  插件依赖: android

注意事项:
  - 会自动启动代理服务器
  - 界面运行在浏览器中
  - 支持拖拽跟踪文件进行分析
  - 提供Window和Surface的可视化分析
EOF
}

gs_android_winscope_dump() {
    local output_dir="${1:-winscope_dumps}"
    local device_id="${2:-}"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_android_winscope_dump_help
                return 0
                ;;
            -o|--output)
                output_dir="$2"
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
    
    _gs_android_winscope_check_deps || return 2
    _gs_android_winscope_check_device || return 1
    
    local resolved_device_id
    resolved_device_id=$(_gs_android_resolve_device "$device_id")
    
    # 创建输出目录
    mkdir -p "$output_dir"
    
    echo "收集Winscope转储数据..."
    echo "输出目录: $output_dir"
    
    # 收集Window Manager状态转储
    echo "收集Window Manager状态..."
    if _gs_android_execute "$resolved_device_id" shell "dumpsys window --proto windows" > "$output_dir/wm_dump_$(date +%Y%m%d_%H%M%S).pb"; then
        echo "Window Manager转储已保存"
    else
        echo "警告: Window Manager转储失败" >&2
    fi
    
    # 收集Surface Flinger状态转储
    echo "收集Surface Flinger状态..."
    if _gs_android_execute "$resolved_device_id" shell "dumpsys SurfaceFlinger --proto dump" > "$output_dir/sf_dump_$(date +%Y%m%d_%H%M%S).pb"; then
        echo "Surface Flinger转储已保存"
    else
        echo "警告: Surface Flinger转储失败" >&2
    fi
    
    # 收集额外的调试信息
    echo "收集额外调试信息..."
    _gs_android_execute "$resolved_device_id" shell "dumpsys window displays" > "$output_dir/displays_$(date +%Y%m%d_%H%M%S).txt"
    _gs_android_execute "$resolved_device_id" shell "dumpsys SurfaceFlinger --list" > "$output_dir/sf_layers_$(date +%Y%m%d_%H%M%S).txt"
    
    echo "Winscope转储收集完成！"
    echo "文件保存在: $output_dir"
    
    return 0
}

_show_android_winscope_dump_help() {
    cat << 'EOF'
gs_android_winscope_dump - 收集Winscope状态转储

功能描述:
  收集当前Android Window Manager和Surface Flinger的状态转储

使用方式:
  gs-android-winscope-dump [选项]

选项:
  -o, --output   输出目录，默认winscope_dumps
  -d, --device   指定设备ID
  --help, -h     显示此帮助信息

示例:
  gs-android-winscope-dump
  gs-android-winscope-dump -o current_state
  gs-android-winscope-dump -d emulator-5554
  gs-android-winscope-dump --help

输出文件:
  wm_dump_*.pb     - Window Manager状态转储
  sf_dump_*.pb     - Surface Flinger状态转储
  displays_*.txt   - 显示器信息
  sf_layers_*.txt  - Surface层信息

依赖:
  系统命令: adb
  插件依赖: android

注意事项:
  - 捕获的是瞬时状态
  - 适合调试当前显示问题
  - 文件名包含时间戳
  - 生成的protobuf文件可用Winscope分析
EOF
}