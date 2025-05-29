#!/bin/bash
# -*- coding: utf-8 -*-
# -*- encoding: utf-8 -*-
#
# Android Grep Submodule
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

_gs_android_grep_check_aosp() {
    if [[ ! -d ".repo" && ! -f "build/envsetup.sh" ]]; then
        echo "错误: 当前目录不是Android源码根目录" >&2
        echo "建议: 请在AOSP源码根目录下执行此命令" >&2
        return 1
    fi
    return 0
}

_gs_android_grep_exclude_dirs() {
    echo "-name .repo -prune -o -name .git -prune -o -name out -prune -o"
}

gs_android_grep_java() {
    local pattern="${1:-}"
    
    if [[ "$pattern" == "--help" || "$pattern" == "-h" ]]; then
        _show_android_grep_java_help
        return 0
    fi
    
    if [[ -z "$pattern" ]]; then
        echo "错误: 缺少必需参数" >&2
        echo "使用方式: gs-android-grep-java <搜索模式>" >&2
        echo "使用 'gs-android-grep-java --help' 查看详细帮助" >&2
        return 1
    fi
    
    _gs_android_grep_check_aosp || return 2
    
    echo "在Java文件中搜索: $pattern"
    find . $(_gs_android_grep_exclude_dirs) -type f -name "*.java" \
        -exec grep --color -n "$pattern" {} +
    
    return $?
}

_show_android_grep_java_help() {
    cat << 'EOF'
gs_android_grep_java - 在Java文件中搜索

功能描述:
  在Android源码的所有Java文件中搜索指定模式

使用方式:
  gs-android-grep-java <搜索模式>

参数:
  搜索模式       要搜索的正则表达式或字符串（必需）

选项:
  --help, -h     显示此帮助信息

示例:
  gs-android-grep-java "onCreate"
  gs-android-grep-java "public.*static.*void"
  gs-android-grep-java --help

依赖:
  系统命令: find, grep
  插件依赖: android

注意事项:
  - 自动排除.repo、.git、out目录
  - 支持正则表达式搜索
  - 显示行号和高亮匹配内容
EOF
}

gs_android_grep_cpp() {
    local pattern="${1:-}"
    
    if [[ "$pattern" == "--help" || "$pattern" == "-h" ]]; then
        _show_android_grep_cpp_help
        return 0
    fi
    
    if [[ -z "$pattern" ]]; then
        echo "错误: 缺少必需参数" >&2
        echo "使用方式: gs-android-grep-cpp <搜索模式>" >&2
        echo "使用 'gs-android-grep-cpp --help' 查看详细帮助" >&2
        return 1
    fi
    
    _gs_android_grep_check_aosp || return 2
    
    echo "在C/C++文件中搜索: $pattern"
    find . $(_gs_android_grep_exclude_dirs) -type f \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' -o -name '*.h' -o -name '*.hpp' \) \
        -exec grep --color -n "$pattern" {} +
    
    return $?
}

_show_android_grep_cpp_help() {
    cat << 'EOF'
gs_android_grep_cpp - 在C/C++文件中搜索

功能描述:
  在Android源码的所有C/C++头文件和源文件中搜索指定模式

使用方式:
  gs-android-grep-cpp <搜索模式>

参数:
  搜索模式       要搜索的正则表达式或字符串（必需）

选项:
  --help, -h     显示此帮助信息

示例:
  gs-android-grep-cpp "main"
  gs-android-grep-cpp "class.*:"
  gs-android-grep-cpp --help

依赖:
  系统命令: find, grep
  插件依赖: android

注意事项:
  - 搜索.c .cc .cpp .cxx .h .hpp文件
  - 自动排除编译输出目录
  - 支持正则表达式搜索
EOF
}

gs_android_grep_kotlin() {
    local pattern="${1:-}"
    
    if [[ "$pattern" == "--help" || "$pattern" == "-h" ]]; then
        _show_android_grep_kotlin_help
        return 0  
    fi
    
    if [[ -z "$pattern" ]]; then
        echo "错误: 缺少必需参数" >&2
        echo "使用方式: gs-android-grep-kotlin <搜索模式>" >&2
        echo "使用 'gs-android-grep-kotlin --help' 查看详细帮助" >&2
        return 1
    fi
    
    _gs_android_grep_check_aosp || return 2
    
    echo "在Kotlin文件中搜索: $pattern"
    find . $(_gs_android_grep_exclude_dirs) -type f -name "*.kt" \
        -exec grep --color -n "$pattern" {} +
    
    return $?
}

_show_android_grep_kotlin_help() {
    cat << 'EOF'
gs_android_grep_kotlin - 在Kotlin文件中搜索

功能描述:
  在Android源码的所有Kotlin文件中搜索指定模式

使用方式:
  gs-android-grep-kotlin <搜索模式>

参数:
  搜索模式       要搜索的正则表达式或字符串（必需）

选项:
  --help, -h     显示此帮助信息

示例:
  gs-android-grep-kotlin "fun "
  gs-android-grep-kotlin "class.*:"
  gs-android-grep-kotlin --help

依赖:
  系统命令: find, grep
  插件依赖: android

注意事项:
  - 搜索所有.kt文件
  - 自动排除编译输出目录  
  - 支持正则表达式搜索
EOF
}

gs_android_grep_xml() {
    local pattern="${1:-}"
    
    if [[ "$pattern" == "--help" || "$pattern" == "-h" ]]; then
        _show_android_grep_xml_help
        return 0
    fi
    
    if [[ -z "$pattern" ]]; then
        echo "错误: 缺少必需参数" >&2
        echo "使用方式: gs-android-grep-xml <搜索模式>" >&2
        echo "使用 'gs-android-grep-xml --help' 查看详细帮助" >&2
        return 1
    fi
    
    _gs_android_grep_check_aosp || return 2
    
    echo "在XML文件中搜索: $pattern"
    find . $(_gs_android_grep_exclude_dirs) -type f -name "*.xml" \
        -exec grep --color -n "$pattern" {} +
    
    return $?
}

_show_android_grep_xml_help() {
    cat << 'EOF'
gs_android_grep_xml - 在XML文件中搜索

功能描述:
  在Android源码的所有XML文件中搜索指定模式

使用方式:
  gs-android-grep-xml <搜索模式>

参数:
  搜索模式       要搜索的正则表达式或字符串（必需）

选项:
  --help, -h     显示此帮助信息

示例:
  gs-android-grep-xml "android:name"
  gs-android-grep-xml "permission"
  gs-android-grep-xml --help

依赖:
  系统命令: find, grep
  插件依赖: android

注意事项:
  - 搜索所有.xml文件，包括布局、配置等
  - 自动排除编译输出目录
  - 适用于搜索权限、组件声明等
EOF
}

gs_android_grep_manifest() {
    local pattern="${1:-}"
    
    if [[ "$pattern" == "--help" || "$pattern" == "-h" ]]; then
        _show_android_grep_manifest_help
        return 0
    fi
    
    if [[ -z "$pattern" ]]; then
        echo "错误: 缺少必需参数" >&2
        echo "使用方式: gs-android-grep-manifest <搜索模式>" >&2
        echo "使用 'gs-android-grep-manifest --help' 查看详细帮助" >&2
        return 1
    fi
    
    _gs_android_grep_check_aosp || return 2
    
    echo "在AndroidManifest.xml文件中搜索: $pattern"
    find . $(_gs_android_grep_exclude_dirs) -type f -name "AndroidManifest.xml" \
        -exec grep --color -n "$pattern" {} +
    
    return $?
}

_show_android_grep_manifest_help() {
    cat << 'EOF'  
gs_android_grep_manifest - 在AndroidManifest.xml中搜索

功能描述:
  在Android源码的所有AndroidManifest.xml文件中搜索指定模式

使用方式:
  gs-android-grep-manifest <搜索模式>

参数:
  搜索模式       要搜索的正则表达式或字符串（必需）

选项:
  --help, -h     显示此帮助信息

示例:
  gs-android-grep-manifest "permission"
  gs-android-grep-manifest "android:exported"
  gs-android-grep-manifest --help

依赖:
  系统命令: find, grep
  插件依赖: android

注意事项:
  - 仅搜索AndroidManifest.xml文件
  - 适用于查找权限、组件配置等
  - 自动排除编译输出目录
EOF
}

gs_android_grep_makefile() {
    local pattern="${1:-}"
    
    if [[ "$pattern" == "--help" || "$pattern" == "-h" ]]; then
        _show_android_grep_makefile_help
        return 0
    fi
    
    if [[ -z "$pattern" ]]; then
        echo "错误: 缺少必需参数" >&2
        echo "使用方式: gs-android-grep-makefile <搜索模式>" >&2
        echo "使用 'gs-android-grep-makefile --help' 查看详细帮助" >&2
        return 1
    fi
    
    _gs_android_grep_check_aosp || return 2
    
    echo "在构建文件中搜索: $pattern"
    
    case $(uname -s) in
        Darwin)
            find -E . $(_gs_android_grep_exclude_dirs) -type f \
                -iregex '.*/(Makefile|Makefile\..*|.*\.make|.*\.mak|.*\.mk|.*\.bp)' \
                -exec grep --color -n "$pattern" {} +
            ;;
        *)
            find . $(_gs_android_grep_exclude_dirs) -type f \
                -regextype posix-egrep \
                -iregex '(.*\/Makefile|.*\/Makefile\..*|.*\.make|.*\.mak|.*\.mk|.*\.bp)' \
                -exec grep --color -n "$pattern" {} +
            ;;
    esac
    
    return $?
}

_show_android_grep_makefile_help() {
    cat << 'EOF'
gs_android_grep_makefile - 在构建文件中搜索

功能描述:
  在Android源码的构建文件(Makefile、Android.mk、Android.bp等)中搜索指定模式

使用方式:
  gs-android-grep-makefile <搜索模式>

参数:
  搜索模式       要搜索的正则表达式或字符串（必需）

选项:
  --help, -h     显示此帮助信息

示例:
  gs-android-grep-makefile "LOCAL_MODULE"
  gs-android-grep-makefile "android_app"
  gs-android-grep-makefile --help

依赖:
  系统命令: find, grep
  插件依赖: android

注意事项:
  - 搜索Makefile、.mk、.bp等构建文件
  - 适用于查找模块定义、依赖关系等
  - 自动适配不同操作系统的find命令
EOF
}

gs_android_grep_source() {
    local pattern="${1:-}"
    
    if [[ "$pattern" == "--help" || "$pattern" == "-h" ]]; then
        _show_android_grep_source_help
        return 0
    fi
    
    if [[ -z "$pattern" ]]; then
        echo "错误: 缺少必需参数" >&2
        echo "使用方式: gs-android-grep-source <搜索模式>" >&2
        echo "使用 'gs-android-grep-source --help' 查看详细帮助" >&2
        return 1
    fi
    
    _gs_android_grep_check_aosp || return 2
    
    echo "在所有源代码文件中搜索: $pattern"
    
    case $(uname -s) in
        Darwin)
            find -E . $(_gs_android_grep_exclude_dirs) -type f \
                -iregex '.*\.(c|h|cc|cpp|hpp|cxx|S|java|kt|xml|sh|mk|aidl|vts|proto|py|go|rs)' \
                -exec grep --color -n "$pattern" {} +
            ;;
        *)
            find . $(_gs_android_grep_exclude_dirs) -type f \
                -regextype posix-egrep \
                -iregex '.*\.(c|h|cc|cpp|hpp|cxx|S|java|kt|xml|sh|mk|aidl|vts|proto|py|go|rs)' \
                -exec grep --color -n "$pattern" {} +
            ;;
    esac
    
    return $?
}

_show_android_grep_source_help() {
    cat << 'EOF'
gs_android_grep_source - 在所有源代码文件中搜索

功能描述:
  在Android源码的所有源代码文件中搜索指定模式，包括多种编程语言

使用方式:
  gs-android-grep-source <搜索模式>

参数:
  搜索模式       要搜索的正则表达式或字符串（必需）

选项:
  --help, -h     显示此帮助信息

示例:
  gs-android-grep-source "SystemProperties"
  gs-android-grep-source "PERMISSION.*CAMERA"
  gs-android-grep-source --help

依赖:
  系统命令: find, grep
  插件依赖: android

注意事项:
  - 搜索多种源码文件类型
  - 包括C/C++、Java、Kotlin、Python、Go等
  - 搜索范围最广，结果可能较多
EOF
}

gs_android_grep_resource() {
    local pattern="${1:-}"
    
    if [[ "$pattern" == "--help" || "$pattern" == "-h" ]]; then
        _show_android_grep_resource_help
        return 0
    fi
    
    if [[ -z "$pattern" ]]; then
        echo "错误: 缺少必需参数" >&2
        echo "使用方式: gs-android-grep-resource <搜索模式>" >&2
        echo "使用 'gs-android-grep-resource --help' 查看详细帮助" >&2
        return 1
    fi
    
    _gs_android_grep_check_aosp || return 2
    
    echo "在资源文件中搜索: $pattern"
    
    local res_dirs
    res_dirs=($(find . $(_gs_android_grep_exclude_dirs) -name res -type d))
    
    if [[ ${#res_dirs[@]} -eq 0 ]]; then
        echo "未找到资源目录"
        return 1
    fi
    
    for dir in "${res_dirs[@]}"; do
        find "$dir" -type f -name '*.xml' -exec grep --color -n "$pattern" {} +
    done
    
    return $?
}

_show_android_grep_resource_help() {
    cat << 'EOF'
gs_android_grep_resource - 在Android资源文件中搜索

功能描述:
  在Android源码的所有res目录下的资源文件中搜索指定模式

使用方式:
  gs-android-grep-resource <搜索模式>

参数:
  搜索模式       要搜索的正则表达式或字符串（必需）

选项:
  --help, -h     显示此帮助信息

示例:
  gs-android-grep-resource "string name"
  gs-android-grep-resource "@drawable"
  gs-android-grep-resource --help

依赖:
  系统命令: find, grep
  插件依赖: android

注意事项:
  - 仅搜索res目录下的XML文件
  - 适用于查找字符串资源、布局等
  - 自动定位所有res目录
EOF
}

gs_android_grep_sepolicy() {
    local pattern="${1:-}"
    
    if [[ "$pattern" == "--help" || "$pattern" == "-h" ]]; then
        _show_android_grep_sepolicy_help
        return 0
    fi
    
    if [[ -z "$pattern" ]]; then
        echo "错误: 缺少必需参数" >&2
        echo "使用方式: gs-android-grep-sepolicy <搜索模式>" >&2
        echo "使用 'gs-android-grep-sepolicy --help' 查看详细帮助" >&2
        return 1
    fi
    
    _gs_android_grep_check_aosp || return 2
    
    echo "在SEPolicy文件中搜索: $pattern"
    find . $(_gs_android_grep_exclude_dirs) -name sepolicy -type d \
        -exec grep --color -n -r --exclude-dir=\.git "$pattern" {} +
    
    return $?
}

_show_android_grep_sepolicy_help() {
    cat << 'EOF'
gs_android_grep_sepolicy - 在SEPolicy文件中搜索

功能描述:
  在Android源码的所有SEPolicy安全策略文件中搜索指定模式

使用方式:
  gs-android-grep-sepolicy <搜索模式>

参数:
  搜索模式       要搜索的正则表达式或字符串（必需）

选项:
  --help, -h     显示此帮助信息

示例:
  gs-android-grep-sepolicy "allow"
  gs-android-grep-sepolicy "system_server"
  gs-android-grep-sepolicy --help

依赖:
  系统命令: find, grep
  插件依赖: android

注意事项:
  - 搜索所有sepolicy目录下的文件
  - 用于查找安全策略规则
  - 包含类型定义、权限规则等
EOF
}

gs_android_grep_rc() {
    local pattern="${1:-}"
    
    if [[ "$pattern" == "--help" || "$pattern" == "-h" ]]; then
        _show_android_grep_rc_help
        return 0
    fi
    
    if [[ -z "$pattern" ]]; then
        echo "错误: 缺少必需参数" >&2
        echo "使用方式: gs-android-grep-rc <搜索模式>" >&2
        echo "使用 'gs-android-grep-rc --help' 查看详细帮助" >&2
        return 1
    fi
    
    _gs_android_grep_check_aosp || return 2
    
    echo "在RC配置文件中搜索: $pattern"
    find . $(_gs_android_grep_exclude_dirs) -type f -name "*.rc*" \
        -exec grep --color -n "$pattern" {} +
    
    return $?
}

_show_android_grep_rc_help() {
    cat << 'EOF'
gs_android_grep_rc - 在RC配置文件中搜索

功能描述:
  在Android源码的所有RC配置文件中搜索指定模式

使用方式:
  gs-android-grep-rc <搜索模式>

参数:
  搜索模式       要搜索的正则表达式或字符串（必需）

选项:
  --help, -h     显示此帮助信息

示例:
  gs-android-grep-rc "service"
  gs-android-grep-rc "on boot"
  gs-android-grep-rc --help

依赖:
  系统命令: find, grep
  插件依赖: android

注意事项:
  - 搜索所有.rc和.rc.*文件
  - 包含init配置、服务定义等
  - 用于查找系统启动配置
EOF
}

gs_android_grep_go() {
    local pattern="${1:-}"
    
    if [[ "$pattern" == "--help" || "$pattern" == "-h" ]]; then
        _show_android_grep_go_help
        return 0
    fi
    
    if [[ -z "$pattern" ]]; then
        echo "错误: 缺少必需参数" >&2
        echo "使用方式: gs-android-grep-go <搜索模式>" >&2
        echo "使用 'gs-android-grep-go --help' 查看详细帮助" >&2
        return 1
    fi
    
    _gs_android_grep_check_aosp || return 2
    
    echo "在Go文件中搜索: $pattern"
    find . $(_gs_android_grep_exclude_dirs) -type f -name "*.go" \
        -exec grep --color -n "$pattern" {} +
    
    return $?
}

_show_android_grep_go_help() {
    cat << 'EOF'
gs_android_grep_go - 在Go文件中搜索

功能描述:
  在Android源码的所有Go语言文件中搜索指定模式

使用方式:
  gs-android-grep-go <搜索模式>

参数:
  搜索模式       要搜索的正则表达式或字符串（必需）

选项:
  --help, -h     显示此帮助信息

示例:
  gs-android-grep-go "func "
  gs-android-grep-go "import"
  gs-android-grep-go --help

依赖:
  系统命令: find, grep
  插件依赖: android

注意事项:
  - 搜索所有.go文件
  - 主要用于Soong构建系统
  - 包含构建逻辑和工具代码
EOF
}

gs_android_grep_rust() {
    local pattern="${1:-}"
    
    if [[ "$pattern" == "--help" || "$pattern" == "-h" ]]; then
        _show_android_grep_rust_help
        return 0
    fi
    
    if [[ -z "$pattern" ]]; then
        echo "错误: 缺少必需参数" >&2
        echo "使用方式: gs-android-grep-rust <搜索模式>" >&2
        echo "使用 'gs-android-grep-rust --help' 查看详细帮助" >&2
        return 1
    fi
    
    _gs_android_grep_check_aosp || return 2
    
    echo "在Rust文件中搜索: $pattern"
    find . $(_gs_android_grep_exclude_dirs) -type f -name "*.rs" \
        -exec grep --color -n "$pattern" {} +
    
    return $?
}

_show_android_grep_rust_help() {
    cat << 'EOF'
gs_android_grep_rust - 在Rust文件中搜索

功能描述:
  在Android源码的所有Rust语言文件中搜索指定模式

使用方式:
  gs-android-grep-rust <搜索模式>

参数:
  搜索模式       要搜索的正则表达式或字符串（必需）

选项:
  --help, -h     显示此帮助信息

示例:
  gs-android-grep-rust "fn "
  gs-android-grep-rust "use "
  gs-android-grep-rust --help

依赖:
  系统命令: find, grep
  插件依赖: android

注意事项:
  - 搜索所有.rs文件
  - Rust在Android中用于系统组件
  - 包含安全关键的底层代码
EOF
}