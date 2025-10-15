#!/bin/bash

# Shell Simple Plugin - Pure Shell Script Example
# 纯Shell脚本插件示例

# @plugin_function
# name: hello
# description:
#   zh: 简单问候命令
#   en: Simple greeting command
# usage: gs shell-simple hello [name]
# examples:
#   - gs shell-simple hello
#   - gs shell-simple hello world
hello() {
    local name="${1:-World}"
    echo "🌍 Hello, $name! This is a pure Shell plugin function."
}

# @plugin_function
# name: system_check
# description:
#   zh: 系统状态检查
#   en: System status check
# usage: gs shell-simple system_check
# examples:
#   - gs shell-simple system_check
system_check() {
    echo "🔍 Shell Simple: System Check"
    echo "================================"
    echo "OS: $(uname -s)"
    echo "Architecture: $(uname -m)"
    echo "User: $USER"
    echo "Shell: $SHELL"
    echo "Working Directory: $(pwd)"
    echo "Date: $(date)"
}

# @plugin_function
# name: env_info
# description:
#   zh: 环境变量信息
#   en: Environment variables info
# usage: gs shell-simple env_info [pattern]
# examples:
#   - gs shell-simple env_info
#   - gs shell-simple env_info PATH
env_info() {
    local pattern="${1:-.*}"
    echo "🌐 Shell Simple: Environment Variables"
    echo "======================================"
    if [[ -n "$1" ]]; then
        echo "Filtered by pattern: $pattern"
        env | grep -i "$pattern" | head -10
    else
        echo "Showing first 10 environment variables:"
        env | head -10
    fi
}

# Main dispatcher - handle function calls when script is executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -gt 0 ]]; then
        case "$1" in
            hello|system_check|env_info)
                "$@"
                ;;
            *)
                echo "❌ Unknown function: $1"
                echo "Available functions: hello, system_check, env_info"
                exit 1
                ;;
        esac
    else
        echo "Usage: $0 <function_name> [args...]"
        echo "Available functions: hello, system_check, env_info"
        exit 1
    fi
fi
