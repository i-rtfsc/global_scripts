#!/bin/bash

# Tools Subplugin - Shell Implementation
# Subplugin for hybrid-with-subplugins main plugin

# @plugin_function
# name: shell_tool
# description:
#   zh: Shell工具功能
#   en: Shell tool functionality
# usage: gs hybrid-with-subplugins tools shell_tool
# examples:
#   - gs hybrid-with-subplugins tools shell_tool
shell_tool() {
    echo "🔨 hybrid-with-subplugins tools shell_tool | Subplugin: tools | Implementation: Shell | Parent: Full hybrid"
}

# Main dispatcher - handle function calls when script is executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -gt 0 ]]; then
        case "$1" in
            shell_tool)
                "$@"
                ;;
            *)
                echo "❌ Unknown function: $1"
                echo "Available functions: shell_tool"
                exit 1
                ;;
        esac
    else
        echo "Usage: $0 <function_name> [args...]"
        echo "Available functions: shell_tool"
        exit 1
    fi
fi
