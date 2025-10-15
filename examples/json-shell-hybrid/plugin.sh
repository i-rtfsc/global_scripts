#!/bin/bash
# JSON+Shell Hybrid Plugin Example
# JSON+Shell混合插件示例

# @plugin_function
# name: shell_info
# description:
#   zh: Shell函数信息（混合主插件中的Shell部分）
#   en: Shell function info (shell part in hybrid main plugin)
# usage: gs json-shell-hybrid shell_info
# examples:
#   - gs json-shell-hybrid shell_info
shell_info() {
    echo "🐚 JSON+Shell Hybrid: Shell Component"
    echo "======================================"
    echo "Plugin Type: JSON+Shell Hybrid"
    echo "Shell Functions: ✅ Active"
    echo "JSON Commands: ✅ Available"
    echo "Integration: ✅ Seamless"
    echo "Shell Component Features:"
    echo "  - Native bash execution"
    echo "  - Direct system integration"
    echo "  - Fast command processing"
}

# @plugin_function
# name: shell_demo
# description:
#   zh: Shell功能演示
#   en: Shell functionality demonstration
# usage: gs json-shell-hybrid shell_demo [mode]
# examples:
#   - gs json-shell-hybrid shell_demo
#   - gs json-shell-hybrid shell_demo interactive
shell_demo() {
    local mode="${1:-basic}"
    echo "🎯 JSON+Shell Hybrid: Shell Demo"
    echo "================================="
    echo "Demo Mode: $mode"
    echo "Shell Features:"
    echo "  ✅ Command line processing"
    echo "  ✅ Environment variable access"
    echo "  ✅ File system operations"
    echo "  ✅ Process management"
    
    if [[ "$mode" == "interactive" ]]; then
        echo ""
        echo "Interactive features:"
        echo "  - Current user: $USER"
        echo "  - Current directory: $(pwd)"
        echo "  - Shell version: $BASH_VERSION"
    fi
}

# Main dispatcher - handle function calls when script is executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -gt 0 ]]; then
        case "$1" in
            shell_info|shell_demo)
                "$@"
                ;;
            *)
                echo "❌ Unknown function: $1"
                echo "Available functions: shell_info, shell_demo"
                exit 1
                ;;
        esac
    else
        echo "Usage: $0 <function_name> [args...]"
        echo "Available functions: shell_info, shell_demo"
        exit 1
    fi
fi
