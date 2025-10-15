#!/bin/bash

# Shell-Python Hybrid Plugin - Mixed Shell and Python Implementation
# Demonstrates combining shell and Python functions

# @plugin_function
# name: shell_info
# description:
#   zh: Shell函数信息（混合插件中的Shell部分）
#   en: Shell function info (shell part in hybrid plugin)
# usage: gs shell-python-hybrid shell_info
# examples:
#   - gs shell-python-hybrid shell_info
shell_info() {
    echo "🐚 shell-python-hybrid Shell Info | Source: plugin.sh | Works with Python functions | Shell Version: $BASH_VERSION"
}

# @plugin_function
# name: system_check
# description:
#   zh: 系统检查（Shell实现）
#   en: System check (shell implementation)
# usage: gs shell-python-hybrid system_check
# examples:
#   - gs shell-python-hybrid system_check
system_check() {
    echo "🔍 shell-python-hybrid System Check | OS: $(uname -s) | Available: Shell + Python | Memory: $(free -h 2>/dev/null | grep Mem | awk '{print $2}' || echo 'N/A')"
}
