#!/bin/bash

# Hybrid Plugin with Subplugins - Shell Part
# Demonstrates full hybrid implementation with subplugin support

# @plugin_function
# name: shell_info
# description:
#   zh: Shell函数信息（混合主插件中的Shell部分）
#   en: Shell function info (shell part in hybrid main plugin)
# usage: gs hybrid-with-subplugins shell_info
# examples:
#   - gs hybrid-with-subplugins shell_info
shell_info() {
    echo "🐚 hybrid-with-subplugins Shell Info | Main Plugin: Shell function | Subplugins: tools, services | Implementation: Full hybrid"
}

# @plugin_function
# name: list_subplugins
# description:
#   zh: 列出所有子插件（Shell实现）
#   en: List all subplugins (shell implementation)
# usage: gs hybrid-with-subplugins list_subplugins
# examples:
#   - gs hybrid-with-subplugins list_subplugins
list_subplugins() {
    echo "📂 hybrid-with-subplugins Subplugins (Shell): | 1. tools (混合工具) | 2. services (混合服务)"
}
