#!/bin/bash
# -*- coding: utf-8 -*-
#
# System Proxy Subplugin
# - HTTP/HTTPS 代理管理
# - 设置和清除系统代理环境变量
#
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

# 代理配置
PROXY_IP="127.0.0.1"
PROXY_PORT="7890"

# @plugin_function
# name: on
# description:
#   zh: 开启系统代理
#   en: Enable system proxy
# usage: gs system proxy on
# examples:
#   - gs system proxy on
gs_system_proxy_on() {
    local proxy_url="http://${PROXY_IP}:${PROXY_PORT}"
    local no_proxy_hosts="${PROXY_IP},localhost"

    # 设置环境变量
    export http_proxy="${proxy_url}"
    export https_proxy="${proxy_url}"
    export no_proxy="${no_proxy_hosts}"
    export HTTP_PROXY="${proxy_url}"
    export HTTPS_PROXY="${proxy_url}"
    export NO_PROXY="${no_proxy_hosts}"

    echo "✅ 已开启代理: ${proxy_url}"
}

# @plugin_function
# name: off
# description:
#   zh: 关闭系统代理
#   en: Disable system proxy
# usage: gs system proxy off
# examples:
#   - gs system proxy off
gs_system_proxy_off() {
    # 清除环境变量
    unset http_proxy
    unset https_proxy
    unset no_proxy
    unset HTTP_PROXY
    unset HTTPS_PROXY
    unset NO_PROXY

    echo "❌ 已关闭代理"
}

# @plugin_function
# name: status
# description:
#   zh: 查看代理状态
#   en: Show proxy status
# usage: gs system proxy status
# examples:
#   - gs system proxy status
gs_system_proxy_status() {
    if [ -n "$http_proxy" ] || [ -n "$https_proxy" ] || [ -n "$HTTP_PROXY" ] || [ -n "$HTTPS_PROXY" ]; then
        echo "🌐 当前代理状态: 已启用"
        [ -n "$http_proxy" ] && echo "  http_proxy: $http_proxy"
        [ -n "$https_proxy" ] && echo "  https_proxy: $https_proxy"
        [ -n "$no_proxy" ] && echo "  no_proxy: $no_proxy"
        [ -n "$HTTP_PROXY" ] && echo "  HTTP_PROXY: $HTTP_PROXY"
        [ -n "$HTTPS_PROXY" ] && echo "  HTTPS_PROXY: $HTTPS_PROXY"
        [ -n "$NO_PROXY" ] && echo "  NO_PROXY: $NO_PROXY"
    else
        echo "🚫 当前代理状态: 已禁用"
    fi
}

# @plugin_function
# name: config
# description:
#   zh: 查看代理配置
#   en: Show proxy configuration
# usage: gs system proxy config
# examples:
#   - gs system proxy config
gs_system_proxy_config() {
    cat <<EOF
⚙️  代理配置信息:
  代理地址: ${PROXY_IP}
  代理端口: ${PROXY_PORT}
  代理URL:  http://${PROXY_IP}:${PROXY_PORT}

🔧 支持的环境变量:
  http_proxy, https_proxy, no_proxy
  HTTP_PROXY, HTTPS_PROXY, NO_PROXY
EOF
}