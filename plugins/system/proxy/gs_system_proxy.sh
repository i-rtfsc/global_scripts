#!/bin/bash
# -*- coding: utf-8 -*-
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2022 anqi.huang@outlook.com
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


ip=127.0.0.1
port=7890

# 开启系统代理
function gs_system_proxy_on() {
    export http_proxy=http://${ip}:${port}
    export https_proxy=http://${ip}:${port}
    export no_proxy=${ip},localhost
    export HTTP_PROXY=http://${ip}:${port}
    export HTTPS_PROXY=http://${ip}:${port}
    export NO_PROXY=${ip},localhost
    echo -e "\033[32m[√] 已开启代理\033[0m"
}

# 关闭系统代理
function gs_system_proxy_off(){
    unset http_proxy
    unset https_proxy
    unset no_proxy
    unset HTTP_PROXY
    unset HTTPS_PROXY
    unset NO_PROXY
    echo -e "\033[31m[×] 已关闭代理\033[0m"
}
