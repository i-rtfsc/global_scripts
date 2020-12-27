#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2020 anqi.huang@outlook.com
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

import json
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "../"))

from base.smart_log import smart_log
from gerrit.bot_patch import BotPatch


class BotGerrit(object):

    def search_patch(self, cmd):
        smart_log(cmd)
        try:
            process = os.popen(cmd)
            outputs = process.readlines()

            del outputs[-1]  # 删除最后一个元素
            patchs = list()
            for output in outputs:
                result = json.loads(output)
                patchs.append(BotPatch(result))
            process.close()
            return patchs

        except:
            pass

        return None
