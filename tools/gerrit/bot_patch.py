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


import os
import sys

# sys.path.append(os.path.join(os.path.dirname(__file__), "../"))


class BotPatch(object):

    def __init__(self, result):
        # 提交人
        self.owner_name = result["owner"]["email"]
        # patch地址
        self.url = result["url"]
        # branch
        self.branch = result["branch"]
        # status
        self.status = result["status"]
        # number
        self.number = result["number"]
        self.commitMessage = result["commitMessage"]

        def __getitem__(self, key):
            return getattr(self, key)

        def __str__(self):
            print(['%s:%s' % item for item in self.__dict__.items()])
