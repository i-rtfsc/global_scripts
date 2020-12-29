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


class SyncCodeConfig(object):
    def __init__(self, _dict):
        self.project = _dict['project']

        if len(_dict['branch'].split(';')) > 0:
            self.branchs = list(set(_dict['branch'].split(';')))
        else:
            self.branchs = _dict['branch']

        self.source_origin = _dict['source_origin']
        self.target_origin = _dict['target_origin']
        self.copy = _dict['copy']

    def __getitem__(self, key):
        return getattr(self, key)

    def __str__(self):
        print(['%s:%s' % item for item in self.__dict__.items()])

    @staticmethod
    def get_configs():
        configs = list()
        path = os.path.join(os.path.dirname(__file__), ".sync_code_configs.json")
        with open(path, 'r') as json_data:
            dicts = json.loads(json_data.read(), object_hook=dict)
            for _dict in dicts:
                config = SyncCodeConfig(_dict)
                configs.append(config)

        return configs
