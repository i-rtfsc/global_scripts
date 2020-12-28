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


class AndroidImageConfig(object):
    def __init__(self, ftp_server, user, pwd, _dict):
        self.ftp_server = ftp_server
        self.user = user
        self.pwd = pwd
        self.project = _dict['project']
        self.source = _dict['source']
        self.destination = _dict['destination']

    def __getitem__(self, key):
        return getattr(self, key)

    def __str__(self):
        print(['%s:%s' % item for item in self.__dict__.items()])

    @staticmethod
    def get_configs():
        configs = list()
        path = os.path.join(os.path.dirname(__file__), ".android_image.json")
        with open(path, 'r') as f:
            json_config = json.loads(f.read())
            ftp_server = json_config["auth"]["ftp_server"]
            user = json_config["auth"]["user"]
            pwd = json_config["auth"]["pwd"]
            images = json_config["image"]
            for _dict in images:
                config = AndroidImageConfig(ftp_server, user, pwd, _dict)
                configs.append(config)

        return configs
