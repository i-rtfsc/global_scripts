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
import datetime
import json
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "../"))


class JenkinsReleaseConfig(object):
    def __init__(self, server, user, token, _dict):
        hours = int(datetime.datetime.now().strftime('%H'))
        self.server = server
        self.user = user
        self.token = token
        self.project = _dict['project']
        self.source = _dict['source']
        self.destination = _dict['destination']
        self.gerrit_sql = _dict['gerrit_sql'].format(branch=self.source, hours=hours)

    def __getitem__(self, key):
        return getattr(self, key)

    def __str__(self):
        print(['%s:%s' % item for item in self.__dict__.items()])

    @staticmethod
    def get_configs():
        configs = list()
        path = os.path.join(os.path.dirname(__file__), ".jenkins_release.json")
        with open(path, 'r') as f:
            json_config = json.loads(f.read())
            server = json_config["netrc"]["server"]
            user = json_config["netrc"]["user"]
            pwd = json_config["netrc"]["token"]
            images = json_config["apk"]
            for _dict in images:
                config = JenkinsReleaseConfig(server, user, pwd, _dict)
                configs.append(config)

        return configs
