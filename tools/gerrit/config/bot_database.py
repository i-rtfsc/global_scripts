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
import dataset


class BotDatabase(object):

    def __init__(self):
        path = os.path.join(os.path.dirname(__file__), ".bot-issue.db")
        self.db = dataset.connect('sqlite:///' + path)
        self.table_issue = self.db['issue']

    def get_database(self):
        return self.db

    def get_table_issue(self):
        return self.table_issue
