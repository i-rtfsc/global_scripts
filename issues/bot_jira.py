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

# https://jira.readthedocs.io/en/master/examples.html
from jira import JIRA

sys.path.append(os.path.join(os.path.dirname(__file__), "../"))
from issues.bot_issue import BotIssue


class BotJira(object):
    def __init__(self, service, fields, user, pwd):
        self.jira_service = service
        self.jira_user = user
        self.jira_pwd = pwd
        self.jira_fields = fields
        self.jira = JIRA(server=self.jira_service, basic_auth=(self.jira_user, self.jira_pwd))

    def search_jql(self, jql):
        jira_issues = list()
        issues = self.jira.search_issues(jql, maxResults=1000, fields=self.jira_fields)
        for issue in issues:
            bot_issues = BotIssue(self.jira_service, issue)
            jira_issues.append(bot_issues)
        return jira_issues

    def search_issue(self, search_issue):
        result = self.jira.issue(search_issue, fields=self.jira_fields)
        return BotIssue(self.jira_service, result)
