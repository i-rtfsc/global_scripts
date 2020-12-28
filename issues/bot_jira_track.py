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

sys.path.append(os.path.join(os.path.dirname(__file__), "../"))

from config.jira_track_config import JiraTrackConfig
from config.jira_server_config import JiraServerConfig
from config.user_config import UserConfig
from im.we_chat import Bot
from issues.bot_jira import BotJira

review_message = "# [{}]({})\n" \
                 " \n" \
                 "> <font color=\"comment\">有问题需要处理</font>\n\n"


class BotJiraTrack(object):

    def send_track(self, who):
        jira_server = JiraServerConfig.get_configs()
        local_bot_jira = BotJira(jira_server.service, jira_server.fields, jira_server.user, jira_server.pwd)
        jql = JiraTrackConfig.get_configs().jira_track
        bot_issues = local_bot_jira.search_jql(jql)
        for bot_issue in bot_issues:
            message = review_message.format(bot_issue.issue, bot_issue.link)
            bot = Bot(UserConfig.get_configs().__getitem__(who))
            bot.set_text(message, type='markdown').send()


# if __name__ == "__main__":
#     jira_track = BotJiraTrack()
#     jira_track.send_track("bot_owner")
