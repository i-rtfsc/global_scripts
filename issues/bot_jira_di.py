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

from base.smart_log import smart_log
from config.jira_di_config import JiraDiConfig
from config.jira_server_config import JiraServerConfig
from config.user_config import UserConfig
from im.we_chat import Bot
from issues.bot_jira import BotJira

TOTAL = "总数"
DI = [10, 3, 1, 0.1]

project = "all"
who = "bot_owner"
auto = False

message_format = "# {who}问题总数 = <font color=\"warning\">{total}</font>\n" \
                 "> 致命 = <font color=\"warning\">{level_1}</font>\n" \
                 "> 严重 = <font color=\"warning\">{level_2}</font>\n" \
                 "> 一般 = <font color=\"comment\">{level_3}</font>\n" \
                 "> 提示 = <font color=\"comment\">{level_4}</font>\n" \
                 "> 总DI = <font color=\"warning\">{di}</font>\n\n"


class BotJiraDI(object):

    def fetch_issues(self, config):
        if config.project != "x":
            jira_server = JiraServerConfig.get_configs()
            local_bot_jira = BotJira(jira_server.service, jira_server.fields, jira_server.user, jira_server.pwd)
            local_bot_issues = local_bot_jira.search_jql(config.jql)
            smart_log('共 %d 个问题待解决' % len(local_bot_issues))

            # sort = sorted(bot_issues, key=lambda x: (x["assignee"], x["di"]))
            # # 多字段分组
            # user_group = groupby(sort, key=lambda x: (x["assignee"], x["di"], x["issue"]))
            # for key, group in user_group:
            #     print(key[0], key[1], key[2])

            return local_bot_issues

    def parse_issues(self, config, local_bot_issues):
        dicts = dict()
        dicts[TOTAL] = [0, 0, 0, 0, 0, 0.0]

        for botIssue in local_bot_issues:
            assignee = botIssue.assignee
            level = botIssue.level

            if assignee not in dicts:
                dicts[assignee] = [0, 0, 0, 0, 0, 0.0]

            if "致命" == level:
                # 致命+1
                dicts[assignee][0] += 1
                # 总数+1
                dicts[assignee][4] += 1
                # DI值+10
                dicts[assignee][5] += DI[0]
                #######################
                # 致命+1
                dicts[TOTAL][0] += 1
                # 总数+1
                dicts[TOTAL][4] += 1
                # DI值+10
                dicts[TOTAL][5] += DI[0]
            elif "严重" == level:
                dicts[assignee][1] += 1
                # 总数+1
                dicts[assignee][4] += 1
                # DI值+3
                dicts[assignee][5] += DI[1]
                #######################
                dicts[TOTAL][1] += 1
                # 总数+1
                dicts[TOTAL][4] += 1
                # DI值+3
                dicts[TOTAL][5] += DI[1]
            elif "一般" == level:
                dicts[assignee][2] += 1
                # 总数+1
                dicts[assignee][4] += 1
                # DI值+1
                dicts[assignee][5] += DI[2]
                #######################
                dicts[TOTAL][2] += 1
                # 总数+1
                dicts[TOTAL][4] += 1
                # DI值+1
                dicts[TOTAL][5] += DI[2]
            elif "提示" == level:
                dicts[assignee][3] += 1
                # 总数+1
                dicts[assignee][4] += 1
                # DI值+0.1
                dicts[assignee][5] += DI[3]
                #######################
                dicts[TOTAL][3] += 1
                # 总数+1
                dicts[TOTAL][4] += 1
                # DI值+0.1
                dicts[TOTAL][5] += DI[3]

        local_sub_message = ""
        for key, values in dicts.items():
            # smart_log("key = %s , values = %s" % (key, values))
            if key != TOTAL:
                local_sub_message += message_format.format(who=key, total=values[4], level_1=values[0],
                                                           level_2=values[1],
                                                           level_3=values[2], level_4=values[3],
                                                           di=float("{:.2f}".format(values[5])))

        last_message = message_format.format(who=config.title, total=dicts[TOTAL][4], level_1=dicts[TOTAL][0],
                                             level_2=dicts[TOTAL][1],
                                             level_3=dicts[TOTAL][2], level_4=dicts[TOTAL][3],
                                             di=float("{:.2f}".format(dicts[TOTAL][5])))

        return last_message + local_sub_message

    def send_impl(self, config, who):
        local_bot_issues = self.fetch_issues(config)
        if local_bot_issues != None and len(local_bot_issues) > 0:
            message = self.parse_issues(config, local_bot_issues)
            smart_log(message)
            bot = Bot(UserConfig.get_configs().__getitem__(who))
            bot.set_text(message, type='markdown').send()

    def send_di(self, project, who):
        for config in JiraDiConfig.get_configs():
            if project == "all":
                self.send_impl(config=config, who=who)
            elif config.project == project:
                self.send_impl(config=config, who=who)

# if __name__ == "__main__":
#     botJiraDI = BotJiraDI()
#     botJiraDI.send_di("all", "bot_owner")
