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
from config.bot_database import BotDatabase
from config.gerrit_review_config import GerritReviewConfig
from config.jira_server_config import JiraServerConfig
from config.user_config import UserConfig
from gerrit.bot_gerrit import BotGerrit
from im.we_chat import Bot
from issues.bot_jira import BotJira

who = "bot_owner"
auto = False

bot_database = BotDatabase()

review_message = "# [{}]({})\n" \
                 " \n" \
                 "> <font color=\"comment\">处理人：{}</font>\n\n" \
                 "> <font color=\"comment\">请帮忙review，有问题-1，没有问题+1</font>\n\n" \
                 "> {}\n" \
                 "\n" \
                 "\n\n备注：\n" \
                 " {}" \
                 "\n\n"


class BotGerritReview:

    def send_review(self, config, who):
        jira_server = JiraServerConfig.get_configs()
        bot_jira = BotJira(jira_server.service, jira_server.fields, jira_server.user, jira_server.pwd)
        cmd = config.base_sql + config.comment_sql.format(status='open', comment='need_review')
        bot_patches = BotGerrit().search_patch(cmd)
        if bot_patches is None:
            smart_log("send patch error")
            return 0

        for botPatch in bot_patches:
            flags = False
            result = bot_database.table_issue.find_one(issue=botPatch.number)
            if result is not None:
                if result["dock_team"] == 1:
                    smart_log("dock team %s has been saved\n" % (botPatch.number))
                else:
                    flags = True
                    self.tableIssue.update(dict(issue=botPatch.number, dock_team=1, game_team=result["game_team"]),
                                           ["issue"])
                    smart_log("dock team %s need save(update)\n" % (botPatch.number))
            else:
                flags = True
                bot_database.table_issue.insert(dict(issue=botPatch.number, dock_team=1, game_team=0))
                smart_log("dock team %s need save\n" % (botPatch.number))

            if (flags):
                issue = "Patch未填单号"
                link = "botPatch.url"

                if botPatch.issue != "null":
                    bot_issue = bot_jira.searchIssue(botPatch.issue)
                    if bot_issue is not None:
                        issue = bot_issue.issue
                        link = bot_issue.link

                message = review_message.format(issue, link, botPatch.owner_name, botPatch.url, botPatch.commitMessage)
                smart_log(message)
                bot = Bot(UserConfig.get_configs().__getitem__(who))
                bot.set_text(message, type='markdown').send()
                # bot.set_text('', type='text').set_mentioned_list(["@all"]).send()

    def fetch_review(self, project, who):
        configs = GerritReviewConfig.get_configs()
        for config in configs:
            if project == "all":
                self.send_review(config, who)
            elif project == config.project:
                self.send_review(config, who)


# if __name__ == "__main__":
#     gerrit_review = BotGerritReview()
#     gerrit_review.fetch_review("all", "bot_owner")
