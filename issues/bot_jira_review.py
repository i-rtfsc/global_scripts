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
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "../"))

from base.smart_log import smart_log
from config.bot_database import BotDatabase
from config.jira_review_config import JiraReviewConfig
from config.jira_server_config import JiraServerConfig
from config.user_config import UserConfig

from im.we_chat import Bot
from issues.bot_jira import BotJira

bot_database = BotDatabase()

review_message = "# [{}]({})\n" \
                 " \n" \
                 "> <font color=\"comment\">处理人：{}</font>\n\n" \
                 "> <font color=\"comment\">请帮忙review，有问题-1，没有问题+1</font>\n\n" \
                 "> {}\n" \
                 "\n" \
                 " {}" \
                 "\n\n"


class BotJiraReview:

    def send_review(self, who):
        jira_server = JiraServerConfig.get_configs()
        local_bot_jira = BotJira(jira_server.service, jira_server.fields, jira_server.user, jira_server.pwd)
        jql = JiraReviewConfig.get_configs().jira_jql_review
        bot_issues = local_bot_jira.search_jql(jql)
        for botIssue in bot_issues:
            if "" != botIssue.comment:
                flags = False
                result = bot_database.table_issue.find_one(issue=botIssue.issue)
                if result is not None:
                    if result["dock_team"] == 1:
                        smart_log("dock team %s has been saved" % (botIssue.issue))
                    else:
                        flags = True
                        bot_database.table_issue.update(
                            dict(issue=botIssue.issue, dock_team=1, game_team=result["game_team"]),
                            ["issue"])
                        smart_log("dock team %s need save(update)" % (botIssue.issue))
                else:
                    flags = True
                    bot_database.table_issue.insert(dict(issue=botIssue.issue, dock_team=1, game_team=0))
                    smart_log("dock team %s need save" % (botIssue.issue))

                if (flags):
                    message = review_message.format(botIssue.issue, botIssue.link,
                                                    botIssue.commentAuthor, botIssue.comment, "")
                    smart_log(message)
                    bot = Bot(UserConfig.get_configs().__getitem__(who))
                    bot.set_text(message, type='markdown').send()
                    # bot.set_text('', type='text').set_mentioned_list(["@all"]).send()

# if __name__ == "__main__":
#     jira_review = BotJiraReview()
#     jira_review.send_review("bot_owner")
