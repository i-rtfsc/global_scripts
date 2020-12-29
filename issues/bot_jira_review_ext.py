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
import time

sys.path.append(os.path.join(os.path.dirname(__file__), "../"))

from base.smart_log import smart_log
from config.bot_database import BotDatabase
from config.jira_review_config import JiraReviewConfig
from config.jira_server_config import JiraServerConfig
from config.user_config import UserConfig
from im.we_chat import Bot
from issues.bot_jira import BotJira

bot_database = BotDatabase()

comment_message = "#{count} : {who}\n" \
                  "{comment}\n\n"

author_message = "{who} : 提交{count}笔\n"

total_message_count = "\n总计提交 : {count}笔\n"

time_message = "截止{time}, 需要合入提交一共 : {count}笔\n\n"


class BotJiraReviewExt(object):

    def send_review_ext(self, who, force):
        jira_server = JiraServerConfig.get_configs()
        local_bot_jira = BotJira(jira_server.service, jira_server.fields, jira_server.user, jira_server.pwd)
        jql = JiraReviewConfig.get_configs().jira_jql_review_ext
        bot_issues = local_bot_jira.search_jql(jql)

        dicts = dict()
        issue_count = 0
        total_comment_message = ""
        total_author_message = ""

        if force:
            flags = False
        else:
            flags = True

        for bot_issue in bot_issues:
            if "" != bot_issue.comment:
                if (flags):
                    result = bot_database.table_issue.find_one(issue=bot_issue.issue)
                    if result is not None:
                        if result["game_team"] == 1:
                            smart_log("game team %s has been saved\n" % bot_issue.issue)
                        else:
                            flags = False
                            bot_database.table_issue.update(
                                dict(issue=bot_issue.issue, dock_team=result["dock_team"], game_team=1), ["issue"])
                            smart_log("game team %s need save(update)\n" % bot_issue.issue)
                    else:
                        flags = False
                        bot_database.table_issue.insert(dict(issue=bot_issue.issue, dock_team=0, game_team=1))
                        smart_log("game team %s need save\n" % bot_issue.issue)

                if bot_issue.commentAuthor not in dicts:
                    dicts[bot_issue.commentAuthor] = [0]

                dicts[bot_issue.commentAuthor][0] += 1
                issue_count += 1

                total_comment_message = total_comment_message + comment_message.format(count=str(issue_count),
                                                                                       who=bot_issue.commentAuthor,
                                                                                       comment=bot_issue.comment)
        for key, values in dicts.items():
            # smart_log("key = %s , values = %s" % (key, values))
            count = str(values)
            total_author_message = total_author_message + author_message.format(who=key, count=count)

        total_message = time_message.format(time=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), count=str(
            issue_count)) + total_comment_message + total_message_count.format(
            count=str(issue_count)) + total_author_message

        if flags:
            smart_log("game team has been notify")
        else:
            smart_log(total_message)
            if issue_count > 0:
                bot = Bot(UserConfig.get_configs().__getitem__(who))
                bot.set_text(total_message, type='text').send()

# if __name__ == "__main__":
#     jira_review_ext = BotJiraReviewExt()
#     jira_review_ext.send_review_ext("bot_owner", True)
