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
from config.gerrit_merged_config import GerritMergedConfig
from config.jira_server_config import JiraServerConfig
from config.user_config import UserConfig

from gerrit.bot_gerrit import BotGerrit
from im.we_chat import Bot
from issues.bot_jira import BotJira

merged_message = "{issue}: {title} \n" \
                 "---> 处理人: {owner}\n" \
                 "---> Jira地址: {issue_link}\n" \
                 "---> Gerrit地址: {patch_link}\n\n"


class BotGerritMerged(object):

    def send_merged(self, config, who):
        jira_server = JiraServerConfig.get_configs()
        bot_jira = BotJira(jira_server.service, jira_server.fields, jira_server.user, jira_server.pwd)
        today = datetime.date.today()
        yesterday = today - datetime.timedelta(days=1)

        cmd = config.base_sql + config.time_sql.format(branch=config.branch, status='merged', yesterday=yesterday,
                                                       today=today)
        bot_patches = BotGerrit().search_patch(cmd)
        if bot_patches is None:
            smart_log("search merged patch error")
            return 0

        if len(bot_patches) > 0:
            message = "%s %s 模块合入%s分支问题数 = %d \n" \
                      "👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 \n" % (
                          config.project, yesterday, config.branch, len(bot_patches))

            for bot_patch in bot_patches:
                bot_issue = bot_jira.searchIssue(bot_patch.issue)
                message += merged_message.format(issue=bot_patch.issue,
                                                 issue_link=bot_patch.issue_link,
                                                 owner=bot_patch.owner_name,
                                                 patch_link=bot_patch.url,
                                                 title=bot_issue.title)

            smart_log(message)

            # send myself
            bot = Bot(UserConfig.get_configs().__getitem__("bot_owner"))
            bot.set_text(message, type='text').send()

            # send who, except bot_owner
            if who != "bot_owner":
                bot = Bot(UserConfig.get_configs().__getitem__(who))
                bot.set_text(message, type='text').send()

    def fetch_merged(self, project, branch, who):
        configs = GerritMergedConfig.get_configs()
        for config in configs:
            if project == config.project:
                if branch == "all":
                    self.send_merged(config, who)
                elif branch == config.branch:
                    self.send_merged(config, who)

# if __name__ == "__main__":
#     bot_gerrit_merged = BotGerritMerged()
#     bot_gerrit_merged.fetch_merged("all", "all", "bot_owner")
