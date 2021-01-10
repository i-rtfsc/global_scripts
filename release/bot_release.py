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
import jenkins
from urlextract import URLExtract

sys.path.append(os.path.join(os.path.dirname(__file__), "../"))

from base.smart_log import smart_log
from config.user_config import UserConfig
from config.jenkins_release_config import JenkinsReleaseConfig
from gerrit.bot_gerrit import BotGerrit
from im.we_chat import Bot


class BotRelease(object):

    def work_impl(self, config, who):
        # 不自动build_job了
        # param = {'APK_LIST': 'app_project', 'BASE_BRANCH': 'code_branch', 'RELEASE_BRANCH': 'apk_branch',
        #          'RELEASE_OPTION': 'review'}
        # param['APK_LIST'] = config.project
        # param['BASE_BRANCH'] = config.source
        # param['RELEASE_BRANCH'] = config.destination
        # smart_log("param = %s " % param)
        # server = jenkins.Jenkins(config.server, config.user, config.token)
        # result = server.build_job('DB_bsui_release', param)
        # smart_log(result)
        # last_build_number = server.get_job_info('DB_bsui_release')['lastCompletedBuild']['number']
        # build_info = server.get_build_console_output('DB_bsui_release', last_build_number)
        # matches = URLExtract().find_urls(build_info)
        # if len(matches):
        #     for url in matches:
        #         if "http://gerrit.blackshark.com" in url:
        #             smart_log("gerrit = %s " % url)
        #             bot = Bot(UserConfig.get_configs().__getitem__("bot_owner"))
        #             bot.set_text(url, type='text').send()

        bot_patches = BotGerrit().search_patch(config.gerrit_sql)
        if len(bot_patches) > 0:
            message = "今日 %s 模块合入 %s 分支数量 = %d , 请检查是否需要release到 %s 分支 \n" \
                      % (config.project, config.source, len(bot_patches), config.destination)
            bot = Bot(UserConfig.get_configs().__getitem__(who))
            bot.set_text(message, type='text').send()

    def work(self, project, who):
        for config in JenkinsReleaseConfig.get_configs():
            smart_log("config project = %s" % config.project)
            if project == "all":
                self.work_impl(config, who)
            if project == config.project:
                self.work_impl(config, who)


if __name__ == "__main__":
    BotRelease().work("all", "bot_owner")
