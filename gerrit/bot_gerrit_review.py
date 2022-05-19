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
import threading
import time
import schedule

from config.bot_database import BotDatabase
from config.gerrit_config import GerritConfig
from bot_gerrit import BotGerrit

# import outside dir
sys.path.append(os.path.join(os.path.dirname(__file__), "../"))
from im.fei_shu import FeiShu

auto = True


class BotGerritReview(object):
    def __init__(self, project):
        self.project = project
        self.bot_database = BotDatabase()
        self.review_message = "处理人 = {who}" \
                              "\n\n" \
                              "{url}" \
                              "\n\n" \
                              "备注： \n" \
                              "{commit}" \
                              "\n\n"

    def send_review(self, config):
        cmd = config.sql
        bot_patches = BotGerrit().search_patch(cmd)
        if bot_patches is None:
            print("send patch error")
            return 0

        for bot_patch in bot_patches:
            flags = True
            result = self.bot_database.table_issue.find_one(issue=bot_patch.number)
            if result is not None:
                if result["review"] == 1:
                    print("review column %s has been saved\n" % bot_patch.number)
                else:
                    flags = True
                    self.tableIssue.update(dict(issue=bot_patch.number, review=1), ["issue"])
                    print("review column %s need save(update)\n" % bot_patch.number)
            else:
                flags = True
                self.bot_database.table_issue.insert(dict(issue=bot_patch.number, review=1))
                print("review column %s need save\n" % bot_patch.number)

            if flags:
                message = self.review_message.format(who=bot_patch.owner_name,
                                                     url=bot_patch.url,
                                                     commit=bot_patch.commitMessage)
                print(message)
                bot = FeiShu(config.bot)
                bot.send_text(message)

    def fetch_review(self):
        print(self.project)
        configs = GerritConfig.get_configs()
        for config in configs:
            if self.project == config.project:
                self.send_review(config)

    def run_threaded(self, job_func):
        job_thread = threading.Thread(target=job_func)
        job_thread.start()

    def gerrit_review_job(self):
        self.fetch_review()


def main():
    gerrit_review = BotGerritReview("review")
    gerrit_review.gerrit_review_job()

    if auto:
        schedule.every(5).minutes.do(gerrit_review.run_threaded, gerrit_review.gerrit_review_job)

    return 0


if __name__ == "__main__":
    main()
    while auto:
        schedule.run_pending()
