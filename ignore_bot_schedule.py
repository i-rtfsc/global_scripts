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

sys.path.append(os.path.join(os.path.dirname(__file__), "./"))

from base.smart_log import smart_log
from issues.bot_jira_di import BotJiraDI
from issues.bot_jira_review import BotJiraReview
from issues.bot_jira_review_ext import BotJiraReviewExt
from issues.bot_jira_track import BotJiraTrack
from gerrit.bot_gerrit_review import BotGerritReview
from gerrit.bot_gerrit_merged import BotGerritMerged

bot_jira_dI = BotJiraDI()

jira_review = BotJiraReview()

jira_review_ext = BotJiraReviewExt()

jira_track = BotJiraTrack()

gerrit_review = BotGerritReview()

bot_gerrit_merged = BotGerritMerged()


def run_threaded(job_func):
    job_thread = threading.Thread(target=job_func)
    job_thread.start()


def di_job():
    # kaiser/penrose / all
    # bot_owner / bot_team
    bot_jira_dI.send_di("all", "bot_owner")


def jira_review_job():
    # bot_owner / bot_team
    jira_review.send_review("bot_owner")


def jira_review_ext_job():
    jira_review_ext.send_review_ext("bot_owner", False)


def jira_track_job():
    jira_track.send_track("bot_owner")


def gerrit_review_job():
    # bot_owner / bot_team
    gerrit_review.fetch_review("all", "bot_owner")


def gerrit_merged_job():
    # bot_owner / bot_team
    bot_gerrit_merged.fetch_merged("GameDock", "all", "bot_owner")
    bot_gerrit_merged.fetch_merged("GameDockEngine", "bsui_q", "bot_owner")


def main():
    smart_log(os.path.abspath(__file__))

    di_job()
    jira_review_job()
    jira_track_job()
    gerrit_review_job()
    gerrit_merged_job()

    # schedule.every(5).minutes.do(run_threaded, di_job)
    for i in ["10:00", "17:30"]:
        schedule.every().monday.at(i).do(run_threaded, di_job)
        schedule.every().tuesday.at(i).do(run_threaded, di_job)
        schedule.every().wednesday.at(i).do(run_threaded, di_job)
        schedule.every().thursday.at(i).do(run_threaded, di_job)
        schedule.every().friday.at(i).do(run_threaded, di_job)

    for i in ["10:00", "14:00", "17:00"]:
        schedule.every().monday.at(i).do(run_threaded, jira_track_job)
        schedule.every().tuesday.at(i).do(run_threaded, jira_track_job)
        schedule.every().wednesday.at(i).do(run_threaded, jira_track_job)
        schedule.every().thursday.at(i).do(run_threaded, jira_track_job)
        schedule.every().friday.at(i).do(run_threaded, jira_track_job)

    schedule.every(5).minutes.do(run_threaded, jira_review_job)

    schedule.every(5).minutes.do(run_threaded, jira_review_ext_job)

    schedule.every(5).minutes.do(run_threaded, gerrit_review_job)

    for i in ["10:00"]:
        schedule.every().monday.at(i).do(run_threaded, gerrit_merged_job)
        schedule.every().tuesday.at(i).do(run_threaded, gerrit_merged_job)
        schedule.every().wednesday.at(i).do(run_threaded, gerrit_merged_job)
        schedule.every().thursday.at(i).do(run_threaded, gerrit_merged_job)
        schedule.every().friday.at(i).do(run_threaded, gerrit_merged_job)
        schedule.every().saturday.at(i).do(run_threaded, gerrit_merged_job)
        schedule.every().sunday.at(i).do(run_threaded, gerrit_merged_job)

    return 0


if __name__ == "__main__":
    main()
    while True:
        schedule.run_pending()
        time.sleep(5)
