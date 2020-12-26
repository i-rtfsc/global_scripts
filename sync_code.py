#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
#  Copyright (c) 2020 anqi.huang@outlook.com
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
import datetime
import json
import os
import optparse

import threading
import time

import schedule


class Config(object):
    def __init__(self, _dict, branch):
        self.project = _dict['project']
        self.branch = branch
        self.source_origin = _dict['source_origin']
        self.target_origin = _dict['target_origin']
        self.copy = _dict['copy']


config = Config({'project': 'x', 'source_origin': 'x', 'target_origin': 'x', 'copy': 'x'}, 'x')


def parseargs():
    usage = "usage: %prog [options] arg1 arg2"
    parser = optparse.OptionParser(usage=usage)

    option_group = optparse.OptionGroup(parser, "gradle build app options")

    option_group.add_option("-p", "--project", dest="project",
                            help="which project",
                            default="")
    option_group.add_option("-b", "--branch", dest="branch",
                            help="which branch", default="")

    parser.add_option_group(option_group)

    (options, args) = parser.parse_args()

    return (options, args)


def log(message):
    print("%s -> %s" % (datetime.datetime.now(), message))


def exec_cmd(command):
    # process = subprocess.Popen(args=command, stdout=subprocess.PIPE, stderr=None, shell=True)
    # # Launch the shell command:
    # output = process.communicate()
    # return output[0]
    os.system(command)
    # log(command)


def work(config):
    git_remove_origin = 'git remote remove origin'
    git_checkout = 'git checkout '
    git_pull = 'git pull origin '
    git_push = 'git push --set-upstream origin '

    exec_cmd(git_remove_origin)
    exec_cmd(config.source_origin)
    exec_cmd(config.copy)
    exec_cmd(git_checkout + config.branch)
    exec_cmd(git_pull + config.branch)

    exec_cmd(git_remove_origin)
    exec_cmd(config.target_origin)
    exec_cmd(git_push + config.branch)


def work_job():
    work(config)


def run_threaded(job_func):
    job_thread = threading.Thread(target=job_func)
    job_thread.start()


schedule.every(5).minutes.do(run_threaded, work_job)


def main():
    print(os.path.abspath(__file__))
    (options, args) = parseargs()
    project = options.project.strip()
    branch = options.branch.strip()
    print("sync project = %s , branch = %s " % (project, branch))

    with open(".sync_code_configs.json") as json_data:
        dicts = json.loads(json_data.read(), object_hook=dict)
        for _dict in dicts:
            _config = Config(_dict, branch)
            if project == _config.project:
                global config
                config = _config
                work(config)

    return 0


if __name__ == "__main__":
    main()
    while True:
        schedule.run_pending()
        time.sleep(5)
