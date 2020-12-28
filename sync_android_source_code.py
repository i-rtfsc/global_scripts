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
import optparse
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "../"))

from base.smart_log import smart_log

from config.sync_android_source_code_config import SyncAndroidSourceCodeConfig


def parseargs():
    usage = "usage: %prog [options] arg1 arg2"
    parser = optparse.OptionParser(usage=usage)

    option_group = optparse.OptionGroup(parser, "gradle build app options")

    option_group.add_option("-p", "--project", dest="project",
                            help="which project",
                            default="")
    option_group.add_option("-j", "--thread", dest="thread",
                            help="max thread",
                            default="32")

    parser.add_option_group(option_group)

    (options, args) = parser.parse_args()

    return (options, args)


def exec_cmd(command):
    # process = subprocess.Popen(args=command, stdout=subprocess.PIPE, stderr=None, shell=True)
    # # Launch the shell command:
    # output = process.communicate()
    # return output[0]
    os.system(command)
    # smart_log(command)


def work(config, max_thread):
    cmd_repo_ini = config.repo_init
    cmd_rm_out = 'rm -rf out'
    cmd_repo_sync = 'repo sync -j%s' % max_thread
    cmd_repo_sync_no_tags = 'repo sync -cdj %s --no-tags ' % max_thread

    exec_cmd(cmd_repo_ini)
    exec_cmd(cmd_rm_out)
    exec_cmd(cmd_repo_sync)
    exec_cmd(cmd_repo_sync_no_tags)


def main():
    smart_log(os.path.abspath(__file__))
    (options, args) = parseargs()
    project = options.project.strip()
    max_thread = options.thread.strip()
    smart_log("sync project = %s , max thread = %s" % (project, max_thread))

    for config in SyncAndroidSourceCodeConfig.get_configs():
        if project == config.project:
            work(config, max_thread)

    return 0


if __name__ == "__main__":
    main()
