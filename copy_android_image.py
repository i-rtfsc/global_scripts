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
import optparse
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "../"))

from base.smart_log import smart_log
from config.android_image_config import AndroidImageConfig
from ftp.ftpretty import ftpretty


def parseargs():
    usage = "usage: %prog [options] arg1 arg2"
    parser = optparse.OptionParser(usage=usage)

    build_time = str(datetime.datetime.now().date())

    option_group = optparse.OptionGroup(parser, "copy android image options")

    option_group.add_option("-p", "--project", dest="project",
                            help="which project",
                            default="mobius_user_dev")
    option_group.add_option("-t", "--time", dest="time",
                            help="build time",
                            default=build_time)

    parser.add_option_group(option_group)

    (options, args) = parser.parse_args()

    return (options, args)


def work(image, build_time):
    f = ftpretty(image.ftp_server, image.user, image.pwd)
    source = image.source.format(day=build_time)
    destination = image.destination.format(day=build_time)
    smart_log("copy daily build time = %s, destination = %s" % (build_time, destination))
    f.get(source, destination)


def main():
    smart_log(os.path.abspath(__file__))
    (options, args) = parseargs()
    project = options.project.strip()
    time = options.time.strip()
    smart_log("copy android image project = %s, build time = %s " % (project, time))

    images = AndroidImageConfig.get_configs()
    for image in images:
        if project == image.project:
            work(image, time)

    return 0


if __name__ == "__main__":
    main()
