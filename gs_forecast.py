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


def parseargs():
    usage = "usage: %prog [options] arg1 arg2"
    parser = optparse.OptionParser(usage=usage)

    buildoptiongroup = optparse.OptionGroup(parser, "git push to gerrit options")

    buildoptiongroup.add_option("-y", "--language", dest="language",
                                help="supported languages", default="zh")
    buildoptiongroup.add_option("-l", "--location", dest="location",
                                help="supported location types", default="shanghai+pudong")

    parser.add_option_group(buildoptiongroup)

    (options, args) = parser.parse_args()

    return (options, args)


def main():
    print(os.path.abspath(__file__))
    (options, args) = parseargs()
    language = options.language.strip()
    location = options.location.strip()

    cmd = "curl -H \"Accept-Language: %s\" wttr.in/%s " % (language, location)
    print(cmd)
    os.system(cmd)

    return 0


if __name__ == "__main__":
    main()
