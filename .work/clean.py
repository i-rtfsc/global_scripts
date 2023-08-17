#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2023 anqi.huang@outlook.com
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

import optparse
import os

def parseargs():
    usage = "usage: %prog [options] arg1 arg2"
    parser = optparse.OptionParser(usage=usage)

    buildoptiongroup = optparse.OptionGroup(parser, "rm build/.cxx temp dir")

    buildoptiongroup.add_option("-d", "--dir", dest="dir",
                                help="dir", default="/home/solo/code/github/as-aosp")

    parser.add_option_group(buildoptiongroup)

    (options, args) = parser.parse_args()

    return (options, args)


def work(root_dir):
    for root, dirs, files in os.walk(root_dir):
        for dir in dirs:
            path = os.path.join(root, dir)
            if "build" == dir or ".cxx" == dir:
                print(path)
                os.system("rm -rf {}".format(path))


def main():
    (options, args) = parseargs()
    dir = options.dir.strip()
    work(dir)

    return 0


if __name__ == "__main__":
    main()
