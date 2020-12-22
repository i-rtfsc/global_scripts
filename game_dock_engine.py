#!/usr/bin/env python
# coding:utf-8
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

import os
import optparse


def parseargs():
    usage = "usage: %prog [options] arg1 arg2"
    parser = optparse.OptionParser(usage=usage)

    buildoptiongroup = optparse.OptionGroup(parser, "push game dock engine options")

    buildoptiongroup.add_option("-p", "--push", dest="source",
                                help="source file path",
                                default="~/vm/8350/out/target/product/kaiser/vendor")

    parser.add_option_group(buildoptiongroup)

    (options, args) = parser.parse_args()

    return (options, args)


def main():
    print(os.path.abspath(__file__))
    (options, args) = parseargs()
    source = options.source.strip()

    os.system("adb root")
    os.system("adb remount")

    os.system("adb push %s/bin/hw/com.blackshark.gamedockengine.hal@1.0-service vendor/bin/hw/" % source)
    os.system("adb push %s/lib/com.blackshark.gamedockengine.hal@1.0.so /vendor/lib/" % source)
    os.system("adb push %s/lib/com.blackshark.gamedockengine.hal@1.0-adapter-helper.so /vendor/lib/" % source)
    os.system("adb push %s/lib64/com.blackshark.gamedockengine.hal@1.0.so /vendor/lib64/" % source)
    os.system("adb push %s/lib64/com.blackshark.gamedockengine.hal@1.0-adapter-helper.so /vendor/lib64/" % source)

    os.system("adb shell killall com.blackshark.gamedockengine.hal@1.0-service")

    return 0


if __name__ == "__main__":
    main()
