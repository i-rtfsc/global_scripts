#!/usr/bin/env python
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
import commands
import re


def parseargs():
    usage = "usage: %prog [options] arg1 arg2"
    parser = optparse.OptionParser(usage=usage)

    buildoptiongroup = optparse.OptionGroup(parser, "git push to gerrit options")

    buildoptiongroup.add_option("-b", "--branch", dest="branch",
                                help="what remote branch want to push", default="bsui_stable5.0_20210105")
    buildoptiongroup.add_option("-r", "--reviewer", dest="reviewer",
                                help="reivew email address", default="wayne.xiong@blackshark.com,"
                                                                     "solo.huang@blackshark.com,"
                                                                     "lucy.zeng@blackshark.com,"
                                                                     "rick.hu@blackshark.com,"
                                                                     "lyng.li@blackshark.com")
    buildoptiongroup.add_option("-d", "--drafts", action="store_true", dest="drafts",
                                help="push to gerrit as drafts", default=False)

    parser.add_option_group(buildoptiongroup)

    (options, args) = parser.parse_args()

    return (options, args)


def main():
    print(os.path.abspath(__file__))
    (options, args) = parseargs()
    branch = options.branch.strip()
    reviewer = options.reviewer.strip()
    drafts = options.drafts

    cmd = "git log -n 1"
    ret, output = commands.getstatusoutput(cmd)
    if ret != 0:
        print("git cmd fail:\n %s" % (output))
    elif "Change-Id" not in output:
        print("No Change-Id in commit message!")
        print("Get commit-msg by \"scp -p -P 29418 gerrit host:hooks/commit-msg .git/hooks/\".")
        print("git commit --amend again.")
        return 1

    cmd = "git config --get user.name"
    ret, output = commands.getstatusoutput(cmd)
    if ret != 0:
        print("")
    elif not output:
        print("No git user name, add your git email by \"git config --global user.name [your name]\".")
        return 1
    cmd = "git config --get user.email"
    ret, output = commands.getstatusoutput(cmd)
    if ret != 0:
        print("")
    elif not output:
        print("No git user email, add your git email by \"git config --global user.email xxx@yyyy.com\".")
        return 1

    cmd = "git remote -v"
    ret, output = commands.getstatusoutput(cmd)
    if ret != 0:
        print("git cmd fail:\n %s" % (output))
    else:
        remote_L = output.splitlines()
        if not remote_L:
            print("No remote address")
            print("git remote add origin ssh://xxx.yyy.zzz/abc/abc")
            return 1
        remote_L = [re.split("[\t ]", line)[1] for line in remote_L if "(push)" in line]
        remote_L = list(set(remote_L))

        remote = remote_L[0]
        remote_L_len = len(remote_L)
        if remote_L_len > 1:
            for i in range(0, remote_L_len):
                print("[%2s]" % i, remote_L[i])
            choice = raw_input("which remote you want? please input [%s - %s] or exit? " % (0, remote_L_len - 1))
            try:
                index = int(choice)
            except ValueError as e:
                print("exit")
                return 1
            if index > remote_L_len or index < 0:
                print("[%s] out of index" % (index))
                return 1
            remote = remote_L[index]
            print("your choice remote [%s]" % (index))

        if branch:
            cmd = "git push %s HEAD:refs/for/%s" % (remote, branch)
            if drafts:
                cmd = "git push %s HEAD:refs/drafts/%s" % (remote, branch)
            if reviewer:
                reviewers = reviewer.split(',')
                if len(reviewers) > 0:
                    for email in reviewers:
                        if cmd.__contains__("%r"):
                            cmd += ",r=%s" % (email)
                        else:
                            cmd += "%%r=%s" % (email)
                else:
                    cmd += "%%r=%s" % (reviewer)
            print("git push cmd: %s" % (cmd))
            os.system(cmd)
        else:
            cmd = "git branch -a"
            os.system(cmd)
            return 1

    return 0


if __name__ == "__main__":
    main()
