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
import subprocess

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET


def parseargs():
    usage = "usage: %prog [options] arg1 arg2"
    parser = optparse.OptionParser(usage=usage)

    buildoptiongroup = optparse.OptionGroup(parser, "git op repo project")

    buildoptiongroup.add_option("-b", "--branch", dest="branch",
                                help="what remote branch", default=None)

    parser.add_option_group(buildoptiongroup)

    (options, args) = parser.parse_args()

    return (options, args)


class Options(object):
    pwd = os.getcwd()
    cmd = None
    branch = None
    projects = None


def file_exists(file):
    exists = os.path.isfile(file) and os.path.exists(file)
    return exists


def dir_exists(file):
    exists = os.path.isdir(file) and os.path.exists(file)
    return exists


def parse_project(file):
    projects = []
    with open(file, 'r') as f:
        for line in f.readlines():
            projects.append(line.strip())

    return projects


def parse_branch(dir):
    project = dict()

    file_manifest = os.path.join(dir, ".repo/manifest.xml")
    if file_exists(file_manifest):
        tree = ET.parse(file_manifest)
        for elem in tree.iterfind('include'):
            # 获取文件名
            file_name = elem.attrib["name"]

        file_project = os.path.join(dir, ".repo/manifests", file_name)
        if file_exists(file_project):
            tree = ET.parse(file_project)
            for global_elem in tree.iterfind('default'):
                global_revision = global_elem.attrib["revision"]

            for elem in tree.iterfind('project'):
                path = elem.attrib["path"]
                try:
                    revision = elem.attrib["revision"]
                except Exception:
                    revision = global_revision

                project[path] = revision

    return project


def checkout(opt):
    project_branch = parse_branch(opt.pwd)

    for project in opt.projects:
        print("start checkout project = {}".format(project))
        dir = os.path.join(opt.pwd, project)
        if dir_exists(os.path.join(dir, ".git")):
            os.chdir(dir)
            ret, output = subprocess.getstatusoutput("git branch -r")
            if ret != 0:
                print("project = {}, git branch -a fail {}".format(project, output))
            else:

                for line in output.splitlines():
                    if "origin" in line:
                        branch = line.strip()

                        origin = branch.split("/")[0]
                        real_branch = branch.split("/")[1]

                        if "origin" == origin:
                            cmd = "git checkout -b {} {}".format(real_branch, branch)
                            print("checkout project = {}, branch = {}".format(project, real_branch))
                            os.system(cmd)

            # 根据 .repo 中 每个仓的 revision ，切回到默认分支
            branch = project_branch.get(project)
            if branch is None:
                cmd = "git checkout {}".format(branch)
                os.system(cmd)

            os.chdir(opt.pwd)
        else:
            print("run sync in root dir")


def sync(opt):
    project_branch = parse_branch(opt.pwd)

    for project in opt.projects:
        print("start sync project = {}".format(project))
        dir = os.path.join(opt.pwd, project)
        if dir_exists(os.path.join(dir, ".git")):
            os.chdir(dir)
            ret, output = subprocess.getstatusoutput("git branch --list|sed 's/\*//g'")
            if ret != 0:
                print("project = {}, git branch --list fail {}".format(project, output))
            else:
                for line in output.splitlines():
                    branch = line.strip()
                    print("fetching project = {}, branch = {}".format(project, branch))
                    cmd = "git checkout " + branch
                    os.system(cmd)
                    os.system("git clean -dfx")
                    os.system("git reset --hard")
                    os.system("git pull --rebase")

            # 根据 .repo 中 每个仓的 revision ，切回到默认分支
            branch = project_branch.get(project)
            if branch is None:
                cmd = "git checkout {}".format(branch)
                os.system(cmd)

            os.chdir(opt.pwd)
        else:
            print("run sync in root dir")


def work(opt):
    if opt.cmd == "sync":
        sync(opt)
    elif opt.cmd == "checkout":
        checkout(opt)


def main():
    opt = Options()

    (options, args) = parseargs()
    opt.cmd = args[0]

    opt.branch = options.branch

    file = os.path.join(opt.pwd, ".repo/project.list")
    print(file)
    if file_exists(file):
        opt.projects = parse_project(file)

    if opt.projects is None:
        print("has not project file")
        return 0

    work(opt)

    return 0


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        exit()
