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


def parseargs():
    usage = "usage: %prog [options] arg1 arg2"
    parser = optparse.OptionParser(usage=usage)

    buildoptiongroup = optparse.OptionGroup(parser, "core project git")

    buildoptiongroup.add_option("-b", "--branch", dest="branch",
                                help="what remote branch", default="QSSI_QUF10_base")
    buildoptiongroup.add_option("-f", "--file", dest="file",
                                help="project list", default="project_gerrit.list")
    buildoptiongroup.add_option("-u", "--user", dest="user",
                                help="user", default="x-huanganqi")
    buildoptiongroup.add_option("-g", "--gerrit", dest="gerrit",
                                help="gerrit", default="@gerrit-master.rnd.meizu.com")

    parser.add_option_group(buildoptiongroup)

    (options, args) = parser.parse_args()

    return (options, args)


class Environment(object):
    cmd = ""
    branch = ""
    user = ""
    gerrit = ""
    project_file = None


class Project(object):
    project = ""
    dir = ""


def file_exists(file):
    exists = os.path.isfile(file) and os.path.exists(file)
    return exists


def dir_exists(file):
    exists = os.path.isdir(file) and os.path.exists(file)
    return exists


def parse_file(file):
    projects = []
    with open(file, 'r') as f:
        for line in f.readlines():
            # 忽略注释
            if line.strip()[0:1] == "#":
                print(line)
                continue

            project = Project()
            project.project = line.split(",")[0].strip()
            project.dir = line.split(",")[1].strip()
            projects.append(project)

    return projects


def other(env):
    print("don't support cmd = " + env.cmd)


def init(env):
    pwd = os.getcwd()
    projects = parse_file(env.project_file)

    os.chdir(pwd)

    for pro in projects:
        project = pro.project
        dir = pro.dir
        git_dir = os.path.join(pwd, pro.dir)
        if dir_exists(os.path.join(git_dir, ".git")):
            print(git_dir + " git project exists")
            os.chdir(git_dir)

            ret, output = subprocess.getstatusoutput("git branch -r")
            if ret != 0:
                print("git branch --list fail:\n %s" % (output))
            else:
                for line in output.splitlines():
                    if line.split("/")[-1] == env.branch:
                        os.system("git checkout -b {} {}".format(env.branch, line))

        else:
            print("first init " + project)
            git_cmd = "git clone \"ssh://{user}{gerrit}:9999/{project}\" -b {branch} {dir} && scp -p -P 9999 {user}{gerrit}:hooks/commit-msg \"{dir}/.git/hooks/\""
            cmd = git_cmd.format(user=env.user, gerrit=env.gerrit, project=project, dir=dir, branch=env.branch)
            print(cmd)
            os.system(cmd)

        os.chdir(pwd)


def sync(env):
    pwd = os.getcwd()
    projects = parse_file(env.project_file)
    for pro in projects:
        dir = os.path.join(pwd, pro.dir)
        if dir_exists(os.path.join(dir, ".git")):
            print(dir, "gitdir exists")
            os.chdir(dir)

            ret, output = subprocess.getstatusoutput("git branch --list|sed 's/\*//g'")
            if ret != 0:
                print("git branch --list fail:\n %s" % (output))
            else:
                for line in output.splitlines():
                    branch = line.strip()
                    os.system("git checkout ".format(branch))
                    os.system("git clean -dfx")
                    os.system("git reset --hard")
                    os.system("git pull --rebase")

            os.system("git checkout ".format(env.branch))
            os.chdir(pwd)


def main():
    env = Environment()

    (options, args) = parseargs()
    env.cmd = args[0]
    env.branch = options.branch.strip()
    env.user = options.user.strip()
    env.gerrit = options.gerrit.strip()

    file_name = options.file.strip()

    pwd = os.getcwd()
    script_dir = os.path.dirname(os.path.abspath(__file__))

    for file in [file_name, os.path.join(pwd, file_name), os.path.join(script_dir, file_name)]:
        if file_exists(file):
            env.project_file = file

    if env.project_file is None:
        print("project list file not exists")
        exit(-1)

    print("cmd =", env.cmd, ", branch =", env.branch, ", project list file =", env.project_file)

    if env.cmd == "init":
        init(env)
    elif env.cmd == "sync":
        sync(env)
    else:
        other(env)

    return 0


if __name__ == "__main__":
    main()
