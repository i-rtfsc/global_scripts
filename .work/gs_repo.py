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


import json
import optparse
import os
import subprocess
import time


def parseargs():
    usage = "usage: %prog [options] arg1 arg2"
    parser = optparse.OptionParser(usage=usage)

    buildoptiongroup = optparse.OptionGroup(parser, "core project git")

    buildoptiongroup.add_option("-r", "--remote", dest="remote",
                                help="which remote", default=None)
    buildoptiongroup.add_option("-b", "--branch", dest="branch",
                                help="what remote branch", default=None)
    buildoptiongroup.add_option("-f", "--file", dest="file",
                                help="project list file", default="project.json")
    buildoptiongroup.add_option("-c", "--config", dest="config",
                                help="config list file", default="config.json")

    parser.add_option_group(buildoptiongroup)

    (options, args) = parser.parse_args()

    return (options, args)


def get_time_str():
    return time.strftime("%Y-%m-%d %H:%M:%S ", time.localtime())


class Color():
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    UNDERLINE = '\033[4m'
    BLINK = '\33[5m'
    RESET = '\033[0m'


class Log:

    @staticmethod
    def i(*message):
        line = get_time_str()
        for msg in message:
            line += msg

        print(Color.MAGENTA, line, Color.RESET)

    @staticmethod
    def d(*message):
        line = get_time_str()
        for msg in message:
            line += msg

        print(Color.WHITE, line, Color.RESET)

    @staticmethod
    def w(*message):
        line = get_time_str()
        for msg in message:
            line += msg

        print(Color.YELLOW, line, Color.RESET)

    @staticmethod
    def e(*message):
        line = get_time_str()
        for msg in message:
            line += msg

        print(Color.RED, line, Color.RESET)


class Project(object):
    def __init__(self, _dict):
        self.remote = _dict['remote']
        self.project = _dict['project']
        self.path = _dict['path']
        self.branch = _dict['branch']

    def __getitem__(self, key):
        return getattr(self, key)

    def __str__(self):
        print(['%s:%s' % item for item in self.__dict__.items()])


class Options(object):
    cmd = None
    remote = None
    branch = None
    configs = None
    projects = None


def file_exists(file):
    exists = os.path.isfile(file) and os.path.exists(file)
    return exists


def dir_exists(file):
    exists = os.path.isdir(file) and os.path.exists(file)
    return exists


def parse_config(file):
    configs = dict()
    with open(file, 'r') as f:
        dicts = json.loads(f.read(), object_hook=dict)
        for _dict in dicts:
            configs[_dict['remote']] = _dict['cmd']

    return configs


def parse_project(file):
    projects = []
    with open(file, 'r') as f:
        dicts = json.loads(f.read(), object_hook=dict)
        for _dict in dicts:
            project = Project(_dict)
            projects.append(project)

    return projects


def other(opt):
    Log.e("don't support cmd = " + opt.cmd)


def init(opt):
    pwd = os.getcwd()
    os.chdir(pwd)

    for pro in opt.projects:
        print("")
        Log.i("start init ", pro.project)
        remote = pro.remote

        check_remote = (opt.remote == remote) or (opt.remote is None or opt.remote == "all")
        if check_remote:
            project = pro.project
            path = pro.path
            if opt.branch is None:
                branch = pro.branch
            else:
                branch = opt.branch

            git_dir = os.path.join(pwd, path)

            if dir_exists(os.path.join(git_dir, ".git")):
                Log.d(git_dir, " git project exists")
                os.chdir(git_dir)

                ret, output = subprocess.getstatusoutput("git branch -r")
                if ret != 0:
                    Log.e("git branch --list fail:\n %s" % (output))
                else:
                    for line in output.splitlines():
                        if line.split("/")[-1] == opt.branch:
                            os.system("git checkout -b {} {}".format(opt.branch, line))

            else:
                Log.i("first init " + project)
                git_cmd = opt.configs[remote]
                cmd = git_cmd.format(project=project, dir=path, branch=branch)
                Log.d(cmd)
                ret, output = subprocess.getstatusoutput(cmd)
                if ret != 0:
                    Log.e("git clone fail:\n %s" % (output))
        else:
            Log.e("error, don't support remote = " + remote + ", project = " + pro.project)

        os.chdir(pwd)


def sync(opt):
    pwd = os.getcwd()

    for pro in opt.projects:
        print("")
        Log.i("start sync " + pro.project)
        dir = os.path.join(pwd, pro.path)
        if dir_exists(os.path.join(dir, ".git")):
            Log.d(dir, " git project exists")
            os.chdir(dir)

            ret, output = subprocess.getstatusoutput("git branch --list|sed 's/\*//g'")
            if ret != 0:
                Log.e("git branch --list fail:\n %s" % (output))
            else:
                for line in output.splitlines():
                    branch = line.strip()
                    Log.d("fetching project " + branch)
                    cmd = "git checkout " + branch
                    os.system(cmd)
                    os.system("git clean -dfx")
                    os.system("git reset --hard")
                    os.system("git pull --rebase")

            branch = opt.branch
            if branch is None:
                branch = pro.branch

            cmd = "git checkout " + branch
            Log.d(cmd)
            ret, output = subprocess.getstatusoutput(cmd)
            if ret != 0:
                Log.e("git checkout fail:\n %s" % (output))

            os.chdir(pwd)
        else:
            Log.e("run sync in root dir.")


def unlock(opt):
    pwd = os.getcwd()
    for pro in opt.projects:
        dir = os.path.join(pwd, pro.path)
        file = os.path.join(dir, ".git", "index.lock")
        if file_exists(file):
            Log.e("rm lock file " + file)
            os.system("rm -rf {}".format(file))


def main():
    opt = Options()

    (options, args) = parseargs()
    opt.cmd = args[0]

    opt.remote = options.remote
    opt.branch = options.branch
    config_file_name = options.config.strip()
    project_file_name = options.file.strip()

    pwd = os.getcwd()
    script_dir = os.path.dirname(os.path.abspath(__file__))

    config_file = os.path.join(script_dir, config_file_name)
    if file_exists(config_file):
        opt.configs = parse_config(config_file)

    for file in [project_file_name, os.path.join(pwd, project_file_name), os.path.join(script_dir, project_file_name)]:
        if file_exists(file):
            opt.projects = parse_project(file)

    if opt.configs is None:
        Log.e("has not config file")
        return 0

    if opt.projects is None:
        Log.e("has not project file")
        return 0

    if opt.cmd == "init":
        init(opt)
    elif opt.cmd == "sync":
        sync(opt)
    elif opt.cmd == "unlock":
        unlock(opt)
    else:
        other(opt)

    return 0


if __name__ == "__main__":
    main()
