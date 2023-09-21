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
import logging
import optparse
import os
import subprocess

from concurrent.futures import ThreadPoolExecutor, as_completed


def parseargs():
    usage = "usage: %prog [options] arg1 arg2"
    parser = optparse.OptionParser(usage=usage)

    buildoptiongroup = optparse.OptionGroup(parser, "core project git")

    buildoptiongroup.add_option("-r", "--remote", dest="remote",
                                help="which remote", default=None)
    buildoptiongroup.add_option("-b", "--branch", dest="branch",
                                help="what remote branch", default=None)
    buildoptiongroup.add_option("-j", "--thread", dest="thread",
                                help="work thread num", default=1)
    buildoptiongroup.add_option("-f", "--file", dest="file",
                                help="project list file", default="project.json")
    buildoptiongroup.add_option("-c", "--config", dest="config",
                                help="config list file", default="config.json")

    parser.add_option_group(buildoptiongroup)

    (options, args) = parser.parse_args()

    return (options, args)


class TerminalLogger(object):
    def __init__(self, level=logging.INFO, log_file=None):
        """Create a configured instance of logger."""
        fmt = '[%(asctime)s] %(levelname)s : %(message)s'
        date_fmt = '%Y-%m-%d %H:%M:%S'
        formatter = logging.Formatter(fmt, datefmt=date_fmt)

        logger = logging.getLogger()

        if log_file:
            if not os.path.exists(log_file):
                pardir = os.path.abspath(os.path.join(log_file, os.pardir))
                if not os.path.exists(pardir):
                    os.makedirs(pardir)
                file = open(log_file, 'w')
                file.close()
            fh = logging.FileHandler(filename=log_file, mode='a')
            fh.setFormatter(formatter)
            logger.addHandler(fh)

        logger.setLevel(level)
        logger.info("logger get or created.")

        self.logger = logger


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
    thread = None
    pwd = os.getcwd()
    logger = TerminalLogger(log_file=os.path.join(pwd, "repo.log")).logger


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


def split_list(lst, size):
    return [lst[i:i + size] for i in range(0, len(lst), size)]


def other(opt, task_num, pwd, projects):
    opt.logger.error("don't support cmd = {}".format(opt.cmd))


def init(opt, task_num, pwd, projects):
    os.chdir(pwd)

    # for pro in tqdm(projects, desc="task={}".format(task_num)):
    for pro in projects:
        opt.logger.info("task = {}, start init project = {}".format(task_num, pro.project))
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
                opt.logger.debug("git project exists, project = {}".format(task_num, pro.project))
                os.chdir(git_dir)

                ret, output = subprocess.getstatusoutput("git branch -r")
                if ret != 0:
                    opt.logger.error("project = {}, git branch --list fail {}".format(pro.project, output))
                else:
                    for line in output.splitlines():
                        if line.split("/")[-1] == opt.branch:
                            os.system("git checkout -b {} {}".format(opt.branch, line))

            else:
                opt.logger.info("first init project = {}".format(pro.project))
                git_cmd = opt.configs[remote]
                cmd = git_cmd.format(project=project, dir=path, branch=branch)
                opt.logger.debug(cmd)
                ret, output = subprocess.getstatusoutput(cmd)
                if ret != 0:
                    opt.logger.error("project = {}, git clone fail {}".format(pro.project, output))
        else:
            opt.logger.error("project = {}, don't support remote = {}".format(pro.project, remote))

        os.chdir(pwd)


def sync(opt, task_num, pwd, projects):
    # for pro in tqdm(projects, desc="task={}".format(task_num)):
    for pro in projects:
        opt.logger.info("task = {}, start sync project = {}".format(task_num, pro.project))
        dir = os.path.join(pwd, pro.path)
        if dir_exists(os.path.join(dir, ".git")):
            os.chdir(dir)
            ret, output = subprocess.getstatusoutput("git branch --list|sed 's/\*//g'")
            if ret != 0:
                opt.logger.error("project = {}, git branch --list fail {}".format(pro.project, output))
            else:
                for line in output.splitlines():
                    branch = line.strip()
                    opt.logger.debug("fetching project = {}, branch = {}".format(pro.project, branch))
                    cmd = "git checkout " + branch
                    os.system(cmd)
                    os.system("git clean -dfx")
                    os.system("git reset --hard")
                    os.system("git pull --rebase")

            branch = opt.branch
            if branch is None:
                branch = pro.branch

            cmd = "git checkout " + branch
            opt.logger.debug("project = {}, {}".format(pro.project, cmd))
            ret, output = subprocess.getstatusoutput(cmd)
            if ret != 0:
                opt.logger.error("project = {}, git checkout fail {}".format(pro.project, output))

            os.chdir(pwd)
        else:
            opt.logger.error("run sync in root dir")


def undepth(opt, task_num, pwd, projects):
    # for pro in tqdm(projects, desc="task={}".format(task_num)):
    for pro in projects:
        opt.logger.info("task = {}, start un-depth project = {}".format(task_num, pro.project))
        dir = os.path.join(pwd, pro.path)
        if dir_exists(os.path.join(dir, ".git")):
            os.chdir(dir)

            branch = opt.branch
            if branch is None:
                branch = pro.branch

            cmd = "git fetch --unshallow origin " + branch
            opt.logger.debug("project = {}, {}".format(pro.project, cmd))
            ret, output = subprocess.getstatusoutput(cmd)
            if ret != 0:
                opt.logger.error("project = {}, git fetch fail {}".format(pro.project, output))

            os.chdir(pwd)
        else:
            opt.logger.error("run un-depth in root dir")


def unlock(opt, task_num, pwd, projects):
    for pro in projects:
        dir = os.path.join(pwd, pro.path)
        file = os.path.join(dir, ".git", "index.lock")
        if file_exists(file):
            opt.logger.error("rm lock file = ".format(file))
            os.system("rm -rf {}".format(file))


def work(opt):
    if opt.thread <= 1:
        if opt.cmd == "init":
            init(opt, 0, opt.pwd, opt.projects)
        elif opt.cmd == "sync":
            sync(opt, 0, opt.pwd, opt.projects)
        elif opt.cmd == "undepth":
            undepth(opt, 0, opt.pwd, opt.projects)
        elif opt.cmd == "unlock":
            unlock(opt, 0, opt.pwd, opt.projects)
        else:
            other(opt, 0, opt.pwd, opt.projects)
    else:
        size = len(opt.projects)
        split_size = size // opt.thread + 1
        opt.logger.info("[{}]project size = {}, split size = {}".format(opt.cmd, size, split_size))

        projects = split_list(opt.projects, split_size)
        thread = len(projects)
        opt.logger.info("[{}]thread = {}".format(opt.cmd, thread))

        executor = ThreadPoolExecutor(max_workers=thread)
        tasks = []

        task_num = 0
        for sub_projects in projects:
            task_num = task_num + 1
            args = (opt, task_num, opt.pwd, sub_projects)

            if opt.cmd == "init":
                task = executor.submit(int, *args)
            elif opt.cmd == "sync":
                task = executor.submit(sync, *args)
            elif opt.cmd == "undepth":
                task = executor.submit(undepth, *args)
            elif opt.cmd == "unlock":
                task = executor.submit(unlock, *args)
            else:
                task = executor.submit(other, *args)

            tasks.append(task)

        as_completed(tasks)


def main():
    opt = Options()

    (options, args) = parseargs()
    opt.cmd = args[0]

    opt.remote = options.remote
    opt.branch = options.branch
    opt.thread = int(options.thread)

    config_file_name = options.config.strip()
    project_file_name = options.file.strip()

    script_dir = os.path.dirname(os.path.abspath(__file__))

    config_file = os.path.join(script_dir, config_file_name)
    if file_exists(config_file):
        opt.configs = parse_config(config_file)

    for file in [project_file_name, os.path.join(opt.pwd, project_file_name), os.path.join(script_dir, project_file_name)]:
        if file_exists(file):
            opt.projects = parse_project(file)

    if opt.configs is None:
        opt.logger.error("has not config file")
        return 0

    if opt.projects is None:
        opt.logger.error("has not project file")
        return 0

    work(opt)

    return 0


if __name__ == "__main__":
    main()
