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

# https://github.com/checkstyle/checkstyle/tags
# https://www.cnblogs.com/ziyuyuyu/p/9914272.html


import optparse
import os
import re
import shutil
import subprocess
import sys


class CheckCodeStyle:
    def __init__(self, git_dir, style):
        self.git_dir = git_dir
        self.out_root_dir = os.path.join(self.git_dir, "out")
        self.out_code_style_dir = os.path.join(self.git_dir, "out", "codestyle")
        self.check_code_style_dir = os.path.join(os.environ["_GS_ROOT_PATH"], "codestyle")
        self.style = style

    def get_files(self, suffix_name):
        files = list()
        for (dirpath, dirnames, filenames) in os.walk(self.git_dir):
            if re.search(
                    r'^\s*$|/build/|/out/|/test/|/androidTest/|/commonTest/|/jvmTest/|/jsTest/|/iosTest/|/third.*?/|/proto.*?/|test\.[a-z]*$',
                    dirpath, re.I):  # 过滤不检测路径
                pass
            else:
                files += [os.path.join(dirpath, file) for file in filenames if file.endswith(suffix_name)]

        return files

    def copy_tmp_file(self, files):
        for file in files:
            temp_file = file.replace(self.git_dir, "")
            # target_file = os.path.join(self.out_code_style_dir, temp_file)
            target_file = self.out_code_style_dir + temp_file
            target_dir = os.path.dirname(target_file)
            if not os.path.exists(target_dir):
                os.makedirs(target_dir)

            shutil.copy2(file, target_dir)

    def delete_tmp_file(self):
        try:
            shutil.rmtree(self.out_code_style_dir)
        except OSError as e:
            print("Error: %s - %s." % (e.filename, e.strerror))

    def run_java(self):
        check_style_jar_file = os.path.join(self.check_code_style_dir, "checkstyle-9.1-all.jar")
        check_style_xml_file = os.path.join(self.check_code_style_dir, "checks_" + self.style + ".xml")
        check_result_file = os.path.join(self.out_root_dir, "java_results.log")

        # shell 和 python 使用如下通配符会报错
        # 所有换成copy文件的方案，copy完成之后再删除
        # 为何不for每一个文件然后执行检查？
        # 最开始猜测这种方案效率很低，经过测试果然很慢
        # 这个方案是4秒 ，for文件再每一个独单检查总共要101秒
        # source_file = self.git_dir + "/**/*/src/**/*.java"
        # copy
        self.copy_tmp_file(self.get_files(".java"))

        cmd = "java -jar {check_style_jar} -c {check_style_xml} -o {output_file} {source_file}".format(
            check_style_jar=check_style_jar_file,
            check_style_xml=check_style_xml_file,
            output_file=check_result_file,
            source_file=self.out_code_style_dir)
        print(cmd)
        os.system(cmd)

        # 删除刚才的中间文件
        self.delete_tmp_file()

    def run_kt(self):
        check_style_cli_jar_file = os.path.join(self.check_code_style_dir, "detekt-cli-1.20.0-all.jar")
        check_style_formatting_jar_file = os.path.join(self.check_code_style_dir, "detekt-formatting-1.20.0.jar")

        check_style_xml_file = os.path.join(self.check_code_style_dir, "checks_" + self.style + ".yml")
        if os.path.exists(check_style_xml_file) is False:
            check_style_xml_file = os.path.join(self.check_code_style_dir, "detekt_strict_mode.yml")

        check_result_file = os.path.join(self.out_root_dir, "kt_results.log")

        # copy
        # self.copy_tmp_file(self.get_files(".kt"))

        cmd = "java -jar {check_style_jar} -p {formatting_jar_file} -c {check_style_xml} -i {source_file} --parallel > {output_file}".format(
            check_style_jar=check_style_cli_jar_file,
            formatting_jar_file=check_style_formatting_jar_file,
            check_style_xml=check_style_xml_file,
            source_file=self.git_dir,
            output_file=check_result_file)
        os.system(cmd)

        # 删除刚才的中间文件
        # self.delete_tmp_file()


def parseargs():
    usage = "usage: %prog [options] arg1 arg2"
    parser = optparse.OptionParser(usage=usage)

    buildoptiongroup = optparse.OptionGroup(parser, "git push to gerrit options")

    buildoptiongroup.add_option("-s", "--style", dest="style",
                                help="check style", default="strict_mode")

    parser.add_option_group(buildoptiongroup)

    (options, args) = parser.parse_args()

    return (options, args)


def get_git_dir():
    result = None
    git_cmd = "git rev-parse --show-toplevel"
    process = os.popen(git_cmd)
    outputs = process.readlines()
    if len(outputs) != 0:
        result = outputs[0]
    return result.strip()


def main():
    # get git root dir
    git_dir = get_git_dir()
    if git_dir is None:
        print("git root dir wasn't exist")
        return 0

    # get input info
    (options, args) = parseargs()
    style = options.style.strip()

    # check java code style
    checker = CheckCodeStyle(git_dir, style)
    checker.run_java()
    # checker.run_kt()

    return 0


if __name__ == "__main__":
    main()
