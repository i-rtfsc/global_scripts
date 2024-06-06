#!/usr/bin/env python3

import os
import subprocess
import sys

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET


def parse_sync(project, arg):
    cmd = "repo sync {} {}".format(project, arg)
    print(cmd)
    ret, output = subprocess.getstatusoutput(cmd)
    if ret != 0:
        print(output)


def main(arg):
    root_dir = os.getcwd()
    file = os.path.join(root_dir, "mini-aosp.xml")
    if not os.path.exists(file):
        from pathlib import Path
        home_directory = str(Path.home())
        print(home_directory)
        file = os.path.join(home_directory, "code/github/.repo/manifests/", "mini-aosp.xml")

    if not os.path.exists(file):
        print("can not find mini-aosp.xml")
        return 0

    tree = ET.parse(file)

    for elem in tree.iterfind('project'):
        project = elem.attrib["name"]
        parse_sync(project, arg)

    return 0


if __name__ == "__main__":
    try:
        main(' '.join(sys.argv[1:]))
    except KeyboardInterrupt:
        exit()
