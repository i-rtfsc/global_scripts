#!/usr/bin/env python3

import os

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET


def parse_xml(file):
    projects = []
    tree = ET.parse(file)
    for elem in tree.iterfind('project'):
        project = elem.attrib["name"]
        try:
            path = elem.attrib["path"]
        except Exception:
            path = project

        projects.append(project + "," + path)

    return projects


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))

    u_file = os.path.join(script_dir, "../test/", "manifest-u.xml")
    projects = parse_xml(u_file)

    t_file = os.path.join(script_dir, "../test/", "manifest-t.xml")
    projects.extend(parse_xml(t_file))

    # 去重复
    projects = list(dict.fromkeys(projects))
    projects.sort()

    for project in projects:
        print(project)

    return 0


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        exit()
