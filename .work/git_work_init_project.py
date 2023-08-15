#!/usr/bin/env python3

import os

from string import Template

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

template = """{
    "remote": "${remote}",
    "project": "${project}",
    "path": "${path}",
    "branch": "${branch}"
},
"""

def parse_xml(file):
    projects = []
    tree = ET.parse(file)

    for global_elem in tree.iterfind('default'):
        global_remote = global_elem.attrib["remote"]
        branch = global_elem.attrib["revision"]

    for elem in tree.iterfind('project'):
        project = elem.attrib["name"]
        try:
            path = elem.attrib["path"]
            branch = global_elem.attrib["revision"]
        except Exception:
            path = project

        text = Template(template).substitute({'remote': "gerrit",
                                              'project': project,
                                              'path': path,
                                              'branch': branch
                                              })

        projects.append(text)

    return projects


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # u_file = os.path.join(script_dir, "../test/", "manifest-u.xml")
    # projects = parse_xml(u_file)

    t_file = os.path.join(script_dir, "../test/", "manifest-t.xml")
    projects = parse_xml(t_file)

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
