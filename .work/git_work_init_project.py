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
    links = []
    tree = ET.parse(file)

    for global_elem in tree.iterfind('default'):
        global_remote = global_elem.attrib["remote"]
        branch = global_elem.attrib["revision"]

    for elem in tree.iterfind('project'):
        project = elem.attrib["name"]
        try:
            path = elem.attrib["path"]
        except Exception:
            path = project

        try:
            new_branch = elem.attrib["revision"]
        except Exception:
            new_branch = branch

        text = Template(template).substitute({'remote': "gerrit",
                                              'project': project,
                                              'path': path,
                                              'branch': new_branch
                                              })

        projects.append(text)

        for link_elem in elem.iterfind('linkfile'):
            dest = link_elem.attrib["dest"]
            src = link_elem.attrib["src"]
            links.append({'path': path,
                          'dest': dest,
                          'src': src})
            # parse_link(down_dir + path + "/" + src, dest)

        for link_elem in elem.iterfind('copyfile'):
            dest = link_elem.attrib["dest"]
            src = link_elem.attrib["src"]
            # parse_link(down_dir + path + "/" + src, dest)
            links.append({'path': path,
                          'dest': dest,
                          'src': src})

    return projects, links


def parse_link(src, dest):
    print("rm -rf " + dest)
    print("mkdir -p " + os.path.dirname(dest))
    print("ln -s {} {}".format(src, dest))


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))

    down_dir = "/home/solo/workspace/code/flyme/"
    file_xml = os.path.join(script_dir, "../test/", "manifest-u.xml")
    file_json = os.path.join(script_dir, "../test/", "project-u.json")

    projects, links = parse_xml(file_xml)

    with open(file_json, 'w') as f:
        f.write("[")
        for project in projects:
            f.write(project)
        f.write("]")

    for link in links:
        path = link['path']
        src = link['src']
        dest = link['dest']
        parse_link(os.path.join(down_dir, path, src), os.path.join(down_dir, dest))

    return 0


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        exit()
