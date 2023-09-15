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
    cmd = "rm -rf " + dest + "\n"
    cmd += "mkdir -p " + os.path.dirname(dest) + "\n"
    cmd += "ln -s {} {}".format(src, dest) + "\n"
    # print(cmd)
    return cmd


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))

    down_dir = "/home/solo/code/aosp/"
    file_xml = os.path.join(script_dir, "../test/", "manifest-u.xml")
    file_json = os.path.join(script_dir, "../test/", "project-u.json")
    file_link = os.path.join(script_dir, "../test/", "link-u.sh")

    projects, links = parse_xml(file_xml)

    with open(file_json, 'w') as f:
        f.write("[")
        for project in projects:
            f.write(project)
        f.write("]")

    with open(file_link, 'w') as f:
        PATH = "$DOWN_PATH/"
        f.write("DOWN_PATH={}\n".format(down_dir))
        for link in links:
            path = link['path']
            src = link['src']
            dest = link['dest']
            f.write(parse_link(os.path.join(PATH, path, src), os.path.join(PATH, dest)))

    return 0


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        exit()
