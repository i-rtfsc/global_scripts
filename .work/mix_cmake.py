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

from string import Template

# 生成cmake文件模板
cmake_template = """cmake_minimum_required(VERSION 3.5)
project(${project_name})

# set(CMAKE_CXX_STANDARD 20)

set(ANDROID_ROOT ${BUILD_NATIVE_ROOT})
#set(ANDROID_ROOT "/home/solo/code/aosp")

set(AOSP_SYSTEM_COMMON true)
set(AOSP_AV false)
set(AOSP_ART false)
set(AOSP_BIONIC false)
set(AOSP_SYSTEM false)
set(AOSP_EXTERNAL false)
set(AOSP_PACKAGES false)
set(AOSP_BOOTABLE false)
# set(AOSP_PREBUILTS false)
set(AOSP_HARDWARE false)
set(AOSP_OUT false)

file(GLOB SOURCE_FILES${code_files})

include_directories(${include_directories})

file (GLOB_RECURSE HEADERS${header_files})

${ext_template}

add_executable(
        ${project_name}
        ${SOURCE_FILES}
        ${HEADERS}
)
"""

ext_template_src = """
# add aosp ${msg}
if (${AOSP_${FEATURE}})
    message("enable aosp ${msg}")

    # add aosp ${msg} src
    file(GLOB SOURCE_FILES_${FEATURE}${code_files})
    # append aosp ${msg} src
    list (APPEND SOURCE_FILES ${SOURCE_FILES_${FEATURE}})

    # add aosp ${msg} header dir
    include_directories(${include_dirs})

    # add aosp ${msg} header file
    file (GLOB_RECURSE HEADERS_${FEATURE}${header_files})
    # append aosp ${msg} header
    list (APPEND HEADERS ${HEADERS_${FEATURE}})
endif ()
"""

ext_template = """
# add aosp ${msg}
if (${AOSP_${FEATURE}})
    message("enable aosp ${msg}")

    # add aosp ${msg} header dir
    include_directories(${include_dirs})

    # add aosp ${msg} header file
    file (GLOB_RECURSE HEADERS_${FEATURE}${header_files})
    # append aosp ${msg} header
    list (APPEND HEADERS ${HEADERS_${FEATURE}})
endif ()
"""


def parseargs():
    usage = "usage: %prog [options] arg1 arg2"
    parser = optparse.OptionParser(usage=usage)

    buildoptiongroup = optparse.OptionGroup(parser, "mix cmake file")

    buildoptiongroup.add_option("-r", "--root", dest="root",
                                help="root dir", default="/home/solo/code/github/global_scripts/test/clion/")
    buildoptiongroup.add_option("-p", "--project", dest="project",
                                help="project name(android_runtime,android_services,inputflinger,surfaceflinger), or aosp-native[all projects]",
                                default="ExtServices")

    parser.add_option_group(buildoptiongroup)

    (options, args) = parser.parse_args()

    return (options, args)


def fast_scandir(dirname):
    folders = [f.path for f in os.scandir(dirname) if f.is_dir()]
    for dirname in list(folders):
        folders.extend(fast_scandir(dirname))

    return folders


def write_text(file, text):
    print(file)
    directory = os.path.dirname(file)
    if not os.path.exists(directory):
        os.makedirs(directory)

    with open(file, 'w') as f:
        f.write(text)


def work(project_name, root, project_list):
    code_dirs = []
    header_dirs = []
    include_dirs = []

    for project_dir in project_list:
        project_dirs = fast_scandir(os.path.join(root, project_dir))
        project_dirs.append(os.path.join(root, project_dir))
        project_dirs.sort()

        for dir in project_dirs:
            if "arm64" in dir:
                for file in os.listdir(dir):
                    # print(os.path.join(dir, file))
                    with open(os.path.join(dir, file), 'r') as f:
                        for line in f.readlines():
                            if "${ANDROID_ROOT}" in line:
                                if line[0:3] == "set":
                                    continue

                                suffix_name = line.split("/")[-1].replace("\"", "")
                                # print(suffix_name)
                                if ".c" in suffix_name:
                                    suffix_name = line.split("/")[-1]
                                    new_line = line.replace(suffix_name, "*." + suffix_name.split(".")[-1])
                                    code_dirs.append(new_line)
                                    # code_dirs.append(line)
                                elif ".h" in suffix_name:
                                    header_dirs.append(line)
                                else:
                                    include_dirs.append(line)

    # 去重
    code_dirs = list(dict.fromkeys(code_dirs))
    header_dirs = list(dict.fromkeys(header_dirs))
    include_dirs = list(dict.fromkeys(include_dirs))

    # 排序
    code_dirs.sort()
    header_dirs.sort()
    include_dirs.sort()

    # print("project_dirs=", project_dirs)
    # print("code_dirs=", code_dirs)
    # print("header_dirs=", header_dirs)

    code_files = "\n"
    code_files_av = "\n"
    code_files_out = "\n"
    code_files_art = "\n"
    code_files_bionic = "\n"
    code_files_external = "\n"
    code_files_packages = "\n"
    code_files_vendor = "\n"
    code_files_hardware = "\n"
    code_files_bootable = "\n"
    code_files_prebuilts = "\n"

    code_files_system_common = "\n"
    code_files_system = "\n"

    for code in code_dirs:
        if "${ANDROID_ROOT}/frameworks/av/" in code:
            code_files_av += "\t" + code
        elif "${ANDROID_ROOT}/out/" in code:
            code_files_out += "\t" + code
        elif "${ANDROID_ROOT}/art/" in code:
            code_files_art += "\t" + code
        elif "${ANDROID_ROOT}/bionic/" in code:
            code_files_bionic += "\t" + code
        elif "${ANDROID_ROOT}/external/" in code:
            code_files_external += "\t" + code
        elif "${ANDROID_ROOT}/packages/" in code:
            code_files_packages += "\t" + code
        elif "${ANDROID_ROOT}/vendor/" in code or "${ANDROID_ROOT}/device/" in code:
            code_files_vendor += "\t" + code
        elif "${ANDROID_ROOT}/hardware/" in code \
                or "${ANDROID_ROOT}/frameworks/hardware/interfaces/" in code:
            code_files_hardware += "\t" + code
        elif "${ANDROID_ROOT}/bootable/" in code:
            code_files_bootable += "\t" + code
        elif "${ANDROID_ROOT}/prebuilts/" in code:
            code_files_prebuilts += "\t" + code
        elif "${ANDROID_ROOT}/system/" in code:
            if "${ANDROID_ROOT}/system/core/" in code \
                    or "${ANDROID_ROOT}/system/libbase/" in code \
                    or "${ANDROID_ROOT}/system/libfmq/" in code \
                    or "${ANDROID_ROOT}/system/libhidl/" in code \
                    or "${ANDROID_ROOT}/system/libhwbinder/" in code \
                    or "${ANDROID_ROOT}/system/logging/" in code \
                    or "${ANDROID_ROOT}/system/tools/aidl/" in code \
                    or "${ANDROID_ROOT}/system/tools/hidl/" in code \
                    or "${ANDROID_ROOT}/system/tools/sysprop/" in code:
                code_files_system_common += "\t" + code
            else:
                code_files_system += "\t" + code
        elif "${ANDROID_ROOT}/libnativehelper/" in code:
            # libnativehelper 也认为是common
            code_files_system_common += "\t" + code
        elif "${ANDROID_ROOT}/test/" in code \
                or "${ANDROID_ROOT}/tools/" in code:
            # 忽略
            continue
        else:
            code_files += code

    # print(code_files)

    header_files = "\n"
    header_files_av = "\n"
    header_files_out = "\n"
    header_files_art = "\n"
    header_files_bionic = "\n"
    header_files_external = "\n"
    header_files_packages = "\n"
    header_files_vendor = "\n"
    header_files_hardware = "\n"
    header_files_bootable = "\n"
    header_files_prebuilts = "\n"

    header_files_system_common = "\n"
    header_files_system = "\n"

    for header in header_dirs:
        if "${ANDROID_ROOT}/frameworks/av/" in header:
            header_files_av += "\t" + header
        elif "${ANDROID_ROOT}/out/" in header:
            header_files_out += "\t" + header
        elif "${ANDROID_ROOT}/art/" in header:
            header_files_art += "\t" + header
        elif "${ANDROID_ROOT}/bionic/" in header:
            header_files_bionic += "\t" + header
        elif "${ANDROID_ROOT}/external/" in header:
            header_files_external += "\t" + header
        elif "${ANDROID_ROOT}/packages/" in header:
            header_files_packages += "\t" + header
        elif "${ANDROID_ROOT}/vendor/" in header or "${ANDROID_ROOT}/device/" in header:
            header_files_vendor += "\t" + header
        elif "${ANDROID_ROOT}/hardware/" in header \
                or "${ANDROID_ROOT}/frameworks/hardware/interfaces/" in header:
            header_files_hardware += "\t" + header
        elif "${ANDROID_ROOT}/bootable/" in header:
            header_files_bootable += "\t" + header
        elif "${ANDROID_ROOT}/prebuilts/" in header:
            header_files_prebuilts += "\t" + header
        elif "${ANDROID_ROOT}/system/" in header:
            if "${ANDROID_ROOT}/system/core/" in header \
                    or "${ANDROID_ROOT}/system/libbase/" in header \
                    or "${ANDROID_ROOT}/system/libfmq/" in header \
                    or "${ANDROID_ROOT}/system/libhidl/" in header \
                    or "${ANDROID_ROOT}/system/libhwbinder/" in header \
                    or "${ANDROID_ROOT}/system/logging/" in header \
                    or "${ANDROID_ROOT}/system/tools/aidl/" in header \
                    or "${ANDROID_ROOT}/system/tools/hidl/" in header \
                    or "${ANDROID_ROOT}/system/tools/sysprop/" in header:
                header_files_system_common += "\t" + header
            else:
                header_files_system += "\t" + header
        elif "${ANDROID_ROOT}/libnativehelper/" in header:
            # libnativehelper 也认为是common
            header_files_system_common += "\t" + header
        elif "${ANDROID_ROOT}/test/" in header \
                or "${ANDROID_ROOT}/tools/" in header:
            # 忽略
            continue
        else:
            header_files += header

    # print(header_files)

    include_directories = "\n"
    include_directories_av = "\n"
    include_directories_out = "\n"
    include_directories_art = "\n"
    include_directories_bionic = "\n"
    include_directories_external = "\n"
    include_directories_packages = "\n"
    include_directories_vendor = "\n"
    include_directories_hardware = "\n"
    include_directories_bootable = "\n"
    include_directories_prebuilts = "\n"

    include_directories_system_common = "\n"
    include_directories_system = "\n"

    for project in include_dirs:
        if "${ANDROID_ROOT}/frameworks/av/" in project:
            include_directories_av += "\t" + project
        elif "${ANDROID_ROOT}/out/" in project:
            include_directories_out += "\t" + project
        elif "${ANDROID_ROOT}/art/" in project:
            include_directories_art += "\t" + project
        elif "${ANDROID_ROOT}/bionic/" in project:
            include_directories_bionic += "\t" + project
        elif "${ANDROID_ROOT}/external/" in project:
            include_directories_external += "\t" + project
        elif "${ANDROID_ROOT}/packages/" in project:
            include_directories_packages += "\t" + project
        elif "${ANDROID_ROOT}/vendor/" in project or "${ANDROID_ROOT}/device/" in project:
            include_directories_vendor += "\t" + project
        elif "${ANDROID_ROOT}/hardware/" in project \
                or "${ANDROID_ROOT}/frameworks/hardware/interfaces/" in project:
            include_directories_hardware += "\t" + project
        elif "${ANDROID_ROOT}/bootable/" in project:
            include_directories_bootable += "\t" + project
        elif "${ANDROID_ROOT}/prebuilts/" in project:
            include_directories_prebuilts += "\t" + project
        elif "${ANDROID_ROOT}/system/" in project:
            if "${ANDROID_ROOT}/system/core/" in project \
                    or "${ANDROID_ROOT}/system/libbase/" in project \
                    or "${ANDROID_ROOT}/system/libfmq/" in project \
                    or "${ANDROID_ROOT}/system/libhidl/" in project \
                    or "${ANDROID_ROOT}/system/libhwbinder/" in project \
                    or "${ANDROID_ROOT}/system/logging/" in project \
                    or "${ANDROID_ROOT}/system/tools/aidl/" in project \
                    or "${ANDROID_ROOT}/system/tools/hidl/" in project \
                    or "${ANDROID_ROOT}/system/tools/sysprop/" in project:
                include_directories_system_common += "\t" + project
            else:
                include_directories_system += "\t" + project
        elif "${ANDROID_ROOT}/libnativehelper/" in project:
            # libnativehelper 也认为是common
            include_directories_system_common += "\t" + project
        elif "${ANDROID_ROOT}/test/" in project \
                or "${ANDROID_ROOT}/tools/" in project:
            # 忽略
            continue
        else:
            include_directories += project

    cmake_file = os.path.join(os.path.dirname(__file__), "../", project_name, "CMakeLists.txt")

    # system_common
    ext_text = "\n"
    if "${ANDROID_ROOT}" in code_files_system_common:
        ext_text += Template(ext_template_src).safe_substitute({'FEATURE': "SYSTEM_COMMON",
                                                                'msg': "system common",
                                                                'code_files': code_files_system_common,
                                                                'include_dirs': include_directories_system_common,
                                                                'header_files': header_files_system_common
                                                                })
    else:
        ext_text += Template(ext_template).safe_substitute({'FEATURE': "SYSTEM_COMMON",
                                                            'msg': "system common",
                                                            'include_dirs': include_directories_system_common,
                                                            'header_files': header_files_system_common
                                                            })
    # av
    ext_text += "\n"
    if "${ANDROID_ROOT}" in code_files_av:
        ext_text += Template(ext_template_src).safe_substitute({'FEATURE': "AV",
                                                                'msg': "av",
                                                                'code_files': code_files_av,
                                                                'include_dirs': include_directories_av,
                                                                'header_files': header_files_av
                                                                })
    else:
        ext_text += Template(ext_template).safe_substitute({'FEATURE': "AV",
                                                            'msg': "av",
                                                            'include_dirs': include_directories_av,
                                                            'header_files': header_files_av
                                                            })

    # art
    ext_text += "\n"
    if "${ANDROID_ROOT}" in code_files_art:
        ext_text += Template(ext_template_src).safe_substitute({'FEATURE': "ART",
                                                                'msg': "art",
                                                                'code_files': code_files_art,
                                                                'include_dirs': include_directories_art,
                                                                'header_files': header_files_art
                                                                })
    else:
        ext_text += Template(ext_template).safe_substitute({'FEATURE': "ART",
                                                            'msg': "art",
                                                            'include_dirs': include_directories_art,
                                                            'header_files': header_files_art
                                                            })

    # bionic
    ext_text += "\n"
    if "${ANDROID_ROOT}" in code_files_bionic:
        ext_text += Template(ext_template_src).safe_substitute({'FEATURE': "BIONIC",
                                                                'msg': "bionic",
                                                                'code_files': code_files_bionic,
                                                                'include_dirs': include_directories_bionic,
                                                                'header_files': header_files_bionic
                                                                })
    else:
        ext_text += Template(ext_template).safe_substitute({'FEATURE': "BIONIC",
                                                            'msg': "bionic",
                                                            'include_dirs': include_directories_bionic,
                                                            'header_files': header_files_bionic
                                                            })

    # system
    ext_text += "\n"
    if "${ANDROID_ROOT}" in code_files_system:
        ext_text += Template(ext_template_src).safe_substitute({'FEATURE': "SYSTEM",
                                                                'msg': "system",
                                                                'code_files': code_files_system,
                                                                'include_dirs': include_directories_system,
                                                                'header_files': header_files_system
                                                                })
    else:
        ext_text += Template(ext_template).safe_substitute({'FEATURE': "SYSTEM",
                                                            'msg': "system",
                                                            'include_dirs': include_directories_system,
                                                            'header_files': header_files_system
                                                            })

    # external
    ext_text += "\n"
    if "${ANDROID_ROOT}" in code_files_external:
        ext_text += Template(ext_template_src).safe_substitute({'FEATURE': "EXTERNAL",
                                                                'msg': "external",
                                                                'code_files': code_files_external,
                                                                'include_dirs': include_directories_external,
                                                                'header_files': header_files_external
                                                                })
    else:
        ext_text += Template(ext_template).safe_substitute({'FEATURE': "EXTERNAL",
                                                            'msg': "external",
                                                            'include_dirs': include_directories_external,
                                                            'header_files': header_files_external
                                                            })

    # packages
    ext_text += "\n"
    if "${ANDROID_ROOT}" in code_files_packages:
        ext_text += Template(ext_template_src).safe_substitute({'FEATURE': "PACKAGES",
                                                                'msg': "packages",
                                                                'code_files': code_files_packages,
                                                                'include_dirs': include_directories_packages,
                                                                'header_files': header_files_packages
                                                                })
    else:
        ext_text += Template(ext_template).safe_substitute({'FEATURE': "PACKAGES",
                                                            'msg': "packages",
                                                            'include_dirs': include_directories_packages,
                                                            'header_files': header_files_packages
                                                            })

    # bootable
    ext_text += "\n"
    if "${ANDROID_ROOT}" in code_files_bootable:
        ext_text += Template(ext_template_src).safe_substitute({'FEATURE': "BOOTABLE",
                                                                'msg': "bootable",
                                                                'code_files': code_files_bootable,
                                                                'include_dirs': include_directories_bootable,
                                                                'header_files': header_files_bootable
                                                                })
    else:
        ext_text += Template(ext_template).safe_substitute({'FEATURE': "BOOTABLE",
                                                            'msg': "bootable",
                                                            'include_dirs': include_directories_bootable,
                                                            'header_files': header_files_bootable
                                                            })

    # # prebuilts
    # ext_text += "\n"
    # if "${ANDROID_ROOT}" in code_files_prebuilts:
    #     ext_text += Template(ext_template_src).safe_substitute({'FEATURE': "PREBUILTS",
    #                                                             'msg': "prebuilts",
    #                                                             'code_files': code_files_prebuilts,
    #                                                             'include_dirs': include_directories_prebuilts,
    #                                                             'header_files': header_files_prebuilts
    #                                                             })
    # else:
    #     ext_text += Template(ext_template).safe_substitute({'FEATURE': "PREBUILTS",
    #                                                         'msg': "prebuilts",
    #                                                         'include_dirs': include_directories_prebuilts,
    #                                                         'header_files': header_files_prebuilts
    #                                                         })

    # hardware
    ext_text += "\n"
    if "${ANDROID_ROOT}" in code_files_hardware:
        ext_text += Template(ext_template_src).safe_substitute({'FEATURE': "HARDWARE",
                                                                'msg': "hardware",
                                                                'code_files': code_files_hardware,
                                                                'include_dirs': include_directories_hardware,
                                                                'header_files': header_files_hardware
                                                                })
    else:
        ext_text += Template(ext_template).safe_substitute({'FEATURE': "HARDWARE",
                                                            'msg': "hardware",
                                                            'include_dirs': include_directories_hardware,
                                                            'header_files': header_files_hardware
                                                            })

    # out
    ext_text += "\n"
    if "${ANDROID_ROOT}" in code_files_out:
        ext_text += Template(ext_template_src).safe_substitute({'FEATURE': "OUT",
                                                                'msg': "out",
                                                                'code_files': code_files_out,
                                                                'include_dirs': include_directories_out,
                                                                'header_files': header_files_out
                                                                })
    else:
        ext_text += Template(ext_template).safe_substitute({'FEATURE': "OUT",
                                                            'msg': "out",
                                                            'include_dirs': include_directories_out,
                                                            'header_files': header_files_out
                                                            })

    cmake_file_text = Template(cmake_template).substitute({'project_name': project_name,
                                                           'code_files': code_files,
                                                           'include_directories': include_directories,
                                                           'header_files': header_files,
                                                           'BUILD_NATIVE_ROOT': "${BUILD_NATIVE_ROOT}",
                                                           'SOURCE_FILES': "${SOURCE_FILES}",
                                                           'HEADERS': "${HEADERS}",
                                                           'ext_template': ext_text,
                                                           })

    write_text(cmake_file, cmake_file_text)


def get_dirs(project):
    dirs = []

    android_runtime = ["frameworks/base/core/jni"]

    android_services = ["frameworks/base/libs/services",
                        "frameworks/base/services/core/jni",
                        "frameworks/base/services/incremental"]

    inputflinger = ["frameworks/native/services/inputflinger"]

    surfaceflinger = ["frameworks/native/services/surfaceflinger"]

    aosp_native = ["frameworks/base",
                   "frameworks/native",
                   "frameworks/av",
                   "frameworks/hardware/interfaces",
                   "system/core",
                   "system/libbase/",
                   "system/libfmq/",
                   "system/libhidl/",
                   "system/libhwbinder/",
                   "system/logging/",
                   "system/tools/aidl/",
                   "system/tools/hidl/",
                   "system/tools/sysprop/",
                   "hardware/libhardware/",
                   "hardware/interfaces/",
                   ]

    connectivity = [
        "packages/modules/Connectivity",
        "frameworks/libs/net"
    ]

    wifi = [
        "packages/modules/Wifi"
    ]

    ExtServices = [
        "packages/modules/ExtServices"
    ]

    NeuralNetworks = [
        "packages/modules/NeuralNetworks"
    ]

    if project == "android_runtime":
        dirs.extend(android_runtime)
    elif project == "android_services":
        dirs.extend(android_services)
    elif project == "inputflinger":
        dirs.extend(inputflinger)
    elif project == "surfaceflinger":
        dirs.extend(surfaceflinger)
    elif project == "aosp-native":
        dirs.extend(aosp_native)
    elif project == "connectivity":
        return connectivity
    elif project == "wifi":
        return wifi
    elif project == "ExtServices":
        return ExtServices
    elif project == "NeuralNetworks":
        return NeuralNetworks
    else:
        dirs.extend(aosp_native)

    return dirs


def main():
    (options, args) = parseargs()
    root = options.root.strip()
    project = options.project.strip()

    work(project, root, get_dirs(project))

    return 0


if __name__ == "__main__":
    main()
