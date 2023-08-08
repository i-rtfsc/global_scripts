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

set(AOSP_SYSTEM_COMMON true)
set(AOSP_OUT false)
set(AOSP_AV false)
set(AOSP_ART false)
set(AOSP_BIONIC false)
set(AOSP_SYSTEM false)
set(AOSP_EXTERNAL false)
set(AOSP_PACKAGES false)
set(AOSP_HARDWARE false)
set(AOSP_VENDOR false)

file(GLOB SOURCE_FILES${code_files})

include_directories(${include_directories})

file (GLOB_RECURSE HEADERS${header_files})

# add aosp system common
if (${AOSP_SYSTEM_COMMON})
    message("enable aosp system common")

    # add aosp system common src
    file(GLOB SOURCE_FILES_SYSTEM_COMMON${code_files_system_common})
    # append aosp system common src
    list (APPEND SOURCE_FILES ${SOURCE_FILES_SYSTEM_COMMON})
    
    # add aosp system common header dir
    include_directories(${include_directories_system_common})

    # add aosp system common header file
    file (GLOB_RECURSE HEADERS_SYSTEM_COMMON${header_files_system_common})    
    # append aosp system common header
    list (APPEND HEADERS ${HEADERS_SYSTEM_COMMON})    
endif ()

# add aosp system
if (${AOSP_SYSTEM})
    message("enable aosp system")

    # add aosp system src
    file(GLOB SOURCE_FILES_SYSTEM${code_files_system})
    # append aosp system common src
    list (APPEND SOURCE_FILES ${SOURCE_FILES_SYSTEM})
    
    # add aosp system header dir
    include_directories(${include_directories_system})

    # add aosp system header file
    file (GLOB_RECURSE HEADERS_SYSTEM${header_files_system})    
    # append aosp system header
    list (APPEND HEADERS ${HEADERS_SYSTEM})    
endif ()

# add aosp av
if (${AOSP_AV})
    message("enable aosp av")

    # add aosp av src
    file(GLOB SOURCE_FILES_AV${code_files_av})
    # append aosp av src
    list (APPEND SOURCE_FILES ${SOURCE_FILES_AV})
    
    # add aosp av header dir
    include_directories(${include_directories_av})

    # add aosp av header file
    file (GLOB_RECURSE HEADERS_AV${header_files_av})    
    # append aosp av header
    list (APPEND HEADERS ${HEADERS_AV})    
endif ()

# add aosp out
if (${AOSP_OUT})
    message("enable aosp out")

    # add aosp out src
    file(GLOB SOURCE_FILES_OUT${code_files_out})
    # append aosp out src
    list (APPEND SOURCE_FILES ${SOURCE_FILES_OUT})
    
    # add aosp out header dir
    include_directories(${include_directories_out})

    # add aosp out header file
    file (GLOB_RECURSE HEADERS_OUT${header_files_out})    
    # append aosp out header
    list (APPEND HEADERS ${HEADERS_OUT})    
endif ()

# add aosp art
if (${AOSP_ART})
    message("enable aosp art")

    # add aosp art src
    file(GLOB SOURCE_FILES_ART${code_files_art})
    # append aosp art src
    list (APPEND SOURCE_FILES ${SOURCE_FILES_ART})
    
    # add aosp art header dir
    include_directories(${include_directories_art})

    # add aosp art header file
    file (GLOB_RECURSE HEADERS_ART${header_files_art})    
    # append aosp art header
    list (APPEND HEADERS ${HEADERS_ART})    
endif ()

# add aosp external
if (${AOSP_BIONIC})
    message("enable aosp bionic")

    # add aosp bionic src
    file(GLOB SOURCE_FILES_BIONIC${code_files_bionic})
    # append aosp bionic src
    list (APPEND SOURCE_FILES ${SOURCE_FILES_BIONIC})
    
    # add aosp bionic header dir
    include_directories(${include_directories_bionic})

    # add aosp bionic header file
    file (GLOB_RECURSE HEADERS_BIONIC${header_files_bionic})    
    # append aosp bionic header
    list (APPEND HEADERS ${HEADERS_BIONIC})    
endif ()

# add aosp external
if (${AOSP_EXTERNAL})
    message("enable aosp external")

    # add aosp external src
    file(GLOB SOURCE_FILES_EXTERNAL${code_files_external})
    # append aosp external src
    list (APPEND SOURCE_FILES ${SOURCE_FILES_EXTERNAL})
    
    # add aosp external header dir
    include_directories(${include_directories_external})

    # add aosp external header file
    file (GLOB_RECURSE HEADERS_EXTERNAL${header_files_external})    
    # append aosp external header
    list (APPEND HEADERS ${HEADERS_EXTERNAL})    
endif ()

# add aosp packages
if (${AOSP_PACKAGES})
    message("enable aosp packages")

    # add aosp packages src
    file(GLOB SOURCE_FILES_PACKAGES${code_files_packages})
    # append aosp packages src
    list (APPEND SOURCE_FILES ${SOURCE_FILES_PACKAGES})
    
    # add aosp packages header dir
    include_directories(${include_directories_packages})

    # add aosp packages header file
    file (GLOB_RECURSE HEADERS_PACKAGES${header_files_packages})    
    # append aosp packages header
    list (APPEND HEADERS ${HEADERS_PACKAGES})    
endif ()

# add aosp hardware
if (${AOSP_HARDWARE})
    message("enable aosp hardware")

    # add aosp hardware src
    file(GLOB SOURCE_FILES_HARDWARE${code_files_hardware})
    # append aosp hardware src
    list (APPEND SOURCE_FILES ${SOURCE_FILES_HARDWARE})
    
    # add aosp hardware header dir
    include_directories(${include_directories_hardware})

    # add aosp hardware header file
    file (GLOB_RECURSE HEADERS_HARDWARE${header_files_hardware})    
    # append aosp hardware header
    list (APPEND HEADERS ${HEADERS_HARDWARE})    
endif ()

# add aosp vendor
if (${AOSP_VENDOR})
    message("enable aosp vendor")

    # add aosp vendor src
    file(GLOB SOURCE_FILES_VENDOR${code_files_vendor})
    # append aosp vendor src
    list (APPEND SOURCE_FILES ${SOURCE_FILES_VENDOR})
    
    # add aosp vendor header dir
    include_directories(${include_directories_vendor})

    # add aosp vendor header file
    file (GLOB_RECURSE HEADERS_VENDOR${header_files_vendor})    
    # append aosp vendor header
    list (APPEND HEADERS ${HEADERS_VENDOR})    
endif ()

add_executable(
        ${project_name}
        ${SOURCE_FILES}
        ${HEADERS}
)
"""

# 生成cmake文件模板
cmake_template_mini = """cmake_minimum_required(VERSION 3.5)
project(${project_name})

# set(CMAKE_CXX_STANDARD 20)

set(ANDROID_ROOT ${BUILD_NATIVE_ROOT})

set(AOSP_SYSTEM_COMMON true)
set(AOSP_OUT false)
set(AOSP_AV false)
set(AOSP_ART false)
set(AOSP_BIONIC false)
set(AOSP_SYSTEM false)
set(AOSP_EXTERNAL false)
set(AOSP_PACKAGES false)
set(AOSP_HARDWARE false)
set(AOSP_VENDOR false)

file(GLOB SOURCE_FILES${code_files})

include_directories(${include_directories})

file (GLOB_RECURSE HEADERS${header_files})

# add aosp system common
if (${AOSP_SYSTEM_COMMON})
    message("enable aosp system common")

    # add aosp system common header dir
    include_directories(${include_directories_system_common})

    # add aosp system common header file
    file (GLOB_RECURSE HEADERS_SYSTEM_COMMON${header_files_system_common})    
    # append aosp system common header
    list (APPEND HEADERS ${HEADERS_SYSTEM_COMMON})    
endif ()

# add aosp system
if (${AOSP_SYSTEM})
    message("enable aosp system")

    # add aosp system header dir
    include_directories(${include_directories_system})

    # add aosp system header file
    file (GLOB_RECURSE HEADERS_SYSTEM${header_files_system})    
    # append aosp system header
    list (APPEND HEADERS ${HEADERS_SYSTEM})    
endif ()

# add aosp av
if (${AOSP_AV})
    message("enable aosp av")

    # add aosp av src
    file(GLOB SOURCE_FILES_AV${code_files_av})
    # append aosp av src
    list (APPEND SOURCE_FILES ${SOURCE_FILES_AV})

    # add aosp av header dir
    include_directories(${include_directories_av})

    # add aosp av header file
    file (GLOB_RECURSE HEADERS_AV${header_files_av})    
    # append aosp av header
    list (APPEND HEADERS ${HEADERS_AV})    
endif ()

# add aosp out
if (${AOSP_OUT})
    message("enable aosp out")

    # add aosp out header dir
    include_directories(${include_directories_out})

    # add aosp out header file
    file (GLOB_RECURSE HEADERS_OUT${header_files_out})    
    # append aosp out header
    list (APPEND HEADERS ${HEADERS_OUT})    
endif ()

# add aosp art
if (${AOSP_ART})
    message("enable aosp art")

    # add aosp art header dir
    include_directories(${include_directories_art})

    # add aosp art header file
    file (GLOB_RECURSE HEADERS_ART${header_files_art})    
    # append aosp art header
    list (APPEND HEADERS ${HEADERS_ART})    
endif ()

# add aosp external
if (${AOSP_BIONIC})
    message("enable aosp bionic")

    # add aosp bionic header dir
    include_directories(${include_directories_bionic})

    # add aosp bionic header file
    file (GLOB_RECURSE HEADERS_BIONIC${header_files_bionic})    
    # append aosp bionic header
    list (APPEND HEADERS ${HEADERS_BIONIC})    
endif ()

# add aosp external
if (${AOSP_EXTERNAL})
    message("enable aosp external")

    # add aosp external header dir
    include_directories(${include_directories_external})

    # add aosp external header file
    file (GLOB_RECURSE HEADERS_EXTERNAL${header_files_external})    
    # append aosp external header
    list (APPEND HEADERS ${HEADERS_EXTERNAL})    
endif ()

# add aosp packages
if (${AOSP_PACKAGES})
    message("enable aosp packages")

    # add aosp packages header dir
    include_directories(${include_directories_packages})

    # add aosp packages header file
    file (GLOB_RECURSE HEADERS_PACKAGES${header_files_packages})    
    # append aosp packages header
    list (APPEND HEADERS ${HEADERS_PACKAGES})    
endif ()

# add aosp hardware
if (${AOSP_HARDWARE})
    message("enable aosp hardware")

    # add aosp hardware header dir
    include_directories(${include_directories_hardware})

    # add aosp hardware header file
    file (GLOB_RECURSE HEADERS_HARDWARE${header_files_hardware})    
    # append aosp hardware header
    list (APPEND HEADERS ${HEADERS_HARDWARE})    
endif ()

# add aosp vendor
if (${AOSP_VENDOR})
    message("enable aosp vendor")

    # add aosp vendor header dir
    include_directories(${include_directories_vendor})

    # add aosp vendor header file
    file (GLOB_RECURSE HEADERS_VENDOR${header_files_vendor})    
    # append aosp vendor header
    list (APPEND HEADERS ${HEADERS_VENDOR})    
endif ()

add_executable(
        ${project_name}
        ${SOURCE_FILES}
        ${HEADERS}
)
"""


def parseargs():
    usage = "usage: %prog [options] arg1 arg2"
    parser = optparse.OptionParser(usage=usage)

    buildoptiongroup = optparse.OptionGroup(parser, "generate cmake file")

    buildoptiongroup.add_option("-r", "--root", dest="root",
                                help="root dir", default="/home/solo/code/flyme")
    buildoptiongroup.add_option("-p", "--project", dest="project",
                                help="project name(android_runtime,android_services,inputflinger,surfaceflinger,media), or aosp-native[all projects]",
                                default="aosp-native")

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


def work(project_name, project_list):
    code_dirs = []
    header_dirs = []
    include_dirs = []

    for project_dir in project_list:

        project_dirs = fast_scandir(project_dir)
        project_dirs.append(project_dir)
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
        elif "${ANDROID_ROOT}/vendor/" in code:
            code_files_vendor += "\t" + code
        elif "${ANDROID_ROOT}/hardware/" in code:
            code_files_hardware += "\t" + code
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
        elif "${ANDROID_ROOT}/vendor/" in header:
            header_files_vendor += "\t" + header
        elif "${ANDROID_ROOT}/hardware/" in header:
            header_files_hardware += "\t" + header
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
            header_files_hardware += "\t" + header
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
        elif "${ANDROID_ROOT}/vendor/" in project:
            include_directories_vendor += "\t" + project
        elif "${ANDROID_ROOT}/hardware/" in project:
            include_directories_hardware += "\t" + project
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

    # cmake_file = os.path.join(os.path.dirname(__file__), project_name, "CMakeLists.txt")
    cmake_file = os.path.join(os.path.dirname(__file__), "../", project_name, "CMakeLists.txt")
    # cmake_file_text = Template(cmake_template).substitute({'project_name': project_name,
    #                                                        'code_files': code_files,
    #                                                        'include_directories': include_directories,
    #                                                        'header_files': header_files,
    #                                                        'BUILD_NATIVE_ROOT': "${BUILD_NATIVE_ROOT}",
    #                                                        'SOURCE_FILES': "${SOURCE_FILES}",
    #                                                        'HEADERS': "${HEADERS}",
    #                                                        # system common
    #                                                        'AOSP_SYSTEM_COMMON': "${AOSP_SYSTEM_COMMON}",
    #                                                        'SOURCE_FILES_SYSTEM_COMMON': "${SOURCE_FILES_SYSTEM_COMMON}",
    #                                                        'HEADERS_SYSTEM_COMMON': "${HEADERS_SYSTEM_COMMON}",
    #                                                        'code_files_system_common': code_files_system_common + "\t",
    #                                                        'include_directories_system_common': include_directories_system_common + "\t",
    #                                                        'header_files_system_common': header_files_system_common + "\t",
    #                                                        # # system
    #                                                        'AOSP_SYSTEM': "${AOSP_SYSTEM}",
    #                                                        'SOURCE_FILES_SYSTEM': "${SOURCE_FILES_SYSTEM}",
    #                                                        'HEADERS_SYSTEM': "${HEADERS_SYSTEM}",
    #                                                        'code_files_system': code_files_system + "\t",
    #                                                        'include_directories_system': include_directories_system + "\t",
    #                                                        'header_files_system': header_files_system + "\t",
    #                                                        # av
    #                                                        'AOSP_AV': "${AOSP_AV}",
    #                                                        'SOURCE_FILES_AV': "${SOURCE_FILES_AV}",
    #                                                        'HEADERS_AV': "${HEADERS_AV}",
    #                                                        'code_files_av': code_files_av + "\t",
    #                                                        'include_directories_av': include_directories_av + "\t",
    #                                                        'header_files_av': header_files_av + "\t",
    #                                                        # out
    #                                                        'AOSP_OUT': "${AOSP_OUT}",
    #                                                        'SOURCE_FILES_OUT': "${SOURCE_FILES_OUT}",
    #                                                        'HEADERS_OUT': "${HEADERS_OUT}",
    #                                                        'code_files_out': code_files_out + "\t",
    #                                                        'include_directories_out': include_directories_out + "\t",
    #                                                        'header_files_out': header_files_out + "\t",
    #                                                        # art
    #                                                        'AOSP_ART': "${AOSP_ART}",
    #                                                        'SOURCE_FILES_ART': "${SOURCE_FILES_ART}",
    #                                                        'HEADERS_ART': "${HEADERS_ART}",
    #                                                        'code_files_art': code_files_art + "\t",
    #                                                        'include_directories_art': include_directories_art + "\t",
    #                                                        'header_files_art': header_files_art + "\t",
    #                                                        # bionic
    #                                                        'AOSP_BIONIC': "${AOSP_BIONIC}",
    #                                                        'SOURCE_FILES_BIONIC': "${SOURCE_FILES_BIONIC}",
    #                                                        'HEADERS_BIONIC': "${HEADERS_BIONIC}",
    #                                                        'code_files_bionic': code_files_bionic + "\t",
    #                                                        'include_directories_bionic': include_directories_bionic + "\t",
    #                                                        'header_files_bionic': header_files_bionic + "\t",
    #                                                        # external
    #                                                        'AOSP_EXTERNAL': "${AOSP_EXTERNAL}",
    #                                                        'SOURCE_FILES_EXTERNAL': "${SOURCE_FILES_EXTERNAL}",
    #                                                        'HEADERS_EXTERNAL': "${HEADERS_EXTERNAL}",
    #                                                        'code_files_external': code_files_external + "\t",
    #                                                        'include_directories_external': include_directories_external + "\t",
    #                                                        'header_files_external': header_files_external + "\t",
    #                                                        # packages
    #                                                        'AOSP_PACKAGES': "${AOSP_PACKAGES}",
    #                                                        'SOURCE_FILES_PACKAGES': "${SOURCE_FILES_PACKAGES}",
    #                                                        'HEADERS_PACKAGES': "${HEADERS_PACKAGES}",
    #                                                        'code_files_packages': code_files_packages + "\t",
    #                                                        'include_directories_packages': include_directories_packages + "\t",
    #                                                        'header_files_packages': header_files_packages + "\t",
    #                                                        # hardware
    #                                                        'AOSP_HARDWARE': "${AOSP_HARDWARE}",
    #                                                        'SOURCE_FILES_HARDWARE': "${SOURCE_FILES_HARDWARE}",
    #                                                        'HEADERS_HARDWARE': "${HEADERS_HARDWARE}",
    #                                                        'code_files_hardware': code_files_hardware + "\t",
    #                                                        'include_directories_hardware': include_directories_hardware + "\t",
    #                                                        'header_files_hardware': header_files_hardware + "\t",
    #                                                        # vendor
    #                                                        'AOSP_VENDOR': "${AOSP_VENDOR}",
    #                                                        'SOURCE_FILES_VENDOR': "${SOURCE_FILES_VENDOR}",
    #                                                        'HEADERS_VENDOR': "${HEADERS_VENDOR}",
    #                                                        'code_files_vendor': code_files_vendor + "\t",
    #                                                        'include_directories_vendor': include_directories_vendor + "\t",
    #                                                        'header_files_vendor': header_files_vendor + "\t",
    #                                                        })

    cmake_file_text = Template(cmake_template_mini).substitute({'project_name': project_name,
                                                           'code_files': code_files,
                                                           'include_directories': include_directories,
                                                           'header_files': header_files,
                                                           'BUILD_NATIVE_ROOT': "${BUILD_NATIVE_ROOT}",
                                                           'SOURCE_FILES': "${SOURCE_FILES}",
                                                           'HEADERS': "${HEADERS}",
                                                           # system common
                                                           'AOSP_SYSTEM_COMMON': "${AOSP_SYSTEM_COMMON}",
                                                           'HEADERS_SYSTEM_COMMON': "${HEADERS_SYSTEM_COMMON}",
                                                           'include_directories_system_common': include_directories_system_common + "\t",
                                                           'header_files_system_common': header_files_system_common + "\t",
                                                           # # system
                                                           'AOSP_SYSTEM': "${AOSP_SYSTEM}",
                                                           'HEADERS_SYSTEM': "${HEADERS_SYSTEM}",
                                                           'include_directories_system': include_directories_system + "\t",
                                                           'header_files_system': header_files_system + "\t",
                                                           # av
                                                           'AOSP_AV': "${AOSP_AV}",
                                                           'SOURCE_FILES_AV': "${SOURCE_FILES_AV}",
                                                           'HEADERS_AV': "${HEADERS_AV}",
                                                           'code_files_av': code_files_av + "\t",
                                                           'include_directories_av': include_directories_av + "\t",
                                                           'header_files_av': header_files_av + "\t",
                                                           # out
                                                           'AOSP_OUT': "${AOSP_OUT}",
                                                           'HEADERS_OUT': "${HEADERS_OUT}",
                                                           'include_directories_out': include_directories_out + "\t",
                                                           'header_files_out': header_files_out + "\t",
                                                           # art
                                                           'AOSP_ART': "${AOSP_ART}",
                                                           'HEADERS_ART': "${HEADERS_ART}",
                                                           'include_directories_art': include_directories_art + "\t",
                                                           'header_files_art': header_files_art + "\t",
                                                           # bionic
                                                           'AOSP_BIONIC': "${AOSP_BIONIC}",
                                                           'HEADERS_BIONIC': "${HEADERS_BIONIC}",
                                                           'include_directories_bionic': include_directories_bionic + "\t",
                                                           'header_files_bionic': header_files_bionic + "\t",
                                                           # external
                                                           'AOSP_EXTERNAL': "${AOSP_EXTERNAL}",
                                                           'HEADERS_EXTERNAL': "${HEADERS_EXTERNAL}",
                                                           'include_directories_external': include_directories_external + "\t",
                                                           'header_files_external': header_files_external + "\t",
                                                           # packages
                                                           'AOSP_PACKAGES': "${AOSP_PACKAGES}",
                                                           'HEADERS_PACKAGES': "${HEADERS_PACKAGES}",
                                                           'include_directories_packages': include_directories_packages + "\t",
                                                           'header_files_packages': header_files_packages + "\t",
                                                           # hardware
                                                           'AOSP_HARDWARE': "${AOSP_HARDWARE}",
                                                           'HEADERS_HARDWARE': "${HEADERS_HARDWARE}",
                                                           'include_directories_hardware': include_directories_hardware + "\t",
                                                           'header_files_hardware': header_files_hardware + "\t",
                                                           # vendor
                                                           'AOSP_VENDOR': "${AOSP_VENDOR}",
                                                           'HEADERS_VENDOR': "${HEADERS_VENDOR}",
                                                           'include_directories_vendor': include_directories_vendor + "\t",
                                                           'header_files_vendor': header_files_vendor + "\t",
                                                           })

    write_text(cmake_file, cmake_file_text)


def main():
    (options, args) = parseargs()
    root = options.root.strip()
    project = options.project.strip()

    # work("update_engine",
    #      ["/home/solo/code/github/global_scripts/test/clion/system/update_engine"])

    # work("android_runtime",
    #      ["/home/solo/code/github/global_scripts/test/clion/frameworks/base/core/jni"])


    # work("android-services",
    #      ["/home/solo/code/github/global_scripts/test/clion/frameworks/base/libs/services",
    #       "/home/solo/code/github/global_scripts/test/clion/frameworks/base/services/core/jni",
    #       "/home/solo/code/github/global_scripts/test/clion/frameworks/base/services/incremental"])

    # work("surfaceflinger", ["/home/solo/code/github/global_scripts/test/clion/frameworks/native/services/surfaceflinger"])
    # work("inputflinger", ["/home/solo/code/github/global_scripts/test/clion/frameworks/native/services/inputflinger"])

    work("aosp-native", ["/home/solo/code/github/global_scripts/test/clion/frameworks/base",
                         "/home/solo/code/github/global_scripts/test/clion/frameworks/native",
                         "/home/solo/code/github/global_scripts/test/clion/frameworks/av"
                         ])

    return 0


if __name__ == "__main__":
    main()
