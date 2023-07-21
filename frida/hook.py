import optparse
import os
import sys

import frida


def parseargs():
    usage = "usage: %prog [options] arg1 arg2"
    parser = optparse.OptionParser(usage=usage)

    buildoptiongroup = optparse.OptionGroup(parser, "git push to gerrit options")

    buildoptiongroup.add_option("-p", "--package", dest="package",
                                help="package name", default="system_server")
    buildoptiongroup.add_option("-f", "--file", dest="file",
                                help="file name", default="")

    parser.add_option_group(buildoptiongroup)

    (options, args) = parser.parse_args()

    return (options, args)


# 自定义回调函数
def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)


def get_js_code(js_file):
    return open(js_file, 'r').read()


if __name__ == '__main__':
    (options, args) = parseargs()
    package_name = options.package.strip()
    file_name = options.file.strip()

    if os.path.exists(file_name):
        # 传进来的文件就带有路径
        file = file_name
    else:
        file = os.path.join(os.path.join(os.path.dirname(os.path.abspath(__file__))), file_name)

    if os.path.isfile(file) is False or os.path.exists(file) is False:
        print(package_name, file)
        exit(-1)

    # 附加到进程并得到进程对象
    process = frida.get_usb_device().attach(package_name)
    # 指定JavaScript脚本
    script = process.create_script(get_js_code(file))
    # 加载JavaScript脚本
    script.on('message', on_message)
    script.load()
    # 读取返回输入
    sys.stdin.read()
