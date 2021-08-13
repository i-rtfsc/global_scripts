#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -*- encoding: utf-8 -*-


import optparse
import os
import sys

import requests

sys.path.append(os.path.join(os.path.dirname(__file__), "../../"))
from config.user_config import UserConfig


def parseargs():
    usage = "usage: %prog [options] arg1 arg2"
    parser = optparse.OptionParser(usage=usage)

    option = optparse.OptionGroup(parser, "copy file options")
    option.add_option("-u", "--user", dest="user", type="string",
                      help="source data dir", default="")
    option.add_option("-p", "--pwd", dest="pwd", type="string",
                      help="out data dir", default="")
    parser.add_option_group(option)

    (options, args) = parser.parse_args()

    return (options, args)


def main():
    print(os.path.abspath(__file__))
    (options, args) = parseargs()
    user = options.user.strip()
    pwd = options.pwd.strip()
    if user == '' or pwd == '':
        user, pwd = UserConfig.get_user()

    host = "http://1.1.1.3"
    endpoint = "/ac_portal/login.php"
    url = ''.join([host, endpoint])

    data = dict()
    data['opr'] = 'pwdLogin'
    data['rememberPwd'] = 1
    data['userName'] = user
    data['pwd'] = pwd
    r = requests.post(url, data)
    print(r.content)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        # User interrupt the program with ctrl+c
        exit()
