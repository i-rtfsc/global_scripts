#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2022 anqi.huang@outlook.com
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


import os
import sys
import json
import time
import hmac
import hashlib
import base64

sys.path.append(os.path.join(os.path.dirname(__file__), "../"))

if sys.version_info > (3, 0):
    from urllib.request import urlopen, Request
    from urllib.parse import quote_plus
else:
    from urllib2 import urlopen, Request
    from urllib import quote_plus


class FeiShu(object):
    def __init__(self, token):
        self.url = self.parse_url(token)
        self.headers = {"Content-Type": "application/json"}

    def parse_url(self, token):
        url_pre = "https://open.feishu.cn/open-apis/bot/v2/hook/{}"
        return url_pre.format(token)

    def send_text(self, text):
        data = {
            "msg_type": "text",
            "content": {"text": text}
        }
        return self._post(data)

    def _post(self, data):
        data = json.dumps(data)
        req = Request(self.url, data=data.encode("utf-8"), headers=self.headers)
        response = urlopen(req)
        the_page = response.read()
        return json.loads(the_page.decode("utf-8"))
