#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2024 anqi.huang@outlook.com
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

import argparse
import hashlib
import os
import re
import time

from datetime import datetime
from enum import Enum
from logging import getLogger, Logger, StreamHandler
from string import Template
from typing import Dict
from urllib.parse import urlparse

import parsel
import requests
from bs4 import BeautifulSoup

MARKDOWN = {
    'h1': ('\n# ', '\n'),
    'h2': ('\n## ', '\n'),
    'h3': ('\n### ', '\n'),
    'h4': ('\n#### ', '\n'),
    'h5': ('\n##### ', '\n'),
    'h6': ('\n###### ', '\n'),
    'code': ('`', '`'),
    'ul': ('', ''),
    'ol': ('', ''),
    'li': ('- ', ''),
    'blockquote': ('\n> ', '\n'),
    'em': ('**', '**'),
    'strong': ('**', '**'),
    'block_code': ('\n```\n', '\n```\n'),
    'span': ('', ''),
    'p': ('\n', '\n'),
    'p_with_out_class': ('\n', '\n'),
    'inline_p': ('', ''),
    'inline_p_with_out_class': ('', ''),
    'b': ('**', '**'),
    'i': ('*', '*'),
    'del': ('~~', '~~'),
    'hr': ('\n---', '\n\n'),
    'thead': ('\n', '|------\n'),
    'tbody': ('\n', '\n'),
    'td': ('|', ''),
    'th': ('|', ''),
    'tr': ('', '\n')
}

BlOCK_ELEMENTS = {
    'h1': '<h1.*?>(.*?)</h1>',
    'h2': '<h2.*?>(.*?)</h2>',
    'h3': '<h3.*?>(.*?)</h3>',
    'h4': '<h4.*?>(.*?)</h4>',
    'h5': '<h5.*?>(.*?)</h5>',
    'h6': '<h6.*?>(.*?)</h6>',
    'hr': '<hr/>',
    'blockquote': '<blockquote.*?>(.*?)</blockquote>',
    'ul': '<ul.*?>(.*?)</ul>',
    'ol': '<ol.*?>(.*?)</ol>',
    'block_code': '<pre.*?><code.*?>(.*?)</code></pre>',
    'p': '<p\s.*?>(.*?)</p>',
    'p_with_out_class': '<p>(.*?)</p>',
    'thead': '<thead.*?>(.*?)</thead>',
    'tr': '<tr>(.*?)</tr>'
}

INLINE_ELEMENTS = {
    'td': '<td>(.*?)</td>',
    'tr': '<tr>(.*?)</tr>',
    'th': '<th>(.*?)</th>',
    'b': '<b>(.*?)</b>',
    'i': '<i>(.*?)</i>',
    'del': '<del>(.*?)</del>',
    'inline_p': '<p\s.*?>(.*?)</p>',
    'inline_p_with_out_class': '<p>(.*?)</p>',
    'code': '<code.*?>(.*?)</code>',
    'span': '<span.*?>(.*?)</span>',
    'ul': '<ul.*?>(.*?)</ul>',
    'ol': '<ol.*?>(.*?)</ol>',
    'li': '<li.*?>(.*?)</li>',
    'img': '<img.*?src="(.*?)".*?>(.*?)</img>',
    'a': '<a.*?href="(.*?)".*?>(.*?)</a>',
    'em': '<em.*?>(.*?)</em>',
    'strong': '<strong.*?>(.*?)</strong>'
}

DELETE_ELEMENTS = ['<span.*?>', '</span>', '<div.*?>', '</div>']


class Element:
    def __init__(self, start_pos, end_pos, content, tag, is_block=False):
        self.start_pos = start_pos
        self.end_pos = end_pos
        self.content = content
        self._elements = []
        self.is_block = is_block
        self.tag = tag
        self._result = None

        if self.is_block:
            self.parse_inline()

    def __str__(self):
        wrapper = MARKDOWN.get(self.tag)
        self._result = '{}{}{}'.format(wrapper[0], self.content, wrapper[1])
        return self._result

    def parse_inline(self):
        for tag, pattern in INLINE_ELEMENTS.items():

            if tag == 'a':
                self.content = re.sub(pattern, '[\g<2>](\g<1>)', self.content)
            elif tag == 'img':
                self.content = re.sub(pattern, '![\g<2>](\g<1>)', self.content)
            elif self.tag == 'ul' and tag == 'li':
                self.content = re.sub(pattern, '- \g<1>', self.content)
            elif self.tag == 'ol' and tag == 'li':
                self.content = re.sub(pattern, '1. \g<1>', self.content)
            elif self.tag == 'thead' and tag == 'tr':
                self.content = re.sub(pattern, '\g<1>\n', self.content.replace('\n', ''))
            elif self.tag == 'tr' and tag == 'th':
                self.content = re.sub(pattern, '|\g<1>', self.content.replace('\n', ''))
            elif self.tag == 'tr' and tag == 'td':
                self.content = re.sub(pattern, '|\g<1>', self.content.replace('\n', ''))
            else:
                wrapper = MARKDOWN.get(tag)
                self.content = re.sub(pattern, '{}\g<1>{}'.format(wrapper[0], wrapper[1]), self.content)


class Tomd:
    def __init__(self, html='', options=None):
        self.html = html
        self.options = options
        self._markdown = ''

    def convert(self, html, options=None):
        elements = []
        for tag, pattern in BlOCK_ELEMENTS.items():
            for m in re.finditer(pattern, html, re.I | re.S | re.M):
                element = Element(start_pos=m.start(),
                                  end_pos=m.end(),
                                  content=''.join(m.groups()),
                                  tag=tag,
                                  is_block=True)
                can_append = True
                for e in elements:
                    if e.start_pos < m.start() and e.end_pos > m.end():
                        can_append = False
                    elif e.start_pos > m.start() and e.end_pos < m.end():
                        elements.remove(e)
                if can_append:
                    elements.append(element)

        elements.sort(key=lambda element: element.start_pos)
        self._markdown = ''.join([str(e) for e in elements])

        for index, element in enumerate(DELETE_ELEMENTS):
            self._markdown = re.sub(element, '', self._markdown)
        return self._markdown

    @property
    def markdown(self):
        self.convert(self.html, self.options)
        return self._markdown


class Utils:
    @staticmethod
    def is_valid_url(url):
        result = urlparse(url)
        return all([result.scheme, result.netloc])

    @staticmethod
    def is_user_homepage_or_article(url):
        """
        返回：用户名，flags
        flags=1, 爬单个文章
        flags=2, 爬所有文章
        flags=-1, 出错
        """
        if url.startswith('https://blog.csdn.net/'):
            user_name = url.split('/')[3]
            if user_name:
                if '/' in url[len('https://blog.csdn.net/' + user_name) + 1:]:
                    return user_name, Flags.SINGLE
                else:
                    return user_name, Flags.ALL
            else:
                return user_name, Flags.ERROR
        else:
            return "", Flags.ERROR

    @staticmethod
    def generate_md5(input_string):
        md5_hash = hashlib.md5(input_string.encode()).hexdigest()
        return md5_hash

    @staticmethod
    def rename_image_if_needed(filename):
        return filename.split('#')[0]


class DebugManager:
    _COLOR_RESET = "\u001B[0m"
    _COLOR_RED = "\u001B[31m"
    _COLOR_GREEN = "\u001B[32m"
    _COLOR_BLUE = "\u001B[34m"
    _COLOR_YELLOW = "\u001B[33m"

    _DATE_TEMPLATE = "date"

    _logger: Logger

    @staticmethod
    def create_logger(level: str):
        DebugManager._logger = getLogger(__name__)
        DebugManager._logger.setLevel(level)
        DebugManager._logger.addHandler(StreamHandler())

    @staticmethod
    def _process_template(message: str, kwargs: Dict) -> str:
        if DebugManager._DATE_TEMPLATE in kwargs:
            kwargs[
                DebugManager._DATE_TEMPLATE] = f"{datetime.strftime(kwargs[DebugManager._DATE_TEMPLATE], '%d-%m-%Y %H:%M:%S:%f')}"

        return Template(message).substitute(kwargs)

    @staticmethod
    def i(message: str, **kwargs):
        message = DebugManager._process_template(message, kwargs)
        DebugManager._logger.info(f"{DebugManager._COLOR_GREEN}{message}{DebugManager._COLOR_RESET}")

    @staticmethod
    def d(message: str, **kwargs):
        message = DebugManager._process_template(message, kwargs)
        DebugManager._logger.debug(f"{DebugManager._COLOR_BLUE}{message}{DebugManager._COLOR_RESET}")

    @staticmethod
    def w(message: str, **kwargs):
        message = DebugManager._process_template(message, kwargs)
        DebugManager._logger.warning(f"{DebugManager._COLOR_YELLOW}{message}{DebugManager._COLOR_RESET}")

    @staticmethod
    def e(message: str, **kwargs):
        message = DebugManager._process_template(message, kwargs)
        DebugManager._logger.error(message)


class Flags(Enum):
    ERROR = -1
    SINGLE = 0
    ALL = 1


class CSDN(object):
    def __init__(self, url, local, out_dir, cookie=None):
        """
        :param url:
            1. 输入： https://blog.csdn.net/用户名 ，则获取该用户所有文章
            2. 输入： https://blog.csdn.net/用户名/文章地址 ，则单篇文章
            3. 输入： 用户 （等同于 https://blog.csdn.net/用户名 ）
        """
        self.url = url

        if Utils.is_valid_url(url):
            self.username, self.flags = Utils.is_user_homepage_or_article(url)
        else:
            self.username = url
            self.flags = Flags.ALL

        self.headers = self.get_headers(cookie)

        self.out_dir = os.path.join(out_dir, self.username)
        self.local = local

        self.session = requests.Session()
        self.TaskQueue = list()

        self.debug()

    def get_headers(self, cookie):
        request_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36 Edg/84.0.522.52",
            "Referer": "https://blog.csdn.net/",
            "Connection": "keep-alive"
        }
        if cookie is not None:
            request_headers["Cookie"] = cookie

        return request_headers

    def start(self):
        if self.flags == Flags.ALL:
            num = 0
            articles = [None]
            while len(articles) > 0:
                num += 1
                url = u'https://blog.csdn.net/' + self.username + '/article/list/' + str(num)
                response = self.session.get(url=url, headers=self.headers)
                html = response.text
                soup = BeautifulSoup(html, "html.parser")
                articles = soup.find_all('div', attrs={"class": "article-item-box csdn-tracking-statistics"})
                for article in articles:
                    self.TaskQueue.append(article.a['href'])
        elif self.flags == Flags.SINGLE:
            self.TaskQueue.append(self.url)
        else:
            DebugManager.e("解析url错误，请输入正确的url")

    def process(self):
        while len(self.TaskQueue) > 0:
            article_href = self.TaskQueue.pop()
            DebugManager.d("正在处理URL：{}".format(article_href))
            self.spider_article(article_href)

    def debug(self):
        DebugManager.d(str(['%s:%s' % item for item in self.__dict__.items()]))

    def update_local_pic_content(self, text):
        if self.local == 1:
            res_dir = os.path.join(self.out_dir, 'res')
            if not os.path.exists(res_dir):
                os.makedirs(res_dir)

            # 正则表达式提取 img 标签行
            img_urls = re.findall(r'<img src="(https://[^"]+)"[^>]*>', text)
            # 下载图片并保存到 res 目录，同时替换 img 标签行
            for img_url in img_urls:
                img_name = Utils.generate_md5(img_url) + "_" + img_url.split('/')[-1]
                if "." in img_name:
                    pass
                else:
                    img_name = img_name + ".png"
                img_name = Utils.rename_image_if_needed(img_name)
                img_path = os.path.join(res_dir, img_name)
                # 下载图片
                response = requests.get(img_url)
                with open(img_path, 'wb') as file:
                    file.write(response.content)

                # 替换 img 标签行
                img_md = f'![](res/{img_name})'
                text = re.sub(rf'<img src="{img_url}"[^>]*>', img_md, text)

            return text
        else:
            return text

    def metadata(self, title, url):
        data = "---\n"
        data += "title: {}\n".format(title)
        data += "date: {}\n".format(time.strftime("%Y-%m-%d", time.localtime()))
        data += "reference:\n"
        data += "  - {}\n".format(url)
        data += "---\n"
        return data

    def spider_article(self, url):
        # 创建目录
        if not os.path.exists(self.out_dir):
            os.makedirs(self.out_dir)

        html = requests.get(url=url, headers=self.headers).text
        page = parsel.Selector(html)
        # 创建解释器
        title = page.css(".title-article::text").get()
        content = page.css("article").get()
        content = re.sub("<a.*?a>", "", content)
        content = re.sub("<br>", "", content)
        content = re.sub("&lt;", "<", content)  # 新增
        content = re.sub("&gt;", ">", content)  # 新增
        # import tomd
        # text = tomd.Tomd(content).markdown
        text = Tomd(content).markdown
        text = self.update_local_pic_content(text)

        # 解决文件名包含特殊字符导致无法读写问题
        file_path = os.path.join(self.out_dir, "{}.md".format(re.sub(r'[\/:：*?"<>|\n]', '-', title)))
        with open(file_path, mode="w", encoding="utf-8") as f:
            f.write(self.metadata(title, url))
            f.write(text)


class Options(object):
    # url = "{input_user_name}"
    # url = "https://blog.csdn.net/{input_user_name}/"
    # url = "https://blog.csdn.net/{input_user_name}/article/details/{input_article_id}"
    url = None
    local = 0
    out = os.path.join(os.getcwd(), "csdn")
    debug = 1
    # 打开 https://blog.csdn.net/用户名
    # 右键 “检查”
    # 选择 Network
    # 点击 name 是 blog.csdn.net 选项（可能是别的）
    # 找到 Request Headers
    cookie = None


def parseargs(opt):
    """
    解析命令行参数
    """
    parser = argparse.ArgumentParser(description="download csdn article")
    parser.add_argument("--url", dest="url",
                        help="可输入用户名、用户主页爬全部文章；也可输入单篇文章链接爬此文章", default=opt.url)
    parser.add_argument("--local", dest="local",
                        help="local picture", default=opt.local)
    parser.add_argument("--out", dest="out",
                        help="out dir", default=opt.out)

    return parser.parse_args()


def work(opt):
    csdn = CSDN(opt.url, opt.local, opt.out)
    csdn.start()
    csdn.process()


def main():
    opt = Options()
    args = parseargs(opt)
    opt.url = args.url
    opt.local = args.local
    opt.out = args.out

    DebugManager.create_logger("DEBUG" if opt.debug else "ERROR")
    if opt.url is None:
        DebugManager.e("未输入 url")
        return 0

    work(opt)

    return 0


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        exit()
