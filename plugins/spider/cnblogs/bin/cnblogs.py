#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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

# Standard library imports
import argparse
import hashlib
import logging
import os
import re
import signal
import time

from concurrent.futures import TimeoutError
from enum import Enum
from functools import wraps
from logging import getLogger, Logger, StreamHandler
from urllib.parse import urlparse

# Third-party library imports
import requests
from bs4 import BeautifulSoup


def timeout(seconds=10):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            def _handle_timeout(signum, frame):
                raise TimeoutError(f"Function {func.__name__} took too long to execute.")

            old_handler = signal.signal(signal.SIGALRM, _handle_timeout)
            signal.alarm(seconds)
            try:
                return func(*args, **kwargs)
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old_handler)

        return wrapper

    return decorator


class Markdownify:
    from markdownify import MarkdownConverter

    def __init__(self, html):
        self.html = self.remove_elements(html, [r'<span.*?>', r'</span>', r'<div.*?>', r'</div>'])

    def remove_elements(self, html, elements):
        for element in elements:
            html = re.sub(element, '', html, flags=re.DOTALL)
        return html

    class CustomMarkdownConverter(MarkdownConverter):

        def convert_img(self, el, text, convert_as_inline):
            src = el.get('data-original-src') or el.get('src')
            alt = el.get('alt', '')
            title = el.get('title', '')

            if src.startswith('//'):
                src = 'https:' + src

            return f'![{alt}]({src})'

        def convert_a(self, el, text, convert_as_inline):
            if el.find('img') is not None:
                return text
            else:
                href = el.get('href', '')
                if href.startswith('//'):
                    href = 'https:' + href
                return f'[{text}]({href})'

        def escape(self, text):
            return text

    @property
    def markdown(self):
        return self.CustomMarkdownConverter().convert(self.html)


class Utils:
    @staticmethod
    def is_valid_url(url):
        result = urlparse(url)
        return all([result.scheme, result.netloc])

    @staticmethod
    def is_user_homepage_or_article(url):
        if url.startswith('https://www.cnblogs.com/'):
            splits = url.split('/')
            if len(splits) <= 4:
                user_name = splits[3].split('?')[0]
                return user_name, Flags.ALL
            else:
                user_name = splits[3]
                return user_name, Flags.SINGLE
        else:
            return "", Flags.ERROR

    @staticmethod
    def generate_md5(input_string):
        return hashlib.md5(input_string.encode()).hexdigest()

    @staticmethod
    def rename_image_if_needed(filename):
        return filename.split('#')[0]

    @staticmethod
    def sanitize_filename(title):
        """
        Sanitize the given title to be used as a valid filename in Windows, replacing '[' with '<' and ']' with '>'.

        Args:
            title (str): The original title string.

        Returns:
            str: A sanitized title with specific replacements for '[' and ']'.
        """
        # Replace '[' with '(' and ']' with ')'
        title = title.replace('[', '(').replace(']', ')')

        # Define a pattern to match all other invalid characters except '(' and ')'
        invalid_chars_pattern = r'[\\/:*?"|]'

        # Replace other invalid characters with '-'
        sanitized_title = re.sub(invalid_chars_pattern, '-', title)

        # Strip leading or trailing whitespace that might result in invalid filenames
        sanitized_title = sanitized_title.strip()

        return sanitized_title


class DebugManager:
    _COLOR_RESET = "\u001B[0m"
    _COLOR_RED = "\u001B[31m"
    _COLOR_GREEN = "\u001B[32m"
    _COLOR_BLUE = "\u001B[34m"
    _COLOR_YELLOW = "\u001B[33m"

    _logger: Logger

    @staticmethod
    def create_logger(level: int):
        DebugManager._logger = getLogger(__name__)
        DebugManager._logger.setLevel(level)
        DebugManager._logger.addHandler(StreamHandler())

    @staticmethod
    def _process_template(message: str) -> str:
        date = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        return f"[{date}] {message}"

    @staticmethod
    def i(message: str):
        message = DebugManager._process_template(message)
        DebugManager._logger.info(f"{DebugManager._COLOR_GREEN}{message}{DebugManager._COLOR_RESET}")

    @staticmethod
    def d(message: str):
        message = DebugManager._process_template(message)
        DebugManager._logger.debug(f"{DebugManager._COLOR_BLUE}{message}{DebugManager._COLOR_RESET}")

    @staticmethod
    def w(message: str):
        message = DebugManager._process_template(message)
        DebugManager._logger.warning(f"{DebugManager._COLOR_YELLOW}{message}{DebugManager._COLOR_RESET}")

    @staticmethod
    def e(message: str):
        message = DebugManager._process_template(message)
        DebugManager._logger.error(message)


class Flags(Enum):
    ERROR = -1
    SINGLE = 0
    ALL = 1


class MetadataGenerator:
    def metadata(self, title, url, date, tags):
        """生成Markdown格式的元数据。

        Args:
            title (str): 文章标题。
            url (str): 参考链接。
            date (str): 文章时间。
            tags (list): 标签列表。

        Returns:
            str: 生成的Markdown格式的元数据字符串。
        """
        data = "---\n"
        data += f"title: {title}\n"
        data += f"date: {date}\n"

        if tags:
            data += "tags:\n"
            for tag in tags:
                data += f"  - {tag}\n"

        data += f"reference:\n  - {url}\n---\n\n"
        return data


class CNBlogs:
    def __init__(self, url, local, out_dir, cookie=None):
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
        self.task_queue = list()
        self.metadata_generator = MetadataGenerator()

        self.debug()

    def get_headers(self, cookie):
        request_headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7',
            'Connection': 'keep-alive',
            'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                           'AppleWebKit/537.36 (KHTML, like Gecko) '
                           'Chrome/67.0.3396.62 Safari/537.36'),
        }
        if cookie is not None:
            request_headers["Cookie"] = cookie

        return request_headers

    def start(self):
        if self.flags == Flags.ALL:
            page_num = 0
            articles = [None]
            while articles:
                page_num += 1
                url = f'https://www.cnblogs.com/{self.username}?page={page_num}'
                response = self.session.get(url=url, headers=self.headers)
                html = response.text
                soup = BeautifulSoup(html, "html.parser")
                articles = soup.find_all('div', class_='postTitle')

                for article in articles:
                    title_span = article.find('span')
                    if title_span:
                        article_title = title_span.get_text(strip=True)
                        article_href = article.find('a')['href']
                        self.task_queue.append((article_title, article_href))

        elif self.flags == Flags.SINGLE:
            self.task_queue.append((None, self.url))
        else:
            DebugManager.e("解析url错误，请输入正确的url")

    def process(self):
        total_size = len(self.task_queue)
        while self.task_queue:
            article_title, article_href = self.task_queue.pop()
            current_size = total_size - len(self.task_queue)
            DebugManager.i(f"正在处理 {current_size}/{total_size}, url = {article_href}")
            self.spider_article(article_href, article_title)

    def spider_article(self, url, title=None):
        if not os.path.exists(self.out_dir):
            os.makedirs(self.out_dir, exist_ok=True)

        html = requests.get(url=url, headers=self.headers).text
        soup = BeautifulSoup(html, 'html.parser')

        if title is None:
            title = soup.find('h1', class_='postTitle').get_text(strip=True)

        if title is None:
            DebugManager.e("No <h1> tag with title attribute found")
            return

        content = soup.find('div', id='cnblogs_post_body')
        content = str(content) if content else None

        if content is None:
            DebugManager.e("No <cnblogs_post_body> id found")
            with open(os.path.join(self.out_dir, "error.txt"), mode="a", encoding="utf-8") as f:
                f.write(f"\"{url}\"\n")
            return

        tags = self.extract_tags(soup)
        # 查找 id 为 "post-date" 的 span 标签，并获取其文本内容
        span_tag = soup.find('span', id='post-date')
        date_text = span_tag.get_text(strip=True)

        try:
            title = Utils.sanitize_filename(title)
            text = self.content2markdown(content)
            file_path = os.path.join(self.out_dir, "{}.md".format(title))
            DebugManager.i(f"{file_path}\n")
            with open(file_path, mode="w", encoding="utf-8") as f:
                f.write(self.metadata_generator.metadata(title, url, date_text, tags))
                f.write(text)
        except Exception as e:
            DebugManager.e(f"Error processing {url}: {str(e)}")
            file_path = os.path.join(self.out_dir, "ERROR-{}.md".format(re.sub(r'[/:：*?"<>|\n]', '-', title)))
            with open(file_path, mode="w", encoding="utf-8") as f:
                f.write(f"{url}\n\n")
                f.write(content)

    def extract_tags(self, soup):
        """从HTML中提取标签."""
        meta_tag = soup.find('meta', {'name': 'keywords'})
        if meta_tag and 'content' in meta_tag.attrs:
            return [tag.strip() for tag in meta_tag['content'].split(',')]
        return []

    @timeout(10)
    def content2markdown(self, content):
        return Markdownify(content).markdown

    def debug(self):
        DebugManager.d(str([f'{k}:{v}' for k, v in self.__dict__.items()]))


class Options:
    # url = "{input_user_name}"
    # url = "https://www.cnblogs.com/{input_user_name}/"
    # url = "https://www.cnblogs.com/{input_user_name}/p/{input_article_id}"
    url = None
    local = 0
    out = os.path.join(os.getcwd(), "cnblogs")
    debug = 1
    cookie = None


def parseargs(opt):
    parser = argparse.ArgumentParser(description="Download CNBlogs articles")
    parser.add_argument("--url", dest="url",
                        help="Enter username to crawl all articles from user homepage; or input single article link to crawl that article",
                        default=opt.url)
    parser.add_argument("--local", dest="local",
                        help="Local picture", default=opt.local)
    parser.add_argument("--out", dest="out",
                        help="Output directory", default=opt.out)

    return parser.parse_args()


def work(opt):
    cnblogs = CNBlogs(opt.url, opt.local, opt.out)
    cnblogs.start()
    cnblogs.process()


def check_and_install_library():
    try:
        import markdownify
        return 1
    except ImportError:
        DebugManager.e("markdownify 未安装，请使用命令：pip install markdownify 进行安装")
        return -1


def main():
    opt = Options()
    args = parseargs(opt)
    opt.url = args.url
    opt.local = args.local
    opt.out = args.out

    DebugManager.create_logger(logging.DEBUG if opt.debug else logging.ERROR)
    if opt.url is None:
        DebugManager.e("未输入 url")
        return 0

    if check_and_install_library() < 0:
        return 0

    work(opt)

    return 0


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        exit()
