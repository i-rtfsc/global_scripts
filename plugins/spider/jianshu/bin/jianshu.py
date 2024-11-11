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
    """Decorator to timeout a function after a specified number of seconds."""
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
            title = el.get('image-caption', alt)

            if src.startswith('//'):
                src = 'https:' + src

            return f'![{alt}]({src})'

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
        """
        Determine if the URL is a user's homepage or a single article.
        Returns:
            tuple: (username, flag) where flag is 1 for single article, 2 for all articles, -1 for error
        """
        if url.startswith('https://www.jianshu.com/u/'):
            user_name = url.split('/')[4].split('?')[0]
            return user_name, Flags.ALL
        elif url.startswith('https://www.jianshu.com/p/'):
            return "", Flags.SINGLE
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
        Sanitize the given title to be used as a valid filename in Windows.

        Args:
            title (str): The original title string.

        Returns:
            str: A sanitized title with invalid characters replaced by '-'.
        """
        # Define a pattern to match all invalid characters
        invalid_chars_pattern = r'[\\/:"*?<>|]'

        # Replace invalid characters with '-'
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


class JianShu:
    def __init__(self, url, local, out_dir, cookie=None):
        if Utils.is_valid_url(url):
            self.username, self.flags = Utils.is_user_homepage_or_article(url)
        else:
            self.username = url
            self.flags = Flags.ALL

        if self.flags == Flags.ALL:
            self.url = f'https://www.jianshu.com/u/{self.username}?order_by=shared_at'
        elif self.flags == Flags.SINGLE:
            self.url = url

        self.headers = self.get_headers(cookie)
        self.out_dir = os.path.join(out_dir, self.username or '')
        self.local = local
        self.session = requests.Session()
        self.task_queue = list()

        self.debug()

    def get_headers(self, cookie):
        request_headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7',
            'Connection': 'keep-alive',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.62 Safari/537.36',
            'Host': 'www.jianshu.com',
            "X-Requested-With": 'XMLHttpRequest'
        }
        if cookie is not None:
            request_headers["Cookie"] = cookie

        return request_headers

    def start(self):
        if self.flags == Flags.ALL:
            self.open_webdriver()
        elif self.flags == Flags.SINGLE:
            self.task_queue.append((None, self.url))
        else:
            DebugManager.e("解析url错误，请输入正确的url")

    def open_webdriver(self):
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options

        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        prefs = {"profile.managed_default_content_settings.images": 2}
        chrome_options.add_experimental_option("prefs", prefs)

        start_time = time.time()
        driver = webdriver.Chrome(options=chrome_options)

        end_time = time.time()
        elapsed_time = end_time - start_time
        hours, rem = divmod(elapsed_time, 3600)
        minutes, seconds = divmod(rem, 60)
        DebugManager.d(f"open webdriver耗时: {int(hours)}小时 {int(minutes)}分钟 {seconds:.2f}秒")

        try:
            driver.get(url=self.url)

            SCROLL_PAUSE_TIME = 2
            last_height = driver.execute_script("return document.body.scrollHeight")
            while True:
                driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                time.sleep(SCROLL_PAUSE_TIME)
                new_height = driver.execute_script("return document.body.scrollHeight")
                if new_height == last_height:
                    break
                last_height = new_height

            html = driver.page_source
            soup = BeautifulSoup(html, "lxml")
            articles = soup.find_all('li', class_='have-img') + soup.find_all('li', class_='')

            for article in articles:
                title_tag = article.find('a', class_='title')
                if title_tag:
                    title = title_tag.text.strip()
                    href = title_tag['href']
                    url = f'https://www.jianshu.com{href}'
                    self.task_queue.append((title, url))

        finally:
            driver.quit()

    def process(self):
        total_size = len(self.task_queue)
        while self.task_queue:
            article_title, article_href = self.task_queue.pop()
            current_size = total_size - len(self.task_queue)
            DebugManager.i(f"正在处理 {current_size}/{total_size} , url = {article_href}")
            self.spider_article(article_href, article_title)

    def spider_article(self, url, title=None):
        response = self.session.get(url=url, headers=self.headers)
        html_content = response.text

        user_id_match = re.search(r'href="/u/([0-9a-fA-F]+)"', html_content)
        username_match = re.search(r'<span class="_22gUMi">(.*?)</span>', html_content)
        if user_id_match and username_match:
            self.username = user_id_match.group(1)
            username = username_match.group(1)
            out_dir = os.path.join(self.out_dir, self.username)
        else:
            out_dir = self.out_dir

        if not os.path.exists(out_dir):
            os.makedirs(out_dir, exist_ok=True)

        if title is None:
            title_match = re.search(r'<h1[^>]*title="([^"]*)"', html_content)
            title = title_match.group(1) if title_match else None

        if title is None:
            DebugManager.e("No <h1> tag with title attribute found")
            return

        article_match = re.search(r'<article[^>]*>(.*?)</article>', html_content, re.DOTALL)
        article_content = article_match.group(1) if article_match else None

        if article_content is None:
            DebugManager.e("No <article> tag found")
            with open(os.path.join(self.out_dir, "error.txt"), mode="a", encoding="utf-8") as f:
                f.write(f"\"{url}\"\n")
            return

        try:
            text = self.content2markdown(article_content)
            file_path = os.path.join(out_dir, "{}.md".format(Utils.sanitize_filename(title)))
            DebugManager.i(f"{file_path}\n")
            with open(file_path, mode="w", encoding="utf-8") as f:
                f.write(self.metadata(title, url))
                f.write(text)
        except TimeoutError:
            DebugManager.e(f"content to markdown timed out for {url}")
            file_path = os.path.join(out_dir, "ERROR-{}.md".format(re.sub(r'[\/:：*?"<>|\n]', '-', title)))
            with open(file_path, mode="w", encoding="utf-8") as f:
                f.write(f"{url}\n\n")
                f.write(article_content)

    @timeout(10)
    def content2markdown(self, content):
        return Markdownify(content).markdown

    def update_local_pic_content(self, text):
        if self.local == 1:
            res_dir = os.path.join(self.out_dir, 'res')
            if not os.path.exists(res_dir):
                os.makedirs(res_dir, exist_ok=True)

            img_urls = re.findall(r'<img src="(https://[^"]+)"[^>]*>', text)
            for img_url in img_urls:
                img_name = Utils.generate_md5(img_url) + "_" + img_url.split('/')[-1]
                if "." not in img_name:
                    img_name += ".png"
                img_name = Utils.rename_image_if_needed(img_name)
                img_path = os.path.join(res_dir, img_name)
                response = requests.get(img_url)
                with open(img_path, 'wb') as file:
                    file.write(response.content)

                img_md = f'![](res/{img_name})'
                text = re.sub(rf'<img src="{img_url}"[^>]*>', img_md, text)

            return text
        else:
            return text

    def metadata(self, title, url):
        data = "---\n"
        data += f"title: {title}\n"
        data += f"date: {time.strftime('%Y-%m-%d', time.localtime())}\n"
        data += f"reference:\n  - {url}\n---\n\n"
        return data

    def debug(self):
        DebugManager.d(str([f'{k}:{v}' for k, v in self.__dict__.items()]))


class Options:
    # url = "{input_user_name}"
    # url = "https://www.jianshu.com/u/{input_user_name}"
    # url = "https://www.jianshu.com/u/{input_user_name}?order_by=shared_at"
    url = None
    local = 0
    out = os.path.join(os.getcwd(), "jianshu")
    debug = 1
    cookie = None


def parseargs(opt):
    parser = argparse.ArgumentParser(description="Download JianShu articles")
    parser.add_argument("--url", dest="url",
                        help="Enter username to crawl all articles from user homepage; or input single article link to crawl that article",
                        default=opt.url)
    parser.add_argument("--local", dest="local",
                        help="Local picture", default=opt.local)
    parser.add_argument("--out", dest="out",
                        help="Output directory", default=opt.out)

    return parser.parse_args()


def work(opt):
    jianshu = JianShu(opt.url, opt.local, opt.out)
    jianshu.start()
    jianshu.process()


def check_and_install_library():
    try:
        import selenium
        import markdownify
        return 1
    except ImportError as e:
        DebugManager.e(f"{e.name} 未安装，请使用命令：pip install {e.name} 进行安装")
        return -1


def main():
    opt = Options()
    args = parseargs(opt)
    opt.url = args.url
    opt.local = args.local
    opt.out = args.out

    DebugManager.create_logger(logging.DEBUG if opt.debug else logging.ERROR)
    if not opt.url:
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
