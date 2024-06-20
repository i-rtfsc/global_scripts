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
            # 获取图像的src、alt和title
            src = el.get('data-original-src') or el.get('src')
            alt = el.get('alt', '')
            title = el.get('image-caption', alt)

            # 确保src是绝对URL
            if src.startswith('//'):
                src = 'https:' + src

            return f'![{alt}]({src})'

        # Markdownify默认行为：
        # 下划线前默认加斜杠，比如 a_b 就默认 a\_b
        # 加上这个能改掉这些默认行为
        def escape(self, text):
            return text  # 覆盖默认的转义行为

    @property
    def markdown(self):
        return self.CustomMarkdownConverter().convert(self.html)
        # from markdownify import markdownify as md
        # return md(self.html)


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
        if url.startswith('https://www.jianshu.com/u/'):
            user_name = url.split('/')[4].split('?')[0]
            return user_name, Flags.ALL
        elif url.startswith('https://www.jianshu.com/p/'):
            return "", Flags.SINGLE
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

    _logger: Logger

    @staticmethod
    def create_logger(level: int):
        DebugManager._logger = getLogger(__name__)
        DebugManager._logger.setLevel(level)
        DebugManager._logger.addHandler(StreamHandler())

    @staticmethod
    def _process_template(message: str) -> str:
        # if DebugManager._DATE_TEMPLATE in kwargs:
        #     kwargs[
        #         DebugManager._DATE_TEMPLATE] = f"{datetime.strftime(kwargs[DebugManager._DATE_TEMPLATE], '%d-%m-%Y %H:%M:%S:%f')}"
        #
        # return Template(message).substitute(kwargs)
        date = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        return "[" + date + "] " + message

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


class JianShu(object):
    def __init__(self, url, local, out_dir, cookie=None):
        """
        :param url:
            1. 输入： https://www.jianshu.com/u/{用户名}?order_by=shared_at ，则获取该用户所有文章
            2. 输入： https://www.jianshu.com/p/xxx ，则单篇文章
            3. 输入： 用户 （等同于 https://www.jianshu.com/u/用户名 ）
        """
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

        # self.out_dir = os.path.join(out_dir, self.username)
        self.out_dir = out_dir
        self.local = local

        self.session = requests.Session()
        self.TaskQueue = list()

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
            self.TaskQueue.append((None, self.url))
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
        # 或者webdriver.Firefox(), webdriver.Edge()等
        driver = webdriver.Chrome(options=chrome_options)

        end_time = time.time()
        elapsed_time = end_time - start_time
        hours, rem = divmod(elapsed_time, 3600)
        minutes, seconds = divmod(rem, 60)
        DebugManager.d(f"open webdriver耗时: {int(hours)}小时 {int(minutes)}分钟 {seconds:.2f}秒")

        try:
            # 打开目标网页
            driver.get(url=self.url)

            # 设置滚动暂停时间
            SCROLL_PAUSE_TIME = 2
            # 获取页面高度
            last_height = driver.execute_script("return document.body.scrollHeight")
            while True:
                # 向下滚动到页面底部
                driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                # 等待页面加载
                time.sleep(SCROLL_PAUSE_TIME)
                # 计算新的页面高度并与上次的页面高度进行比较
                new_height = driver.execute_script("return document.body.scrollHeight")
                if new_height == last_height:
                    break
                last_height = new_height

            # 获取滚动后页面的HTML内容
            html = driver.page_source
            soup = BeautifulSoup(html, "lxml")
            articles = soup.find_all('li', class_='have-img') + soup.find_all('li', class_='')

            # 提取标题及其对应的链接
            for article in articles:
                title_tag = article.find('a', class_='title')
                if title_tag:
                    title = title_tag.text.strip()
                    href = title_tag['href']
                    url = f'https://www.jianshu.com{href}'
                    self.TaskQueue.append((title, url))

        finally:
            # 关闭浏览器
            driver.quit()

    def process(self):
        size = len(self.TaskQueue)
        while len(self.TaskQueue) > 0:
            (article_title, article_href) = self.TaskQueue.pop()
            current_size = size - len(self.TaskQueue)
            DebugManager.i("正在处理 {}/{} , url = {}".format(str(current_size), str(size), article_href))
            self.spider_article(article_href, article_title)

    def spider_article(self, url, title=None):
        response = self.session.get(url=url, headers=self.headers)
        html_content = response.text

        user_id_match = re.search(r'href="/u/([0-9a-fA-F]+)"', html_content)
        username_match = re.search(r'<span class="_22gUMi">(.*?)</span>', html_content)
        if user_id_match and username_match:
            # 用户ID
            self.username = user_id_match.group(1)
            # 用户昵称
            username = username_match.group(1)
            # 用户昵称可能会变，用户ID是不变的
            out_dir = os.path.join(self.out_dir, self.username)
        else:
            out_dir = self.out_dir

        # 创建目录
        if not os.path.exists(out_dir):
            os.makedirs(out_dir)

        if title is None:
            pattern = re.compile(r'<h1[^>]*title="([^"]*)"', re.DOTALL)
            match = pattern.search(html_content)
            if match:
                title = match.group(1)
            else:
                title = None

        if title is None:
            DebugManager.e("No <h1> tag with title attribute found")
            return

        pattern = re.compile(r'<article[^>]*>(.*?)</article>', re.DOTALL)
        match = pattern.search(html_content)
        if match:
            article_content = match.group(1)
        else:
            article_content = None

        if article_content is None:
            DebugManager.e("No <article> tag found")
            with open(os.path.join(self.out_dir, "error.txt"), mode="a", encoding="utf-8") as f:
                f.write("\"" + url + "\"")
                f.write("\n")
            return

        try:
            text = self.content2markdown(article_content)
            # 解决文件名包含特殊字符导致无法读写问题
            file_path = os.path.join(out_dir, "{}.md".format(re.sub(r'[\/:：*?"<>|\n]', '-', title)))
            DebugManager.i(f"{file_path}\n")
            with open(file_path, mode="w", encoding="utf-8") as f:
                f.write(self.metadata(title, url))
                f.write(text)
        except TimeoutError:
            DebugManager.e(f"content to markdown timed out for {url}")
            # 转化成 md 超时，直接保存 html 格式
            file_path = os.path.join(out_dir, "ERROR-{}.md".format(re.sub(r'[\/:：*?"<>|\n]', '-', title)))
            with open(file_path, mode="w", encoding="utf-8") as f:
                f.write(url)
                f.write("\n\n")
                f.write(article_content)

    @timeout(10)
    def content2markdown(self, content):
        return Markdownify(content).markdown

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
        data += "---\n\n"
        return data

    def debug(self):
        DebugManager.d(str(['%s:%s' % item for item in self.__dict__.items()]))


class Options(object):
    # url = "{input_user_name}"
    # url = "https://www.jianshu.com/u/{input_user_name}"
    # url = "https://www.jianshu.com/u/{input_user_name}?order_by=shared_at"
    url = None
    local = 0
    out = os.path.join(os.getcwd(), "jianshu")
    debug = 1
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
    csdn = JianShu(opt.url, opt.local, opt.out)
    csdn.start()
    csdn.process()


def check_and_install_library():
    try:
        import selenium
        import markdownify
        return 1
    except ImportError as e:
        DebugManager.e(f"{e.name} 未安装，请使用命令：pip install {e.name} 进行安装, ", )
        # subprocess.check_call([sys.executable, "-m", "pip", "install", "selenium"])
        # subprocess.check_call([sys.executable, "-m", "pip", "install", "markdownify"])
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
