#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2020 anqi.huang@outlook.com
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

class BotIssue:
    comment = ""
    commentAuthor = ""
    level = ""
    di = 0
    assignee = "Unknown"

    def __init__(self, base_url, issue):
        # 单号
        self.issue = issue.key
        # 网站
        self.link = base_url + "browse/" + issue.key
        # 标题
        self.title = issue.fields.summary
        # bug描述
        self.description = issue.fields.description
        # 分配到任务的人
        try:
            self.assignee = issue.fields.assignee.displayName.replace('BP', '')
        except:
            pass
        # 状态
        self.status = issue.fields.status
        if "SR" in self.issue or "JUIXIII" in self.issue:
            print("需求")
        else:
            try:
                # 严重程度
                if issue.fields.customfield_15121 != None:
                    self.level = issue.fields.customfield_15121.value
                    if "致命" == self.level:
                        self.di = 10
                    elif "严重" == self.level:
                        self.di = 3
                    elif "一般" == self.level:
                        self.di = 1
                    elif "提示" == self.level:
                        self.di = 0.1

            except:
                pass

            try:
                # 修改方案
                if issue.fields.customfield_15111 != None:
                    self.modification = issue.fields.customfield_15111
            except:
                pass

            try:
                # 原因分析
                if issue.fields.customfield_15115 != None:
                    self.reason_analysis = issue.fields.customfield_15115
            except:
                pass

            try:
                # 测试建议
                if issue.fields.customfield_16206 != None:
                    self.test_suggestion = issue.fields.customfield_16206
            except:
                pass

            try:
                # 自测结果
                if issue.fields.customfield_15502 != None:
                    self.test_result = issue.fields.customfield_15502
            except:
                pass

            try:
                # 回归失败次数
                if issue.fields.customfield_17402 != None:
                    self.fix_fail_count = issue.fields.customfield_17402
            except:
                pass

            try:
                # 审核失败次数
                if issue.fields.customfield_17403 != None:
                    self.check_fail_count = issue.fields.customfield_17403
            except:
                pass

        try:
            # 备注(只关心：包含"=>问题"，"=>解法"的评论)
            for comment in issue.fields.comment.comments:
                if "=>问题" in comment.body or "=> 问题" in comment.body or "=>解法" in comment.body or "=> 解法" in comment.body:
                    self.comment = comment.body
                    self.commentAuthor = comment.author.displayName.replace('BP', '')
        except:
            pass

    def __getitem__(self, key):
        return getattr(self, key)

    def __str__(self):
        print(['%s:%s' % item for item in self.__dict__.items()])
