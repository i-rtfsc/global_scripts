"""
System Repo Subplugin
- Android Repo 源管理
- 通过 REPO_URL 环境变量控制 repo 工具的源地址
"""

import sys
import os
from pathlib import Path
from typing import List

# Ensure project root on sys.path
project_root = Path(__file__).resolve().parents[3]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from gscripts.plugins.decorators import plugin_function, subplugin
from gscripts.plugins.base import BasePlugin
from gscripts.core.config_manager import CommandResult


@subplugin("repo")
class SystemRepoSubplugin(BasePlugin):
    def __init__(self):
        self.name = "repo"
        self.parent_plugin = "system"
        self.repo_sources = {
            "google": {
                "name": "Google 官方源",
                "url": "https://gerrit.googlesource.com/git-repo"
            },
            "intel": {
                "name": "Intel 镜像源",
                "url": "https://gerrit.intel.com/git-repo"
            },
            "tsinghua": {
                "name": "清华大学镜像源",
                "url": "https://mirrors.tuna.tsinghua.edu.cn/git/git-repo"
            }
        }

    def _set_repo_url(self, source_key: str) -> CommandResult:
        """设置Repo源URL"""
        if source_key not in self.repo_sources:
            return CommandResult(success=False, error=f"未知的Repo源: {source_key}")

        try:
            source = self.repo_sources[source_key]

            # 先取消设置现有的REPO_URL
            if "REPO_URL" in os.environ:
                del os.environ["REPO_URL"]

            # 设置新的REPO_URL
            os.environ["REPO_URL"] = source["url"]

            return CommandResult(
                success=True,
                output=f"✅ 已切换到 {source['name']}\n🔗 REPO_URL: {source['url']}"
            )

        except Exception as e:
            return CommandResult(success=False, error=f"设置Repo源失败: {str(e)}")

    @plugin_function(
        name="status",
        description={"zh": "查看当前Repo源配置", "en": "Show current repo source configuration"},
        usage="gs system repo status",
        examples=["gs system repo status"],
    )
    async def status(self, args: List[str] = None) -> CommandResult:
        """查看当前Repo源配置"""
        current_url = os.environ.get("REPO_URL")

        if current_url:
            # 查找匹配的源
            matched_source = None
            for key, source in self.repo_sources.items():
                if source["url"] == current_url:
                    matched_source = f"{source['name']} ({key})"
                    break

            if matched_source:
                status_text = f"🌐 当前Repo源: {matched_source}\n🔗 REPO_URL: {current_url}"
            else:
                status_text = f"🌐 当前Repo源: 自定义源\n🔗 REPO_URL: {current_url}"

            return CommandResult(success=True, output=status_text)
        else:
            return CommandResult(success=True, output="🚫 未设置REPO_URL，将使用默认源")

    @plugin_function(
        name="google",
        description={"zh": "切换到Google官方源", "en": "Switch to Google official source"},
        usage="gs system repo google",
        examples=["gs system repo google"],
    )
    async def google(self, args: List[str] = None) -> CommandResult:
        """切换到Google官方源"""
        return self._set_repo_url("google")

    @plugin_function(
        name="intel",
        description={"zh": "切换到Intel镜像源", "en": "Switch to Intel mirror"},
        usage="gs system repo intel",
        examples=["gs system repo intel"],
    )
    async def intel(self, args: List[str] = None) -> CommandResult:
        """切换到Intel镜像源"""
        return self._set_repo_url("intel")

    @plugin_function(
        name="tsinghua",
        description={"zh": "切换到清华大学镜像源", "en": "Switch to Tsinghua mirror"},
        usage="gs system repo tsinghua",
        examples=["gs system repo tsinghua"],
    )
    async def tsinghua(self, args: List[str] = None) -> CommandResult:
        """切换到清华大学镜像源"""
        return self._set_repo_url("tsinghua")
