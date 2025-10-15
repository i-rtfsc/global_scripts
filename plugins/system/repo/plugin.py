"""
System Repo Subplugin
- Android Repo 源管理
- 通过 REPO_URL 环境变量控制 repo 工具的源地址
- 移植自 tmp/global_scripts-v2/plugins/repo/bin 的功能
"""

import sys
import os
import subprocess
from pathlib import Path
from typing import List, Dict, Tuple

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

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

    def _run_cmd(self, cmd: str, cwd: str = None) -> Tuple[int, str]:
        """执行命令并返回结果"""
        try:
            result = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)
            return result.returncode, result.stdout.strip() if result.stdout else ""
        except Exception as e:
            return 1, str(e)

    def _file_exists(self, filepath: str) -> bool:
        """检查文件是否存在"""
        return os.path.isfile(filepath) and os.path.exists(filepath)

    def _dir_exists(self, dirpath: str) -> bool:
        """检查目录是否存在"""
        return os.path.isdir(dirpath) and os.path.exists(dirpath)

    def _parse_project_list(self, filepath: str) -> List[str]:
        """解析项目列表文件"""
        projects = []
        try:
            with open(filepath, 'r') as f:
                for line in f.readlines():
                    project = line.strip()
                    if project:
                        projects.append(project)
        except Exception as e:
            print(f"Error parsing project list: {e}")
        return projects

    def _parse_manifest_branches(self, root_dir: str) -> Dict[str, str]:
        """解析manifest文件获取每个项目的分支信息"""
        project_branches = {}
        
        manifest_file = os.path.join(root_dir, ".repo/manifest.xml")
        if not self._file_exists(manifest_file):
            return project_branches

        try:
            tree = ET.parse(manifest_file)
            # 处理include标签
            for elem in tree.iterfind('include'):
                include_file = elem.attrib.get("name")
                if include_file:
                    project_file = os.path.join(root_dir, ".repo/manifests", include_file)
                    if self._file_exists(project_file):
                        project_tree = ET.parse(project_file)
                        
                        # 获取默认revision
                        global_revision = None
                        for default_elem in project_tree.iterfind('default'):
                            global_revision = default_elem.attrib.get("revision")
                        
                        # 解析每个项目
                        for project_elem in project_tree.iterfind('project'):
                            path = project_elem.attrib.get("path")
                            revision = project_elem.attrib.get("revision", global_revision)
                            if path and revision:
                                project_branches[path] = revision
        except Exception as e:
            print(f"Error parsing manifest: {e}")
        
        return project_branches

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
        name="sync",
        description={"zh": "同步repo项目（支持清理模式）", "en": "Sync repo projects with optional clean mode"},
        usage="gs system repo sync [clean]",
        examples=["gs system repo sync", "gs system repo sync clean"],
    )
    async def sync(self, args: List[str] = None) -> CommandResult:
        """同步repo项目"""
        args = args or []
        clean_mode = "clean" in args or "c" in args
        
        root_dir = os.getcwd()
        project_list_file = os.path.join(root_dir, ".repo/project.list")
        
        if not self._file_exists(project_list_file):
            return CommandResult(success=False, error="未找到 .repo/project.list 文件，请确保在repo工作目录中执行")
        
        projects = self._parse_project_list(project_list_file)
        if not projects:
            return CommandResult(success=False, error="项目列表为空")
        
        project_branches = self._parse_manifest_branches(root_dir)
        
        output_lines = []
        errors = []
        
        for project in projects:
            output_lines.append(f"开始同步项目: {project}")
            project_dir = os.path.join(root_dir, project)
            git_dir = os.path.join(project_dir, ".git")
            
            if not self._dir_exists(git_dir):
                output_lines.append(f"  跳过 {project}：不是git仓库")
                continue
            
            # 获取分支列表
            ret, branch_output = self._run_cmd("git branch --list | sed 's/*//g'", project_dir)
            if ret != 0:
                errors.append(f"项目 {project} 获取分支列表失败: {branch_output}")
                continue
            
            # 同步每个分支
            for line in branch_output.splitlines():
                branch = line.strip()
                if not branch:
                    continue
                
                output_lines.append(f"  同步分支: {project}/{branch}")
                
                # 切换到分支
                ret, _ = self._run_cmd(f"git checkout {branch}", project_dir)
                if ret != 0:
                    continue
                
                # 清理或重置
                if clean_mode:
                    self._run_cmd("git clean -dfx", project_dir)
                    self._run_cmd("git reset --hard", project_dir)
                else:
                    self._run_cmd("git checkout .", project_dir)
                
                # 拉取更新
                ret, pull_output = self._run_cmd("git pull --rebase", project_dir)
                if ret != 0:
                    errors.append(f"  {project}/{branch} 拉取失败: {pull_output}")
            
            # 切换回默认分支
            default_branch = project_branches.get(project)
            if default_branch:
                self._run_cmd(f"git checkout {default_branch}", project_dir)
        
        result_output = "\n".join(output_lines)
        if errors:
            result_output += "\n\n错误:\n" + "\n".join(errors)
            return CommandResult(success=False, error=result_output)
        
        return CommandResult(success=True, output=result_output)

    @plugin_function(
        name="checkout",
        description={"zh": "为repo项目创建所有远程分支", "en": "Checkout all remote branches for repo projects"},
        usage="gs system repo checkout",
        examples=["gs system repo checkout"],
    )
    async def checkout(self, args: List[str] = None) -> CommandResult:
        """为repo项目创建所有远程分支"""
        root_dir = os.getcwd()
        project_list_file = os.path.join(root_dir, ".repo/project.list")
        
        if not self._file_exists(project_list_file):
            return CommandResult(success=False, error="未找到 .repo/project.list 文件，请确保在repo工作目录中执行")
        
        projects = self._parse_project_list(project_list_file)
        if not projects:
            return CommandResult(success=False, error="项目列表为空")
        
        project_branches = self._parse_manifest_branches(root_dir)
        
        output_lines = []
        errors = []
        
        for project in projects:
            output_lines.append(f"开始检出项目: {project}")
            project_dir = os.path.join(root_dir, project)
            git_dir = os.path.join(project_dir, ".git")
            
            if not self._dir_exists(git_dir):
                output_lines.append(f"  跳过 {project}：不是git仓库")
                continue
            
            # 获取远程分支
            ret, remote_output = self._run_cmd("git branch -r", project_dir)
            if ret != 0:
                errors.append(f"项目 {project} 获取远程分支失败: {remote_output}")
                continue
            
            # 为每个origin分支创建本地分支
            for line in remote_output.splitlines():
                branch_info = line.strip()
                if "origin" not in branch_info:
                    continue
                
                parts = branch_info.split("/")
                if len(parts) >= 2 and parts[0] == "origin":
                    remote_name = parts[0]
                    branch_name = parts[1]
                    
                    output_lines.append(f"  创建分支: {project}/{branch_name}")
                    cmd = f"git checkout -b {branch_name} {branch_info}"
                    self._run_cmd(cmd, project_dir)
            
            # 切换回默认分支
            default_branch = project_branches.get(project)
            if default_branch:
                self._run_cmd(f"git checkout {default_branch}", project_dir)
        
        result_output = "\n".join(output_lines)
        if errors:
            result_output += "\n\n错误:\n" + "\n".join(errors)
            return CommandResult(success=False, error=result_output)
        
        return CommandResult(success=True, output=result_output)

    @plugin_function(
        name="mini",
        description={"zh": "同步mini-aosp.xml配置的项目", "en": "Sync projects defined in mini-aosp.xml"},
        usage="gs system repo mini [repo_sync_args]",
        examples=["gs system repo mini", "gs system repo mini -j4"],
    )
    async def mini(self, args: List[str] = None) -> CommandResult:
        """同步mini-aosp.xml配置的项目"""
        args = args or []
        sync_args = " ".join(args)
        
        root_dir = os.getcwd()
        mini_manifest = os.path.join(root_dir, "mini-aosp.xml")
        
        # 如果当前目录没有，尝试从家目录查找
        if not self._file_exists(mini_manifest):
            home_dir = str(Path.home())
            mini_manifest = os.path.join(home_dir, "code/github/.repo/manifests/mini-aosp.xml")
        
        if not self._file_exists(mini_manifest):
            return CommandResult(success=False, error="未找到 mini-aosp.xml 文件")
        
        try:
            tree = ET.parse(mini_manifest)
        except Exception as e:
            return CommandResult(success=False, error=f"解析 mini-aosp.xml 失败: {e}")
        
        output_lines = []
        errors = []
        
        for elem in tree.iterfind('project'):
            project_name = elem.attrib.get("name")
            if not project_name:
                continue
            
            cmd = f"repo sync {project_name} {sync_args}".strip()
            output_lines.append(f"执行: {cmd}")
            
            ret, output = self._run_cmd(cmd)
            if ret != 0:
                errors.append(f"同步 {project_name} 失败: {output}")
            else:
                output_lines.append(f"  {project_name} 同步完成")
        
        result_output = "\n".join(output_lines)
        if errors:
            result_output += "\n\n错误:\n" + "\n".join(errors)
            return CommandResult(success=False, error=result_output)
        
        return CommandResult(success=True, output=result_output)

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