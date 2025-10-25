"""
MultiRepo Plugin
- 多仓库管理工具
- 支持 repo 和 git clone 两种后端
- 灵活的 manifest 文件解析
"""

import sys
import os
import subprocess
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from enum import Enum

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

# Ensure project root on sys.path
project_root = Path(__file__).resolve().parents[2]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from gscripts.plugins.decorators import plugin_function
from gscripts.plugins.base import BasePlugin
from gscripts.core.config_manager import CommandResult
from gscripts.core.logger import get_logger

logger = get_logger(tag="PLUGIN.MULTIREPO", name=__name__)


class BackendMode(Enum):
    """后端模式枚举"""
    REPO = "repo"  # 使用 repo 命令
    GIT = "git"    # 使用 git clone


class MultiRepoPlugin(BasePlugin):
    """多仓库管理插件"""

    def __init__(self):
        self.name = "multirepo"
        self.plugin_dir = Path(__file__).parent
        self.manifests_dir = self.plugin_dir / "manifests"

    def _run_cmd(self, cmd: str, cwd: str = None, capture: bool = True) -> Tuple[int, str]:
        """
        执行命令并返回结果

        Args:
            cmd: 要执行的命令
            cwd: 工作目录
            capture: 是否捕获输出（False 时输出直接显示到终端）
        """
        try:
            if capture:
                # 捕获模式：用于需要解析输出的命令
                result = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)
                output = result.stdout.strip() if result.stdout else ""
                error = result.stderr.strip() if result.stderr else ""
                combined = f"{output}\n{error}".strip() if error else output
                return result.returncode, combined
            else:
                # 实时输出模式：用于 git clone 等长时间运行的命令
                result = subprocess.run(cmd, shell=True, cwd=cwd)
                return result.returncode, ""
        except Exception as e:
            return 1, str(e)

    def _file_exists(self, filepath: str) -> bool:
        """检查文件是否存在"""
        return os.path.isfile(filepath) and os.path.exists(filepath)

    def _dir_exists(self, dirpath: str) -> bool:
        """检查目录是否存在"""
        return os.path.isdir(dirpath) and os.path.exists(dirpath)

    def _is_valid_manifest(self, filepath: str) -> bool:
        """验证是否为有效的 manifest XML 文件"""
        if not self._file_exists(filepath):
            return False

        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
            # 检查是否有 manifest 根元素和至少一个 project
            return root.tag == "manifest" and len(list(root.iterfind('project'))) > 0
        except Exception as e:
            logger.warning(f"Invalid manifest file {filepath}: {e}")
            return False

    def resolve_manifest(self, manifest_arg: str) -> Optional[str]:
        """
        解析 manifest 文件路径（优先级）：
        1. 如果是绝对路径，直接使用
        2. 如果文件存在于当前目录（作为完整文件名），直接使用
        3. 当前目录下查找 <manifest_arg>.xml
        4. 插件内置 manifests 目录下查找

        Returns:
            str: manifest 文件的绝对路径，如果未找到返回 None
        """
        # 1. 绝对路径（可能带或不带 .xml 后缀）
        if os.path.isabs(manifest_arg):
            if self._is_valid_manifest(manifest_arg):
                logger.info(f"Using absolute path manifest: {manifest_arg}")
                return manifest_arg
            else:
                logger.warning(f"Invalid manifest at absolute path: {manifest_arg}")
                return None

        # 2. 当前目录下的完整文件名（比如 "default.xml"）
        # 使用 PWD 环境变量获取用户的真实工作目录
        user_cwd = os.getenv('PWD') or os.getcwd()
        cwd_path = Path(user_cwd) / manifest_arg
        if cwd_path.exists() and self._is_valid_manifest(str(cwd_path)):
            logger.info(f"Using current directory manifest: {cwd_path}")
            return str(cwd_path)

        # 3. 当前目录下查找 <manifest_arg>.xml（比如 "default" -> "default.xml"）
        if not manifest_arg.endswith('.xml'):
            cwd_manifest = Path(user_cwd) / f"{manifest_arg}.xml"
            if cwd_manifest.exists() and self._is_valid_manifest(str(cwd_manifest)):
                logger.info(f"Using current directory manifest: {cwd_manifest}")
                return str(cwd_manifest)

        # 4. 内置 manifests（不带 .xml 后缀）
        if not manifest_arg.endswith('.xml'):
            builtin_manifest = self.manifests_dir / f"{manifest_arg}.xml"
            if builtin_manifest.exists() and self._is_valid_manifest(str(builtin_manifest)):
                logger.info(f"Using builtin manifest: {builtin_manifest}")
                return str(builtin_manifest)

        logger.error(f"Manifest not found: {manifest_arg}")
        return None

    def _parse_manifest_projects(self, manifest_path: str) -> List[Dict]:
        """
        解析 manifest 文件获取所有项目信息

        Returns:
            List[Dict]: 项目列表，每个项目包含 name, path, remote, revision 等信息
        """
        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()

            # 获取 remote 配置
            remotes = {}
            for remote_elem in root.iterfind('remote'):
                remote_name = remote_elem.attrib.get('name')
                remote_fetch = remote_elem.attrib.get('fetch')
                if remote_name and remote_fetch:
                    remotes[remote_name] = remote_fetch

            # 获取 default 配置
            default_remote = None
            default_revision = None
            for default_elem in root.iterfind('default'):
                default_remote = default_elem.attrib.get('remote')
                default_revision = default_elem.attrib.get('revision')

            # 解析所有项目
            projects = []
            for project_elem in root.iterfind('project'):
                project_name = project_elem.attrib.get('name')
                if not project_name:
                    continue

                project_path = project_elem.attrib.get('path', project_name)
                project_remote = project_elem.attrib.get('remote', default_remote)
                project_revision = project_elem.attrib.get('revision', default_revision)

                # 构建完整的 git URL
                git_url = None
                if project_remote and project_remote in remotes:
                    remote_fetch = remotes[project_remote]
                    # 确保 URL 拼接时不会出现双斜杠
                    remote_fetch = remote_fetch.rstrip('/')
                    git_url = f"{remote_fetch}/{project_name}"

                projects.append({
                    'name': project_name,
                    'path': project_path,
                    'remote': project_remote,
                    'revision': project_revision,
                    'url': git_url
                })

            return projects

        except Exception as e:
            logger.error(f"Failed to parse manifest {manifest_path}: {e}")
            return []

    def _parse_project_list(self, filepath: str) -> List[str]:
        """解析项目列表文件（repo 模式）"""
        projects = []
        try:
            with open(filepath, 'r') as f:
                for line in f.readlines():
                    project = line.strip()
                    if project:
                        projects.append(project)
        except Exception as e:
            logger.error(f"Error parsing project list: {e}")
        return projects

    def _parse_manifest_branches(self, root_dir: str) -> Dict[str, str]:
        """解析manifest文件获取每个项目的分支信息（repo 模式）"""
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
            logger.error(f"Error parsing manifest: {e}")

        return project_branches

    # ==================== 命令实现 ====================

    @plugin_function(
        name="list",
        description={"zh": "列出所有内置 manifest 文件", "en": "List all builtin manifest files"},
        usage="gs multirepo list",
        examples=["gs multirepo list"],
    )
    async def list_manifests(self, args: List[str] = None) -> CommandResult:
        """列出所有内置 manifest"""
        if not self.manifests_dir.exists():
            return CommandResult(success=False, error="Manifests 目录不存在")

        manifests = []
        for manifest_file in self.manifests_dir.glob("*.xml"):
            if self._is_valid_manifest(str(manifest_file)):
                manifests.append(manifest_file.stem)

        if not manifests:
            return CommandResult(success=True, output="📋 没有找到内置 manifest 文件")

        output = "📋 内置 Manifest 文件:\n"
        for manifest in sorted(manifests):
            output += f"  • {manifest}\n"

        output += f"\n💡 使用方法: gs multirepo init <manifest_name> [--backend=repo|git]"

        return CommandResult(success=True, output=output)

    @plugin_function(
        name="init",
        description={"zh": "初始化多仓库项目（默认使用 git）", "en": "Initialize multi-repo project (default: git)"},
        usage="gs multirepo init [manifest] [--backend=git|repo]",
        examples=[
            "gs multirepo init",
            "gs multirepo init mini-aosp",
            "gs multirepo init mini-aosp --backend=repo",
            "gs multirepo init /path/to/custom.xml"
        ],
    )
    async def init(self, args: List[str] = None) -> CommandResult:
        """初始化多仓库项目"""
        args = args or []

        # 解析参数：提取 backend 和 manifest
        backend = BackendMode.GIT  # 默认使用 git（无需安装 repo 工具）
        manifest_arg = None
        extra_args = []

        for arg in args:
            if arg.startswith("--backend="):
                backend_str = arg.split("=")[1]
                if backend_str == "git":
                    backend = BackendMode.GIT
                elif backend_str == "repo":
                    backend = BackendMode.REPO
                else:
                    return CommandResult(
                        success=False,
                        error=f"未知的后端模式: {backend_str}，支持 'repo' 或 'git'"
                    )
            elif not arg.startswith("--"):
                # 第一个非选项参数作为 manifest
                if manifest_arg is None:
                    manifest_arg = arg
                else:
                    extra_args.append(arg)
            else:
                extra_args.append(arg)

        # 如果没有指定 manifest，自动检测当前目录
        if not manifest_arg:
            # 使用 PWD 环境变量获取用户的真实工作目录
            # 因为 uv run --directory 会改变 os.getcwd()
            user_cwd = os.getenv('PWD') or os.getcwd()
            cwd = Path(user_cwd)
            xml_files = list(cwd.glob("*.xml"))

            if not xml_files:
                return CommandResult(
                    success=False,
                    error="未找到 manifest 文件\n"
                          "请指定 manifest 名称，或在当前目录创建 .xml 文件\n"
                          "使用 'gs multirepo list' 查看内置 manifest"
                )

            # 优先使用 default.xml，否则使用第一个
            default_xml = cwd / "default.xml"
            if default_xml.exists():
                manifest_arg = str(default_xml)
                logger.info(f"Auto-detected manifest: default.xml")
            else:
                manifest_arg = str(xml_files[0])
                logger.info(f"Auto-detected manifest: {xml_files[0].name}")

        # 解析 manifest 文件
        manifest_path = self.resolve_manifest(manifest_arg)
        if not manifest_path:
            return CommandResult(
                success=False,
                error=f"未找到 manifest: {manifest_arg}\n使用 'gs multirepo list' 查看可用的 manifest"
            )

        # 根据后端模式初始化
        if backend == BackendMode.REPO:
            return await self._init_with_repo(manifest_path, extra_args)
        else:
            return await self._init_with_git(manifest_path)

    async def _init_with_repo(self, manifest_path: str, extra_args: List[str]) -> CommandResult:
        """使用 repo 命令初始化"""
        # 检查 repo 是否安装
        ret, _ = self._run_cmd("which repo")
        if ret != 0:
            return CommandResult(
                success=False,
                error="未找到 repo 命令，请先安装 repo 工具"
            )

        # 使用 repo init 和 repo sync
        output_lines = []

        # 过滤掉 --backend 参数，传递给 repo sync
        sync_args = [arg for arg in extra_args if not arg.startswith("--backend=")]
        sync_args_str = " ".join(sync_args)

        # 执行 repo sync
        cmd = f"repo sync -m {Path(manifest_path).name} {sync_args_str}".strip()
        output_lines.append(f"📦 执行: {cmd}")

        ret, output = self._run_cmd(cmd)
        if ret != 0:
            return CommandResult(
                success=False,
                error=f"repo sync 失败:\n{output}"
            )

        output_lines.append(output)
        output_lines.append("\n✅ Repo 项目初始化成功")
        output_lines.append("📂 .repo 目录已创建")

        return CommandResult(success=True, output="\n".join(output_lines))

    async def _init_with_git(self, manifest_path: str) -> CommandResult:
        """使用 git clone 初始化"""
        projects = self._parse_manifest_projects(manifest_path)
        if not projects:
            return CommandResult(
                success=False,
                error=f"无法从 manifest 解析项目: {manifest_path}"
            )

        # 使用 PWD 环境变量获取用户的工作目录
        user_cwd = os.getenv('PWD') or os.getcwd()

        print(f"📦 使用 git clone 模式初始化 {len(projects)} 个项目")
        print(f"📂 工作目录: {user_cwd}")
        print()

        errors = []
        success_count = 0

        for idx, project in enumerate(projects, 1):
            project_name = project['name']
            project_path = project['path']
            project_url = project['url']
            project_revision = project['revision']

            if not project_url:
                error_msg = f"❌ {project_name}: 缺少 URL"
                print(error_msg)
                errors.append(error_msg)
                continue

            print(f"[{idx}/{len(projects)}] 📥 克隆: {project_name} -> {project_path}")
            print(f"           URL: {project_url}")

            # 克隆项目（实时输出到终端）
            clone_cmd = f"git clone {project_url} {project_path}"
            ret, _ = self._run_cmd(clone_cmd, cwd=user_cwd, capture=False)

            if ret != 0:
                error_msg = f"❌ {project_name}: clone 失败"
                print(error_msg)
                errors.append(error_msg)
                print()
                continue

            # 切换到指定分支/tag
            if project_revision:
                print(f"           🌿 切换到分支/tag: {project_revision}")
                project_full_path = os.path.join(user_cwd, project_path)
                ret, _ = self._run_cmd(f"git checkout {project_revision}", project_full_path, capture=False)
                if ret != 0:
                    error_msg = f"⚠️  {project_name}: 切换到 {project_revision} 失败"
                    print(error_msg)
                    errors.append(error_msg)

            print(f"           ✅ 完成")
            print()
            success_count += 1

        # 汇总结果
        print("=" * 60)
        print(f"✅ 成功克隆: {success_count}/{len(projects)}")

        if errors:
            print()
            print("❌ 错误列表:")
            for error in errors:
                print(f"  {error}")
            return CommandResult(success=False, output=f"部分项目克隆失败 ({success_count}/{len(projects)})")

        return CommandResult(success=True, output=f"所有项目克隆成功 ({success_count}/{len(projects)})")


    @plugin_function(
        name="sync",
        description={"zh": "同步repo项目（支持清理模式）", "en": "Sync repo projects with optional clean mode"},
        usage="gs multirepo sync [clean]",
        examples=["gs multirepo sync", "gs multirepo sync clean"],
    )
    async def sync(self, args: List[str] = None) -> CommandResult:
        """同步repo项目（仅 repo 模式）"""
        args = args or []
        clean_mode = "clean" in args or "c" in args

        root_dir = os.getcwd()
        project_list_file = os.path.join(root_dir, ".repo/project.list")

        if not self._file_exists(project_list_file):
            return CommandResult(
                success=False,
                error="未找到 .repo/project.list 文件\n"
                      "请确保在 repo 工作目录中执行，或使用 'gs multirepo init' 初始化项目"
            )

        projects = self._parse_project_list(project_list_file)
        if not projects:
            return CommandResult(success=False, error="项目列表为空")

        project_branches = self._parse_manifest_branches(root_dir)

        output_lines = []
        errors = []

        for project in projects:
            output_lines.append(f"🔄 同步项目: {project}")
            project_dir = os.path.join(root_dir, project)
            git_dir = os.path.join(project_dir, ".git")

            if not self._dir_exists(git_dir):
                output_lines.append(f"  ⏭️  跳过 {project}：不是git仓库")
                continue

            # 获取分支列表
            ret, branch_output = self._run_cmd("git branch --list | sed 's/*//g'", project_dir)
            if ret != 0:
                errors.append(f"❌ {project} 获取分支列表失败: {branch_output}")
                continue

            # 同步每个分支
            for line in branch_output.splitlines():
                branch = line.strip()
                if not branch:
                    continue

                output_lines.append(f"  📍 同步分支: {project}/{branch}")

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
                    errors.append(f"❌ {project}/{branch} 拉取失败: {pull_output}")

            # 切换回默认分支
            default_branch = project_branches.get(project)
            if default_branch:
                self._run_cmd(f"git checkout {default_branch}", project_dir)

        result_output = "\n".join(output_lines)
        if errors:
            result_output += "\n\n❌ 错误:\n" + "\n".join(errors)
            return CommandResult(success=False, error=result_output)

        return CommandResult(success=True, output=result_output + "\n\n✅ 同步完成")

    @plugin_function(
        name="checkout",
        description={"zh": "为repo项目创建所有远程分支", "en": "Checkout all remote branches for repo projects"},
        usage="gs multirepo checkout",
        examples=["gs multirepo checkout"],
    )
    async def checkout(self, args: List[str] = None) -> CommandResult:
        """为repo项目创建所有远程分支（仅 repo 模式）"""
        root_dir = os.getcwd()
        project_list_file = os.path.join(root_dir, ".repo/project.list")

        if not self._file_exists(project_list_file):
            return CommandResult(
                success=False,
                error="未找到 .repo/project.list 文件\n"
                      "请确保在 repo 工作目录中执行"
            )

        projects = self._parse_project_list(project_list_file)
        if not projects:
            return CommandResult(success=False, error="项目列表为空")

        project_branches = self._parse_manifest_branches(root_dir)

        output_lines = []
        errors = []

        for project in projects:
            output_lines.append(f"📋 检出项目: {project}")
            project_dir = os.path.join(root_dir, project)
            git_dir = os.path.join(project_dir, ".git")

            if not self._dir_exists(git_dir):
                output_lines.append(f"  ⏭️  跳过 {project}：不是git仓库")
                continue

            # 获取远程分支
            ret, remote_output = self._run_cmd("git branch -r", project_dir)
            if ret != 0:
                errors.append(f"❌ {project} 获取远程分支失败: {remote_output}")
                continue

            # 为每个origin分支创建本地分支
            for line in remote_output.splitlines():
                branch_info = line.strip()
                if "origin" not in branch_info:
                    continue

                parts = branch_info.split("/")
                if len(parts) >= 2 and parts[0] == "origin":
                    branch_name = parts[1]

                    output_lines.append(f"  🌿 创建分支: {project}/{branch_name}")
                    cmd = f"git checkout -b {branch_name} {branch_info}"
                    self._run_cmd(cmd, project_dir)

            # 切换回默认分支
            default_branch = project_branches.get(project)
            if default_branch:
                self._run_cmd(f"git checkout {default_branch}", project_dir)

        result_output = "\n".join(output_lines)
        if errors:
            result_output += "\n\n❌ 错误:\n" + "\n".join(errors)
            return CommandResult(success=False, error=result_output)

        return CommandResult(success=True, output=result_output + "\n\n✅ 检出完成")

    @plugin_function(
        name="status",
        description={"zh": "查看当前工作目录状态", "en": "Show current workspace status"},
        usage="gs multirepo status",
        examples=["gs multirepo status"],
    )
    async def status(self, args: List[str] = None) -> CommandResult:
        """查看当前工作目录状态"""
        root_dir = os.getcwd()

        output_lines = []
        output_lines.append("📊 MultiRepo 工作目录状态")
        output_lines.append("=" * 50)

        # 检测是否为 repo 模式
        repo_dir = os.path.join(root_dir, ".repo")
        if self._dir_exists(repo_dir):
            output_lines.append("🔧 后端模式: repo")
            output_lines.append(f"📂 Repo 目录: {repo_dir}")

            # 检查 manifest
            manifest_file = os.path.join(repo_dir, "manifest.xml")
            if self._file_exists(manifest_file):
                output_lines.append(f"📄 Manifest: {manifest_file}")

            # 统计项目
            project_list_file = os.path.join(repo_dir, "project.list")
            if self._file_exists(project_list_file):
                projects = self._parse_project_list(project_list_file)
                output_lines.append(f"📦 项目数量: {len(projects)}")
        else:
            output_lines.append("🔧 后端模式: git clone (或未初始化)")
            output_lines.append("💡 提示: 使用 'gs multirepo init <manifest>' 初始化项目")

        return CommandResult(success=True, output="\n".join(output_lines))
