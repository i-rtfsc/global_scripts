"""
Template Engine for Global Scripts
使用 Jinja2 渲染各种配置文件和脚本模板
消除 setup.py 中的字符串拼接硬编码
"""

import datetime
import platform
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False


class TemplateEngine:
    """
    模板引擎类

    使用 Jinja2 渲染各种脚本和配置文件
    支持自定义模板目录和上下文变量
    """

    def __init__(self, templates_dir: Optional[Path] = None):
        """
        初始化模板引擎

        Args:
            templates_dir: 模板目录路径，默认为项目根目录的 templates/

        Raises:
            ImportError: 如果 Jinja2 未安装
            FileNotFoundError: 如果模板目录不存在
        """
        if not JINJA2_AVAILABLE:
            raise ImportError(
                "Jinja2 is required for template rendering. "
                "Install it with: pip install jinja2"
            )

        if templates_dir is None:
            # 默认模板目录：项目根目录/templates
            current_file = Path(__file__)
            project_root = current_file.parent.parent.parent.parent
            templates_dir = project_root / "templates"

        self.templates_dir = templates_dir

        if not self.templates_dir.exists():
            raise FileNotFoundError(f"Templates directory not found: {self.templates_dir}")

        # 创建 Jinja2 环境
        self.env = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            autoescape=select_autoescape(['html', 'xml']),
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=True
        )

        # 注册自定义过滤器
        self._register_filters()

    def _register_filters(self):
        """注册自定义 Jinja2 过滤器"""
        self.env.filters['quote_shell'] = self._quote_shell
        self.env.filters['escape_shell'] = self._escape_shell
        self.env.filters['join_path'] = self._join_path

    @staticmethod
    def _quote_shell(value: str) -> str:
        """Shell 字符串引号包裹"""
        return f'"{value}"'

    @staticmethod
    def _escape_shell(value: str) -> str:
        """转义 Shell 特殊字符"""
        # 简单转义，实际应用中可能需要更复杂的逻辑
        return value.replace('"', '\\"').replace('$', '\\$').replace('`', '\\`')

    @staticmethod
    def _join_path(*parts: str) -> str:
        """拼接路径"""
        return str(Path(*parts))

    def render_template(self, template_name: str, context: Dict[str, Any]) -> str:
        """
        渲染模板

        Args:
            template_name: 模板文件名（相对于templates_dir）
            context: 模板上下文变量字典

        Returns:
            str: 渲染后的字符串

        Raises:
            jinja2.TemplateNotFound: 模板文件不存在
            jinja2.TemplateSyntaxError: 模板语法错误
        """
        template = self.env.get_template(template_name)
        return template.render(**context)

    def render_env_sh(
        self,
        source_dir: Path,
        cache_dir: Path,
        plugins: Dict[str, Dict],
        language: str = 'zh',
        show_examples: bool = True,
        **extra_context
    ) -> str:
        """
        渲染 env.sh 脚本

        Args:
            source_dir: 源码目录
            cache_dir: 缓存目录
            plugins: 插件信息字典
            language: 语言设置
            show_examples: 是否显示示例
            **extra_context: 额外的上下文变量

        Returns:
            str: 渲染后的 env.sh 内容
        """
        # 构建基础上下文
        context = {
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'source_dir': str(source_dir),
            'gs_root': str(source_dir.resolve()),
            'cache_dir': str(cache_dir.resolve()),
            'language': language,
            'show_examples': show_examples,
            'version': self._get_version(),
            'platform': platform.system().lower(),
            'prompt_theme': 'bitstream',  # 默认主题
            'config_exports': {},
            'aliases': []
        }

        # 处理配置导出
        context['config_exports'] = self._extract_config_exports(source_dir)

        # 处理 alias 插件
        context['aliases'] = self._extract_aliases(plugins)

        # 合并额外上下文
        context.update(extra_context)

        return self.render_template('env.sh.j2', context)

    def render_env_fish(
        self,
        source_dir: Path,
        cache_dir: Path,
        plugins: Dict[str, Dict],
        language: str = 'zh',
        show_examples: bool = True,
        **extra_context
    ) -> str:
        """
        渲染 env.fish 脚本

        Args:
            source_dir: 源码目录
            cache_dir: 缓存目录
            plugins: 插件信息字典
            language: 语言设置
            show_examples: 是否显示示例
            **extra_context: 额外的上下文变量

        Returns:
            str: 渲染后的 env.fish 内容
        """
        # Fish 模板待实现，目前先返回空字符串
        # TODO: 创建 env.fish.j2 模板
        return ""

    def _get_version(self) -> str:
        """获取项目版本"""
        # 从 VERSION 文件读取
        try:
            version_file = self.source_dir / "VERSION"
            if version_file.exists():
                return version_file.read_text().strip()
        except Exception:
            pass

        # 如果 VERSION 文件不存在，尝试从系统配置加载
        try:
            from .system_config_loader import get_system_config
            return get_system_config().project.version
        except Exception:
            return "unknown"

    def _extract_config_exports(self, source_dir: Path) -> Dict[str, Any]:
        """
        从 gs.json 提取需要导出的配置

        Args:
            source_dir: 源码目录

        Returns:
            Dict: 配置键值对
        """
        import json

        config_file = source_dir / "config" / "gs.json"
        if not config_file.exists():
            return {}

        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)

            # 过滤掉复杂类型（dict/list）和特殊键
            exports = {}
            skip_keys = {'system_plugins', 'custom_plugins', 'prompt_theme'}

            for key, value in config.items():
                if key in skip_keys or isinstance(value, (dict, list)):
                    continue
                exports[key] = value

            return exports
        except Exception:
            return {}

    def _extract_aliases(self, plugins: Dict[str, Dict]) -> List[Dict[str, Any]]:
        """
        从插件信息中提取 alias 配置

        Args:
            plugins: 插件信息字典

        Returns:
            List: alias 配置列表
        """
        aliases = []

        for plugin_name, plugin_info in plugins.items():
            alias_info = plugin_info.get('alias')
            if not alias_info or not isinstance(alias_info, dict):
                continue

            # 提取 sources
            sources = alias_info.get('sources', [])
            if isinstance(sources, dict):
                # 新格式：dict
                bash_sources = sources.get('bash', [])
                zsh_sources = sources.get('zsh', [])
                sources = list(dict.fromkeys(bash_sources + zsh_sources))
            elif not isinstance(sources, list):
                sources = []

            if not sources:
                continue

            # 构建 alias 信息
            shells = alias_info.get('shells', ['bash', 'zsh'])
            shell_conditions = []
            if 'bash' in shells:
                shell_conditions.append('[ -n "$BASH_VERSION" ]')
            if 'zsh' in shells:
                shell_conditions.append('[ -n "$ZSH_VERSION" ]')

            alias_data = {
                'name': plugin_name,
                'interactive_only': alias_info.get('interactive_only', True),
                'priority': alias_info.get('priority', 100),
                'shells': shells,
                'shell_check': ' || '.join(shell_conditions) if shell_conditions else None,
                'sources': [
                    {
                        'path': source,
                        'full_path': f'$GS_ROOT/plugins/{plugin_name}/{source}'
                    }
                    for source in sources
                ]
            }

            aliases.append(alias_data)

        # 按优先级排序
        aliases.sort(key=lambda x: (x['priority'], x['name']))

        return aliases


# 全局模板引擎单例
_global_engine: Optional[TemplateEngine] = None


def get_template_engine() -> TemplateEngine:
    """
    获取全局模板引擎单例

    Returns:
        TemplateEngine: 模板引擎实例
    """
    global _global_engine
    if _global_engine is None:
        _global_engine = TemplateEngine()
    return _global_engine
