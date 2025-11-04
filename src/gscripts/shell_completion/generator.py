#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Completion generator based on router index
使用 Jinja2 模板生成补全脚本，去除硬编码
"""

import datetime
from pathlib import Path
from typing import Dict, List, Tuple

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..core.logger import get_logger

logger = get_logger(tag="SHELL.COMPLETION", name=__name__)


class CompletionGenerator:
    """Generate shell completions from router index using Jinja2 templates"""

    # System commands that should always be available
    SYSTEM_COMMANDS = [
        "help",
        "version",
        "plugin",
        "refresh",
        "status",
        "doctor",
        "parser",
    ]
    PLUGIN_SUBCOMMANDS = ["list", "info", "enable", "disable", "create"]

    def __init__(self, router_index_path: Path, templates_dir: Path = None):
        """
        Initialize with router index path

        Args:
            router_index_path: Path to router.json
            templates_dir: Path to templates directory (auto-detected if None)
        """
        self.router_index_path = router_index_path
        self.index = self._load_router_index()

        # Setup Jinja2 environment
        if templates_dir is None:
            # Auto-detect: src/gscripts/resources/templates
            templates_dir = Path(__file__).parent.parent / "resources" / "templates"

        if not templates_dir.exists():
            raise FileNotFoundError(f"Templates directory not found: {templates_dir}")

        self.jinja_env = Environment(
            loader=FileSystemLoader(str(templates_dir)),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def _load_router_index(self) -> Dict:
        """Load router index from JSON file"""
        if not self.router_index_path.exists():
            return {}

        try:
            import json

            with open(self.router_index_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load router index: {e}")
            return {}

    def _parse_commands(
        self, plugin_name: str
    ) -> Tuple[List[str], Dict[str, List[str]]]:
        """
        Parse commands from plugin

        Returns:
            (single_word_commands, multi_word_commands_map)

        Example:
            (['aosp', 'list'], {'brew': ['aliyun', 'github'], 'config': ['backup']})
        """
        plugins = self.index.get("plugins", {})
        plugin_data = plugins.get(plugin_name, {})
        commands = plugin_data.get("commands", {})

        single_word = []
        multi_word = {}

        for cmd_key in commands.keys():
            parts = cmd_key.split(" ", 1)
            if len(parts) == 1:
                # Single word command
                single_word.append(cmd_key)
            else:
                # Multi-word command
                first, rest = parts
                if first not in multi_word:
                    multi_word[first] = []
                multi_word[first].append(rest)

        return sorted(single_word), multi_word

    def _prepare_bash_context(self) -> Dict:
        """Prepare template context for bash completion"""
        plugins = self.index.get("plugins", {})
        plugin_names = sorted(plugins.keys())

        # Build plugin commands structure
        plugin_commands = {}
        for plugin_name in plugin_names:
            single_word, multi_word = self._parse_commands(plugin_name)

            # Collect all level-2 commands (single word + first word of multi-word)
            level2_commands = set(single_word)
            level2_commands.update(multi_word.keys())

            plugin_commands[plugin_name] = {
                "level2": sorted(level2_commands) if level2_commands else None,
                "level3": multi_word if multi_word else None,
            }

        return {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "system_commands": self.SYSTEM_COMMANDS,
            "plugin_subcommands": self.PLUGIN_SUBCOMMANDS,
            "plugin_names": plugin_names,
            "plugins": plugin_commands,
        }

    def _prepare_zsh_fish_context(self, language: str = "zh") -> Dict:
        """Prepare template context for zsh/fish completion"""
        # Get system command descriptions
        try:
            from ..utils.i18n import I18nManager

            i18n = I18nManager(chinese=(language == "zh"))
            help_desc = i18n.get_message("commands.help")
            version_desc = i18n.get_message("commands.version")
            plugin_desc = i18n.get_message("commands.plugin_management")
            refresh_desc = i18n.get_message("commands.refresh")
            status_desc = i18n.get_message("commands.system_status")
            doctor_desc = i18n.get_message("commands.doctor")
            parser_desc = i18n.get_message("commands.parser_management")
        except Exception:
            # Fallback to hardcoded if i18n fails
            if language == "zh":
                help_desc = "显示帮助信息"
                version_desc = "显示版本信息"
                plugin_desc = "插件管理"
                refresh_desc = "刷新系统"
                status_desc = "显示系统状态"
                doctor_desc = "系统诊断"
                parser_desc = "解析器管理"
            else:
                help_desc = "Show help information"
                version_desc = "Show version information"
                plugin_desc = "Plugin management"
                refresh_desc = "Refresh configuration"
                status_desc = "Show system status"
                doctor_desc = "Check system health"
                parser_desc = "Parser management"

        return {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "router_index_path": str(self.router_index_path.resolve()),
            "language": language,
            "help_desc": help_desc,
            "version_desc": version_desc,
            "plugin_desc": plugin_desc,
            "refresh_desc": refresh_desc,
            "status_desc": status_desc,
            "doctor_desc": doctor_desc,
            "parser_desc": parser_desc,
        }

    def generate_bash_completion(self) -> str:
        """Generate bash completion script using template"""
        template = self.jinja_env.get_template("completion.bash.j2")
        context = self._prepare_bash_context()
        return template.render(**context)

    def generate_zsh_completion(self, language: str = "zh") -> str:
        """Generate zsh completion script using template"""
        template = self.jinja_env.get_template("completion.zsh.j2")
        context = self._prepare_zsh_fish_context(language)
        return template.render(**context)

    def generate_fish_completion(self, language: str = "zh") -> str:
        """Generate fish completion script using template"""
        template = self.jinja_env.get_template("completion.fish.j2")
        context = self._prepare_zsh_fish_context(language)
        return template.render(**context)


def generate_completions_from_index(
    router_index_path: Path, output_dir: Path, language: str = "zh"
) -> Tuple[Path, Path, Path]:
    """
    Generate completion scripts from router index

    Args:
        router_index_path: Path to router/index.json or router.json
        output_dir: Output directory for completion scripts
        language: Language for descriptions ('zh' or 'en')

    Returns:
        (bash_file_path, zsh_file_path, fish_file_path)
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    generator = CompletionGenerator(router_index_path)

    # Generate bash completion
    bash_content = generator.generate_bash_completion()
    bash_file = output_dir / "gs.bash"
    with open(bash_file, "w", encoding="utf-8") as f:
        f.write(bash_content)

    # Generate zsh completion
    zsh_content = generator.generate_zsh_completion(language=language)
    zsh_file = output_dir / "gs.zsh"
    with open(zsh_file, "w", encoding="utf-8") as f:
        f.write(zsh_content)

    # Generate fish completion
    fish_content = generator.generate_fish_completion(language=language)
    fish_file = output_dir / "gs.fish"
    with open(fish_file, "w", encoding="utf-8") as f:
        f.write(fish_content)

    logger.info(f"Generated completion scripts: {bash_file}, {zsh_file}, {fish_file}")

    return bash_file, zsh_file, fish_file
