"""
Sample plugin fixtures for testing.

Provides reusable plugin metadata and content for various plugin types.
"""

import pytest
from pathlib import Path
from typing import Dict, Any

from gscripts.models.plugin import PluginMetadata, PluginType
from gscripts.models.function import FunctionInfo


@pytest.fixture
def sample_plugin_metadata() -> PluginMetadata:
    """Provide basic plugin metadata for testing."""
    return PluginMetadata(
        name="testplugin",
        version="1.0.0",
        author="Test Author",
        description={"zh": "测试插件", "en": "Test plugin"},
        type=PluginType.PYTHON,
        enabled=True,
        path=Path("/test/plugins/testplugin"),
    )


@pytest.fixture
def sample_python_plugin_content() -> str:
    """Provide sample Python plugin code."""
    return '''"""Test Python plugin"""
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).resolve().parents[2]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from gscripts.plugins.base import BasePlugin
from gscripts.plugins.decorators import plugin_function
from gscripts.models import CommandResult


class TestPlugin(BasePlugin):
    """Test plugin for testing purposes."""

    def __init__(self):
        self.name = "testplugin"

    @plugin_function(
        name="hello",
        description={"zh": "打招呼", "en": "Say hello"},
        usage="gs testplugin hello [name]",
        examples=["gs testplugin hello world"],
    )
    async def hello(self, args: list = None) -> CommandResult:
        """Say hello to someone."""
        name = args[0] if args else "world"
        return CommandResult(
            success=True,
            output=f"Hello, {name}!",
            exit_code=0,
        )

    @plugin_function(
        name="goodbye",
        description={"zh": "告别", "en": "Say goodbye"},
        usage="gs testplugin goodbye",
    )
    async def goodbye(self, args: list = None) -> CommandResult:
        """Say goodbye."""
        return CommandResult(
            success=True,
            output="Goodbye!",
            exit_code=0,
        )
'''


@pytest.fixture
def sample_shell_plugin_content() -> str:
    """Provide sample shell plugin script."""
    return """#!/bin/bash
# Test shell plugin

# @plugin_function
# name: list
# description:
#   zh: 列出文件
#   en: List files
# usage: gs testshell list [path]
# examples:
#   - gs testshell list /tmp
function testshell_list() {
    local path="${1:-.}"
    ls -la "$path"
}

# @plugin_function
# name: echo
# description:
#   zh: 回显文本
#   en: Echo text
# usage: gs testshell echo <text>
function testshell_echo() {
    echo "$@"
}
"""


@pytest.fixture
def sample_config_plugin_content() -> Dict[str, Any]:
    """Provide sample config plugin JSON."""
    return {
        "functions": [
            {
                "name": "status",
                "description": {"zh": "显示状态", "en": "Show status"},
                "command": "git status",
                "usage": "gs testconfig status",
            },
            {
                "name": "log",
                "description": {"zh": "显示日志", "en": "Show log"},
                "command": "git log --oneline -n 10",
                "usage": "gs testconfig log",
            },
        ]
    }


@pytest.fixture
def sample_plugin_json() -> Dict[str, Any]:
    """Provide sample plugin.json metadata."""
    return {
        "name": "testplugin",
        "version": "1.0.0",
        "author": "Test Author",
        "description": {"zh": "测试插件", "en": "Test plugin"},
        "type": "python",
        "entry": "plugin.py",
        "enabled": True,
    }


@pytest.fixture
def sample_hybrid_plugin_structure(temp_dir: Path) -> Path:
    """
    Create a sample hybrid plugin with multiple subplugins.

    Returns the path to the plugin directory.
    """
    plugin_dir = temp_dir / "testhybrid"
    plugin_dir.mkdir()

    # Main plugin.json
    import json

    plugin_json = {
        "name": "testhybrid",
        "version": "1.0.0",
        "author": "Test Author",
        "description": {"zh": "混合插件", "en": "Hybrid plugin"},
        "type": "hybrid",
        "enabled": True,
        "subplugins": [
            {
                "name": "python_sub",
                "type": "python",
                "entry": "python_sub/plugin.py",
                "description": {"zh": "Python子插件", "en": "Python subplugin"},
            },
            {
                "name": "shell_sub",
                "type": "shell",
                "entry": "shell_sub/plugin.sh",
                "description": {"zh": "Shell子插件", "en": "Shell subplugin"},
            },
        ],
    }

    with open(plugin_dir / "plugin.json", "w") as f:
        json.dump(plugin_json, f, indent=2)

    # Create subplugins
    python_sub_dir = plugin_dir / "python_sub"
    python_sub_dir.mkdir()

    shell_sub_dir = plugin_dir / "shell_sub"
    shell_sub_dir.mkdir()

    # Add minimal plugin files
    (python_sub_dir / "plugin.py").write_text("# Python subplugin\npass")
    (shell_sub_dir / "plugin.sh").write_text("#!/bin/bash\n# Shell subplugin\n")

    return plugin_dir


@pytest.fixture
def sample_function_info() -> FunctionInfo:
    """Provide sample FunctionInfo for testing."""
    return FunctionInfo(
        name="test_function",
        description={"zh": "测试函数", "en": "Test function"},
        usage="gs plugin test_function [args]",
        examples=["gs plugin test_function example"],
        plugin_name="testplugin",
        subplugin_name="",
        method_name="test_function",
        is_async=True,
    )
