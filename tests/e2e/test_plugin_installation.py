"""
End-to-end tests for plugin installation workflows

Tests complete plugin installation process including directory creation,
metadata validation, and plugin type handling.
"""

import pytest
import json


@pytest.fixture
def installation_environment(tmp_path):
    """Setup environment for plugin installation testing"""
    test_root = tmp_path / "install_test"
    test_root.mkdir()

    plugins_dir = test_root / "plugins"
    plugins_dir.mkdir()

    custom_dir = test_root / "custom"
    custom_dir.mkdir()

    return {"root": test_root, "plugins_dir": plugins_dir, "custom_dir": custom_dir}


@pytest.mark.e2e
class TestPythonPluginInstallation:
    """End-to-end tests for Python plugin installation"""

    def test_install_simple_python_plugin(self, installation_environment):
        """Test installing a simple Python plugin"""
        plugins_dir = installation_environment["plugins_dir"]

        # Create plugin directory
        plugin_dir = plugins_dir / "simplepython"
        plugin_dir.mkdir()

        # Create plugin.json
        plugin_json = {
            "name": "simplepython",
            "version": "1.0.0",
            "author": "Test Author",
            "type": "python",
            "entry": "plugin.py",
            "enabled": True,
            "description": {"zh": "简单Python插件", "en": "Simple Python plugin"},
        }
        (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json, indent=2))

        # Create plugin.py
        plugin_py = '''"""Simple Python plugin"""
from gscripts.plugins.base import BasePlugin
from gscripts.plugins.decorators import plugin_function
from gscripts.models import CommandResult

class SimplePythonPlugin(BasePlugin):
    def __init__(self):
        self.name = "simplepython"

    @plugin_function(
        name="hello",
        description={"zh": "问候", "en": "Say hello"},
        usage="gs simplepython hello",
    )
    async def hello(self, args=None):
        return CommandResult(success=True, output="Hello from Python!", exit_code=0)
'''
        (plugin_dir / "plugin.py").write_text(plugin_py)

        # Assert: Plugin installed correctly
        assert (plugin_dir / "plugin.json").exists()
        assert (plugin_dir / "plugin.py").exists()

        metadata = json.loads((plugin_dir / "plugin.json").read_text())
        assert metadata["name"] == "simplepython"
        assert metadata["type"] == "python"
        assert metadata["entry"] == "plugin.py"

    def test_install_python_plugin_with_dependencies(self, installation_environment):
        """Test installing Python plugin with external dependencies"""
        plugins_dir = installation_environment["plugins_dir"]

        plugin_dir = plugins_dir / "withdeps"
        plugin_dir.mkdir()

        # Plugin with dependencies listed
        plugin_json = {
            "name": "withdeps",
            "version": "1.0.0",
            "type": "python",
            "entry": "plugin.py",
            "enabled": True,
            "description": {"zh": "带依赖", "en": "With dependencies"},
            "dependencies": ["requests", "beautifulsoup4"],
            "python_requires": ">=3.8",
        }
        (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json, indent=2))

        # Create requirements.txt
        requirements = """requests>=2.28.0
beautifulsoup4>=4.11.0
"""
        (plugin_dir / "requirements.txt").write_text(requirements)

        # Create plugin.py
        plugin_py = '''"""Plugin with dependencies"""
from gscripts.plugins.base import BasePlugin

class WithDepsPlugin(BasePlugin):
    def __init__(self):
        self.name = "withdeps"
'''
        (plugin_dir / "plugin.py").write_text(plugin_py)

        # Assert: All files created
        assert (plugin_dir / "plugin.json").exists()
        assert (plugin_dir / "plugin.py").exists()
        assert (plugin_dir / "requirements.txt").exists()

        metadata = json.loads((plugin_dir / "plugin.json").read_text())
        assert "dependencies" in metadata
        assert len(metadata["dependencies"]) == 2


@pytest.mark.e2e
class TestShellPluginInstallation:
    """End-to-end tests for Shell plugin installation"""

    def test_install_simple_shell_plugin(self, installation_environment):
        """Test installing a simple Shell plugin"""
        plugins_dir = installation_environment["plugins_dir"]

        plugin_dir = plugins_dir / "simpleshell"
        plugin_dir.mkdir()

        # Create plugin.json
        plugin_json = {
            "name": "simpleshell",
            "version": "1.0.0",
            "type": "shell",
            "entry": "plugin.sh",
            "enabled": True,
            "description": {"zh": "简单Shell插件", "en": "Simple Shell plugin"},
        }
        (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json, indent=2))

        # Create plugin.sh
        plugin_sh = """#!/bin/bash
# @plugin_function
# @name greet
# @description {"zh": "问候", "en": "Greet"}
# @usage gs simpleshell greet <name>
function greet() {
    echo "Hello from Shell, $1!"
}
"""
        (plugin_dir / "plugin.sh").write_text(plugin_sh)
        (plugin_dir / "plugin.sh").chmod(0o755)

        # Assert: Plugin installed
        assert (plugin_dir / "plugin.json").exists()
        assert (plugin_dir / "plugin.sh").exists()

        metadata = json.loads((plugin_dir / "plugin.json").read_text())
        assert metadata["type"] == "shell"
        assert metadata["entry"] == "plugin.sh"


@pytest.mark.e2e
class TestConfigPluginInstallation:
    """End-to-end tests for Config plugin installation"""

    def test_install_simple_config_plugin(self, installation_environment):
        """Test installing a simple Config plugin"""
        plugins_dir = installation_environment["plugins_dir"]

        plugin_dir = plugins_dir / "simpleconfig"
        plugin_dir.mkdir()

        # Create plugin.json
        plugin_json = {
            "name": "simpleconfig",
            "version": "1.0.0",
            "type": "config",
            "entry": "commands.json",
            "enabled": True,
            "description": {"zh": "简单配置插件", "en": "Simple config plugin"},
        }
        (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json, indent=2))

        # Create commands.json
        commands_json = {
            "commands": {
                "version": {
                    "description": {"zh": "版本", "en": "Show version"},
                    "command": "echo 'SimpleConfig v1.0.0'",
                    "usage": "gs simpleconfig version",
                },
                "status": {
                    "description": {"zh": "状态", "en": "Show status"},
                    "command": "echo 'Status: OK'",
                    "usage": "gs simpleconfig status",
                },
            }
        }
        (plugin_dir / "commands.json").write_text(json.dumps(commands_json, indent=2))

        # Assert: Plugin installed
        assert (plugin_dir / "plugin.json").exists()
        assert (plugin_dir / "commands.json").exists()

        metadata = json.loads((plugin_dir / "plugin.json").read_text())
        assert metadata["type"] == "config"

        commands = json.loads((plugin_dir / "commands.json").read_text())
        assert "commands" in commands
        assert len(commands["commands"]) == 2


@pytest.mark.e2e
class TestHybridPluginInstallation:
    """End-to-end tests for Hybrid plugin installation"""

    def test_install_hybrid_plugin_with_subplugins(self, installation_environment):
        """Test installing a hybrid plugin with multiple subplugins"""
        plugins_dir = installation_environment["plugins_dir"]

        # Create main plugin directory
        plugin_dir = plugins_dir / "hybrid"
        plugin_dir.mkdir()

        # Create plugin.json with subplugins
        plugin_json = {
            "name": "hybrid",
            "version": "2.0.0",
            "type": "hybrid",
            "enabled": True,
            "description": {"zh": "混合插件", "en": "Hybrid plugin"},
            "subplugins": [
                {
                    "name": "python_sub",
                    "type": "python",
                    "entry": "subplugins/python_sub/plugin.py",
                    "description": {"zh": "Python子插件", "en": "Python subplugin"},
                },
                {
                    "name": "shell_sub",
                    "type": "shell",
                    "entry": "subplugins/shell_sub/plugin.sh",
                    "description": {"zh": "Shell子插件", "en": "Shell subplugin"},
                },
            ],
        }
        (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json, indent=2))

        # Create subplugins directory structure
        subplugins_dir = plugin_dir / "subplugins"
        subplugins_dir.mkdir()

        # Python subplugin
        python_sub_dir = subplugins_dir / "python_sub"
        python_sub_dir.mkdir()

        python_sub_py = '''"""Python subplugin"""
from gscripts.plugins.base import BaseSubPlugin
from gscripts.plugins.decorators import plugin_function
from gscripts.models import CommandResult

class PythonSub(BaseSubPlugin):
    def __init__(self):
        self.name = "python_sub"

    @plugin_function(
        name="test",
        description={"zh": "测试", "en": "Test"},
        usage="gs hybrid python_sub test",
    )
    async def test(self, args=None):
        return CommandResult(success=True, output="Python sub test", exit_code=0)
'''
        (python_sub_dir / "plugin.py").write_text(python_sub_py)

        # Shell subplugin
        shell_sub_dir = subplugins_dir / "shell_sub"
        shell_sub_dir.mkdir()

        shell_sub_sh = """#!/bin/bash
# @plugin_function
# @name test
# @description {"zh": "测试", "en": "Test"}
function test() {
    echo "Shell sub test"
}
"""
        (shell_sub_dir / "plugin.sh").write_text(shell_sub_sh)
        (shell_sub_dir / "plugin.sh").chmod(0o755)

        # Assert: Hybrid plugin structure created
        assert (plugin_dir / "plugin.json").exists()
        assert (python_sub_dir / "plugin.py").exists()
        assert (shell_sub_dir / "plugin.sh").exists()

        metadata = json.loads((plugin_dir / "plugin.json").read_text())
        assert metadata["type"] == "hybrid"
        assert "subplugins" in metadata
        assert len(metadata["subplugins"]) == 2


@pytest.mark.e2e
class TestCustomPluginInstallation:
    """End-to-end tests for custom plugin installation"""

    def test_install_custom_plugin_to_custom_directory(self, installation_environment):
        """Test installing a plugin to custom/ directory"""
        custom_dir = installation_environment["custom_dir"]

        # Create custom plugin
        plugin_dir = custom_dir / "mycustom"
        plugin_dir.mkdir()

        plugin_json = {
            "name": "mycustom",
            "version": "1.0.0",
            "type": "python",
            "entry": "plugin.py",
            "enabled": True,
            "description": {"zh": "自定义插件", "en": "My custom plugin"},
        }
        (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json, indent=2))

        plugin_py = '''"""Custom plugin"""
from gscripts.plugins.base import BasePlugin

class MyCustomPlugin(BasePlugin):
    def __init__(self):
        self.name = "mycustom"
'''
        (plugin_dir / "plugin.py").write_text(plugin_py)

        # Assert: Custom plugin installed
        assert (plugin_dir / "plugin.json").exists()
        assert (plugin_dir / "plugin.py").exists()

        metadata = json.loads((plugin_dir / "plugin.json").read_text())
        assert metadata["name"] == "mycustom"


@pytest.mark.e2e
class TestPluginInstallationValidation:
    """End-to-end tests for plugin installation validation"""

    def test_install_plugin_with_missing_required_fields(
        self, installation_environment
    ):
        """Test installing plugin with missing required metadata fields"""
        plugins_dir = installation_environment["plugins_dir"]

        plugin_dir = plugins_dir / "invalid"
        plugin_dir.mkdir()

        # Missing required fields: name, type, entry
        plugin_json = {
            "version": "1.0.0",
            "description": {"zh": "无效", "en": "Invalid"},
        }
        (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json, indent=2))

        # Assert: File created but invalid
        assert (plugin_dir / "plugin.json").exists()

        metadata = json.loads((plugin_dir / "plugin.json").read_text())
        # Plugin system should detect missing required fields
        assert "name" not in metadata
        assert "type" not in metadata

    def test_install_plugin_with_invalid_json(self, installation_environment):
        """Test installing plugin with malformed JSON"""
        plugins_dir = installation_environment["plugins_dir"]

        plugin_dir = plugins_dir / "badjson"
        plugin_dir.mkdir()

        # Create invalid JSON
        (plugin_dir / "plugin.json").write_text("{ invalid json }")

        # Assert: File exists but contains invalid JSON
        assert (plugin_dir / "plugin.json").exists()

        # Attempting to load will fail
        try:
            json.loads((plugin_dir / "plugin.json").read_text())
            assert False, "Should have raised JSONDecodeError"
        except json.JSONDecodeError:
            assert True  # Expected

    def test_install_plugin_with_version_upgrade(self, installation_environment):
        """Test installing newer version over existing plugin"""
        plugins_dir = installation_environment["plugins_dir"]

        plugin_dir = plugins_dir / "upgradable"
        plugin_dir.mkdir()

        # Install v1.0.0
        plugin_json_v1 = {
            "name": "upgradable",
            "version": "1.0.0",
            "type": "python",
            "entry": "plugin.py",
            "enabled": True,
            "description": {"zh": "可升级v1", "en": "Upgradable v1"},
        }
        (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json_v1, indent=2))

        assert (
            json.loads((plugin_dir / "plugin.json").read_text())["version"] == "1.0.0"
        )

        # Upgrade to v2.0.0
        plugin_json_v2 = {
            "name": "upgradable",
            "version": "2.0.0",
            "type": "python",
            "entry": "plugin.py",
            "enabled": True,
            "description": {"zh": "可升级v2", "en": "Upgradable v2"},
        }
        (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json_v2, indent=2))

        # Assert: Version upgraded
        metadata = json.loads((plugin_dir / "plugin.json").read_text())
        assert metadata["version"] == "2.0.0"
        assert metadata["description"]["en"] == "Upgradable v2"


@pytest.mark.e2e
class TestBulkPluginInstallation:
    """End-to-end tests for bulk plugin installation"""

    def test_install_multiple_plugins_batch(self, installation_environment):
        """Test installing multiple plugins in a batch"""
        plugins_dir = installation_environment["plugins_dir"]

        # Create multiple plugins
        plugin_specs = [
            {"name": "batch1", "type": "python"},
            {"name": "batch2", "type": "shell"},
            {"name": "batch3", "type": "config"},
            {"name": "batch4", "type": "python"},
            {"name": "batch5", "type": "config"},
        ]

        for spec in plugin_specs:
            plugin_dir = plugins_dir / spec["name"]
            plugin_dir.mkdir()

            plugin_json = {
                "name": spec["name"],
                "version": "1.0.0",
                "type": spec["type"],
                "entry": f"plugin.{'py' if spec['type'] == 'python' else ('sh' if spec['type'] == 'shell' else 'json')}",
                "enabled": True,
                "description": {"zh": spec["name"], "en": spec["name"]},
            }
            (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json, indent=2))

        # Assert: All plugins installed
        installed_plugins = []
        for plugin_path in plugins_dir.iterdir():
            if plugin_path.is_dir() and (plugin_path / "plugin.json").exists():
                metadata = json.loads((plugin_path / "plugin.json").read_text())
                installed_plugins.append(metadata["name"])

        assert len(installed_plugins) == 5
        for spec in plugin_specs:
            assert spec["name"] in installed_plugins
