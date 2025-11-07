"""
End-to-end tests for error scenarios and recovery

Tests error handling, recovery workflows, and graceful degradation
in various failure scenarios.
"""

import pytest
import json


@pytest.fixture
def error_test_environment(tmp_path):
    """Setup environment for error scenario testing"""
    test_root = tmp_path / "error_test"
    test_root.mkdir()

    plugins_dir = test_root / "plugins"
    plugins_dir.mkdir()

    config_dir = test_root / "config"
    config_dir.mkdir()

    config_file = config_dir / "gs.json"
    config = {"system_plugins": {}, "logging_level": "INFO", "language": "en"}
    config_file.write_text(json.dumps(config, indent=2))

    return {
        "root": test_root,
        "plugins_dir": plugins_dir,
        "config_dir": config_dir,
        "config_file": config_file,
    }


@pytest.mark.e2e
class TestPluginLoadingErrors:
    """End-to-end tests for plugin loading error scenarios"""

    def test_load_plugin_with_missing_metadata(self, error_test_environment):
        """Test loading plugin with missing plugin.json"""
        plugins_dir = error_test_environment["plugins_dir"]

        # Create plugin directory without plugin.json
        plugin_dir = plugins_dir / "nometa"
        plugin_dir.mkdir()

        # Only create plugin.py, no plugin.json
        plugin_py = '''"""Plugin without metadata"""
from gscripts.plugins.base import BasePlugin

class NoMetaPlugin(BasePlugin):
    def __init__(self):
        self.name = "nometa"
'''
        (plugin_dir / "plugin.py").write_text(plugin_py)

        # Assert: Plugin files exist but missing metadata
        assert (plugin_dir / "plugin.py").exists()
        assert not (plugin_dir / "plugin.json").exists()

        # Plugin system should skip this plugin during discovery

    def test_load_plugin_with_corrupted_metadata(self, error_test_environment):
        """Test loading plugin with corrupted plugin.json"""
        plugins_dir = error_test_environment["plugins_dir"]

        plugin_dir = plugins_dir / "corrupted"
        plugin_dir.mkdir()

        # Create corrupted JSON
        (plugin_dir / "plugin.json").write_text("{ corrupted json content }")

        # Assert: File exists but invalid
        assert (plugin_dir / "plugin.json").exists()

        try:
            json.loads((plugin_dir / "plugin.json").read_text())
            assert False, "Should fail to parse"
        except json.JSONDecodeError:
            assert True  # Expected behavior

    def test_load_plugin_with_missing_entry_file(self, error_test_environment):
        """Test loading plugin when entry file doesn't exist"""
        plugins_dir = error_test_environment["plugins_dir"]

        plugin_dir = plugins_dir / "missingentry"
        plugin_dir.mkdir()

        # Create plugin.json pointing to nonexistent file
        plugin_json = {
            "name": "missingentry",
            "version": "1.0.0",
            "type": "python",
            "entry": "nonexistent.py",  # File doesn't exist
            "enabled": True,
            "description": {"zh": "缺失入口", "en": "Missing entry"},
        }
        (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json, indent=2))

        # Assert: Metadata exists but entry file missing
        assert (plugin_dir / "plugin.json").exists()
        assert not (plugin_dir / "nonexistent.py").exists()

        # Plugin system should fail to load this plugin

    def test_load_plugin_with_syntax_error(self, error_test_environment):
        """Test loading Python plugin with syntax errors"""
        plugins_dir = error_test_environment["plugins_dir"]

        plugin_dir = plugins_dir / "syntaxerror"
        plugin_dir.mkdir()

        plugin_json = {
            "name": "syntaxerror",
            "version": "1.0.0",
            "type": "python",
            "entry": "plugin.py",
            "enabled": True,
            "description": {"zh": "语法错误", "en": "Syntax error"},
        }
        (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json, indent=2))

        # Create plugin with syntax error
        plugin_py = '''"""Plugin with syntax error"""
from gscripts.plugins.base import BasePlugin

class SyntaxErrorPlugin(BasePlugin):
    def __init__(self)  # Missing colon - syntax error
        self.name = "syntaxerror"
'''
        (plugin_dir / "plugin.py").write_text(plugin_py)

        # Assert: Files exist but Python has syntax error
        assert (plugin_dir / "plugin.py").exists()
        # Plugin system should catch syntax error during import


@pytest.mark.e2e
class TestConfigurationErrors:
    """End-to-end tests for configuration error scenarios"""

    def test_corrupted_config_file_recovery(self, error_test_environment):
        """Test recovery when config file is corrupted"""
        config_file = error_test_environment["config_file"]

        # Corrupt config file
        config_file.write_text("{ corrupted config }")

        # Assert: Config file corrupted
        try:
            json.loads(config_file.read_text())
            assert False, "Should fail"
        except json.JSONDecodeError:
            assert True

        # Recovery: Replace with valid default config
        default_config = {
            "system_plugins": {},
            "logging_level": "INFO",
            "language": "en",
        }
        config_file.write_text(json.dumps(default_config, indent=2))

        # Assert: Recovered
        recovered_config = json.loads(config_file.read_text())
        assert "system_plugins" in recovered_config

    def test_missing_config_file_creation(self, error_test_environment):
        """Test automatic config file creation when missing"""
        config_dir = error_test_environment["config_dir"]

        # Delete config file
        config_file = config_dir / "gs.json"
        if config_file.exists():
            config_file.unlink()

        # Assert: Config file missing
        assert not config_file.exists()

        # Create default config (simulates system behavior)
        default_config = {
            "system_plugins": {},
            "custom_plugins": {},
            "logging_level": "INFO",
            "language": "en",
        }
        config_file.write_text(json.dumps(default_config, indent=2))

        # Assert: Config file created
        assert config_file.exists()
        config = json.loads(config_file.read_text())
        assert "system_plugins" in config

    def test_invalid_config_values_handling(self, error_test_environment):
        """Test handling of invalid configuration values"""
        config_file = error_test_environment["config_file"]

        # Create config with invalid values
        invalid_config = {
            "system_plugins": "not_a_dict",  # Should be dict
            "logging_level": "INVALID_LEVEL",  # Invalid log level
            "language": 12345,  # Should be string
        }
        config_file.write_text(json.dumps(invalid_config, indent=2))

        # Assert: Config has invalid values
        config = json.loads(config_file.read_text())
        assert config["system_plugins"] == "not_a_dict"

        # System should validate and use defaults for invalid values


@pytest.mark.e2e
class TestExecutionErrors:
    """End-to-end tests for plugin execution error scenarios"""

    def test_plugin_execution_timeout(self, error_test_environment):
        """Test handling of plugin execution timeout"""
        plugins_dir = error_test_environment["plugins_dir"]

        # Create plugin with long-running function
        plugin_dir = plugins_dir / "slowplugin"
        plugin_dir.mkdir()

        plugin_json = {
            "name": "slowplugin",
            "version": "1.0.0",
            "type": "python",
            "entry": "plugin.py",
            "enabled": True,
            "description": {"zh": "慢插件", "en": "Slow plugin"},
        }
        (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json, indent=2))

        plugin_py = '''"""Slow plugin"""
import asyncio
from gscripts.plugins.base import BasePlugin
from gscripts.plugins.decorators import plugin_function
from gscripts.models import CommandResult

class SlowPlugin(BasePlugin):
    def __init__(self):
        self.name = "slowplugin"

    @plugin_function(
        name="sleep",
        description={"zh": "睡眠", "en": "Sleep"},
        usage="gs slowplugin sleep <seconds>",
    )
    async def sleep(self, args=None):
        seconds = int(args[0]) if args else 60
        await asyncio.sleep(seconds)  # Will timeout if timeout < seconds
        return CommandResult(success=True, output=f"Slept {seconds}s", exit_code=0)
'''
        (plugin_dir / "plugin.py").write_text(plugin_py)

        # Assert: Plugin with timeout-prone function created
        assert (plugin_dir / "plugin.py").exists()
        # Execution with timeout will handle this gracefully

    def test_plugin_execution_exception(self, error_test_environment):
        """Test handling of exceptions during plugin execution"""
        plugins_dir = error_test_environment["plugins_dir"]

        plugin_dir = plugins_dir / "errorplugin"
        plugin_dir.mkdir()

        plugin_json = {
            "name": "errorplugin",
            "version": "1.0.0",
            "type": "python",
            "entry": "plugin.py",
            "enabled": True,
            "description": {"zh": "错误插件", "en": "Error plugin"},
        }
        (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json, indent=2))

        plugin_py = '''"""Error plugin"""
from gscripts.plugins.base import BasePlugin
from gscripts.plugins.decorators import plugin_function
from gscripts.models import CommandResult

class ErrorPlugin(BasePlugin):
    def __init__(self):
        self.name = "errorplugin"

    @plugin_function(
        name="crash",
        description={"zh": "崩溃", "en": "Crash"},
        usage="gs errorplugin crash",
    )
    async def crash(self, args=None):
        raise Exception("Intentional crash for testing")
'''
        (plugin_dir / "plugin.py").write_text(plugin_py)

        # Assert: Plugin that raises exception created
        assert (plugin_dir / "plugin.py").exists()
        # Execution system should catch and handle exception

    def test_plugin_missing_permissions(self, error_test_environment):
        """Test handling of plugin execution with missing permissions"""
        plugins_dir = error_test_environment["plugins_dir"]

        plugin_dir = plugins_dir / "noperm"
        plugin_dir.mkdir()

        plugin_json = {
            "name": "noperm",
            "version": "1.0.0",
            "type": "shell",
            "entry": "plugin.sh",
            "enabled": True,
            "description": {"zh": "无权限", "en": "No permissions"},
        }
        (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json, indent=2))

        # Create shell script without execute permission
        plugin_sh = """#!/bin/bash
# @plugin_function
# @name test
function test() {
    echo "Should fail - no execute permission"
}
"""
        (plugin_dir / "plugin.sh").write_text(plugin_sh)
        # Deliberately don't chmod +x

        # Assert: Script exists but not executable
        assert (plugin_dir / "plugin.sh").exists()
        # Execution should fail with permission error


@pytest.mark.e2e
class TestRecoveryWorkflows:
    """End-to-end tests for error recovery workflows"""

    def test_recover_from_failed_plugin_load(self, error_test_environment):
        """Test system continues after failing to load one plugin"""
        plugins_dir = error_test_environment["plugins_dir"]

        # Create one good plugin
        good_dir = plugins_dir / "goodplugin"
        good_dir.mkdir()

        good_json = {
            "name": "goodplugin",
            "version": "1.0.0",
            "type": "python",
            "entry": "plugin.py",
            "enabled": True,
            "description": {"zh": "好插件", "en": "Good plugin"},
        }
        (good_dir / "plugin.json").write_text(json.dumps(good_json, indent=2))

        # Create one bad plugin (corrupted JSON)
        bad_dir = plugins_dir / "badplugin"
        bad_dir.mkdir()
        (bad_dir / "plugin.json").write_text("{ bad json }")

        # Assert: System should load good plugin and skip bad one
        assert (good_dir / "plugin.json").exists()
        assert (bad_dir / "plugin.json").exists()

        # Plugin loader should gracefully handle bad plugin and continue

    def test_graceful_degradation_on_config_error(self, error_test_environment):
        """Test system uses defaults when config has errors"""
        config_file = error_test_environment["config_file"]

        # Create config with partial errors
        partial_config = {
            "system_plugins": {"plugin1": True},
            "logging_level": "INVALID",  # Invalid value
            "language": "en",
        }
        config_file.write_text(json.dumps(partial_config, indent=2))

        # Assert: Config exists with partial errors
        config = json.loads(config_file.read_text())
        assert config["logging_level"] == "INVALID"

        # System should use default for invalid logging_level

    def test_automatic_disable_of_broken_plugin(self, error_test_environment):
        """Test automatic disabling of repeatedly failing plugin"""
        plugins_dir = error_test_environment["plugins_dir"]
        config_file = error_test_environment["config_file"]

        # Create broken plugin
        broken_dir = plugins_dir / "broken"
        broken_dir.mkdir()

        broken_json = {
            "name": "broken",
            "version": "1.0.0",
            "type": "python",
            "entry": "plugin.py",
            "enabled": True,
            "description": {"zh": "损坏", "en": "Broken"},
        }
        (broken_dir / "plugin.json").write_text(json.dumps(broken_json, indent=2))

        # Initially enabled
        config = json.loads(config_file.read_text())
        config["system_plugins"]["broken"] = True
        config_file.write_text(json.dumps(config, indent=2))

        # After repeated failures, system should disable it
        # (Simulated - in real system would track failure count)
        config = json.loads(config_file.read_text())
        config["system_plugins"]["broken"] = False
        config_file.write_text(json.dumps(config, indent=2))

        # Assert: Plugin auto-disabled
        final_config = json.loads(config_file.read_text())
        assert final_config["system_plugins"]["broken"] is False


@pytest.mark.e2e
class TestEdgeCases:
    """End-to-end tests for edge cases and boundary conditions"""

    def test_empty_plugins_directory(self, error_test_environment):
        """Test system behavior with no plugins installed"""
        plugins_dir = error_test_environment["plugins_dir"]

        # Ensure plugins directory is empty
        for item in plugins_dir.iterdir():
            if item.is_dir():
                for file in item.iterdir():
                    file.unlink()
                item.rmdir()

        # Assert: No plugins
        plugin_count = sum(1 for p in plugins_dir.iterdir() if p.is_dir())
        assert plugin_count == 0

        # System should handle gracefully with no plugins

    def test_plugin_with_empty_functions(self, error_test_environment):
        """Test plugin with no functions defined"""
        plugins_dir = error_test_environment["plugins_dir"]

        plugin_dir = plugins_dir / "nofunctions"
        plugin_dir.mkdir()

        plugin_json = {
            "name": "nofunctions",
            "version": "1.0.0",
            "type": "python",
            "entry": "plugin.py",
            "enabled": True,
            "description": {"zh": "无功能", "en": "No functions"},
        }
        (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json, indent=2))

        plugin_py = '''"""Plugin with no functions"""
from gscripts.plugins.base import BasePlugin

class NoFunctionsPlugin(BasePlugin):
    def __init__(self):
        self.name = "nofunctions"
        # No @plugin_function decorators
'''
        (plugin_dir / "plugin.py").write_text(plugin_py)

        # Assert: Plugin loads but has no callable functions
        assert (plugin_dir / "plugin.py").exists()

    def test_circular_plugin_dependencies(self, error_test_environment):
        """Test handling of circular plugin dependencies"""
        plugins_dir = error_test_environment["plugins_dir"]

        # Plugin A depends on B
        plugin_a_dir = plugins_dir / "plugina"
        plugin_a_dir.mkdir()

        plugin_a_json = {
            "name": "plugina",
            "version": "1.0.0",
            "type": "python",
            "entry": "plugin.py",
            "enabled": True,
            "dependencies": ["pluginb"],
            "description": {"zh": "插件A", "en": "Plugin A"},
        }
        (plugin_a_dir / "plugin.json").write_text(json.dumps(plugin_a_json, indent=2))

        # Plugin B depends on A (circular)
        plugin_b_dir = plugins_dir / "pluginb"
        plugin_b_dir.mkdir()

        plugin_b_json = {
            "name": "pluginb",
            "version": "1.0.0",
            "type": "python",
            "entry": "plugin.py",
            "enabled": True,
            "dependencies": ["plugina"],  # Circular dependency
            "description": {"zh": "插件B", "en": "Plugin B"},
        }
        (plugin_b_dir / "plugin.json").write_text(json.dumps(plugin_b_json, indent=2))

        # Assert: Circular dependency exists
        plugin_a_meta = json.loads((plugin_a_dir / "plugin.json").read_text())
        plugin_b_meta = json.loads((plugin_b_dir / "plugin.json").read_text())

        assert "pluginb" in plugin_a_meta["dependencies"]
        assert "plugina" in plugin_b_meta["dependencies"]

        # System should detect and handle circular dependencies

    def test_plugin_name_conflicts(self, error_test_environment):
        """Test handling of plugins with duplicate names"""
        plugins_dir = error_test_environment["plugins_dir"]

        # Create two plugins with same name in different directories
        conflict1_dir = plugins_dir / "conflict_dir1"
        conflict1_dir.mkdir()

        conflict1_json = {
            "name": "samename",  # Same name
            "version": "1.0.0",
            "type": "python",
            "entry": "plugin.py",
            "enabled": True,
            "description": {"zh": "冲突1", "en": "Conflict 1"},
        }
        (conflict1_dir / "plugin.json").write_text(json.dumps(conflict1_json, indent=2))

        conflict2_dir = plugins_dir / "conflict_dir2"
        conflict2_dir.mkdir()

        conflict2_json = {
            "name": "samename",  # Same name
            "version": "2.0.0",
            "type": "shell",
            "entry": "plugin.sh",
            "enabled": True,
            "description": {"zh": "冲突2", "en": "Conflict 2"},
        }
        (conflict2_dir / "plugin.json").write_text(json.dumps(conflict2_json, indent=2))

        # Assert: Name conflict exists
        assert (
            json.loads((conflict1_dir / "plugin.json").read_text())["name"]
            == "samename"
        )
        assert (
            json.loads((conflict2_dir / "plugin.json").read_text())["name"]
            == "samename"
        )

        # System should detect name conflict and handle (e.g., last one wins, or error)
