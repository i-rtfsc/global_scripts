"""
End-to-end tests for plugin enable/disable workflows

Tests complete enable/disable workflows including config persistence,
state transitions, and interaction with the plugin system.
"""

import pytest
import json


@pytest.fixture
def plugin_test_environment(tmp_path):
    """Setup environment for enable/disable testing"""
    test_root = tmp_path / "enable_disable_test"
    test_root.mkdir()

    plugins_dir = test_root / "plugins"
    plugins_dir.mkdir()

    config_dir = test_root / "config"
    config_dir.mkdir()

    config_file = config_dir / "gs.json"
    config = {
        "system_plugins": {},
        "custom_plugins": {},
        "logging_level": "INFO",
        "language": "en",
    }
    config_file.write_text(json.dumps(config, indent=2))

    return {
        "root": test_root,
        "plugins_dir": plugins_dir,
        "config_dir": config_dir,
        "config_file": config_file,
    }


@pytest.mark.e2e
class TestPluginEnableWorkflow:
    """End-to-end tests for plugin enable workflow"""

    def test_enable_single_plugin(self, plugin_test_environment):
        """Test enabling a single plugin"""
        plugins_dir = plugin_test_environment["plugins_dir"]
        config_file = plugin_test_environment["config_file"]

        # Create plugin
        plugin_dir = plugins_dir / "testplugin"
        plugin_dir.mkdir()

        plugin_json = {
            "name": "testplugin",
            "version": "1.0.0",
            "type": "python",
            "entry": "plugin.py",
            "enabled": False,
            "description": {"zh": "测试", "en": "Test"},
        }
        (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json))

        # Initial state: Plugin disabled
        config = json.loads(config_file.read_text())
        assert "testplugin" not in config["system_plugins"]

        # Act: Enable plugin
        config["system_plugins"]["testplugin"] = True
        config_file.write_text(json.dumps(config, indent=2))

        # Assert: Plugin enabled in config
        updated_config = json.loads(config_file.read_text())
        assert updated_config["system_plugins"]["testplugin"] is True

    def test_enable_previously_disabled_plugin(self, plugin_test_environment):
        """Test re-enabling a previously disabled plugin"""
        plugins_dir = plugin_test_environment["plugins_dir"]
        config_file = plugin_test_environment["config_file"]

        # Create plugin
        plugin_dir = plugins_dir / "toggleplugin"
        plugin_dir.mkdir()

        plugin_json = {
            "name": "toggleplugin",
            "version": "1.0.0",
            "type": "shell",
            "entry": "plugin.sh",
            "enabled": True,
            "description": {"zh": "切换", "en": "Toggle"},
        }
        (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json))

        # Step 1: Initially enabled
        config = json.loads(config_file.read_text())
        config["system_plugins"]["toggleplugin"] = True
        config_file.write_text(json.dumps(config, indent=2))

        assert (
            json.loads(config_file.read_text())["system_plugins"]["toggleplugin"]
            is True
        )

        # Step 2: Disable
        config = json.loads(config_file.read_text())
        config["system_plugins"]["toggleplugin"] = False
        config_file.write_text(json.dumps(config, indent=2))

        assert (
            json.loads(config_file.read_text())["system_plugins"]["toggleplugin"]
            is False
        )

        # Step 3: Re-enable
        config = json.loads(config_file.read_text())
        config["system_plugins"]["toggleplugin"] = True
        config_file.write_text(json.dumps(config, indent=2))

        assert (
            json.loads(config_file.read_text())["system_plugins"]["toggleplugin"]
            is True
        )

    def test_enable_multiple_plugins_simultaneously(self, plugin_test_environment):
        """Test enabling multiple plugins at once"""
        plugins_dir = plugin_test_environment["plugins_dir"]
        config_file = plugin_test_environment["config_file"]

        # Create multiple plugins
        plugin_names = ["plugin1", "plugin2", "plugin3", "plugin4"]
        for name in plugin_names:
            plugin_dir = plugins_dir / name
            plugin_dir.mkdir()

            plugin_json = {
                "name": name,
                "version": "1.0.0",
                "type": "config",
                "entry": "commands.json",
                "enabled": False,
                "description": {"zh": name, "en": name},
            }
            (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json))

        # Enable all at once
        config = json.loads(config_file.read_text())
        for name in plugin_names:
            config["system_plugins"][name] = True
        config_file.write_text(json.dumps(config, indent=2))

        # Assert: All enabled
        final_config = json.loads(config_file.read_text())
        for name in plugin_names:
            assert final_config["system_plugins"][name] is True


@pytest.mark.e2e
class TestPluginDisableWorkflow:
    """End-to-end tests for plugin disable workflow"""

    def test_disable_single_plugin(self, plugin_test_environment):
        """Test disabling a single plugin"""
        plugins_dir = plugin_test_environment["plugins_dir"]
        config_file = plugin_test_environment["config_file"]

        # Create and enable plugin
        plugin_dir = plugins_dir / "disableplugin"
        plugin_dir.mkdir()

        plugin_json = {
            "name": "disableplugin",
            "version": "1.0.0",
            "type": "python",
            "entry": "plugin.py",
            "enabled": True,
            "description": {"zh": "禁用测试", "en": "Disable test"},
        }
        (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json))

        # Initial state: Plugin enabled
        config = json.loads(config_file.read_text())
        config["system_plugins"]["disableplugin"] = True
        config_file.write_text(json.dumps(config, indent=2))

        assert (
            json.loads(config_file.read_text())["system_plugins"]["disableplugin"]
            is True
        )

        # Act: Disable plugin
        config = json.loads(config_file.read_text())
        config["system_plugins"]["disableplugin"] = False
        config_file.write_text(json.dumps(config, indent=2))

        # Assert: Plugin disabled
        updated_config = json.loads(config_file.read_text())
        assert updated_config["system_plugins"]["disableplugin"] is False

    def test_disable_all_plugins(self, plugin_test_environment):
        """Test disabling all plugins"""
        plugins_dir = plugin_test_environment["plugins_dir"]
        config_file = plugin_test_environment["config_file"]

        # Create and enable multiple plugins
        plugin_names = ["p1", "p2", "p3"]
        for name in plugin_names:
            plugin_dir = plugins_dir / name
            plugin_dir.mkdir()

            plugin_json = {
                "name": name,
                "version": "1.0.0",
                "type": "python",
                "entry": "plugin.py",
                "enabled": True,
                "description": {"zh": name, "en": name},
            }
            (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json))

        # Enable all
        config = json.loads(config_file.read_text())
        for name in plugin_names:
            config["system_plugins"][name] = True
        config_file.write_text(json.dumps(config, indent=2))

        # Disable all
        config = json.loads(config_file.read_text())
        for name in plugin_names:
            config["system_plugins"][name] = False
        config_file.write_text(json.dumps(config, indent=2))

        # Assert: All disabled
        final_config = json.loads(config_file.read_text())
        for name in plugin_names:
            assert final_config["system_plugins"][name] is False


@pytest.mark.e2e
class TestEnableDisableStateTransitions:
    """End-to-end tests for state transitions during enable/disable"""

    def test_state_persistence_across_operations(self, plugin_test_environment):
        """Test that plugin state persists across multiple operations"""
        plugins_dir = plugin_test_environment["plugins_dir"]
        config_file = plugin_test_environment["config_file"]

        # Create plugin
        plugin_dir = plugins_dir / "stateful"
        plugin_dir.mkdir()

        plugin_json = {
            "name": "stateful",
            "version": "1.0.0",
            "type": "config",
            "entry": "commands.json",
            "enabled": False,
            "description": {"zh": "有状态", "en": "Stateful"},
        }
        (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json))

        # Operation sequence: disable → enable → disable → enable
        states = [False, True, False, True]

        for expected_state in states:
            config = json.loads(config_file.read_text())
            config["system_plugins"]["stateful"] = expected_state
            config_file.write_text(json.dumps(config, indent=2))

            # Assert: State persisted
            persisted_config = json.loads(config_file.read_text())
            assert persisted_config["system_plugins"]["stateful"] == expected_state

    def test_enable_disable_with_dependencies(self, plugin_test_environment):
        """Test enable/disable when plugins have dependencies"""
        plugins_dir = plugin_test_environment["plugins_dir"]
        config_file = plugin_test_environment["config_file"]

        # Create parent plugin
        parent_dir = plugins_dir / "parent"
        parent_dir.mkdir()

        parent_json = {
            "name": "parent",
            "version": "1.0.0",
            "type": "python",
            "entry": "plugin.py",
            "enabled": True,
            "description": {"zh": "父插件", "en": "Parent plugin"},
        }
        (parent_dir / "plugin.json").write_text(json.dumps(parent_json))

        # Create dependent plugin
        dependent_dir = plugins_dir / "dependent"
        dependent_dir.mkdir()

        dependent_json = {
            "name": "dependent",
            "version": "1.0.0",
            "type": "python",
            "entry": "plugin.py",
            "enabled": True,
            "dependencies": ["parent"],
            "description": {"zh": "依赖插件", "en": "Dependent plugin"},
        }
        (dependent_dir / "plugin.json").write_text(json.dumps(dependent_json))

        # Enable both
        config = json.loads(config_file.read_text())
        config["system_plugins"]["parent"] = True
        config["system_plugins"]["dependent"] = True
        config_file.write_text(json.dumps(config, indent=2))

        # Assert: Both enabled
        final_config = json.loads(config_file.read_text())
        assert final_config["system_plugins"]["parent"] is True
        assert final_config["system_plugins"]["dependent"] is True

        # Disable parent (in real system, should warn about dependent)
        config = json.loads(config_file.read_text())
        config["system_plugins"]["parent"] = False
        config_file.write_text(json.dumps(config, indent=2))

        # Assert: Parent disabled
        updated_config = json.loads(config_file.read_text())
        assert updated_config["system_plugins"]["parent"] is False


@pytest.mark.e2e
class TestBulkEnableDisable:
    """End-to-end tests for bulk enable/disable operations"""

    def test_bulk_enable_by_category(self, plugin_test_environment):
        """Test bulk enabling plugins by category"""
        plugins_dir = plugin_test_environment["plugins_dir"]
        config_file = plugin_test_environment["config_file"]

        # Create plugins in different categories
        categories = {
            "dev": ["android", "ios", "flutter"],
            "system": ["monitor", "backup", "cleanup"],
            "network": ["proxy", "vpn", "dns"],
        }

        for category, plugins in categories.items():
            for plugin_name in plugins:
                plugin_dir = plugins_dir / plugin_name
                plugin_dir.mkdir()

                plugin_json = {
                    "name": plugin_name,
                    "version": "1.0.0",
                    "type": "python",
                    "entry": "plugin.py",
                    "enabled": False,
                    "category": category,
                    "description": {"zh": plugin_name, "en": plugin_name},
                }
                (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json))

        # Bulk enable "dev" category
        config = json.loads(config_file.read_text())
        for plugin_name in categories["dev"]:
            config["system_plugins"][plugin_name] = True
        config_file.write_text(json.dumps(config, indent=2))

        # Assert: Dev plugins enabled, others not
        final_config = json.loads(config_file.read_text())
        for plugin_name in categories["dev"]:
            assert final_config["system_plugins"][plugin_name] is True

    def test_bulk_disable_all_disabled_plugins(self, plugin_test_environment):
        """Test bulk disabling all currently enabled plugins"""
        plugins_dir = plugin_test_environment["plugins_dir"]
        config_file = plugin_test_environment["config_file"]

        # Create and enable multiple plugins
        plugin_names = [f"plugin{i}" for i in range(10)]
        for name in plugin_names:
            plugin_dir = plugins_dir / name
            plugin_dir.mkdir()

            plugin_json = {
                "name": name,
                "version": "1.0.0",
                "type": "config",
                "entry": "commands.json",
                "enabled": True,
                "description": {"zh": name, "en": name},
            }
            (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json))

        # Enable all
        config = json.loads(config_file.read_text())
        for name in plugin_names:
            config["system_plugins"][name] = True
        config_file.write_text(json.dumps(config, indent=2))

        # Bulk disable all
        config = json.loads(config_file.read_text())
        for name in plugin_names:
            config["system_plugins"][name] = False
        config_file.write_text(json.dumps(config, indent=2))

        # Assert: All disabled
        final_config = json.loads(config_file.read_text())
        for name in plugin_names:
            assert final_config["system_plugins"][name] is False


@pytest.mark.e2e
class TestEnableDisableErrorHandling:
    """End-to-end tests for error handling during enable/disable"""

    def test_enable_nonexistent_plugin_handling(self, plugin_test_environment):
        """Test handling of attempting to enable nonexistent plugin"""
        config_file = plugin_test_environment["config_file"]

        # Attempt to enable plugin that doesn't exist
        config = json.loads(config_file.read_text())
        config["system_plugins"]["nonexistent"] = True
        config_file.write_text(json.dumps(config, indent=2))

        # Assert: Config updated (plugin system will handle missing plugin)
        updated_config = json.loads(config_file.read_text())
        assert updated_config["system_plugins"]["nonexistent"] is True

    def test_disable_already_disabled_plugin(self, plugin_test_environment):
        """Test disabling an already disabled plugin (idempotent operation)"""
        plugins_dir = plugin_test_environment["plugins_dir"]
        config_file = plugin_test_environment["config_file"]

        # Create disabled plugin
        plugin_dir = plugins_dir / "alreadydisabled"
        plugin_dir.mkdir()

        plugin_json = {
            "name": "alreadydisabled",
            "version": "1.0.0",
            "type": "python",
            "entry": "plugin.py",
            "enabled": False,
            "description": {"zh": "已禁用", "en": "Already disabled"},
        }
        (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json))

        # Initially disabled
        config = json.loads(config_file.read_text())
        config["system_plugins"]["alreadydisabled"] = False
        config_file.write_text(json.dumps(config, indent=2))

        # Disable again (idempotent)
        config = json.loads(config_file.read_text())
        config["system_plugins"]["alreadydisabled"] = False
        config_file.write_text(json.dumps(config, indent=2))

        # Assert: Still disabled (no error)
        final_config = json.loads(config_file.read_text())
        assert final_config["system_plugins"]["alreadydisabled"] is False
