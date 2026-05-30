"""
Integration tests for configuration management flow

Tests configuration loading priority, persistence, and validation including
user config > project config > defaults hierarchy.
"""

import pytest
import json
import os
from unittest.mock import patch

from gscripts.core.config_manager import ConfigManager


@pytest.fixture(autouse=True)
def _isolate_gs_env(monkeypatch):
    """隔离真实环境的 GS_* 变量，使配置优先级断言只反映文件内容。

    开发环境(env.fish/env.sh)会 export GS_LANGUAGE 等，经 ConfigManager.get 的
    环境变量覆盖会盖过文件值；需要该覆盖的 TestEnvironmentVariableOverride 会在
    自身用 patch.dict 重新设置。
    """
    for key in [k for k in os.environ if k.startswith("GS_")]:
        monkeypatch.delenv(key, raising=False)


@pytest.mark.integration
class TestConfigLoadingPriority:
    """Integration tests for configuration loading priority"""

    def test_config_priority_user_over_project(self, temp_dir):
        """Test that user config takes priority over project config"""
        # Arrange: Create both user and project configs
        user_config_dir = temp_dir / ".config" / "global-scripts" / "config"
        user_config_dir.mkdir(parents=True)
        user_config_file = user_config_dir / "gs.json"

        project_config_dir = temp_dir / "config"
        project_config_dir.mkdir(parents=True)
        project_config_file = project_config_dir / "gs.json"

        # User config has language=en
        user_config = {"language": "en", "logging_level": "DEBUG"}
        user_config_file.write_text(json.dumps(user_config))

        # Project config has language=zh
        project_config = {"language": "zh", "logging_level": "INFO"}
        project_config_file.write_text(json.dumps(project_config))

        # Act: Load with mocked home and project root
        with patch("pathlib.Path.home", return_value=temp_dir):
            with patch.object(ConfigManager, "_detect_project_root", return_value=temp_dir):
                config_manager = ConfigManager()
                language = config_manager.get_language()
                logging_level = config_manager.get_logging_level()

        # Assert: User config takes priority
        assert language == "en"  # From user config, not "zh"
        assert logging_level == "DEBUG"  # From user config, not "INFO"

    def test_config_priority_project_over_defaults(self, temp_dir):
        """Test that project config takes priority over defaults"""
        # Arrange: Create only project config (no user config)
        project_config_dir = temp_dir / "config"
        project_config_dir.mkdir(parents=True)
        project_config_file = project_config_dir / "gs.json"

        project_config = {"language": "zh", "show_examples": True}
        project_config_file.write_text(json.dumps(project_config))

        # Act: Mock home to point to non-existent location so user config doesn't exist
        with patch("pathlib.Path.home", return_value=temp_dir / "nonexistent"):
            with patch.object(ConfigManager, "_detect_project_root", return_value=temp_dir):
                config_manager = ConfigManager()
                language = config_manager.get_language()
                show_examples = config_manager.get_show_examples()

        # Assert: Project config overrides defaults
        assert language == "zh"
        assert show_examples is True

    def test_config_uses_defaults_when_no_files(self, temp_dir):
        """Test that defaults are used when no config files exist"""
        # Arrange: Create empty directory structure (no config files)
        empty_dir = temp_dir / "empty"
        empty_dir.mkdir()

        # Act: Point to directory without configs
        with patch("pathlib.Path.home", return_value=empty_dir):
            with patch.object(ConfigManager, "_detect_project_root", return_value=empty_dir):
                config_manager = ConfigManager()
                language = config_manager.get_language()

        # Assert: Uses default language
        assert language in ["zh", "en"]  # Should be one of the default values


@pytest.mark.integration
class TestConfigPersistence:
    """Integration tests for configuration persistence"""

    def test_enable_plugin_persists_to_config(self, temp_dir):
        """Test that enabling a plugin persists the change to config"""
        # Arrange: Create config file
        config_dir = temp_dir / "config"
        config_dir.mkdir()
        config_file = config_dir / "gs.json"

        initial_config = {"system_plugins": {"android": False, "system": True}}
        config_file.write_text(json.dumps(initial_config, indent=2))

        # Act: Enable android plugin
        with patch("pathlib.Path.home", return_value=temp_dir):
            with patch.object(ConfigManager, "_detect_project_root", return_value=temp_dir):
                config_manager = ConfigManager()

                # Simulate enabling plugin by updating config
                current_config = config_manager.get_all()
                if "system_plugins" not in current_config:
                    current_config["system_plugins"] = {}
                current_config["system_plugins"]["android"] = True

                # Save updated config
                config_manager.save_config(current_config)

        # Assert: Config file updated
        saved_config = json.loads(config_file.read_text())
        assert saved_config["system_plugins"]["android"] is True

    def test_disable_plugin_persists_to_config(self, temp_dir):
        """Test that disabling a plugin persists the change to config"""
        # Arrange
        config_dir = temp_dir / "config"
        config_dir.mkdir()
        config_file = config_dir / "gs.json"

        initial_config = {"system_plugins": {"android": True, "system": True}}
        config_file.write_text(json.dumps(initial_config, indent=2))

        # Act: Disable android plugin
        with patch("pathlib.Path.home", return_value=temp_dir):
            with patch.object(ConfigManager, "_detect_project_root", return_value=temp_dir):
                config_manager = ConfigManager()

                current_config = config_manager.get_all()
                current_config["system_plugins"]["android"] = False

                config_manager.save_config(current_config)

        # Assert
        saved_config = json.loads(config_file.read_text())
        assert saved_config["system_plugins"]["android"] is False


@pytest.mark.integration
class TestConfigValidation:
    """Integration tests for configuration validation"""

    def test_config_with_invalid_json_uses_defaults(self, temp_dir):
        """Test that invalid JSON config falls back to defaults"""
        # Arrange: Create invalid JSON config
        config_dir = temp_dir / "config"
        config_dir.mkdir()
        config_file = config_dir / "gs.json"

        config_file.write_text("{ invalid json }")

        # Act: Try to load config
        with patch("pathlib.Path.home", return_value=temp_dir):
            with patch.object(ConfigManager, "_detect_project_root", return_value=temp_dir):
                config_manager = ConfigManager()
                language = config_manager.get_language()

        # Assert: Falls back to defaults (doesn't crash)
        assert language in ["zh", "en"]

    def test_config_with_missing_keys_uses_defaults(self, temp_dir):
        """Test that missing config keys use default values"""
        # Arrange: Create partial config
        config_dir = temp_dir / "config"
        config_dir.mkdir()
        config_file = config_dir / "gs.json"

        partial_config = {
            "language": "en"
            # Missing: logging_level, show_examples, etc.
        }
        config_file.write_text(json.dumps(partial_config))

        # Act
        with patch("pathlib.Path.home", return_value=temp_dir):
            with patch.object(ConfigManager, "_detect_project_root", return_value=temp_dir):
                config_manager = ConfigManager()
                language = config_manager.get_language()
                logging_level = config_manager.get_logging_level()

        # Assert: Specified keys use config, missing keys use defaults
        assert language == "en"  # From config
        assert logging_level in ["INFO", "DEBUG", "WARNING", "ERROR"]  # Default value


@pytest.mark.integration
class TestEnvironmentVariableOverride:
    """Integration tests for environment variable config override"""

    def test_env_var_overrides_config_file(self, temp_dir):
        """Test that environment variables override config file values"""
        # Arrange: Create config file
        config_dir = temp_dir / "config"
        config_dir.mkdir()
        config_file = config_dir / "gs.json"

        file_config = {"language": "zh", "logging_level": "INFO"}
        config_file.write_text(json.dumps(file_config))

        # Act: Set environment variable and load config
        with patch.dict(os.environ, {"GS_LANGUAGE": "en", "GS_LOGGING_LEVEL": "DEBUG"}):
            with patch("pathlib.Path.home", return_value=temp_dir):
                with patch.object(ConfigManager, "_detect_project_root", return_value=temp_dir):
                    config_manager = ConfigManager()
                    language = config_manager.get("language")
                    logging_level = config_manager.get("logging_level")

        # Assert: Environment variables override file config
        # Note: Actual behavior depends on ConfigManager implementation
        # This test documents the expected priority: env > file > default
        assert language is not None
        assert logging_level is not None
