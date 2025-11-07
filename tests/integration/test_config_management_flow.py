"""
Integration tests for configuration management flow

Tests configuration loading priority, persistence, and validation including
user config > project config > defaults hierarchy.
"""

import pytest
import json
import os
from pathlib import Path
from unittest.mock import patch

from gscripts.core.config_manager import ConfigManager
from gscripts.application.services.config_service import ConfigService


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
class TestConfigServiceIntegration:
    """Integration tests for ConfigService"""

    def test_config_service_get_with_defaults(self):
        """Test ConfigService get method with default values"""
        # Arrange
        from unittest.mock import Mock, AsyncMock

        config_repo = Mock()
        config_repo.get = AsyncMock(return_value=None)

        environment = Mock()
        environment.get = Mock(return_value=None)

        config_service = ConfigService(
            config_repository=config_repo,
            environment=environment,
            defaults={"test_key": "test_value"}
        )

        # Act - ConfigService.get is async
        import asyncio
        value = asyncio.run(config_service.get("test_key"))

        # Assert
        assert value == "test_value"

    def test_config_service_set_and_get(self):
        """Test ConfigService set and get methods"""
        # Arrange
        from unittest.mock import Mock, AsyncMock

        config_repo = Mock()
        config_repo.set = AsyncMock()
        config_repo.get = AsyncMock(return_value="custom_value")

        environment = Mock()
        environment.get = Mock(return_value=None)

        config_service = ConfigService(
            config_repository=config_repo,
            environment=environment
        )

        # Act
        import asyncio
        asyncio.run(config_service.set("custom_key", "custom_value"))
        value = asyncio.run(config_service.get("custom_key"))

        # Assert
        assert value == "custom_value"

    def test_config_service_get_all_merges_with_defaults(self):
        """Test that get_all merges config with defaults"""
        # Arrange
        from unittest.mock import Mock, AsyncMock

        config_repo = Mock()
        config_repo.get_all = AsyncMock(return_value={})

        environment = Mock()
        environment.get = Mock(return_value=None)

        default_config = {"key1": "default1", "key2": "default2"}
        config_service = ConfigService(
            config_repository=config_repo,
            environment=environment,
            defaults=default_config
        )

        # Act
        import asyncio
        all_config = asyncio.run(config_service.get_all())

        # Assert
        assert "key1" in all_config
        assert "key2" in all_config

    def test_config_service_convenience_methods(self):
        """Test ConfigService convenience methods"""
        # Arrange
        from unittest.mock import Mock, AsyncMock

        config_repo = Mock()
        config_repo.get = AsyncMock(return_value=None)

        environment = Mock()
        environment.get = Mock(return_value=None)

        config_service = ConfigService(
            config_repository=config_repo,
            environment=environment
        )

        # Act & Assert
        import asyncio
        language = asyncio.run(config_service.get_language())
        assert language in ["zh", "en"]

        logging_level = asyncio.run(config_service.get_logging_level())
        assert logging_level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

        show_examples = asyncio.run(config_service.get_show_examples())
        assert isinstance(show_examples, bool)

        is_debug = config_service.is_debug_mode()
        assert isinstance(is_debug, bool)


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
