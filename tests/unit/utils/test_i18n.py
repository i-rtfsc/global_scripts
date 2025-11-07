"""
Tests for I18nManager

Tests the internationalization utility for multi-language support.
"""

import json
from unittest.mock import patch

from gscripts.utils.i18n import I18nManager, get_i18n_manager, t, set_language


class TestI18nManagerInitialization:
    """Tests for I18nManager initialization"""

    def test_create_manager_with_default_path(self, tmp_path):
        """Test creating manager with default config path"""
        # Arrange & Act
        manager = I18nManager()

        # Assert
        assert manager.config_path is not None
        assert manager.current_language in ["en", "zh"]
        assert isinstance(manager._data, dict)

    @patch.dict("os.environ", {}, clear=True)
    def test_create_manager_with_custom_path(self, tmp_path):
        """Test creating manager with custom config path"""
        # Arrange
        config_file = tmp_path / "test_i18n.json"
        config_data = {
            "locale": {"default": "en"},
            "messages": {"test": {"en": "Hello", "zh": "你好"}},
        }
        config_file.write_text(json.dumps(config_data))

        # Act
        manager = I18nManager(config_path=config_file)

        # Assert
        assert manager.config_path == config_file
        assert manager.current_language == "en"

    def test_create_manager_with_chinese_flag_true(self, tmp_path):
        """Test creating manager with chinese=True"""
        # Arrange
        config_file = tmp_path / "test_i18n.json"
        config_file.write_text(json.dumps({"locale": {"default": "en"}}))

        # Act
        manager = I18nManager(config_path=config_file, chinese=True)

        # Assert
        assert manager.current_language == "zh"

    def test_create_manager_with_chinese_flag_false(self, tmp_path):
        """Test creating manager with chinese=False"""
        # Arrange
        config_file = tmp_path / "test_i18n.json"
        config_file.write_text(json.dumps({"locale": {"default": "zh"}}))

        # Act
        manager = I18nManager(config_path=config_file, chinese=False)

        # Assert
        assert manager.current_language == "en"


class TestLoadConfig:
    """Tests for _load_config method"""

    @patch.dict("os.environ", {}, clear=True)
    def test_load_config_success(self, tmp_path):
        """Test loading config successfully"""
        # Arrange
        config_file = tmp_path / "test_i18n.json"
        config_data = {
            "locale": {"default": "zh"},
            "messages": {"greeting": {"en": "Hello", "zh": "你好"}},
        }
        config_file.write_text(json.dumps(config_data))

        # Act
        manager = I18nManager(config_path=config_file)

        # Assert
        assert manager._data == config_data
        assert manager.current_language == "zh"

    def test_load_config_nonexistent_file(self, tmp_path):
        """Test loading config with nonexistent file"""
        # Arrange
        config_file = tmp_path / "nonexistent.json"

        # Act
        manager = I18nManager(config_path=config_file)

        # Assert
        assert manager._data == {}
        assert manager.current_language == "en"

    @patch.dict("os.environ", {"GS_LANGUAGE": "zh"})
    def test_load_config_with_env_variable(self, tmp_path):
        """Test that GS_LANGUAGE env variable overrides config"""
        # Arrange
        config_file = tmp_path / "test_i18n.json"
        config_data = {"locale": {"default": "en"}}
        config_file.write_text(json.dumps(config_data))

        # Act
        manager = I18nManager(config_path=config_file)

        # Assert
        assert manager.current_language == "zh"

    def test_load_config_with_invalid_json(self, tmp_path):
        """Test loading config with invalid JSON"""
        # Arrange
        config_file = tmp_path / "invalid.json"
        config_file.write_text("invalid json {{{")

        # Act
        manager = I18nManager(config_path=config_file)

        # Assert - Should fallback to defaults
        assert manager._data == {}
        assert manager.current_language == "en"


class TestSetLanguage:
    """Tests for set_language method"""

    def test_set_language_to_chinese(self, tmp_path):
        """Test setting language to Chinese"""
        # Arrange
        config_file = tmp_path / "test_i18n.json"
        config_file.write_text(json.dumps({"locale": {"default": "en"}}))
        manager = I18nManager(config_path=config_file)

        # Act
        manager.set_language("zh")

        # Assert
        assert manager.current_language == "zh"
        import os

        assert os.environ.get("GS_LANGUAGE") == "zh"

    def test_set_language_to_english(self, tmp_path):
        """Test setting language to English"""
        # Arrange
        config_file = tmp_path / "test_i18n.json"
        config_file.write_text(json.dumps({"locale": {"default": "zh"}}))
        manager = I18nManager(config_path=config_file)

        # Act
        manager.set_language("en")

        # Assert
        assert manager.current_language == "en"
        import os

        assert os.environ.get("GS_LANGUAGE") == "en"


class TestGetMessage:
    """Tests for get_message method"""

    def test_get_message_top_level_key(self, tmp_path):
        """Test getting message from top-level key"""
        # Arrange
        config_file = tmp_path / "test_i18n.json"
        config_data = {"greeting": {"en": "Hello", "zh": "你好"}}
        config_file.write_text(json.dumps(config_data))
        manager = I18nManager(config_path=config_file)
        manager.set_language("en")

        # Act
        result = manager.get_message("greeting")

        # Assert
        assert result == "Hello"

    def test_get_message_with_messages_namespace(self, tmp_path):
        """Test getting message from messages.* namespace"""
        # Arrange
        config_file = tmp_path / "test_i18n.json"
        config_data = {"messages": {"welcome": {"en": "Welcome", "zh": "欢迎"}}}
        config_file.write_text(json.dumps(config_data))
        manager = I18nManager(config_path=config_file)
        manager.set_language("en")

        # Act
        result = manager.get_message("welcome")

        # Assert
        assert result == "Welcome"

    def test_get_message_with_chinese_language(self, tmp_path):
        """Test getting Chinese message"""
        # Arrange
        config_file = tmp_path / "test_i18n.json"
        config_data = {"greeting": {"en": "Hello", "zh": "你好"}}
        config_file.write_text(json.dumps(config_data))
        manager = I18nManager(config_path=config_file)
        manager.set_language("zh")

        # Act
        result = manager.get_message("greeting")

        # Assert
        assert result == "你好"

    def test_get_message_fallback_to_english(self, tmp_path):
        """Test fallback to English when language not available"""
        # Arrange
        config_file = tmp_path / "test_i18n.json"
        config_data = {"greeting": {"en": "Hello"}}
        config_file.write_text(json.dumps(config_data))
        manager = I18nManager(config_path=config_file)
        manager.set_language("fr")

        # Act
        result = manager.get_message("greeting")

        # Assert
        assert result == "Hello"

    def test_get_message_fallback_to_chinese(self, tmp_path):
        """Test fallback to Chinese when English not available"""
        # Arrange
        config_file = tmp_path / "test_i18n.json"
        config_data = {"greeting": {"zh": "你好"}}
        config_file.write_text(json.dumps(config_data))
        manager = I18nManager(config_path=config_file)
        manager.set_language("fr")

        # Act
        result = manager.get_message("greeting")

        # Assert
        assert result == "你好"

    def test_get_message_nonexistent_key_returns_key(self, tmp_path):
        """Test that nonexistent key returns the key itself"""
        # Arrange
        config_file = tmp_path / "test_i18n.json"
        config_file.write_text(json.dumps({}))
        manager = I18nManager(config_path=config_file)

        # Act
        result = manager.get_message("nonexistent.key")

        # Assert
        assert result == "nonexistent.key"

    def test_get_message_with_format_kwargs(self, tmp_path):
        """Test message formatting with kwargs"""
        # Arrange
        config_file = tmp_path / "test_i18n.json"
        config_data = {"greeting": {"en": "Hello, {name}!", "zh": "你好，{name}！"}}
        config_file.write_text(json.dumps(config_data))
        manager = I18nManager(config_path=config_file)
        manager.set_language("en")

        # Act
        result = manager.get_message("greeting", name="Alice")

        # Assert
        assert result == "Hello, Alice!"

    def test_get_message_with_format_error(self, tmp_path):
        """Test message formatting with mismatched kwargs"""
        # Arrange
        config_file = tmp_path / "test_i18n.json"
        config_data = {"greeting": {"en": "Hello, {name}!"}}
        config_file.write_text(json.dumps(config_data))
        manager = I18nManager(config_path=config_file)

        # Act - Provide wrong kwargs
        result = manager.get_message("greeting", age=25)

        # Assert - Should return unformatted message
        assert result == "Hello, {name}!"

    def test_get_message_nested_path(self, tmp_path):
        """Test getting message with nested path"""
        # Arrange
        config_file = tmp_path / "test_i18n.json"
        config_data = {
            "errors": {
                "validation": {
                    "required": {"en": "Field is required", "zh": "字段为必填项"}
                }
            }
        }
        config_file.write_text(json.dumps(config_data))
        manager = I18nManager(config_path=config_file)
        manager.set_language("en")

        # Act
        result = manager.get_message("errors.validation.required")

        # Assert
        assert result == "Field is required"


class TestConvenienceMethods:
    """Tests for convenience methods"""

    def test_get_plugin_type_text(self, tmp_path):
        """Test get_plugin_type_text method"""
        # Arrange
        config_file = tmp_path / "test_i18n.json"
        config_data = {
            "plugin_implementation_types": {
                "python": {"en": "Python", "zh": "Python脚本"},
                "shell": {"en": "Shell Script", "zh": "Shell脚本"},
            }
        }
        config_file.write_text(json.dumps(config_data))
        manager = I18nManager(config_path=config_file)
        manager.set_language("en")

        # Act
        result = manager.get_plugin_type_text("python")

        # Assert
        assert result == "Python"

    def test_format_error(self, tmp_path):
        """Test format_error method"""
        # Arrange
        config_file = tmp_path / "test_i18n.json"
        config_data = {
            "errors": {"not_found": {"en": "Item not found", "zh": "未找到项目"}}
        }
        config_file.write_text(json.dumps(config_data))
        manager = I18nManager(config_path=config_file)
        manager.set_language("en")

        # Act
        result = manager.format_error("not_found")

        # Assert
        assert result == "Item not found"

    def test_format_success(self, tmp_path):
        """Test format_success method"""
        # Arrange
        config_file = tmp_path / "test_i18n.json"
        config_data = {
            "success": {"saved": {"en": "Saved successfully", "zh": "保存成功"}}
        }
        config_file.write_text(json.dumps(config_data))
        manager = I18nManager(config_path=config_file)
        manager.set_language("en")

        # Act
        result = manager.format_success("saved")

        # Assert
        assert result == "Saved successfully"


class TestGlobalFunctions:
    """Tests for global convenience functions"""

    def test_get_i18n_manager_returns_singleton(self):
        """Test that get_i18n_manager returns singleton instance"""
        # Act
        manager1 = get_i18n_manager()
        manager2 = get_i18n_manager()

        # Assert
        assert manager1 is manager2

    def test_t_function(self, tmp_path):
        """Test t() shortcut function"""
        # Arrange
        config_file = tmp_path / "test_i18n.json"
        config_data = {"test": {"en": "Test message", "zh": "测试消息"}}
        config_file.write_text(json.dumps(config_data))

        # Reset global instance
        import gscripts.utils.i18n as i18n_module

        i18n_module._i18n_manager = I18nManager(config_path=config_file)
        i18n_module._i18n_manager.set_language("en")

        # Act
        result = t("test")

        # Assert
        assert result == "Test message"

    def test_set_language_function(self, tmp_path):
        """Test global set_language function"""
        # Arrange
        config_file = tmp_path / "test_i18n.json"
        config_file.write_text(json.dumps({"locale": {"default": "en"}}))

        # Reset global instance
        import gscripts.utils.i18n as i18n_module

        i18n_module._i18n_manager = I18nManager(config_path=config_file)

        # Act
        set_language("zh")

        # Assert
        assert get_i18n_manager().current_language == "zh"
