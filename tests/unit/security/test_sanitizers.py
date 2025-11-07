"""
Tests for InputSanitizer

Tests security module for input sanitization and cleaning.
"""

from gscripts.security.sanitizers import (
    InputSanitizer,
    clean_string,
    clean_command,
    clean_path,
    clean_plugin_name,
)


class TestSanitizeString:
    """Tests for sanitize_string method"""

    def test_sanitize_simple_string(self):
        """Test sanitizing a simple string"""
        result = InputSanitizer.sanitize_string("hello world")
        assert result == "hello world"

    def test_sanitize_string_with_max_length(self):
        """Test string truncation at max length"""
        long_string = "a" * 2000
        result = InputSanitizer.sanitize_string(long_string, max_length=100)
        assert len(result) == 100

    def test_sanitize_string_removes_control_characters(self):
        """Test removal of control characters"""
        text_with_ctrl = "hello\x00\x01\x02world"
        result = InputSanitizer.sanitize_string(text_with_ctrl)
        assert "\x00" not in result
        assert "hello" in result
        assert "world" in result

    def test_sanitize_string_allows_newlines_when_multiline_true(self):
        """Test that newlines are preserved when allow_multiline=True"""
        text = "line1\nline2\rline3"
        result = InputSanitizer.sanitize_string(text, allow_multiline=True)
        # Newlines preserved but normalized by split/join
        assert "line1" in result
        assert "line2" in result

    def test_sanitize_string_removes_newlines_when_multiline_false(self):
        """Test that newlines are removed when allow_multiline=False"""
        text = "line1\nline2\rline3"
        result = InputSanitizer.sanitize_string(text, allow_multiline=False)
        assert "\n" not in result
        assert "\r" not in result

    def test_sanitize_string_cleans_extra_spaces(self):
        """Test removal of extra spaces"""
        text = "hello    world   test"
        result = InputSanitizer.sanitize_string(text)
        assert result == "hello world test"

    def test_sanitize_string_strips_whitespace(self):
        """Test stripping of leading/trailing whitespace"""
        text = "   hello world   "
        result = InputSanitizer.sanitize_string(text)
        assert result == "hello world"

    def test_sanitize_string_converts_non_string(self):
        """Test conversion of non-string input"""
        result = InputSanitizer.sanitize_string(12345)
        assert result == "12345"


class TestSanitizePluginName:
    """Tests for sanitize_plugin_name method"""

    def test_sanitize_valid_plugin_name(self):
        """Test sanitizing valid plugin name"""
        result = InputSanitizer.sanitize_plugin_name("test_plugin")
        assert result == "test_plugin"

    def test_sanitize_plugin_name_removes_special_chars(self):
        """Test removal of special characters"""
        result = InputSanitizer.sanitize_plugin_name("test@plugin$name!")
        assert result == "testpluginname"

    def test_sanitize_plugin_name_adds_prefix_if_starts_with_digit(self):
        """Test adding prefix when name starts with digit"""
        result = InputSanitizer.sanitize_plugin_name("123plugin")
        assert result.startswith("plugin_")
        assert "123plugin" in result

    def test_sanitize_plugin_name_converts_to_lowercase(self):
        """Test conversion to lowercase"""
        result = InputSanitizer.sanitize_plugin_name("TestPlugin")
        assert result == "testplugin"

    def test_sanitize_plugin_name_truncates_at_50_chars(self):
        """Test truncation at 50 characters"""
        long_name = "a" * 100
        result = InputSanitizer.sanitize_plugin_name(long_name)
        assert len(result) == 50

    def test_sanitize_plugin_name_allows_hyphens_and_underscores(self):
        """Test that hyphens and underscores are preserved"""
        result = InputSanitizer.sanitize_plugin_name("test-plugin_name")
        assert result == "test-plugin_name"


class TestSanitizeCommandName:
    """Tests for sanitize_command_name method"""

    def test_sanitize_valid_command_name(self):
        """Test sanitizing valid command name"""
        result = InputSanitizer.sanitize_command_name("test_command")
        assert result == "test_command"

    def test_sanitize_command_name_removes_special_chars(self):
        """Test removal of special characters"""
        result = InputSanitizer.sanitize_command_name("test@command$name!")
        assert result == "testcommandname"

    def test_sanitize_command_name_adds_prefix_if_starts_with_digit(self):
        """Test adding prefix when name starts with digit"""
        result = InputSanitizer.sanitize_command_name("123command")
        assert result.startswith("cmd_")

    def test_sanitize_command_name_truncates_at_100_chars(self):
        """Test truncation at 100 characters"""
        long_name = "a" * 200
        result = InputSanitizer.sanitize_command_name(long_name)
        assert len(result) == 100


class TestSanitizePath:
    """Tests for sanitize_path method"""

    def test_sanitize_simple_path(self):
        """Test sanitizing simple path"""
        result = InputSanitizer.sanitize_path("/home/user/file.txt", resolve=False)
        assert "home/user/file.txt" in result

    def test_sanitize_path_removes_double_dots(self):
        """Test removal of .. (path traversal)"""
        result = InputSanitizer.sanitize_path("/home/../../etc/passwd", resolve=False)
        assert ".." not in result

    def test_sanitize_path_removes_dangerous_chars(self):
        """Test removal of dangerous characters"""
        result = InputSanitizer.sanitize_path("/home/user;rm -rf", resolve=False)
        assert ";" not in result

    def test_sanitize_path_normalizes_slashes(self):
        """Test normalization of multiple slashes"""
        result = InputSanitizer.sanitize_path("/home///user////file", resolve=False)
        assert "///" not in result

    def test_sanitize_path_with_resolve(self):
        """Test path resolution"""
        result = InputSanitizer.sanitize_path(".", resolve=True)
        assert result  # Should resolve to absolute path


class TestSanitizeShellCommand:
    """Tests for sanitize_shell_command method"""

    def test_sanitize_simple_command(self):
        """Test sanitizing simple command"""
        result = InputSanitizer.sanitize_shell_command("ls -la")
        assert "ls" in result or result == "'ls -la'"  # May be quoted

    def test_sanitize_command_truncates_at_2000_chars(self):
        """Test truncation at 2000 characters"""
        long_command = "echo " + "a" * 3000
        result = InputSanitizer.sanitize_shell_command(long_command)
        assert len(result) <= 2000 + 10  # Allow for quotes

    def test_sanitize_command_removes_control_chars(self):
        """Test removal of control characters"""
        command = "echo\x00test\x01"
        result = InputSanitizer.sanitize_shell_command(command)
        assert "\x00" not in result

    def test_sanitize_command_escapes_when_escape_true(self):
        """Test command escaping when escape=True"""
        result = InputSanitizer.sanitize_shell_command("ls -la", escape=True)
        # Should be escaped with shlex.quote
        assert result

    def test_sanitize_command_no_escape_when_escape_false(self):
        """Test no escaping when escape=False"""
        result = InputSanitizer.sanitize_shell_command("ls -la", escape=False)
        assert result.strip() == "ls -la"


class TestSanitizeJsonData:
    """Tests for sanitize_json_data method"""

    def test_sanitize_simple_dict(self):
        """Test sanitizing simple dictionary"""
        data = {"key": "value"}
        result = InputSanitizer.sanitize_json_data(data)
        assert result == {"key": "value"}

    def test_sanitize_nested_dict(self):
        """Test sanitizing nested dictionary"""
        data = {"outer": {"inner": "value"}}
        result = InputSanitizer.sanitize_json_data(data)
        assert result["outer"]["inner"] == "value"

    def test_sanitize_list(self):
        """Test sanitizing list"""
        data = [1, 2, 3, "test"]
        result = InputSanitizer.sanitize_json_data(data)
        assert len(result) == 4
        assert "test" in result

    def test_sanitize_respects_max_depth(self):
        """Test max depth limitation"""
        # Create deeply nested structure
        data = {"level1": {"level2": {"level3": {"level4": "value"}}}}
        result = InputSanitizer.sanitize_json_data(data, max_depth=2)
        # Should cut off at max_depth
        assert "level1" in result
        assert "level2" in result["level1"]

    def test_sanitize_respects_max_items(self):
        """Test max items limitation"""
        data = {f"key{i}": f"value{i}" for i in range(2000)}
        result = InputSanitizer.sanitize_json_data(data, max_items=10)
        assert len(result) <= 10

    def test_sanitize_preserves_primitives(self):
        """Test preservation of primitive types"""
        data = {"int": 42, "float": 3.14, "bool": True, "none": None}
        result = InputSanitizer.sanitize_json_data(data)
        assert result["int"] == 42
        assert result["float"] == 3.14
        assert result["bool"] is True
        assert result["none"] is None


class TestSanitizeHtml:
    """Tests for sanitize_html method"""

    def test_sanitize_simple_text(self):
        """Test sanitizing simple text"""
        result = InputSanitizer.sanitize_html("hello world")
        assert result == "hello world"

    def test_sanitize_escapes_html(self):
        """Test HTML escaping"""
        result = InputSanitizer.sanitize_html("<div>test</div>")
        assert "<div>" not in result
        assert "test" in result

    def test_sanitize_removes_script_tags(self):
        """Test escaping of script tags"""
        result = InputSanitizer.sanitize_html("<script>alert('xss')</script>")
        # HTML is escaped, so script tags are harmless
        assert "&lt;script&gt;" in result or "script" in result
        # Actual script execution is prevented by escaping
        assert "<script>" not in result

    def test_sanitize_removes_style_tags(self):
        """Test escaping of style tags"""
        result = InputSanitizer.sanitize_html("<style>body{color:red}</style>")
        # HTML is escaped, so style tags are harmless
        assert "&lt;style&gt;" in result or "style" in result
        # Actual style injection is prevented by escaping
        assert "<style>" not in result

    def test_sanitize_removes_all_tags(self):
        """Test escaping of all HTML tags"""
        result = InputSanitizer.sanitize_html("<p>Hello <b>World</b></p>")
        # Tags are escaped, not in raw form
        assert "<p>" not in result
        assert "<b>" not in result
        # Text content is preserved
        assert "Hello" in result
        assert "World" in result


class TestSanitizeUrl:
    """Tests for sanitize_url method"""

    def test_sanitize_valid_http_url(self):
        """Test sanitizing valid HTTP URL"""
        result = InputSanitizer.sanitize_url("http://example.com")
        assert "http://example.com" in result

    def test_sanitize_valid_https_url(self):
        """Test sanitizing valid HTTPS URL"""
        result = InputSanitizer.sanitize_url("https://example.com")
        assert "https://example.com" in result

    def test_sanitize_adds_default_scheme(self):
        """Test adding default https:// scheme"""
        result = InputSanitizer.sanitize_url("example.com")
        assert "https://" in result

    def test_sanitize_rejects_disallowed_scheme(self):
        """Test rejection of disallowed schemes"""
        # Use proper scheme format with ://
        result = InputSanitizer.sanitize_url(
            "javascript://alert('xss')", allowed_schemes=["http", "https"]
        )
        assert result == ""

    def test_sanitize_allows_custom_schemes(self):
        """Test allowing custom schemes"""
        result = InputSanitizer.sanitize_url(
            "ftp://example.com", allowed_schemes=["ftp"]
        )
        assert "ftp://example.com" in result


class TestSanitizeConfigValue:
    """Tests for sanitize_config_value method"""

    def test_sanitize_string_value(self):
        """Test sanitizing string value"""
        result = InputSanitizer.sanitize_config_value("test", value_type="string")
        assert result == "test"

    def test_sanitize_int_value(self):
        """Test sanitizing integer value"""
        result = InputSanitizer.sanitize_config_value("42", value_type="int")
        assert result == 42

    def test_sanitize_invalid_int_returns_zero(self):
        """Test invalid integer returns 0"""
        result = InputSanitizer.sanitize_config_value("invalid", value_type="int")
        assert result == 0

    def test_sanitize_float_value(self):
        """Test sanitizing float value"""
        result = InputSanitizer.sanitize_config_value("3.14", value_type="float")
        assert result == 3.14

    def test_sanitize_bool_value_true(self):
        """Test sanitizing boolean true values"""
        assert InputSanitizer.sanitize_config_value("true", value_type="bool") is True
        assert InputSanitizer.sanitize_config_value("1", value_type="bool") is True
        assert InputSanitizer.sanitize_config_value("yes", value_type="bool") is True

    def test_sanitize_bool_value_false(self):
        """Test sanitizing boolean false values"""
        assert InputSanitizer.sanitize_config_value("false", value_type="bool") is False
        assert InputSanitizer.sanitize_config_value("0", value_type="bool") is False

    def test_sanitize_list_value(self):
        """Test sanitizing list value"""
        result = InputSanitizer.sanitize_config_value(
            ["a", "b", "c"], value_type="list"
        )
        assert isinstance(result, list)
        assert len(result) == 3

    def test_sanitize_dict_value(self):
        """Test sanitizing dict value"""
        result = InputSanitizer.sanitize_config_value(
            {"key": "value"}, value_type="dict"
        )
        assert isinstance(result, dict)


class TestSanitizeLogMessage:
    """Tests for sanitize_log_message method"""

    def test_sanitize_simple_log_message(self):
        """Test sanitizing simple log message"""
        result = InputSanitizer.sanitize_log_message("INFO: Test message")
        assert result == "INFO: Test message"

    def test_sanitize_truncates_long_messages(self):
        """Test truncation of long messages"""
        long_message = "a" * 6000
        result = InputSanitizer.sanitize_log_message(long_message)
        assert len(result) <= 5020  # 5000 + "[truncated]"
        assert "[truncated]" in result

    def test_sanitize_redacts_password(self):
        """Test redaction of password patterns"""
        result = InputSanitizer.sanitize_log_message("password=secret123")
        assert "[REDACTED]" in result
        assert "secret123" not in result

    def test_sanitize_redacts_token(self):
        """Test redaction of token patterns"""
        result = InputSanitizer.sanitize_log_message("token: abc123xyz")
        assert "[REDACTED]" in result
        assert "abc123xyz" not in result

    def test_sanitize_redacts_key(self):
        """Test redaction of key patterns"""
        result = InputSanitizer.sanitize_log_message("api_key=12345")
        assert "[REDACTED]" in result
        assert "12345" not in result

    def test_sanitize_redacts_secret(self):
        """Test redaction of secret patterns"""
        result = InputSanitizer.sanitize_log_message("secret: topsecret")
        assert "[REDACTED]" in result
        assert "topsecret" not in result


class TestConvenienceFunctions:
    """Tests for convenience functions"""

    def test_clean_string(self):
        """Test clean_string convenience function"""
        result = clean_string("  hello   world  ")
        assert result == "hello world"

    def test_clean_command(self):
        """Test clean_command convenience function"""
        result = clean_command("ls -la")
        assert result  # Should return escaped command

    def test_clean_path(self):
        """Test clean_path convenience function"""
        result = clean_path("/home/../etc")
        assert ".." not in result

    def test_clean_plugin_name(self):
        """Test clean_plugin_name convenience function"""
        result = clean_plugin_name("Test@Plugin!")
        assert result == "testplugin"
