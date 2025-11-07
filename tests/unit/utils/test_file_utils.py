"""
Tests for FileUtils

Tests file operation utilities including async/sync file I/O, JSON handling, and path operations.
"""

import pytest
import json

from gscripts.utils.file_utils import FileUtils


class TestReadTextAsync:
    """Tests for read_text_async method"""

    @pytest.mark.asyncio
    async def test_read_text_async_success(self, tmp_path):
        """Test reading text file asynchronously"""
        # Arrange
        test_file = tmp_path / "test.txt"
        test_content = "Hello, World!"
        test_file.write_text(test_content)

        # Act
        result = await FileUtils.read_text_async(test_file)

        # Assert
        assert result == test_content

    @pytest.mark.asyncio
    async def test_read_text_async_with_encoding(self, tmp_path):
        """Test reading text file with custom encoding"""
        # Arrange
        test_file = tmp_path / "test_utf8.txt"
        test_content = "你好，世界！"
        test_file.write_text(test_content, encoding="utf-8")

        # Act
        result = await FileUtils.read_text_async(test_file, encoding="utf-8")

        # Assert
        assert result == test_content

    @pytest.mark.asyncio
    async def test_read_text_async_nonexistent_file(self, tmp_path):
        """Test reading nonexistent file raises error"""
        # Arrange
        nonexistent_file = tmp_path / "nonexistent.txt"

        # Act & Assert
        with pytest.raises((FileNotFoundError, OSError)):
            await FileUtils.read_text_async(nonexistent_file)


class TestWriteTextAsync:
    """Tests for write_text_async method"""

    @pytest.mark.asyncio
    async def test_write_text_async_success(self, tmp_path):
        """Test writing text file asynchronously"""
        # Arrange
        test_file = tmp_path / "test.txt"
        test_content = "Hello, World!"

        # Act
        await FileUtils.write_text_async(test_file, test_content)

        # Assert
        assert test_file.exists()
        assert test_file.read_text() == test_content

    @pytest.mark.asyncio
    async def test_write_text_async_creates_parent_directory(self, tmp_path):
        """Test that parent directory is created if missing"""
        # Arrange
        test_file = tmp_path / "subdir" / "nested" / "test.txt"
        test_content = "Nested file"

        # Act
        await FileUtils.write_text_async(test_file, test_content)

        # Assert
        assert test_file.exists()
        assert test_file.read_text() == test_content

    @pytest.mark.asyncio
    async def test_write_text_async_with_encoding(self, tmp_path):
        """Test writing text file with custom encoding"""
        # Arrange
        test_file = tmp_path / "test_utf8.txt"
        test_content = "你好，世界！"

        # Act
        await FileUtils.write_text_async(test_file, test_content, encoding="utf-8")

        # Assert
        assert test_file.exists()
        assert test_file.read_text(encoding="utf-8") == test_content


class TestReadJson:
    """Tests for read_json method"""

    def test_read_json_success(self, tmp_path):
        """Test reading JSON file synchronously"""
        # Arrange
        test_file = tmp_path / "test.json"
        test_data = {"key": "value", "number": 42}
        test_file.write_text(json.dumps(test_data))

        # Act
        result = FileUtils.read_json(test_file)

        # Assert
        assert result == test_data

    def test_read_json_with_nested_data(self, tmp_path):
        """Test reading JSON with nested structure"""
        # Arrange
        test_file = tmp_path / "nested.json"
        test_data = {"outer": {"inner": {"value": "nested"}}}
        test_file.write_text(json.dumps(test_data))

        # Act
        result = FileUtils.read_json(test_file)

        # Assert
        assert result["outer"]["inner"]["value"] == "nested"

    def test_read_json_nonexistent_file(self, tmp_path):
        """Test reading nonexistent JSON file raises error"""
        # Arrange
        nonexistent_file = tmp_path / "nonexistent.json"

        # Act & Assert
        with pytest.raises(FileNotFoundError):
            FileUtils.read_json(nonexistent_file)

    def test_read_json_invalid_json(self, tmp_path):
        """Test reading invalid JSON raises error"""
        # Arrange
        test_file = tmp_path / "invalid.json"
        test_file.write_text("invalid json {{{")

        # Act & Assert
        with pytest.raises(json.JSONDecodeError):
            FileUtils.read_json(test_file)


class TestReadJsonAsync:
    """Tests for read_json_async method"""

    @pytest.mark.asyncio
    async def test_read_json_async_success(self, tmp_path):
        """Test reading JSON file asynchronously"""
        # Arrange
        test_file = tmp_path / "test.json"
        test_data = {"key": "value", "number": 42}
        test_file.write_text(json.dumps(test_data))

        # Act
        result = await FileUtils.read_json_async(test_file)

        # Assert
        assert result == test_data

    @pytest.mark.asyncio
    async def test_read_json_async_nonexistent_file(self, tmp_path):
        """Test reading nonexistent JSON file raises error"""
        # Arrange
        nonexistent_file = tmp_path / "nonexistent.json"

        # Act & Assert
        with pytest.raises((FileNotFoundError, OSError)):
            await FileUtils.read_json_async(nonexistent_file)


class TestWriteJson:
    """Tests for write_json method"""

    def test_write_json_success(self, tmp_path):
        """Test writing JSON file synchronously"""
        # Arrange
        test_file = tmp_path / "test.json"
        test_data = {"key": "value", "number": 42}

        # Act
        FileUtils.write_json(test_file, test_data)

        # Assert
        assert test_file.exists()
        loaded_data = json.loads(test_file.read_text())
        assert loaded_data == test_data

    def test_write_json_creates_parent_directory(self, tmp_path):
        """Test that parent directory is created if missing"""
        # Arrange
        test_file = tmp_path / "subdir" / "test.json"
        test_data = {"nested": True}

        # Act
        FileUtils.write_json(test_file, test_data)

        # Assert
        assert test_file.exists()
        loaded_data = json.loads(test_file.read_text())
        assert loaded_data == test_data

    def test_write_json_with_custom_indent(self, tmp_path):
        """Test writing JSON with custom indentation"""
        # Arrange
        test_file = tmp_path / "test.json"
        test_data = {"key": "value"}

        # Act
        FileUtils.write_json(test_file, test_data, indent=4)

        # Assert
        content = test_file.read_text()
        # 4-space indent means longer content
        assert len(content) > len(json.dumps(test_data, indent=2))

    def test_write_json_preserves_unicode(self, tmp_path):
        """Test that Unicode characters are preserved (not escaped)"""
        # Arrange
        test_file = tmp_path / "unicode.json"
        test_data = {"message": "你好世界"}

        # Act
        FileUtils.write_json(test_file, test_data)

        # Assert
        content = test_file.read_text()
        assert "你好世界" in content  # Not escaped as \u4f60...


class TestWriteJsonAsync:
    """Tests for write_json_async method"""

    @pytest.mark.asyncio
    async def test_write_json_async_success(self, tmp_path):
        """Test writing JSON file asynchronously"""
        # Arrange
        test_file = tmp_path / "test.json"
        test_data = {"key": "value", "number": 42}

        # Act
        await FileUtils.write_json_async(test_file, test_data)

        # Assert
        assert test_file.exists()
        loaded_data = json.loads(test_file.read_text())
        assert loaded_data == test_data

    @pytest.mark.asyncio
    async def test_write_json_async_creates_parent_directory(self, tmp_path):
        """Test that parent directory is created if missing"""
        # Arrange
        test_file = tmp_path / "subdir" / "nested" / "test.json"
        test_data = {"nested": True}

        # Act
        await FileUtils.write_json_async(test_file, test_data)

        # Assert
        assert test_file.exists()
        loaded_data = json.loads(test_file.read_text())
        assert loaded_data == test_data


class TestEnsureDirectory:
    """Tests for ensure_directory method"""

    def test_ensure_directory_creates_directory(self, tmp_path):
        """Test creating new directory"""
        # Arrange
        new_dir = tmp_path / "new_directory"

        # Act
        result = FileUtils.ensure_directory(new_dir)

        # Assert
        assert new_dir.exists()
        assert new_dir.is_dir()
        assert result == new_dir

    def test_ensure_directory_with_existing_directory(self, tmp_path):
        """Test with already existing directory"""
        # Arrange
        existing_dir = tmp_path / "existing"
        existing_dir.mkdir()

        # Act
        result = FileUtils.ensure_directory(existing_dir)

        # Assert
        assert existing_dir.exists()
        assert result == existing_dir

    def test_ensure_directory_creates_nested_directories(self, tmp_path):
        """Test creating nested directory structure"""
        # Arrange
        nested_dir = tmp_path / "level1" / "level2" / "level3"

        # Act
        result = FileUtils.ensure_directory(nested_dir)

        # Assert
        assert nested_dir.exists()
        assert nested_dir.is_dir()
        assert result == nested_dir


class TestFindFiles:
    """Tests for find_files method"""

    def test_find_files_with_pattern(self, tmp_path):
        """Test finding files with pattern"""
        # Arrange
        (tmp_path / "file1.txt").touch()
        (tmp_path / "file2.txt").touch()
        (tmp_path / "file3.py").touch()

        # Act
        result = FileUtils.find_files(tmp_path, pattern="*.txt", recursive=False)

        # Assert
        assert len(result) == 2
        assert all(f.suffix == ".txt" for f in result)

    def test_find_files_recursive(self, tmp_path):
        """Test finding files recursively"""
        # Arrange
        (tmp_path / "file1.txt").touch()
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (subdir / "file2.txt").touch()

        # Act
        result = FileUtils.find_files(tmp_path, pattern="*.txt", recursive=True)

        # Assert
        assert len(result) == 2

    def test_find_files_non_recursive(self, tmp_path):
        """Test finding files non-recursively"""
        # Arrange
        (tmp_path / "file1.txt").touch()
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (subdir / "file2.txt").touch()

        # Act
        result = FileUtils.find_files(tmp_path, pattern="*.txt", recursive=False)

        # Assert
        assert len(result) == 1

    def test_find_files_with_wildcard(self, tmp_path):
        """Test finding all files with wildcard"""
        # Arrange
        (tmp_path / "file1.txt").touch()
        (tmp_path / "file2.py").touch()
        (tmp_path / "file3.json").touch()

        # Act
        result = FileUtils.find_files(tmp_path, pattern="*", recursive=False)

        # Assert
        assert len(result) == 3


class TestGetFileSize:
    """Tests for get_file_size method"""

    def test_get_file_size_empty_file(self, tmp_path):
        """Test getting size of empty file"""
        # Arrange
        test_file = tmp_path / "empty.txt"
        test_file.touch()

        # Act
        result = FileUtils.get_file_size(test_file)

        # Assert
        assert result == 0

    def test_get_file_size_with_content(self, tmp_path):
        """Test getting size of file with content"""
        # Arrange
        test_file = tmp_path / "content.txt"
        test_content = "Hello, World!"
        test_file.write_text(test_content)

        # Act
        result = FileUtils.get_file_size(test_file)

        # Assert
        assert result == len(test_content.encode("utf-8"))


class TestGetFileExtension:
    """Tests for get_file_extension method"""

    def test_get_file_extension_with_extension(self):
        """Test getting file extension"""
        # Act
        result = FileUtils.get_file_extension("test.txt")

        # Assert
        assert result == ".txt"

    def test_get_file_extension_multiple_dots(self):
        """Test getting extension from file with multiple dots"""
        # Act
        result = FileUtils.get_file_extension("archive.tar.gz")

        # Assert
        assert result == ".gz"

    def test_get_file_extension_no_extension(self):
        """Test file without extension"""
        # Act
        result = FileUtils.get_file_extension("README")

        # Assert
        assert result == ""

    def test_get_file_extension_converts_to_lowercase(self):
        """Test that extension is converted to lowercase"""
        # Act
        result = FileUtils.get_file_extension("file.TXT")

        # Assert
        assert result == ".txt"


class TestIsConfigFile:
    """Tests for is_config_file method"""

    def test_is_config_file_json(self):
        """Test JSON file is recognized as config file"""
        # Act
        result = FileUtils.is_config_file("config.json")

        # Assert
        assert result is True

    def test_is_config_file_non_config(self):
        """Test non-config file is not recognized"""
        # Act
        result = FileUtils.is_config_file("script.py")

        # Assert
        assert result is False

    def test_is_config_file_uppercase_extension(self):
        """Test uppercase extension is recognized"""
        # Act
        result = FileUtils.is_config_file("config.JSON")

        # Assert
        assert result is True


class TestLoadConfigFile:
    """Tests for load_config_file method"""

    @pytest.mark.asyncio
    async def test_load_config_file_json_success(self, tmp_path):
        """Test loading JSON config file"""
        # Arrange
        config_file = tmp_path / "config.json"
        config_data = {"setting": "value"}
        config_file.write_text(json.dumps(config_data))

        # Act
        result = await FileUtils.load_config_file(config_file)

        # Assert
        assert result == config_data

    @pytest.mark.asyncio
    async def test_load_config_file_nonexistent(self, tmp_path):
        """Test loading nonexistent config file returns None"""
        # Arrange
        nonexistent_file = tmp_path / "nonexistent.json"

        # Act
        result = await FileUtils.load_config_file(nonexistent_file)

        # Assert
        assert result is None

    @pytest.mark.asyncio
    async def test_load_config_file_unsupported_extension(self, tmp_path):
        """Test loading file with unsupported extension returns None"""
        # Arrange
        unsupported_file = tmp_path / "config.yaml"
        unsupported_file.write_text("key: value")

        # Act
        result = await FileUtils.load_config_file(unsupported_file)

        # Assert
        assert result is None

    @pytest.mark.asyncio
    async def test_load_config_file_invalid_json_returns_none(self, tmp_path):
        """Test loading invalid JSON returns None with warning"""
        # Arrange
        invalid_file = tmp_path / "invalid.json"
        invalid_file.write_text("invalid json {{{")

        # Act
        result = await FileUtils.load_config_file(invalid_file)

        # Assert
        assert result is None


class TestSafeFilename:
    """Tests for safe_filename method"""

    def test_safe_filename_removes_dangerous_chars(self):
        """Test removal of dangerous characters"""
        # Act
        result = FileUtils.safe_filename('file<>:"/\\|?*name.txt')

        # Assert
        assert "<" not in result
        assert ">" not in result
        assert ":" not in result
        assert '"' not in result
        assert "/" not in result
        assert "\\" not in result
        assert "|" not in result
        assert "?" not in result
        assert "*" not in result

    def test_safe_filename_removes_consecutive_dots(self):
        """Test removal of consecutive dots"""
        # Act
        result = FileUtils.safe_filename("file...name.txt")

        # Assert
        assert "..." not in result
        assert ".txt" in result  # Extension preserved

    def test_safe_filename_strips_leading_trailing_dots(self):
        """Test stripping of leading and trailing dots"""
        # Act
        result = FileUtils.safe_filename("...filename...")

        # Assert
        assert not result.startswith(".")
        assert not result.endswith(".")

    def test_safe_filename_returns_unnamed_for_empty(self):
        """Test that empty input returns 'unnamed'"""
        # Act
        result = FileUtils.safe_filename("")

        # Assert
        assert result == "unnamed"

    def test_safe_filename_returns_unnamed_for_only_dots(self):
        """Test that filename with only dots returns 'unnamed'"""
        # Act
        result = FileUtils.safe_filename(".....")

        # Assert
        assert result == "unnamed"

    def test_safe_filename_preserves_valid_chars(self):
        """Test that valid characters are preserved"""
        # Act
        result = FileUtils.safe_filename("valid_file-name_123.txt")

        # Assert
        assert result == "valid_file-name_123.txt"
