"""
Unit tests for filesystem operations.

Tests RealFileSystem and InMemoryFileSystem implementations.
"""

import pytest
from pathlib import Path

from gscripts.infrastructure.filesystem.file_operations import (
    RealFileSystem,
    InMemoryFileSystem,
)


@pytest.mark.unit
class TestInMemoryFileSystem:
    """Unit tests for InMemoryFileSystem"""

    def test_write_text_and_read_text(self):
        """Test writing and reading text files"""
        # Arrange
        fs = InMemoryFileSystem()
        path = Path("/test/file.txt")
        content = "Hello, World!"

        # Act
        fs.write_text(path, content)
        result = fs.read_text(path)

        # Assert
        assert result == content

    def test_file_exists_after_write(self):
        """Test that file exists after writing"""
        # Arrange
        fs = InMemoryFileSystem()
        path = Path("/test/file.txt")

        # Act
        fs.write_text(path, "content")

        # Assert
        assert fs.exists(path)

    def test_file_not_exists_initially(self):
        """Test that file doesn't exist initially"""
        # Arrange
        fs = InMemoryFileSystem()
        path = Path("/test/nonexistent.txt")

        # Assert
        assert not fs.exists(path)

    def test_write_json_and_read_json(self):
        """Test writing and reading JSON data"""
        # Arrange
        fs = InMemoryFileSystem()
        path = Path("/test/data.json")
        data = {"key": "value", "number": 42}

        # Act
        fs.write_json(path, data)
        result = fs.read_json(path)

        # Assert
        assert result == data

    def test_read_nonexistent_file_raises_error(self):
        """Test reading nonexistent file raises error"""
        # Arrange
        fs = InMemoryFileSystem()
        path = Path("/test/nonexistent.txt")

        # Act & Assert
        with pytest.raises(FileNotFoundError):
            fs.read_text(path)

    def test_isolation_between_instances(self):
        """Test that different filesystem instances are isolated"""
        # Arrange
        fs1 = InMemoryFileSystem()
        fs2 = InMemoryFileSystem()
        path = Path("/test/file.txt")

        # Act
        fs1.write_text(path, "content1")

        # Assert
        assert fs1.exists(path)
        assert not fs2.exists(path)  # Isolated


class TestRealFileSystem:
    """Unit tests for RealFileSystem"""

    def test_write_text_and_read_text(self, temp_dir):
        """Test writing and reading text files"""
        # Arrange
        fs = RealFileSystem()
        path = temp_dir / "file.txt"
        content = "Hello, Real World!"

        # Act
        fs.write_text(path, content)
        result = fs.read_text(path)

        # Assert
        assert result == content

    def test_write_json_and_read_json(self, temp_dir):
        """Test writing and reading JSON data"""
        # Arrange
        fs = RealFileSystem()
        path = temp_dir / "data.json"
        data = {"key": "value", "list": [1, 2, 3]}

        # Act
        fs.write_json(path, data)
        result = fs.read_json(path)

        # Assert
        assert result == data

    def test_file_exists_after_write(self, temp_dir):
        """Test that file exists after writing"""
        # Arrange
        fs = RealFileSystem()
        path = temp_dir / "file.txt"

        # Act
        fs.write_text(path, "content")

        # Assert
        assert fs.exists(path)

    def test_list_dir_returns_directory_contents(self, temp_dir):
        """Test listing directory contents"""
        # Arrange
        fs = RealFileSystem()
        (temp_dir / "file1.txt").write_text("content1")
        (temp_dir / "file2.txt").write_text("content2")

        # Act
        contents = fs.list_dir(temp_dir)

        # Assert
        assert len(contents) >= 2
        file_names = [p.name for p in contents]
        assert "file1.txt" in file_names
        assert "file2.txt" in file_names

    def test_list_dir_empty_directory(self, temp_dir):
        """Test listing empty directory"""
        # Arrange
        fs = RealFileSystem()
        empty_dir = temp_dir / "empty"
        empty_dir.mkdir()

        # Act
        contents = fs.list_dir(empty_dir)

        # Assert
        assert len(contents) == 0

    def test_list_dir_nonexistent_returns_empty(self, temp_dir):
        """Test listing nonexistent directory returns empty list"""
        # Arrange
        fs = RealFileSystem()
        nonexistent = temp_dir / "nonexistent"

        # Act
        contents = fs.list_dir(nonexistent)

        # Assert
        assert contents == []

    def test_write_creates_parent_directories(self, temp_dir):
        """Test that write_text creates parent directories"""
        # Arrange
        fs = RealFileSystem()
        path = temp_dir / "nested" / "deep" / "file.txt"

        # Act
        fs.write_text(path, "content")

        # Assert
        assert path.exists()
        assert path.parent.exists()

    def test_write_json_creates_parent_directories(self, temp_dir):
        """Test that write_json creates parent directories"""
        # Arrange
        fs = RealFileSystem()
        path = temp_dir / "nested" / "data.json"
        data = {"test": "value"}

        # Act
        fs.write_json(path, data)

        # Assert
        assert path.exists()
        assert path.parent.exists()
