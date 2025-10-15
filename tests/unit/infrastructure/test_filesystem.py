"""
文件系统抽象层的单元测试
"""

import pytest
from pathlib import Path

from src.gscripts.infrastructure.filesystem import (
    RealFileSystem,
    InMemoryFileSystem,
)


class TestInMemoryFileSystem:
    """InMemoryFileSystem 单元测试"""

    def test_file_exists_after_write(self):
        """测试写入后文件存在"""
        fs = InMemoryFileSystem()
        path = Path("/test/file.txt")

        fs.write_text(path, "hello world")

        assert fs.exists(path)

    def test_read_written_text(self):
        """测试读取写入的文本"""
        fs = InMemoryFileSystem()
        path = Path("/test/file.txt")
        content = "hello world"

        fs.write_text(path, content)
        result = fs.read_text(path)

        assert result == content

    def test_read_nonexistent_file_raises_error(self):
        """测试读取不存在的文件抛出异常"""
        fs = InMemoryFileSystem()
        path = Path("/nonexistent.txt")

        with pytest.raises(FileNotFoundError):
            fs.read_text(path)

    def test_write_and_read_json(self):
        """测试JSON读写"""
        fs = InMemoryFileSystem()
        path = Path("/config.json")
        data = {"name": "test", "value": 123}

        fs.write_json(path, data)
        result = fs.read_json(path)

        assert result == data

    def test_list_dir_returns_matching_files(self):
        """测试列出目录内容"""
        fs = InMemoryFileSystem()

        fs.write_text(Path("/dir/file1.txt"), "content1")
        fs.write_text(Path("/dir/file2.txt"), "content2")
        fs.write_text(Path("/other/file3.txt"), "content3")

        files = fs.list_dir(Path("/dir"))

        assert len(files) == 2
        assert Path("/dir/file1.txt") in files
        assert Path("/dir/file2.txt") in files
        assert Path("/other/file3.txt") not in files

    def test_clear_removes_all_files(self):
        """测试清空文件系统"""
        fs = InMemoryFileSystem()
        path = Path("/test.txt")

        fs.write_text(path, "content")
        assert fs.exists(path)

        fs.clear()

        assert not fs.exists(path)


class TestRealFileSystem:
    """RealFileSystem 集成测试"""

    def test_read_and_write_text(self, tmp_path: Path):
        """测试真实文件系统的读写"""
        fs = RealFileSystem()
        file_path = tmp_path / "test.txt"
        content = "test content"

        fs.write_text(file_path, content)

        assert fs.exists(file_path)
        assert fs.read_text(file_path) == content

    def test_write_json(self, tmp_path: Path):
        """测试JSON写入"""
        fs = RealFileSystem()
        file_path = tmp_path / "config.json"
        data = {"key": "value"}

        fs.write_json(file_path, data)

        assert fs.exists(file_path)
        assert fs.read_json(file_path) == data

    def test_list_dir(self, tmp_path: Path):
        """测试列出目录"""
        fs = RealFileSystem()

        (tmp_path / "file1.txt").write_text("content1")
        (tmp_path / "file2.txt").write_text("content2")

        files = fs.list_dir(tmp_path)

        assert len(files) == 2
