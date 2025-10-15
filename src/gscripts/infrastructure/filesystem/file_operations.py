"""
文件系统抽象实现
提供真实和内存文件系统，用于测试隔离
"""

import json
from pathlib import Path
from typing import Dict, Any, List

from ...domain.interfaces import IFileSystem


class RealFileSystem(IFileSystem):
    """真实文件系统实现"""

    def exists(self, path: Path) -> bool:
        """检查路径是否存在"""
        return path.exists()

    def read_text(self, path: Path, encoding: str = 'utf-8') -> str:
        """读取文本文件"""
        return path.read_text(encoding=encoding)

    def write_text(self, path: Path, content: str, encoding: str = 'utf-8') -> None:
        """写入文本文件"""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding=encoding)

    def read_json(self, path: Path) -> Dict[str, Any]:
        """读取 JSON 文件"""
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def write_json(self, path: Path, data: Dict[str, Any]) -> None:
        """写入 JSON 文件"""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def list_dir(self, path: Path) -> List[Path]:
        """列出目录内容"""
        if not path.exists() or not path.is_dir():
            return []
        return list(path.iterdir())


class InMemoryFileSystem(IFileSystem):
    """内存文件系统实现（用于测试）"""

    def __init__(self):
        self._files: Dict[str, str] = {}
        self._directories: set = set()

    def exists(self, path: Path) -> bool:
        """检查路径是否存在"""
        path_str = str(path)
        return path_str in self._files or path_str in self._directories

    def read_text(self, path: Path, encoding: str = 'utf-8') -> str:
        """读取文本文件"""
        path_str = str(path)
        if path_str not in self._files:
            raise FileNotFoundError(f"No such file: {path}")
        return self._files[path_str]

    def write_text(self, path: Path, content: str, encoding: str = 'utf-8') -> None:
        """写入文本文件"""
        # Create all parent directories recursively
        parts = str(path).split('/')
        for i in range(1, len(parts)):
            parent = '/'.join(parts[:i])
            if parent:
                self._directories.add(parent)
        self._files[str(path)] = content

    def read_json(self, path: Path) -> Dict[str, Any]:
        """读取 JSON 文件"""
        content = self.read_text(path)
        return json.loads(content)

    def write_json(self, path: Path, data: Dict[str, Any]) -> None:
        """写入 JSON 文件"""
        # Create all parent directories recursively
        parts = str(path).split('/')
        for i in range(1, len(parts)):
            parent = '/'.join(parts[:i])
            if parent:
                self._directories.add(parent)
        content = json.dumps(data, indent=2, ensure_ascii=False)
        self.write_text(path, content)

    def list_dir(self, path: Path) -> List[Path]:
        """列出目录内容"""
        path_str = str(path)
        # Return immediate children (directories) under this path
        results = set()
        for file_path in self._files.keys():
            if file_path.startswith(path_str + '/'):
                # Get the immediate child (directory or file)
                relative = file_path[len(path_str) + 1:]
                first_part = relative.split('/')[0]
                child_path = Path(path_str) / first_part
                results.add(child_path)
        return list(results)

    def clear(self):
        """清空文件系统（测试用）"""
        self._files.clear()
        self._directories.clear()


__all__ = ['RealFileSystem', 'InMemoryFileSystem']
