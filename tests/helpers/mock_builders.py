"""
Mock builders for complex test objects.

Provides builder classes for constructing complex mocks.
"""

from typing import Optional, Dict, Any, List
from unittest.mock import Mock, AsyncMock
from pathlib import Path

from gscripts.models.plugin import PluginMetadata
from gscripts.models.result import CommandResult


class MockPluginLoaderBuilder:
    """
    Builder for creating mock plugin loaders.

    Usage:
        loader = (MockPluginLoaderBuilder()
                  .with_plugin("test1")
                  .with_plugin("test2")
                  .build())
    """

    def __init__(self):
        self._plugins: Dict[str, Any] = {}
        self._failed_plugins: Dict[str, str] = {}

    def with_plugin(
        self,
        name: str,
        metadata: Optional[PluginMetadata] = None,
    ) -> "MockPluginLoaderBuilder":
        """Add a loaded plugin."""
        if metadata is None:
            from tests.factories.plugin_factory import PluginFactory

            metadata = PluginFactory.create(name=name)

        self._plugins[name] = Mock(metadata=metadata)
        return self

    def with_failed_plugin(
        self,
        name: str,
        error: str = "Failed to load",
    ) -> "MockPluginLoaderBuilder":
        """Add a failed plugin."""
        self._failed_plugins[name] = error
        return self

    def build(self) -> Mock:
        """Build the mock loader."""
        loader = Mock()
        loader.get_loaded_plugins.return_value = self._plugins
        loader.get_failed_plugins.return_value = self._failed_plugins

        # Mock load_all_plugins as async
        async def mock_load_all(*args, **kwargs):
            return self._plugins

        loader.load_all_plugins = AsyncMock(side_effect=mock_load_all)

        return loader


class MockRepositoryBuilder:
    """
    Builder for creating mock repositories.

    Usage:
        repo = (MockRepositoryBuilder()
                .with_plugin(metadata1)
                .with_plugin(metadata2)
                .build())
    """

    def __init__(self):
        self._plugins: Dict[str, PluginMetadata] = {}

    def with_plugin(
        self,
        metadata: PluginMetadata,
    ) -> "MockRepositoryBuilder":
        """Add a plugin to repository."""
        self._plugins[metadata.name] = metadata
        return self

    def with_plugins(
        self,
        plugins: List[PluginMetadata],
    ) -> "MockRepositoryBuilder":
        """Add multiple plugins."""
        for plugin in plugins:
            self._plugins[plugin.name] = plugin
        return self

    def build(self) -> Mock:
        """Build the mock repository."""
        repo = Mock()

        # Mock get_all
        async def mock_get_all():
            return list(self._plugins.values())

        repo.get_all = AsyncMock(side_effect=mock_get_all)

        # Mock get_by_name
        async def mock_get_by_name(name: str):
            return self._plugins.get(name)

        repo.get_by_name = AsyncMock(side_effect=mock_get_by_name)

        # Mock save
        async def mock_save(metadata: PluginMetadata):
            self._plugins[metadata.name] = metadata

        repo.save = AsyncMock(side_effect=mock_save)

        # Mock delete
        async def mock_delete(name: str):
            if name in self._plugins:
                del self._plugins[name]

        repo.delete = AsyncMock(side_effect=mock_delete)

        # Mock exists
        async def mock_exists(name: str):
            return name in self._plugins

        repo.exists = AsyncMock(side_effect=mock_exists)

        return repo


class MockExecutorBuilder:
    """
    Builder for creating mock plugin executors.

    Usage:
        executor = (MockExecutorBuilder()
                    .with_success_result()
                    .build())
    """

    def __init__(self):
        self._result = CommandResult(
            success=True,
            output="Mock output",
            error="",
            exit_code=0,
        )
        self._call_tracker = []

    def with_success_result(
        self,
        output: str = "Success",
    ) -> "MockExecutorBuilder":
        """Configure executor to return success."""
        from tests.factories.result_factory import ResultFactory

        self._result = ResultFactory.success(output=output)
        return self

    def with_failure_result(
        self,
        error: str = "Error",
    ) -> "MockExecutorBuilder":
        """Configure executor to return failure."""
        from tests.factories.result_factory import ResultFactory

        self._result = ResultFactory.failure(error=error)
        return self

    def with_custom_result(
        self,
        result: CommandResult,
    ) -> "MockExecutorBuilder":
        """Configure executor to return custom result."""
        self._result = result
        return self

    def build(self) -> Mock:
        """Build the mock executor."""
        executor = Mock()

        # Track calls
        def track_call(*args, **kwargs):
            self._call_tracker.append((args, kwargs))
            return self._result

        # Mock execute as async
        async def mock_execute(*args, **kwargs):
            return track_call(*args, **kwargs)

        executor.execute = AsyncMock(side_effect=mock_execute)
        executor.get_call_count = lambda: len(self._call_tracker)
        executor.get_calls = lambda: self._call_tracker

        return executor


class MockFileSystemBuilder:
    """
    Builder for creating in-memory filesystem with pre-populated files.

    Usage:
        fs = (MockFileSystemBuilder()
              .with_file("/test/file.txt", "content")
              .with_directory("/test/dir")
              .build())
    """

    def __init__(self):
        from gscripts.infrastructure.filesystem.file_operations import (
            InMemoryFileSystem,
        )

        self._fs = InMemoryFileSystem()

    def with_file(
        self,
        path: Path | str,
        content: str,
    ) -> "MockFileSystemBuilder":
        """Add a file to filesystem."""
        self._fs.write_text(Path(path), content)
        return self

    def with_json_file(
        self,
        path: Path | str,
        data: Dict[str, Any],
    ) -> "MockFileSystemBuilder":
        """Add a JSON file to filesystem."""
        import json

        self._fs.write_text(Path(path), json.dumps(data, indent=2))
        return self

    def with_directory(
        self,
        path: Path | str,
    ) -> "MockFileSystemBuilder":
        """Add a directory to filesystem."""
        self._fs.makedirs(Path(path))
        return self

    def build(self):
        """Build the filesystem."""
        return self._fs
