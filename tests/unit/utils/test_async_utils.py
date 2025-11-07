"""
Tests for AsyncUtils

Tests async utility functions including file operations, task management, and retry logic.
"""

import pytest
import asyncio

from gscripts.utils.async_utils import (
    AsyncFileUtils,
    AsyncUtils,
    AsyncTaskManager,
    async_timeout,
)


class TestAsyncFileUtils:
    """Tests for AsyncFileUtils class"""

    @pytest.mark.asyncio
    async def test_read_text_success(self, tmp_path):
        """Test async text file reading"""
        # Arrange
        test_file = tmp_path / "test.txt"
        test_content = "Hello, async world!"
        test_file.write_text(test_content)

        # Act
        result = await AsyncFileUtils.read_text(test_file)

        # Assert
        assert result == test_content

    @pytest.mark.asyncio
    async def test_read_text_with_encoding(self, tmp_path):
        """Test async reading with custom encoding"""
        # Arrange
        test_file = tmp_path / "test_utf8.txt"
        test_content = "你好，异步世界！"
        test_file.write_text(test_content, encoding="utf-8")

        # Act
        result = await AsyncFileUtils.read_text(test_file, encoding="utf-8")

        # Assert
        assert result == test_content

    @pytest.mark.asyncio
    async def test_write_text_success(self, tmp_path):
        """Test async text file writing"""
        # Arrange
        test_file = tmp_path / "test.txt"
        test_content = "Async write test"

        # Act
        await AsyncFileUtils.write_text(test_file, test_content)

        # Assert
        assert test_file.exists()
        assert test_file.read_text() == test_content

    @pytest.mark.asyncio
    async def test_exists_returns_true_for_existing_file(self, tmp_path):
        """Test exists check for existing file"""
        # Arrange
        test_file = tmp_path / "exists.txt"
        test_file.touch()

        # Act
        result = await AsyncFileUtils.exists(test_file)

        # Assert
        assert result is True

    @pytest.mark.asyncio
    async def test_exists_returns_false_for_nonexistent_file(self, tmp_path):
        """Test exists check for nonexistent file"""
        # Arrange
        test_file = tmp_path / "nonexistent.txt"

        # Act
        result = await AsyncFileUtils.exists(test_file)

        # Assert
        assert result is False


class TestAsyncUtils:
    """Tests for AsyncUtils class"""

    @pytest.mark.asyncio
    async def test_run_with_timeout_completes_within_timeout(self):
        """Test running coroutine within timeout"""

        # Arrange
        async def quick_task():
            await asyncio.sleep(0.01)
            return "completed"

        # Act
        result = await AsyncUtils.run_with_timeout(quick_task(), timeout=1.0)

        # Assert
        assert result == "completed"

    @pytest.mark.asyncio
    async def test_run_with_timeout_raises_on_timeout(self):
        """Test timeout error is raised"""

        # Arrange
        async def slow_task():
            await asyncio.sleep(2.0)
            return "never"

        # Act & Assert
        with pytest.raises(TimeoutError) as exc_info:
            await AsyncUtils.run_with_timeout(slow_task(), timeout=0.1)
        assert "超时" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_gather_with_limit_executes_all_coroutines(self):
        """Test gather with concurrency limit"""

        # Arrange
        async def task(value):
            await asyncio.sleep(0.01)
            return value * 2

        coroutines = [task(i) for i in range(5)]

        # Act
        results = await AsyncUtils.gather_with_limit(coroutines, limit=2)

        # Assert
        assert len(results) == 5
        assert results == [0, 2, 4, 6, 8]

    @pytest.mark.asyncio
    async def test_gather_with_limit_returns_exceptions(self):
        """Test gather with limit returns exceptions"""

        # Arrange
        async def task(value):
            if value == 2:
                raise ValueError("Test error")
            return value

        coroutines = [task(i) for i in range(4)]

        # Act
        results = await AsyncUtils.gather_with_limit(coroutines, limit=2)

        # Assert
        assert len(results) == 4
        assert results[0] == 0
        assert results[1] == 1
        assert isinstance(results[2], ValueError)
        assert results[3] == 3

    @pytest.mark.asyncio
    async def test_retry_async_succeeds_on_first_try(self):
        """Test retry succeeds immediately"""
        # Arrange
        call_count = 0

        async def succeeds_immediately():
            nonlocal call_count
            call_count += 1
            return "success"

        # Act
        result = await AsyncUtils.retry_async(succeeds_immediately, max_retries=3)

        # Assert
        assert result == "success"
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_retry_async_succeeds_after_failures(self):
        """Test retry succeeds after some failures"""
        # Arrange
        call_count = 0

        async def succeeds_on_third_try():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Temporary failure")
            return "success"

        # Act
        result = await AsyncUtils.retry_async(
            succeeds_on_third_try, max_retries=3, delay=0.01
        )

        # Assert
        assert result == "success"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_retry_async_exhausts_retries(self):
        """Test retry raises after max retries"""

        # Arrange
        async def always_fails():
            raise ValueError("Persistent failure")

        # Act & Assert
        with pytest.raises(ValueError) as exc_info:
            await AsyncUtils.retry_async(always_fails, max_retries=2, delay=0.01)
        assert "Persistent failure" in str(exc_info.value)


class TestAsyncRetryDecorator:
    """Tests for async_retry decorator"""

    @pytest.mark.asyncio
    async def test_decorator_usage_pattern(self):
        """Test that retry_async can be used manually"""
        # Arrange
        call_count = 0

        async def flaky_function():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Flaky")
            return "finally worked"

        # Act
        result = await AsyncUtils.retry_async(flaky_function, max_retries=3, delay=0.01)

        # Assert
        assert result == "finally worked"
        assert call_count == 3


class TestAsyncTimeoutDecorator:
    """Tests for async_timeout decorator"""

    @pytest.mark.asyncio
    async def test_decorator_allows_quick_completion(self):
        """Test decorator allows function to complete"""

        # Arrange
        @async_timeout(timeout=1.0)
        async def quick_function():
            await asyncio.sleep(0.01)
            return "done"

        # Act
        result = await quick_function()

        # Assert
        assert result == "done"

    @pytest.mark.asyncio
    async def test_decorator_raises_timeout_error(self):
        """Test decorator raises timeout for slow function"""

        # Arrange
        @async_timeout(timeout=0.1)
        async def slow_function():
            await asyncio.sleep(2.0)
            return "never"

        # Act & Assert
        with pytest.raises(TimeoutError):
            await slow_function()


class TestAsyncTaskManager:
    """Tests for AsyncTaskManager class"""

    @pytest.mark.asyncio
    async def test_add_task_creates_task(self):
        """Test adding task to manager"""
        # Arrange
        manager = AsyncTaskManager(max_concurrent=2)

        async def test_task():
            return "result"

        # Act
        task_name = await manager.add_task("task1", test_task())

        # Assert
        assert task_name == "task1"
        assert "task1" in manager.tasks

    @pytest.mark.asyncio
    async def test_add_duplicate_task_raises_error(self):
        """Test adding duplicate task raises ValueError"""
        # Arrange
        manager = AsyncTaskManager()

        async def test_task():
            await asyncio.sleep(0.1)

        await manager.add_task("task1", test_task())

        # Act & Assert
        with pytest.raises(ValueError) as exc_info:
            await manager.add_task("task1", test_task())
        assert "已存在" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_wait_for_task_returns_result(self):
        """Test waiting for specific task"""
        # Arrange
        manager = AsyncTaskManager()

        async def test_task():
            await asyncio.sleep(0.01)
            return "task_result"

        await manager.add_task("task1", test_task())

        # Act
        result = await manager.wait_for_task("task1")

        # Assert
        assert result == "task_result"
        assert manager.results["task1"] == "task_result"

    @pytest.mark.asyncio
    async def test_wait_for_nonexistent_task_raises_error(self):
        """Test waiting for nonexistent task raises ValueError"""
        # Arrange
        manager = AsyncTaskManager()

        # Act & Assert
        with pytest.raises(ValueError) as exc_info:
            await manager.wait_for_task("nonexistent")
        assert "不存在" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_wait_all_completes_all_tasks(self):
        """Test waiting for all tasks"""
        # Arrange
        manager = AsyncTaskManager()

        async def task(value):
            await asyncio.sleep(0.01)
            return value * 2

        await manager.add_task("task1", task(5))
        await manager.add_task("task2", task(10))

        # Act
        results = await manager.wait_all()

        # Assert
        assert len(results) == 2
        assert results["task1"] == 10
        assert results["task2"] == 20

    @pytest.mark.asyncio
    async def test_cancel_task_cancels_running_task(self):
        """Test cancelling a specific task"""
        # Arrange
        manager = AsyncTaskManager()

        async def long_task():
            await asyncio.sleep(10.0)

        await manager.add_task("long_task", long_task())

        # Act
        result = manager.cancel_task("long_task")

        # Assert
        assert result is True

    @pytest.mark.asyncio
    async def test_cancel_nonexistent_task_returns_false(self):
        """Test cancelling nonexistent task returns False"""
        # Arrange
        manager = AsyncTaskManager()

        # Act
        result = manager.cancel_task("nonexistent")

        # Assert
        assert result is False

    @pytest.mark.asyncio
    async def test_cancel_all_cancels_pending_tasks(self):
        """Test cancelling all tasks"""
        # Arrange
        manager = AsyncTaskManager()

        async def long_task():
            await asyncio.sleep(10.0)

        await manager.add_task("task1", long_task())
        await manager.add_task("task2", long_task())

        # Act
        count = manager.cancel_all()

        # Assert
        assert count == 2

    @pytest.mark.asyncio
    async def test_get_status_returns_task_statuses(self):
        """Test getting status of all tasks"""
        # Arrange
        manager = AsyncTaskManager()

        async def quick_task():
            return "done"

        async def long_task():
            await asyncio.sleep(10.0)

        await manager.add_task("quick", quick_task())
        await manager.add_task("long", long_task())

        # Give quick task time to complete
        await asyncio.sleep(0.05)

        # Act
        statuses = manager.get_status()

        # Assert
        assert "quick" in statuses
        assert "long" in statuses
        # Quick task should be done, long task should be running
        assert statuses["quick"] == "完成"
        assert statuses["long"] == "运行中"
