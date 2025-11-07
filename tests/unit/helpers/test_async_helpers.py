"""
Tests for async helper utilities
"""

import pytest
import asyncio

from tests.helpers.async_helpers import (
    run_async,
    run_async_with_timeout,
    wait_for_condition,
    gather_with_timeout,
)


class TestAsyncHelpers:
    """Tests for async testing utilities"""

    @pytest.mark.asyncio
    async def test_run_async_executes_coroutine(self):
        """Test run_async executes coroutine"""

        # Arrange
        async def sample_coro():
            return "result"

        # Act
        result = await run_async(sample_coro())

        # Assert
        assert result == "result"

    @pytest.mark.asyncio
    async def test_run_async_with_timeout_succeeds_within_timeout(self):
        """Test async operation completes within timeout"""

        # Arrange
        async def quick_operation():
            await asyncio.sleep(0.1)
            return "done"

        # Act
        result = await run_async_with_timeout(quick_operation(), timeout=1.0)

        # Assert
        assert result == "done"

    @pytest.mark.asyncio
    async def test_run_async_with_timeout_raises_on_timeout(self):
        """Test async operation times out"""

        # Arrange
        async def slow_operation():
            await asyncio.sleep(2.0)
            return "done"

        # Act & Assert
        with pytest.raises(asyncio.TimeoutError):
            await run_async_with_timeout(slow_operation(), timeout=0.1)

    @pytest.mark.asyncio
    async def test_wait_for_condition_returns_true_when_met(self):
        """Test wait_for_condition returns True when condition met"""

        # Arrange
        state = {"ready": False}

        async def set_ready():
            await asyncio.sleep(0.1)
            state["ready"] = True

        # Start background task
        asyncio.create_task(set_ready())

        # Act
        result = await wait_for_condition(
            lambda: state["ready"],
            timeout=1.0,
            interval=0.05,
        )

        # Assert
        assert result is True
        assert state["ready"] is True

    @pytest.mark.asyncio
    async def test_wait_for_condition_returns_false_on_timeout(self):
        """Test wait_for_condition returns False on timeout"""

        # Arrange
        state = {"ready": False}

        # Act
        result = await wait_for_condition(
            lambda: state["ready"],
            timeout=0.1,
            interval=0.05,
        )

        # Assert
        assert result is False

    @pytest.mark.asyncio
    async def test_gather_with_timeout_collects_results(self):
        """Test gather_with_timeout collects all results"""

        # Arrange
        async def task1():
            await asyncio.sleep(0.05)
            return "result1"

        async def task2():
            await asyncio.sleep(0.05)
            return "result2"

        # Act
        results = await gather_with_timeout(
            task1(),
            task2(),
            timeout=1.0,
        )

        # Assert
        assert len(results) == 2
        assert "result1" in results
        assert "result2" in results

    @pytest.mark.asyncio
    async def test_gather_with_timeout_raises_on_timeout(self):
        """Test gather_with_timeout raises TimeoutError"""

        # Arrange
        async def slow_task():
            await asyncio.sleep(2.0)
            return "result"

        # Act & Assert
        with pytest.raises(asyncio.TimeoutError):
            await gather_with_timeout(slow_task(), timeout=0.1)

    @pytest.mark.asyncio
    async def test_multiple_async_operations_in_sequence(self):
        """Test running multiple async operations in sequence"""

        # Arrange
        results = []

        async def operation(value):
            await asyncio.sleep(0.05)
            results.append(value)
            return value

        # Act
        await operation(1)
        await operation(2)
        await operation(3)

        # Assert
        assert results == [1, 2, 3]

    @pytest.mark.asyncio
    async def test_multiple_async_operations_in_parallel(self):
        """Test running multiple async operations in parallel"""

        # Arrange
        async def operation(value):
            await asyncio.sleep(0.05)
            return value * 2

        # Act
        results = await asyncio.gather(
            operation(1),
            operation(2),
            operation(3),
        )

        # Assert
        assert results == [2, 4, 6]
