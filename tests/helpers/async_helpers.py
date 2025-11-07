"""
Async testing utilities.

Provides helper functions for testing async code.
"""

import asyncio
from typing import Coroutine, Any, TypeVar
from contextlib import asynccontextmanager

T = TypeVar("T")


async def run_async(coro: Coroutine[Any, Any, T]) -> T:
    """
    Run async coroutine in tests.

    This is a simple wrapper for consistency, though pytest-asyncio
    usually handles this automatically.

    Args:
        coro: Coroutine to run

    Returns:
        Result of coroutine
    """
    return await coro


async def run_async_with_timeout(
    coro: Coroutine[Any, Any, T],
    timeout: float = 5.0,
) -> T:
    """
    Run async coroutine with timeout.

    Args:
        coro: Coroutine to run
        timeout: Timeout in seconds

    Returns:
        Result of coroutine

    Raises:
        asyncio.TimeoutError: If coroutine times out
    """
    return await asyncio.wait_for(coro, timeout=timeout)


@asynccontextmanager
async def timeout_context(seconds: float = 5.0):
    """
    Context manager for async timeout.

    Usage:
        async with timeout_context(1.0):
            await slow_operation()

    Args:
        seconds: Timeout in seconds

    Raises:
        asyncio.TimeoutError: If operations timeout
    """
    try:
        async with asyncio.timeout(seconds):
            yield
    except asyncio.TimeoutError:
        raise


async def wait_for_condition(
    condition: callable,
    timeout: float = 5.0,
    interval: float = 0.1,
) -> bool:
    """
    Wait for a condition to become true.

    Useful for testing async state changes.

    Args:
        condition: Callable that returns bool
        timeout: Maximum time to wait
        interval: Check interval

    Returns:
        True if condition met, False if timeout

    Example:
        await wait_for_condition(lambda: plugin.loaded, timeout=2.0)
    """
    start = asyncio.get_event_loop().time()

    while (asyncio.get_event_loop().time() - start) < timeout:
        if condition():
            return True
        await asyncio.sleep(interval)

    return False


async def gather_with_timeout(
    *coros,
    timeout: float = 5.0,
):
    """
    Gather multiple coroutines with timeout.

    Args:
        *coros: Coroutines to gather
        timeout: Timeout in seconds

    Returns:
        List of results

    Raises:
        asyncio.TimeoutError: If any coroutine times out
    """
    return await asyncio.wait_for(
        asyncio.gather(*coros),
        timeout=timeout,
    )


class AsyncMock:
    """
    Simple async mock for testing.

    For more complex scenarios, use unittest.mock.AsyncMock.
    """

    def __init__(self, return_value=None):
        self.return_value = return_value
        self.call_count = 0
        self.call_args_list = []

    async def __call__(self, *args, **kwargs):
        self.call_count += 1
        self.call_args_list.append((args, kwargs))
        return self.return_value

    def reset(self):
        """Reset call tracking."""
        self.call_count = 0
        self.call_args_list = []
