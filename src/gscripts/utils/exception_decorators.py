"""
Exception handling decorators for plugin loading
"""

import functools
from typing import Optional, Any, Callable
from ..core.logger import get_logger

logger = get_logger(tag="UTILS.DECORATORS", name=__name__)


def handle_plugin_error(
    error_message: str = "Plugin operation failed",
    return_value: Any = None,
    log_level: str = "warning"
):
    """
    Decorator to handle plugin-related exceptions with consistent logging

    Args:
        error_message: Base error message to log
        return_value: Value to return on exception (default None)
        log_level: Logging level - 'debug', 'info', 'warning', 'error'

    Usage:
        @handle_plugin_error("Failed to load plugin", return_value={})
        def load_plugin(self, name: str):
            # ... code that might raise exceptions
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                # Get logger method based on level
                log_func = getattr(logger, log_level, logger.warning)

                # Try to get plugin/file name from args if available
                context = ""
                if args:
                    # Try to extract meaningful context
                    for arg in args[1:]:  # Skip 'self'
                        if hasattr(arg, 'name'):
                            context = f" ({arg.name})"
                            break
                        elif isinstance(arg, str):
                            context = f" ({arg})"
                            break

                log_func(f"{error_message}{context}: {type(e).__name__}: {e}")
                return return_value

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                # Get logger method based on level
                log_func = getattr(logger, log_level, logger.warning)

                # Try to get plugin/file name from args if available
                context = ""
                if args:
                    for arg in args[1:]:  # Skip 'self'
                        if hasattr(arg, 'name'):
                            context = f" ({arg.name})"
                            break
                        elif isinstance(arg, str):
                            context = f" ({arg})"
                            break

                log_func(f"{error_message}{context}: {type(e).__name__}: {e}")
                return return_value

        # Return appropriate wrapper based on whether function is async
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return wrapper

    return decorator


def log_exceptions(func: Callable) -> Callable:
    """
    Simple decorator to log exceptions without suppressing them

    Usage:
        @log_exceptions
        def critical_operation(self):
            # ... code that might raise exceptions
            pass
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Exception in {func.__name__}: {type(e).__name__}: {e}", exc_info=True)
            raise

    @functools.wraps(func)
    async def async_wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Exception in {func.__name__}: {type(e).__name__}: {e}", exc_info=True)
            raise

    if asyncio.iscoroutinefunction(func):
        return async_wrapper
    return wrapper


# Need to import asyncio for iscoroutinefunction check
import asyncio


__all__ = ['handle_plugin_error', 'log_exceptions']
