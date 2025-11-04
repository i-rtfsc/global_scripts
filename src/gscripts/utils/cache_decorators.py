"""
缓存装饰器模块
提供统一的缓存机制，消除重复的缓存逻辑
"""

import time
import hashlib
from pathlib import Path
from typing import Callable, Any, Optional, Dict
from functools import wraps


class CacheEntry:
    """缓存条目"""

    def __init__(self, value: Any, timestamp: float, mtime: Optional[float] = None):
        self.value = value
        self.timestamp = timestamp
        self.mtime = mtime  # 文件修改时间


class CacheManager:
    """缓存管理器"""

    def __init__(self):
        self._cache: Dict[str, CacheEntry] = {}

    def get(self, key: str) -> Optional[CacheEntry]:
        """获取缓存"""
        return self._cache.get(key)

    def set(self, key: str, value: Any, mtime: Optional[float] = None):
        """设置缓存"""
        self._cache[key] = CacheEntry(value=value, timestamp=time.time(), mtime=mtime)

    def clear(self, key: Optional[str] = None):
        """清除缓存"""
        if key:
            self._cache.pop(key, None)
        else:
            self._cache.clear()

    def is_valid(
        self, key: str, ttl: Optional[float] = None, file_path: Optional[Path] = None
    ) -> bool:
        """检查缓存是否有效"""
        entry = self.get(key)
        if not entry:
            return False

        # 检查 TTL
        if ttl is not None:
            if time.time() - entry.timestamp > ttl:
                return False

        # 检查文件修改时间
        if file_path and file_path.exists():
            current_mtime = file_path.stat().st_mtime
            if entry.mtime is None or current_mtime != entry.mtime:
                return False

        return True


# 全局缓存管理器
_cache_manager = CacheManager()


def file_cache(ttl: Optional[float] = 300):
    """
    文件缓存装饰器

    根据文件修改时间自动失效

    Args:
        ttl: 缓存存活时间（秒），None 表示永久

    Usage:
        @file_cache(ttl=300)
        def load_json(file_path: Path) -> dict:
            with open(file_path) as f:
                return json.load(f)
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(file_path: Path, *args, **kwargs):
            # 生成缓存键
            cache_key = f"{func.__name__}:{file_path}"

            # 检查缓存
            if _cache_manager.is_valid(cache_key, ttl, file_path):
                entry = _cache_manager.get(cache_key)
                return entry.value

            # 调用原函数
            result = func(file_path, *args, **kwargs)

            # 存储缓存
            mtime = file_path.stat().st_mtime if file_path.exists() else None
            _cache_manager.set(cache_key, result, mtime)

            return result

        # 添加清除缓存的方法
        wrapper.clear_cache = lambda: _cache_manager.clear()

        return wrapper

    return decorator


def memory_cache(ttl: Optional[float] = 300):
    """
    内存缓存装饰器

    基于函数参数缓存结果

    Args:
        ttl: 缓存存活时间（秒），None 表示永久

    Usage:
        @memory_cache(ttl=60)
        def expensive_computation(n: int) -> int:
            return n ** 2
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # 生成缓存键（基于函数名和参数）
            key_parts = [func.__name__]

            # 添加位置参数
            for arg in args:
                key_parts.append(str(arg))

            # 添加关键字参数
            for k, v in sorted(kwargs.items()):
                key_parts.append(f"{k}={v}")

            # 使用 hash 生成键（避免键太长）
            cache_key = hashlib.md5(":".join(key_parts).encode()).hexdigest()

            # 检查缓存
            if _cache_manager.is_valid(cache_key, ttl):
                entry = _cache_manager.get(cache_key)
                return entry.value

            # 调用原函数
            result = func(*args, **kwargs)

            # 存储缓存
            _cache_manager.set(cache_key, result)

            return result

        # 添加清除缓存的方法
        wrapper.clear_cache = lambda: _cache_manager.clear()

        return wrapper

    return decorator


def async_file_cache(ttl: Optional[float] = 300):
    """
    异步文件缓存装饰器

    Args:
        ttl: 缓存存活时间（秒）

    Usage:
        @async_file_cache(ttl=300)
        async def load_json_async(file_path: Path) -> dict:
            async with aiofiles.open(file_path) as f:
                content = await f.read()
                return json.loads(content)
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(file_path: Path, *args, **kwargs):
            # 生成缓存键
            cache_key = f"{func.__name__}:{file_path}"

            # 检查缓存
            if _cache_manager.is_valid(cache_key, ttl, file_path):
                entry = _cache_manager.get(cache_key)
                return entry.value

            # 调用原函数
            result = await func(file_path, *args, **kwargs)

            # 存储缓存
            mtime = file_path.stat().st_mtime if file_path.exists() else None
            _cache_manager.set(cache_key, result, mtime)

            return result

        # 添加清除缓存的方法
        wrapper.clear_cache = lambda: _cache_manager.clear()

        return wrapper

    return decorator


def clear_all_caches():
    """清除所有缓存"""
    _cache_manager.clear()


def get_cache_stats() -> Dict[str, Any]:
    """
    获取缓存统计信息

    Returns:
        Dict: 缓存统计
    """
    return {
        "total_entries": len(_cache_manager._cache),
        "entries": list(_cache_manager._cache.keys()),
    }
