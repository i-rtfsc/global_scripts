"""
缓存工具
提供插件配置和模块的缓存机制
"""

import json
import time
from functools import lru_cache
from pathlib import Path
from typing import Dict, Any, Optional, Callable
from dataclasses import dataclass, field

from ..core.logger import get_logger


logger = get_logger(tag="UTILS.CACHE", name=__name__)


@dataclass
class CacheEntry:
    """缓存条目"""
    value: Any
    timestamp: float
    ttl: Optional[float] = None  # Time to live in seconds

    def is_expired(self) -> bool:
        """检查是否过期"""
        if self.ttl is None:
            return False
        return (time.time() - self.timestamp) > self.ttl


class PluginConfigCache:
    """插件配置缓存

    缓存plugin.json的内容,避免重复的文件I/O和JSON解析
    """

    def __init__(self, ttl: Optional[float] = None):
        """
        Args:
            ttl: 缓存过期时间(秒),None表示永不过期
        """
        self.ttl = ttl
        self._cache: Dict[str, CacheEntry] = {}
        self._stats = {
            'hits': 0,
            'misses': 0,
            'invalidations': 0
        }

    def get(self, plugin_path: Path) -> Optional[Dict[str, Any]]:
        """从缓存获取插件配置

        Args:
            plugin_path: 插件目录路径

        Returns:
            插件配置字典,如果不在缓存中返回None
        """
        key = str(plugin_path.resolve())

        if key in self._cache:
            entry = self._cache[key]

            if entry.is_expired():
                # 过期,删除
                del self._cache[key]
                logger.debug(f"Cache expired: {key}")
                self._stats['misses'] += 1
                return None

            self._stats['hits'] += 1
            logger.debug(f"Cache hit: {key}")
            return entry.value

        self._stats['misses'] += 1
        return None

    def set(self, plugin_path: Path, config: Dict[str, Any]):
        """设置缓存

        Args:
            plugin_path: 插件目录路径
            config: 插件配置
        """
        key = str(plugin_path.resolve())
        entry = CacheEntry(
            value=config,
            timestamp=time.time(),
            ttl=self.ttl
        )
        self._cache[key] = entry
        logger.debug(f"Cache set: {key}")

    def invalidate(self, plugin_path: Path):
        """使缓存失效

        Args:
            plugin_path: 插件目录路径
        """
        key = str(plugin_path.resolve())
        if key in self._cache:
            del self._cache[key]
            self._stats['invalidations'] += 1
            logger.debug(f"Cache invalidated: {key}")

    def clear(self):
        """清空所有缓存"""
        count = len(self._cache)
        self._cache.clear()
        logger.info(f"Cache cleared: {count} entries")

    def get_stats(self) -> Dict[str, int]:
        """获取缓存统计信息"""
        total = self._stats['hits'] + self._stats['misses']
        hit_rate = (self._stats['hits'] / total * 100) if total > 0 else 0

        return {
            **self._stats,
            'size': len(self._cache),
            'hit_rate': hit_rate
        }


class FileCache:
    """通用文件缓存

    基于文件修改时间的智能缓存
    """

    def __init__(self, max_size: int = 128):
        """
        Args:
            max_size: 最大缓存条目数
        """
        self.max_size = max_size
        self._cache: Dict[str, tuple[Any, float]] = {}  # {path: (content, mtime)}
        self._access_times: Dict[str, float] = {}  # LRU tracking

    def get(
        self,
        file_path: Path,
        loader: Optional[Callable[[Path], Any]] = None
    ) -> Optional[Any]:
        """获取文件内容(带缓存)

        Args:
            file_path: 文件路径
            loader: 加载函数,如果未提供则返回None

        Returns:
            文件内容
        """
        if not file_path.exists():
            return None

        key = str(file_path.resolve())
        current_mtime = file_path.stat().st_mtime

        # 检查缓存
        if key in self._cache:
            cached_content, cached_mtime = self._cache[key]

            if cached_mtime == current_mtime:
                # 缓存命中且未修改
                self._access_times[key] = time.time()
                logger.debug(f"File cache hit: {key}")
                return cached_content

            # 文件已修改,移除旧缓存
            logger.debug(f"File modified, invalidating cache: {key}")
            del self._cache[key]
            del self._access_times[key]

        # 缓存未命中,加载文件
        if loader is None:
            return None

        try:
            content = loader(file_path)
            self._set(key, content, current_mtime)
            return content
        except Exception as e:
            logger.error(f"Failed to load file {file_path}: {e}")
            return None

    def _set(self, key: str, content: Any, mtime: float):
        """内部设置方法"""
        # 检查缓存大小,如果满了则移除最久未访问的
        if len(self._cache) >= self.max_size:
            self._evict_lru()

        self._cache[key] = (content, mtime)
        self._access_times[key] = time.time()

    def _evict_lru(self):
        """移除最久未访问的条目"""
        if not self._access_times:
            return

        lru_key = min(self._access_times.items(), key=lambda x: x[1])[0]
        del self._cache[lru_key]
        del self._access_times[lru_key]
        logger.debug(f"Evicted LRU entry: {lru_key}")

    def clear(self):
        """清空缓存"""
        self._cache.clear()
        self._access_times.clear()


# 预定义的加载器
def json_loader(file_path: Path) -> Dict[str, Any]:
    """JSON文件加载器"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def text_loader(file_path: Path) -> str:
    """文本文件加载器"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return f.read()


# 全局缓存实例
_plugin_config_cache: Optional[PluginConfigCache] = None
_file_cache: Optional[FileCache] = None


def get_plugin_config_cache() -> PluginConfigCache:
    """获取全局插件配置缓存"""
    global _plugin_config_cache
    if _plugin_config_cache is None:
        _plugin_config_cache = PluginConfigCache(ttl=300)  # 5分钟TTL
    return _plugin_config_cache


def get_file_cache() -> FileCache:
    """获取全局文件缓存"""
    global _file_cache
    if _file_cache is None:
        _file_cache = FileCache(max_size=128)
    return _file_cache


# LRU缓存装饰器包装
def cached_plugin_json(func):
    """装饰器:缓存plugin.json加载"""
    cache = get_plugin_config_cache()

    def wrapper(plugin_path: Path) -> Optional[Dict[str, Any]]:
        # 尝试从缓存获取
        cached = cache.get(plugin_path)
        if cached is not None:
            return cached

        # 缓存未命中,调用原函数
        result = func(plugin_path)
        if result is not None:
            cache.set(plugin_path, result)

        return result

    return wrapper


@cached_plugin_json
def load_plugin_json(plugin_path: Path) -> Optional[Dict[str, Any]]:
    """加载plugin.json或其他JSON配置文件(带缓存)

    Args:
        plugin_path: 插件目录路径或JSON配置文件路径

    Returns:
        插件配置字典
    """
    # 智能判断：如果传入的是JSON文件，直接使用；否则拼接plugin.json
    if plugin_path.suffix == '.json' and plugin_path.is_file():
        plugin_json = plugin_path
    elif plugin_path.is_dir():
        plugin_json = plugin_path / "plugin.json"
    else:
        # 不是文件也不是目录，可能路径不存在
        return None

    if not plugin_json.exists():
        return None

    try:
        with open(plugin_json, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                logger.warning(f"Empty JSON file: {plugin_json}")
                return None
            return json.loads(content)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {plugin_json}: {e}")
        return None
    except Exception as e:
        logger.error(f"Failed to load {plugin_json}: {e}")
        return None
