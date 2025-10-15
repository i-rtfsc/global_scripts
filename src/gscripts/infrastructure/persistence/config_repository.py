"""
Config Repository Implementation
Manages configuration persistence and retrieval
"""

from pathlib import Path
from typing import Dict, Any, Optional

from ...domain.interfaces import IConfigRepository, IFileSystem


class ConfigRepository(IConfigRepository):
    """Configuration repository implementation using filesystem"""

    def __init__(self, filesystem: IFileSystem, config_path: Path):
        """
        Initialize config repository

        Args:
            filesystem: Filesystem abstraction
            config_path: Path to configuration file (gs.json)
        """
        self._fs = filesystem
        self._config_path = config_path
        self._cache: Optional[Dict[str, Any]] = None

    async def load(self) -> Dict[str, Any]:
        """Load configuration from file"""
        if self._cache is not None:
            return self._cache.copy()

        if not self._fs.exists(self._config_path):
            self._cache = {}
            return {}

        try:
            self._cache = self._fs.read_json(self._config_path)
            return self._cache.copy()
        except Exception:
            self._cache = {}
            return {}

    async def save(self, config: Dict[str, Any]) -> None:
        """Save configuration to file"""
        self._fs.write_json(self._config_path, config)
        self._cache = config.copy()

    async def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key"""
        config = await self.load()

        # Support nested key access with dot notation (e.g., "logging.level")
        keys = key.split('.')
        value = config

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    async def set(self, key: str, value: Any) -> None:
        """Set configuration value by key"""
        config = await self.load()

        # Support nested key setting with dot notation
        keys = key.split('.')
        current = config

        for k in keys[:-1]:
            if k not in current or not isinstance(current[k], dict):
                current[k] = {}
            current = current[k]

        current[keys[-1]] = value

        await self.save(config)

    def clear_cache(self) -> None:
        """Clear the internal cache (useful for testing)"""
        self._cache = None


__all__ = ['ConfigRepository']
