"""
Config Service (Facade Pattern)
Provides unified interface for configuration access
"""

from typing import Any, Dict, Optional

from ...domain.interfaces import IConfigRepository, IEnvironment


class ConfigService:
    """
    Configuration service using Facade pattern

    Provides unified access to:
    - Configuration file (gs.json) via ConfigRepository
    - Environment variables via IEnvironment
    - Computed/derived configuration values
    """

    def __init__(
        self,
        config_repository: IConfigRepository,
        environment: IEnvironment,
        defaults: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize config service

        Args:
            config_repository: Configuration repository
            environment: Environment variable interface
            defaults: Default configuration values
        """
        self._repository = config_repository
        self._environment = environment
        self._defaults = defaults or self._get_default_config()

    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            "language": "zh",
            "logging": {
                "level": "INFO",
                "file": None,
            },
            "show_examples": False,
            "completion": {
                "show_descriptions": True,
                "show_subcommand_descriptions": True,
            },
            "prompt": {
                "theme": "bitstream",
            },
        }

    async def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value with cascading lookup

        Priority:
        1. Environment variable (GS_<KEY>)
        2. Configuration file (gs.json)
        3. Provided default
        4. Built-in default

        Args:
            key: Configuration key (supports dot notation)
            default: Default value if not found

        Returns:
            Configuration value
        """
        # 1. Try environment variable (GS_ prefix)
        env_key = f"GS_{key.upper().replace('.', '_')}"
        env_value = self._environment.get(env_key)
        if env_value is not None:
            return self._parse_env_value(env_value)

        # 2. Try configuration file
        config_value = await self._repository.get(key)
        if config_value is not None:
            return config_value

        # 3. Try provided default
        if default is not None:
            return default

        # 4. Try built-in defaults
        keys = key.split(".")
        value = self._defaults
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return None

        return value

    async def set(self, key: str, value: Any) -> None:
        """
        Set configuration value

        Args:
            key: Configuration key (supports dot notation)
            value: Configuration value
        """
        await self._repository.set(key, value)

    async def get_all(self) -> Dict[str, Any]:
        """Get all configuration (merged with defaults)"""
        config = self._defaults.copy()
        file_config = await self._repository.load()
        self._merge_dicts(config, file_config)
        return config

    async def reload(self) -> None:
        """Reload configuration from file"""
        self._repository.clear_cache()

    def _parse_env_value(self, value: str) -> Any:
        """Parse environment variable value to appropriate type"""
        # Boolean parsing
        if value.lower() in ("true", "yes", "1"):
            return True
        if value.lower() in ("false", "no", "0"):
            return False

        # Number parsing
        try:
            if "." in value:
                return float(value)
            return int(value)
        except ValueError:
            pass

        # String
        return value

    def _merge_dicts(self, base: Dict, overlay: Dict) -> None:
        """Recursively merge overlay dict into base dict"""
        for key, value in overlay.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_dicts(base[key], value)
            else:
                base[key] = value

    # Convenience methods for common configurations

    async def get_language(self) -> str:
        """Get UI language"""
        return await self.get("language", "zh")

    async def get_logging_level(self) -> str:
        """Get logging level"""
        return await self.get("logging.level", "INFO")

    async def get_show_examples(self) -> bool:
        """Get show examples flag"""
        return await self.get("show_examples", False)

    async def get_prompt_theme(self) -> str:
        """Get prompt theme"""
        return await self.get("prompt.theme", "bitstream")

    async def is_debug_mode(self) -> bool:
        """Check if debug mode is enabled"""
        return await self.get_logging_level() == "DEBUG"


__all__ = ["ConfigService"]
