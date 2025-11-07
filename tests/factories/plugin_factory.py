"""
Plugin factory for generating test PluginMetadata instances.

Provides factory methods for creating varied plugin metadata with sensible defaults.
"""

from typing import Optional, Dict, List

from gscripts.models.plugin import PluginMetadata, PluginType


class PluginFactory:
    """Factory for creating PluginMetadata instances in tests."""

    _counter = 0

    @classmethod
    def create(
        cls,
        name: Optional[str] = None,
        version: str = "1.0.0",
        author: str = "Test Author",
        description: Optional[Dict[str, str]] = None,
        plugin_type: PluginType = PluginType.PYTHON,
        enabled: bool = True,
        **kwargs,
    ) -> PluginMetadata:
        """
        Create a single PluginMetadata instance.

        Args:
            name: Plugin name (auto-generated if None)
            version: Plugin version
            author: Plugin author
            description: Plugin description dict (zh/en)
            plugin_type: Type of plugin (python, shell, json, hybrid)
            enabled: Whether plugin is enabled
            **kwargs: Additional attributes to override

        Returns:
            PluginMetadata instance
        """
        # Auto-generate unique name if not provided
        if name is None:
            cls._counter += 1
            name = f"test_plugin_{cls._counter}"

        # Default description
        if description is None:
            description = {
                "zh": f"{name} 插件",
                "en": f"{name} plugin",
            }

        # Create metadata
        metadata = PluginMetadata(
            name=name,
            version=version,
            author=author,
            description=description,
            type=plugin_type,
            enabled=enabled,
        )

        # Override any additional attributes
        for key, value in kwargs.items():
            if hasattr(metadata, key):
                setattr(metadata, key, value)

        return metadata

    @classmethod
    def create_batch(cls, count: int, **kwargs) -> List[PluginMetadata]:
        """
        Create multiple PluginMetadata instances.

        Args:
            count: Number of plugins to create
            **kwargs: Arguments passed to create()

        Returns:
            List of PluginMetadata instances
        """
        return [cls.create(**kwargs) for _ in range(count)]

    @classmethod
    def create_python(cls, **kwargs) -> PluginMetadata:
        """Create Python plugin metadata."""
        return cls.create(plugin_type=PluginType.PYTHON, **kwargs)

    @classmethod
    def create_shell(cls, **kwargs) -> PluginMetadata:
        """Create Shell plugin metadata."""
        return cls.create(plugin_type=PluginType.SHELL, **kwargs)

    @classmethod
    def create_config(cls, **kwargs) -> PluginMetadata:
        """Create Config/JSON plugin metadata."""
        return cls.create(plugin_type=PluginType.JSON, **kwargs)

    @classmethod
    def create_hybrid(cls, **kwargs) -> PluginMetadata:
        """Create Hybrid plugin metadata."""
        return cls.create(plugin_type=PluginType.HYBRID, **kwargs)

    @classmethod
    def create_disabled(cls, **kwargs) -> PluginMetadata:
        """Create disabled plugin metadata."""
        return cls.create(enabled=False, **kwargs)

    @classmethod
    def create_with_functions(cls, function_count: int = 3, **kwargs) -> PluginMetadata:
        """
        Create plugin metadata with mock functions.

        Args:
            function_count: Number of functions to add
            **kwargs: Arguments passed to create()

        Returns:
            PluginMetadata with functions
        """
        from tests.factories.function_factory import FunctionFactory

        metadata = cls.create(**kwargs)

        # Add mock functions
        functions = FunctionFactory.create_batch(
            count=function_count,
            plugin_name=metadata.name,
        )

        # Note: PluginMetadata might not have a functions attribute
        # depending on the model structure. Adjust as needed.
        if hasattr(metadata, "functions"):
            metadata.functions = {f.name: f for f in functions}

        return metadata

    @classmethod
    def reset_counter(cls):
        """Reset the auto-increment counter (useful between tests)."""
        cls._counter = 0
