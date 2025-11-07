"""
Function factory for generating test FunctionInfo instances.

Provides factory methods for creating varied function metadata with sensible defaults.
"""

from typing import Optional, Dict, List

from gscripts.models.function import FunctionInfo
from gscripts.models.plugin import FunctionType


class FunctionFactory:
    """Factory for creating FunctionInfo instances in tests."""

    _counter = 0

    @classmethod
    def create(
        cls,
        name: Optional[str] = None,
        description: Optional[Dict[str, str]] = None,
        function_type: FunctionType = FunctionType.PYTHON_DECORATED,
        subplugin: str = "",
        usage: Optional[str] = None,
        examples: Optional[List[str]] = None,
        method: Optional[str] = None,
        **kwargs,
    ) -> FunctionInfo:
        """
        Create a single FunctionInfo instance.

        Args:
            name: Function name (auto-generated if None)
            description: Function description dict (zh/en)
            function_type: Type of function
            subplugin: Subplugin name (empty if root plugin)
            usage: Usage string
            examples: List of example commands
            method: Actual method name in code
            **kwargs: Additional attributes to override

        Returns:
            FunctionInfo instance
        """
        # Auto-generate unique name if not provided
        if name is None:
            cls._counter += 1
            name = f"test_function_{cls._counter}"

        # Default description
        if description is None:
            description = {
                "zh": f"{name} 函数",
                "en": f"{name} function",
            }

        # Default usage
        if usage is None:
            if subplugin:
                usage = f"gs plugin {subplugin} {name} [args]"
            else:
                usage = f"gs plugin {name} [args]"

        # Default examples
        if examples is None:
            examples = [usage.replace("[args]", "example")]

        # Method name defaults to function name
        if method is None:
            method = name

        # Create function info
        function_info = FunctionInfo(
            name=name,
            description=description,
            type=function_type,
            subplugin=subplugin,
            usage=usage,
            examples=examples,
            method=method,
        )

        # Override any additional attributes
        for key, value in kwargs.items():
            if hasattr(function_info, key):
                setattr(function_info, key, value)

        return function_info

    @classmethod
    def create_batch(cls, count: int, **kwargs) -> List[FunctionInfo]:
        """
        Create multiple FunctionInfo instances.

        Args:
            count: Number of functions to create
            **kwargs: Arguments passed to create()

        Returns:
            List of FunctionInfo instances
        """
        return [cls.create(**kwargs) for _ in range(count)]

    @classmethod
    def create_python(cls, **kwargs) -> FunctionInfo:
        """Create Python decorated function metadata."""
        return cls.create(function_type=FunctionType.PYTHON_DECORATED, **kwargs)

    @classmethod
    def create_shell(cls, **kwargs) -> FunctionInfo:
        """Create Shell function metadata."""
        return cls.create(function_type=FunctionType.SHELL_ANNOTATED, **kwargs)

    @classmethod
    def create_config(cls, **kwargs) -> FunctionInfo:
        """Create Config function metadata."""
        return cls.create(function_type=FunctionType.CONFIG, **kwargs)

    @classmethod
    def create_with_examples(cls, example_count: int = 3, **kwargs) -> FunctionInfo:
        """
        Create function with multiple example commands.

        Args:
            example_count: Number of examples to generate
            **kwargs: Arguments passed to create()

        Returns:
            FunctionInfo with examples
        """
        name = kwargs.get("name", f"test_function_{cls._counter + 1}")
        subplugin = kwargs.get("subplugin", "")

        examples = []
        for i in range(example_count):
            if subplugin:
                examples.append(f"gs plugin {subplugin} {name} example_{i}")
            else:
                examples.append(f"gs plugin {name} example_{i}")

        return cls.create(examples=examples, **kwargs)

    @classmethod
    def create_for_subplugin(
        cls, subplugin: str, function_names: List[str], **kwargs
    ) -> List[FunctionInfo]:
        """
        Create multiple functions for a specific subplugin.

        Args:
            subplugin: Subplugin name
            function_names: List of function names to create
            **kwargs: Additional arguments passed to create()

        Returns:
            List of FunctionInfo instances
        """
        return [
            cls.create(name=name, subplugin=subplugin, **kwargs)
            for name in function_names
        ]

    @classmethod
    def reset_counter(cls):
        """Reset the auto-increment counter (useful between tests)."""
        cls._counter = 0
