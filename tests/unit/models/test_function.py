"""
Tests for FunctionInfo model
"""

from gscripts.models.function import FunctionInfo
from gscripts.models.plugin import FunctionType
from tests.factories import FunctionFactory


class TestFunctionInfo:
    """Tests for FunctionInfo dataclass"""

    def test_create_function_info_with_required_fields(self):
        """Test creating function info with required fields"""
        # Act
        function = FunctionInfo(
            name="test_func",
            description={"zh": "测试函数", "en": "Test function"},
            type=FunctionType.PYTHON_DECORATED,
            subplugin="",
            usage="gs plugin test_func",
            examples=["gs plugin test_func example"],
            method="test_func",
        )

        # Assert
        assert function.name == "test_func"
        assert function.type == FunctionType.PYTHON_DECORATED
        assert function.subplugin == ""
        assert len(function.examples) == 1

    def test_create_function_using_factory(self):
        """Test creating function using factory"""
        # Act
        function = FunctionFactory.create(name="factory_func")

        # Assert
        assert function.name == "factory_func"
        assert isinstance(function, FunctionInfo)

    def test_create_python_function(self):
        """Test creating Python function with factory"""
        # Act
        function = FunctionFactory.create_python(name="python_func")

        # Assert
        assert function.type == FunctionType.PYTHON_DECORATED
        assert function.name == "python_func"
        assert function.is_python

    def test_create_shell_function(self):
        """Test creating Shell function with factory"""
        # Act
        function = FunctionFactory.create_shell(name="shell_func")

        # Assert
        assert function.type == FunctionType.SHELL_ANNOTATED
        assert function.name == "shell_func"
        assert function.is_shell

    def test_create_config_function(self):
        """Test creating Config function with factory"""
        # Act
        function = FunctionFactory.create_config(name="config_func")

        # Assert
        assert function.type == FunctionType.CONFIG
        assert function.name == "config_func"
        assert function.is_config

    def test_create_function_with_examples(self):
        """Test creating function with multiple examples"""
        # Act
        function = FunctionFactory.create_with_examples(
            name="example_func",
            example_count=3,
        )

        # Assert
        assert len(function.examples) == 3
        assert all("example_func" in ex for ex in function.examples)

    def test_create_functions_for_subplugin(self):
        """Test creating multiple functions for specific subplugin"""
        # Act
        functions = FunctionFactory.create_for_subplugin(
            subplugin="mysub",
            function_names=["func1", "func2", "func3"],
        )

        # Assert
        assert len(functions) == 3
        assert all(f.subplugin == "mysub" for f in functions)
        assert [f.name for f in functions] == ["func1", "func2", "func3"]

    def test_create_batch_functions(self):
        """Test creating multiple functions using factory"""
        # Act
        functions = FunctionFactory.create_batch(count=5)

        # Assert
        assert len(functions) == 5
        assert all(isinstance(f, FunctionInfo) for f in functions)

    def test_function_with_subplugin(self):
        """Test creating function with subplugin"""
        # Act
        function = FunctionFactory.create(
            name="sub_func",
            subplugin="sub",
        )

        # Assert
        assert function.subplugin == "sub"
        assert "sub" in function.usage

    def test_function_full_name_with_subplugin(self):
        """Test full_name property with subplugin"""
        # Arrange
        function = FunctionFactory.create(name="func", subplugin="sub")

        # Act & Assert
        assert function.full_name == "sub-func"

    def test_function_full_name_without_subplugin(self):
        """Test full_name property without subplugin"""
        # Arrange
        function = FunctionFactory.create(name="func", subplugin="")

        # Act & Assert
        assert function.full_name == "func"

    def test_get_description_with_dict(self):
        """Test get_description with dict description"""
        # Arrange
        function = FunctionFactory.create(
            description={"zh": "中文描述", "en": "English description"}
        )

        # Act & Assert
        assert function.get_description("zh") == "中文描述"
        assert function.get_description("en") == "English description"
        # Falls back to zh if language not found
        assert function.get_description("fr") == "中文描述"

    def test_get_description_with_string(self):
        """Test get_description with string description"""
        # Arrange
        function = FunctionFactory.create(description="Simple description")

        # Act & Assert
        assert function.get_description("zh") == "Simple description"
        assert function.get_description("en") == "Simple description"

    def test_is_python_property(self):
        """Test is_python property"""
        # Arrange
        python_func = FunctionFactory.create_python()

        # Assert
        assert python_func.is_python is True
        assert python_func.is_shell is False
        assert python_func.is_config is False

    def test_is_shell_property(self):
        """Test is_shell property"""
        # Arrange
        shell_func = FunctionFactory.create_shell()

        # Assert
        assert shell_func.is_shell is True
        assert shell_func.is_python is False
        assert shell_func.is_config is False

    def test_is_config_property(self):
        """Test is_config property"""
        # Arrange
        config_func = FunctionFactory.create_config()

        # Assert
        assert config_func.is_config is True
        assert config_func.is_python is False
        assert config_func.is_shell is False

    def test_factory_reset_counter(self):
        """Test that factory counter can be reset"""
        # Arrange
        FunctionFactory.reset_counter()

        # Act
        func1 = FunctionFactory.create()
        func2 = FunctionFactory.create()

        # Assert
        assert "test_function_1" in func1.name
        assert "test_function_2" in func2.name

    def test_function_timeout_default(self):
        """Test function has default timeout"""
        # Arrange & Act
        function = FunctionFactory.create()

        # Assert
        assert function.timeout == 30  # Default timeout

    def test_function_with_custom_timeout(self):
        """Test creating function with custom timeout"""
        # Arrange & Act
        function = FunctionFactory.create(timeout=60)

        # Assert
        assert function.timeout == 60
