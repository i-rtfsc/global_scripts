"""
环境变量抽象层的单元测试
"""


from src.gscripts.infrastructure.filesystem import (
    SystemEnvironment,
    MockEnvironment,
)


class TestMockEnvironment:
    """MockEnvironment 单元测试"""

    def test_get_nonexistent_key_returns_none(self):
        """测试获取不存在的键返回None"""
        env = MockEnvironment()

        result = env.get("NONEXISTENT")

        assert result is None

    def test_get_with_default(self):
        """测试使用默认值"""
        env = MockEnvironment()

        result = env.get("NONEXISTENT", "default")

        assert result == "default"

    def test_set_and_get(self):
        """测试设置和获取"""
        env = MockEnvironment()

        env.set("TEST_KEY", "test_value")
        result = env.get("TEST_KEY")

        assert result == "test_value"

    def test_all_returns_copy(self):
        """测试获取所有环境变量"""
        env = MockEnvironment({"KEY1": "value1", "KEY2": "value2"})

        all_env = env.all()

        assert all_env == {"KEY1": "value1", "KEY2": "value2"}

    def test_clear_removes_all(self):
        """测试清空环境变量"""
        env = MockEnvironment({"KEY": "value"})

        env.clear()

        assert env.get("KEY") is None
        assert env.all() == {}

    def test_initial_env(self):
        """测试初始环境变量"""
        initial = {"PATH": "/usr/bin", "HOME": "/home/user"}
        env = MockEnvironment(initial)

        assert env.get("PATH") == "/usr/bin"
        assert env.get("HOME") == "/home/user"


class TestSystemEnvironment:
    """SystemEnvironment 集成测试"""

    def test_get_existing_env_var(self, monkeypatch):
        """测试获取存在的环境变量"""
        monkeypatch.setenv("TEST_VAR", "test_value")
        env = SystemEnvironment()

        result = env.get("TEST_VAR")

        assert result == "test_value"

    def test_set_env_var(self, monkeypatch):
        """测试设置环境变量"""
        env = SystemEnvironment()

        env.set("NEW_VAR", "new_value")

        import os

        assert os.environ.get("NEW_VAR") == "new_value"

    def test_all_returns_dict(self):
        """测试获取所有环境变量返回字典"""
        env = SystemEnvironment()

        all_env = env.all()

        assert isinstance(all_env, dict)
        assert len(all_env) > 0
