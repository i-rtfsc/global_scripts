"""
Root conftest.py - Global pytest configuration and fixtures

This file configures pytest for the entire test suite including:
- Async test support
- Custom markers
- Global fixtures
- Test execution options
"""

import sys
from pathlib import Path

import pytest

# Add src to Python path for imports
project_root = Path(__file__).parent.parent
src_path = project_root / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))


def pytest_configure(config):
    """Configure pytest with custom markers and settings."""
    # Register custom markers
    config.addinivalue_line(
        "markers",
        "slow: marks tests as slow (deselect with '-m \"not slow\"')",
    )
    config.addinivalue_line(
        "markers",
        "integration: marks tests as integration tests",
    )
    config.addinivalue_line(
        "markers",
        "e2e: marks tests as end-to-end tests",
    )
    config.addinivalue_line(
        "markers",
        "unit: marks tests as unit tests (fast, isolated)",
    )
    config.addinivalue_line(
        "markers",
        "asyncio: marks tests as async tests (auto-applied by pytest-asyncio)",
    )


# Enable pytest-asyncio auto mode
pytest_plugins = ("pytest_asyncio",)


@pytest.fixture(scope="session")
def project_root_dir() -> Path:
    """Provide project root directory path."""
    return Path(__file__).parent.parent


@pytest.fixture(scope="session")
def src_dir(project_root_dir: Path) -> Path:
    """Provide src directory path."""
    return project_root_dir / "src"


@pytest.fixture(scope="session")
def tests_dir(project_root_dir: Path) -> Path:
    """Provide tests directory path."""
    return project_root_dir / "tests"


@pytest.fixture(scope="session")
def fixtures_dir(tests_dir: Path) -> Path:
    """Provide test fixtures directory path."""
    return tests_dir / "fixtures"


@pytest.fixture
def temp_dir(tmp_path: Path) -> Path:
    """
    Provide temporary directory for test isolation.

    This is an alias for pytest's tmp_path fixture with a more descriptive name.
    Automatically cleaned up after each test.
    """
    return tmp_path


# Async test configuration
@pytest.fixture(scope="session")
def event_loop_policy():
    """
    Configure asyncio event loop policy for tests.

    This ensures consistent async behavior across all tests.
    """
    import asyncio

    # Use default policy - can be customized if needed
    return asyncio.get_event_loop_policy()


# Global test hooks
def pytest_collection_modifyitems(config, items):
    """
    Modify test collection to add markers automatically.

    - Auto-mark async tests with @pytest.mark.asyncio
    - Auto-mark tests in integration/ with @pytest.mark.integration
    - Auto-mark tests in e2e/ with @pytest.mark.e2e
    - Auto-mark tests in unit/ with @pytest.mark.unit
    """
    for item in items:
        # Get test file path relative to tests directory
        test_path = Path(item.fspath).relative_to(Path(__file__).parent)

        # Auto-mark by directory
        if "integration" in test_path.parts:
            item.add_marker(pytest.mark.integration)
        elif "e2e" in test_path.parts:
            item.add_marker(pytest.mark.e2e)
        elif "unit" in test_path.parts:
            item.add_marker(pytest.mark.unit)

        # Auto-mark slow tests (integration and e2e)
        if any(
            marker in test_path.parts
            for marker in ["integration", "e2e", "performance"]
        ):
            item.add_marker(pytest.mark.slow)


def pytest_report_header(config):
    """Add custom header to pytest output."""
    return [
        "Global Scripts Test Suite",
        f"Project root: {Path(__file__).parent.parent}",
        "Run 'pytest -v' for verbose output",
        "Run 'pytest -m \"not slow\"' to skip slow tests",
    ]
