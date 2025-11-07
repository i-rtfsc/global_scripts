# Testing Guide for Global Scripts

This document provides comprehensive guidance for testing the Global Scripts plugin system.

## Table of Contents

- [Overview](#overview)
- [Test Structure](#test-structure)
- [Running Tests](#running-tests)
- [Writing Tests](#writing-tests)
- [Fixtures and Factories](#fixtures-and-factories)
- [Common Patterns](#common-patterns)
- [Coverage Requirements](#coverage-requirements)
- [Troubleshooting](#troubleshooting)

---

## Overview

### Testing Philosophy

Global Scripts follows a **comprehensive testing strategy** with multiple test levels:

1. **Unit Tests**: Test individual components in isolation
2. **Integration Tests**: Test component interactions and data flow
3. **E2E Tests**: Test complete user workflows with no mocks
4. **Performance Tests**: Benchmark plugin loading, execution, and generation

### Test Statistics

- **Total Tests**: ~1,015 tests
- **Test Files**: 80+ test files
- **Coverage Target**: 80% overall, 75% minimum per module
- **Current Coverage**: 19% (work in progress)

---

## Test Structure

```
tests/
├── conftest.py                 # Global fixtures and pytest configuration
├── __init__.py
│
├── fixtures/                   # Shared test fixtures
│   ├── sample_plugins.py      # Sample plugin metadata and content
│   ├── config_fixtures.py     # Configuration fixtures
│   ├── filesystem_fixtures.py # Filesystem mocks
│   └── process_fixtures.py    # Process execution mocks
│
├── factories/                  # Test data factories
│   ├── plugin_factory.py      # PluginFactory.create()
│   ├── function_factory.py    # FunctionFactory.create()
│   └── result_factory.py      # ResultFactory.success/failure()
│
├── helpers/                    # Test helper utilities
│   ├── assertions.py          # Custom assertions
│   ├── async_helpers.py       # Async test helpers
│   └── mock_builders.py       # Mock object builders
│
├── unit/                       # Unit tests (mirror src structure)
│   ├── cli/
│   ├── application/
│   ├── infrastructure/
│   ├── core/
│   ├── models/
│   ├── plugins/
│   ├── security/
│   └── utils/
│
├── integration/                # Integration tests
│   ├── test_plugin_loading_flow.py
│   ├── test_plugin_execution_flow.py
│   ├── test_cli_command_flow.py
│   ├── test_config_management_flow.py
│   └── test_router_generation.py
│
├── e2e/                        # End-to-end tests
│   ├── test_full_command_execution.py
│   ├── test_plugin_enable_disable.py
│   ├── test_plugin_installation.py
│   └── test_error_scenarios.py
│
├── performance/                # Performance benchmarks
│   ├── test_plugin_loading_speed.py
│   ├── test_command_execution_speed.py
│   └── test_router_generation_speed.py
│
└── scripts/                    # Tests for installation scripts
    └── test_setup.py
```

---

## Running Tests

### Run All Tests

```bash
# Run complete test suite
pytest tests/ -v

# Run with coverage report
pytest tests/ -v --cov=src/gscripts --cov-report=term-missing --cov-report=html

# View HTML coverage report
open htmlcov/index.html
```

### Run Specific Test Types

```bash
# Unit tests only
pytest tests/unit/ -v

# Integration tests only
pytest tests/integration/ -v -m integration

# E2E tests only
pytest tests/e2e/ -v -m e2e

# Performance tests (slow)
pytest tests/performance/ -v -m performance

# Skip slow tests
pytest tests/ -v -m "not slow"
```

### Run Specific Test Files

```bash
# Single file
pytest tests/unit/security/test_sanitizers.py -v

# Multiple files
pytest tests/integration/test_plugin_loading_flow.py tests/integration/test_plugin_execution_flow.py -v

# Specific test class
pytest tests/unit/security/test_sanitizers.py::TestCommandSanitization -v

# Specific test function
pytest tests/unit/security/test_sanitizers.py::TestCommandSanitization::test_sanitize_simple_command -v
```

---

## Writing Tests

### Unit Test Example

```python
"""Unit tests for PluginRepository"""

import pytest
from gscripts.infrastructure.persistence.plugin_repository import PluginRepository


@pytest.mark.unit
class TestPluginRepository:
    """Unit tests for PluginRepository"""

    def test_get_all_plugins(self, mock_filesystem):
        """Test retrieving all plugins"""
        # Arrange
        repository = PluginRepository(
            filesystem=mock_filesystem,
            plugins_dir="/plugins"
        )

        # Act
        plugins = repository.get_all()

        # Assert
        assert isinstance(plugins, list)
        assert len(plugins) > 0
```

---

## Coverage Requirements

### Overall Targets

- **Overall Coverage**: ≥80%
- **Critical Modules**: ≥75% (security, core, application)
- **Utilities**: ≥70%
- **CLI**: ≥60%

### Check Coverage

```bash
# Generate coverage report
pytest tests/ --cov=src/gscripts --cov-report=term-missing --cov-report=html

# View detailed report
open htmlcov/index.html
```

---

**Last Updated**: November 2024
**Test Suite Version**: 5.0.0
