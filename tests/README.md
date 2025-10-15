# Parser Registry Tests

This directory contains comprehensive tests for the Parser Registry Mechanism implementation.

## Overview

The Parser Registry Mechanism enables extensibility through:
- Priority-based parser selection
- Auto-discovery from Entry Points
- Enable/disable functionality
- Custom parser directories
- Configuration-driven behavior

## Test Structure

```
tests/
├── conftest.py                          # Shared fixtures
├── run_parser_tests.sh                  # Test runner script
├── unit/
│   └── plugins/
│       └── parsers/
│           ├── test_registry.py         # FunctionParserRegistry tests
│           └── test_discovery.py        # ParserDiscovery tests
└── integration/
    └── plugins/
        └── test_parser_integration.py   # End-to-end integration tests
```

## Running Tests

### Run All Parser Tests

```bash
./tests/run_parser_tests.sh
```

### Run Specific Test Suites

```bash
# Unit tests only
uv run pytest tests/unit/plugins/parsers/ -v

# Integration tests only
uv run pytest tests/integration/plugins/test_parser_integration.py -v

# With coverage
uv run pytest tests/unit/plugins/parsers/ \
    --cov=src/gscripts/plugins/parsers \
    --cov-report=html \
    --cov-report=term-missing
```

### Run Individual Test Files

```bash
# Registry tests
uv run pytest tests/unit/plugins/parsers/test_registry.py -v

# Discovery tests
uv run pytest tests/unit/plugins/parsers/test_discovery.py -v

# Integration tests
uv run pytest tests/integration/plugins/test_parser_integration.py -v
```

### Run Specific Test Cases

```bash
# Run single test
uv run pytest tests/unit/plugins/parsers/test_registry.py::TestFunctionParserRegistry::test_register_parser_with_metadata -v

# Run tests matching pattern
uv run pytest tests/unit/plugins/parsers/ -k "priority" -v
```

## Test Coverage

### Unit Tests: `test_registry.py`

Tests for `FunctionParserRegistry`:
- ✅ Parser registration with/without metadata
- ✅ Custom names and priorities
- ✅ `register_by_name` method
- ✅ Unregister functionality
- ✅ Enable/disable parsers
- ✅ Parser aliases
- ✅ Get parser by name
- ✅ List parsers (sorted by priority)
- ✅ Get parser info
- ✅ Get parser by file
- ✅ Priority-based selection
- ✅ Disabled parser skipping
- ✅ `parse_all` integration
- ✅ Alias removal on unregister
- ✅ Metadata property access

**Coverage:** ~95% of FunctionParserRegistry code

### Unit Tests: `test_discovery.py`

Tests for `ParserDiscovery`:
- ✅ Initialization
- ✅ Discover from Entry Points
- ✅ Caching mechanism
- ✅ Cache clearing
- ✅ Discover from directories
- ✅ Handle non-existent paths
- ✅ File naming convention (`*_parser.py`)
- ✅ Error handling for malformed files
- ✅ Config-based enable/disable
- ✅ Custom paths discovery
- ✅ Tilde expansion
- ✅ Priority overrides
- ✅ Subdirectory scanning
- ✅ FunctionParser subclass filtering
- ✅ Full integration flow

**Coverage:** ~90% of ParserDiscovery code

### Integration Tests: `test_parser_integration.py`

End-to-end integration tests:
- ✅ Parser registration in loader
- ✅ Custom parser integration
- ✅ Priority-based selection
- ✅ Config-driven enable/disable
- ✅ Priority overrides from config
- ✅ Full plugin loading flow
- ✅ Registry accessibility
- ✅ Multiple parsers same priority
- ✅ Error handling

**Coverage:** Complete workflow from registration to plugin loading

## Test Fixtures

### Shared Fixtures (`conftest.py`)

- `sample_yaml_content`: YAML plugin example
- `sample_toml_content`: TOML plugin example
- `sample_python_plugin`: Python plugin with decorators
- `sample_shell_plugin`: Shell plugin with annotations
- `mock_parser_config`: Basic parser configuration
- `extended_parser_config`: Extended config with custom paths

### Test-Specific Fixtures

Each test file defines mock parsers for isolated testing:
- `TestParser1/2/3`: Simple mock parsers
- `TestDiscoveryParser`: Parser for discovery testing
- `IntegrationYAMLParser`: YAML parser for integration tests

## Writing New Tests

### Unit Test Template

```python
import pytest
from pathlib import Path
from gscripts.plugins.parsers import FunctionParser, parser_metadata

@parser_metadata(name="test", version="1.0.0")
class TestParser(FunctionParser):
    def can_parse(self, file: Path) -> bool:
        return file.suffix == ".test"

    async def parse(self, file, plugin_name, subplugin_name=""):
        return []

def test_my_feature():
    """Test description"""
    parser = TestParser()
    # Test assertions
    assert parser.metadata.name == "test"
```

### Integration Test Template

```python
import pytest
from gscripts.plugins.loader import RefactoredPluginLoader

@pytest.mark.asyncio
async def test_my_integration(tmp_path):
    """Integration test description"""
    # Setup
    plugins_dir = tmp_path / "plugins"
    plugins_dir.mkdir()

    config = {'enabled': ['python', 'shell']}

    # Execute
    loader = RefactoredPluginLoader(plugins_dir, parser_config=config)
    plugins = await loader.load_all_plugins()

    # Assert
    assert plugins is not None
```

## Test Requirements

Tests require the following packages:
- `pytest>=7.0.0`
- `pytest-asyncio>=0.20.0`
- `pytest-cov>=4.0.0`

Install with:
```bash
uv sync --dev
```

## Continuous Integration

Tests are designed to run in CI/CD pipelines:

```yaml
# Example GitHub Actions
- name: Run parser tests
  run: |
    uv sync --dev
    uv run pytest tests/unit/plugins/parsers/ \
                   tests/integration/plugins/test_parser_integration.py \
      --cov=src/gscripts/plugins/parsers \
      --cov-fail-under=80
```

## Debugging Tests

### Enable Verbose Output

```bash
uv run pytest tests/unit/plugins/parsers/test_registry.py -vv
```

### Show Print Statements

```bash
uv run pytest tests/unit/plugins/parsers/ -s
```

### Run with PDB on Failure

```bash
uv run pytest tests/unit/plugins/parsers/ --pdb
```

### Show Slowest Tests

```bash
uv run pytest tests/unit/plugins/parsers/ --durations=10
```

## Known Issues

None currently. All tests passing as of 2025-10-11.

## Contributing

When adding new parser features:

1. Write unit tests first (TDD approach)
2. Add integration tests for end-to-end scenarios
3. Update fixtures in `conftest.py` if needed
4. Ensure coverage stays above 80%
5. Run all tests before submitting PR

## Resources

- [Parser Development Guide](../../docs/extensibility/custom-parsers.md)
- [YAML Parser Example](../../docs/examples/custom_parser/)
- [pytest Documentation](https://docs.pytest.org/)
- [pytest-asyncio Guide](https://pytest-asyncio.readthedocs.io/)

---

**Last Updated:** 2025-10-11
**Test Suite Version:** 1.0.0
**Coverage Target:** 80%+
