# Custom Parser Development Guide

This guide explains how to create custom parsers for Global Scripts, enabling support for new plugin definition formats.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Parser Interface](#parser-interface)
- [Metadata System](#metadata-system)
- [Auto-Discovery](#auto-discovery)
- [Configuration](#configuration)
- [Testing](#testing)
- [Best Practices](#best-practices)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)

## Overview

### What is a Parser?

A parser is a component that reads plugin definition files and extracts function metadata. Global Scripts uses parsers to support multiple plugin formats:

- **Python Parser**: Extracts functions decorated with `@plugin_function`
- **Shell Parser**: Parses shell scripts with annotation comments
- **Config Parser**: Reads JSON-based plugin definitions
- **Custom Parsers**: YOUR extensions for YAML, TOML, XML, etc.

### Why Create a Custom Parser?

- Support your organization's preferred configuration format
- Integrate with existing tooling and workflows
- Add features specific to your use case
- Share parsers with the community

## Architecture

### Parser Registry System

```
┌─────────────────────────────────────┐
│      FunctionParserRegistry         │
│  - Priority-based selection         │
│  - Enable/disable control           │
│  - Metadata introspection           │
└─────────────────────────────────────┘
                 ↓
┌─────────────────────────────────────┐
│       ParserDiscovery               │
│  - Entry Points scanning            │
│  - Directory scanning               │
│  - Configuration loading            │
└─────────────────────────────────────┘
                 ↓
┌─────────────────────────────────────┐
│     Your Custom Parser              │
│  - Implements FunctionParser        │
│  - Uses @parser_metadata            │
│  - Returns List[FunctionInfo]       │
└─────────────────────────────────────┘
```

### Discovery Flow

1. **Built-in Parsers**: Registered first with high priority
2. **Entry Points**: Third-party parsers from installed packages
3. **Custom Directories**: Parsers from `~/.gscripts/parsers/`
4. **Configuration**: Enable/disable and priority overrides

## Quick Start

### 1. Create Your Parser

```python
from pathlib import Path
from typing import List

from gscripts.plugins.parsers import (
    FunctionParser,
    FunctionInfo,
    parser_metadata
)

@parser_metadata(
    name="yaml",
    version="1.0.0",
    supported_extensions=[".yaml", ".yml"],
    priority=100,
    description="YAML configuration parser"
)
class YAMLParser(FunctionParser):
    def can_parse(self, file: Path) -> bool:
        """Check if this parser can handle the file"""
        return file.suffix.lower() in ['.yaml', '.yml']

    async def parse(
        self,
        file: Path,
        plugin_name: str,
        subplugin_name: str = ""
    ) -> List[FunctionInfo]:
        """Parse YAML file and extract functions"""
        # Your parsing logic here
        functions = []
        # ... parse file ...
        return functions
```

### 2. Package Your Parser

Create `pyproject.toml`:

```toml
[project]
name = "gscripts-yaml-parser"
version = "1.0.0"
dependencies = ["global-scripts>=6.0.0", "PyYAML>=6.0"]

[project.entry-points."gscripts.parsers"]
yaml = "yaml_parser:YAMLParser"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

### 3. Install and Use

```bash
# Install your parser
uv pip install .

# Verify installation
gs parser list

# Test parsing
gs parser test plugin.yaml
```

## Parser Interface

### Required Methods

#### `can_parse(file: Path) -> bool`

Determines if this parser can handle a given file.

**Parameters:**
- `file`: Path to the file to check

**Returns:**
- `True` if this parser can handle the file, `False` otherwise

**Example:**
```python
def can_parse(self, file: Path) -> bool:
    # Check by extension
    if file.suffix in ['.yaml', '.yml']:
        return True

    # Or check by content
    try:
        with open(file, 'r') as f:
            first_line = f.readline()
            return first_line.startswith('# YAML Plugin')
    except:
        return False
```

#### `parse(file: Path, plugin_name: str, subplugin_name: str) -> List[FunctionInfo]`

Extracts function definitions from the file.

**Parameters:**
- `file`: Path to the plugin file
- `plugin_name`: Name of the plugin
- `subplugin_name`: Name of the subplugin (empty if none)

**Returns:**
- List of `FunctionInfo` objects

**Example:**
```python
async def parse(
    self,
    file: Path,
    plugin_name: str,
    subplugin_name: str = ""
) -> List[FunctionInfo]:
    functions = []

    with open(file, 'r') as f:
        data = yaml.safe_load(f)

    for func_data in data.get('functions', []):
        function_info = FunctionInfo(
            name=func_data['name'],
            description=func_data['description'],
            command=func_data['command'],
            type=func_data.get('type', 'shell'),
            args=func_data.get('args', []),
            options=func_data.get('options', {}),
            examples=func_data.get('examples', []),
            plugin_name=plugin_name,
            subplugin_name=subplugin_name
        )
        functions.append(function_info)

    return functions
```

### FunctionInfo Structure

```python
@dataclass
class FunctionInfo:
    name: str                    # Function name
    description: str             # Human-readable description
    command: str                 # Command to execute
    type: str                    # 'python', 'shell', 'config'
    args: List[str]              # Argument names
    options: Dict[str, Any]      # Option definitions
    examples: List[str]          # Usage examples
    plugin_name: str             # Parent plugin name
    subplugin_name: str          # Subplugin name (if any)
```

## Metadata System

### Using @parser_metadata

The `@parser_metadata` decorator provides parser information to the system:

```python
@parser_metadata(
    name="yaml",                          # Required: Unique parser name
    version="1.0.0",                      # Semantic version
    supported_extensions=[".yaml", ".yml"], # File extensions
    priority=100,                         # Selection priority (lower = higher)
    description="Parse YAML plugins"     # Human-readable description
)
class YAMLParser(FunctionParser):
    pass
```

### Priority System

Parsers are selected based on priority (lower number = higher priority):

| Priority Range | Usage |
|---------------|-------|
| 1-50 | System/critical parsers |
| 51-100 | Standard parsers |
| 101-200 | Third-party parsers |
| 201+ | Experimental parsers |

**Built-in priorities:**
- Python: 10
- Shell: 20
- Config: 30

### Accessing Metadata

```python
parser = YAMLParser()
metadata = parser.metadata

print(f"Name: {metadata.name}")
print(f"Version: {metadata.version}")
print(f"Extensions: {metadata.supported_extensions}")
```

## Auto-Discovery

### Entry Points (Recommended)

Global Scripts uses Python's Entry Points system for automatic parser discovery.

**In your `pyproject.toml`:**
```toml
[project.entry-points."gscripts.parsers"]
yaml = "my_package.parsers:YAMLParser"
toml = "my_package.parsers:TOMLParser"
```

**Benefits:**
- Automatic discovery on installation
- Standard Python packaging mechanism
- Works with all package managers (pip, uv, poetry)
- No manual registration required

### Custom Directories

Place parsers in custom directories specified in `gs.json`:

```json
{
  "parsers": {
    "custom_paths": [
      "~/.gscripts/parsers",
      "./project/parsers"
    ]
  }
}
```

**File naming convention:** `*_parser.py`

**Example:**
- `~/.gscripts/parsers/yaml_parser.py`
- `~/.gscripts/parsers/xml_parser.py`

## Configuration

### gs.json Parser Configuration

```json
{
  "parsers": {
    "enabled": ["python", "shell", "config", "yaml"],
    "disabled": ["experimental"],
    "custom_paths": [
      "~/.gscripts/parsers",
      "./custom_parsers"
    ],
    "priority_overrides": {
      "yaml": 15
    }
  }
}
```

### Configuration Options

#### `enabled`
List of parser names to enable. Empty means all parsers are enabled.

#### `disabled`
List of parser names to explicitly disable. Takes precedence over `enabled`.

#### `custom_paths`
Directories to scan for custom parsers.

#### `priority_overrides`
Override parser priorities from configuration.

### CLI Management

```bash
# List all parsers
gs parser list

# Show parser details
gs parser info yaml

# Enable a parser
gs parser enable yaml

# Disable a parser
gs parser disable python

# Test file parsing
gs parser test plugin.yaml
```

## Testing

### Unit Testing Your Parser

```python
import pytest
from pathlib import Path
from your_parser import YAMLParser

@pytest.fixture
def parser():
    return YAMLParser()

@pytest.fixture
def sample_yaml(tmp_path):
    yaml_file = tmp_path / "test.yaml"
    yaml_file.write_text("""
functions:
  - name: hello
    description: Say hello
    command: echo "Hello!"
    type: shell
""")
    return yaml_file

@pytest.mark.asyncio
async def test_can_parse_yaml(parser):
    """Test parser recognizes YAML files"""
    assert parser.can_parse(Path("test.yaml"))
    assert parser.can_parse(Path("test.yml"))
    assert not parser.can_parse(Path("test.py"))

@pytest.mark.asyncio
async def test_parse_yaml(parser, sample_yaml):
    """Test parsing YAML content"""
    functions = await parser.parse(sample_yaml, "test_plugin")

    assert len(functions) == 1
    assert functions[0].name == "hello"
    assert functions[0].description == "Say hello"
    assert functions[0].command == 'echo "Hello!"'
    assert functions[0].type == "shell"

@pytest.mark.asyncio
async def test_metadata(parser):
    """Test parser metadata"""
    metadata = parser.metadata

    assert metadata.name == "yaml"
    assert metadata.version == "1.0.0"
    assert ".yaml" in metadata.supported_extensions
```

### Integration Testing

```python
@pytest.mark.asyncio
async def test_parser_registration():
    """Test parser is registered correctly"""
    from gscripts.plugins.loader import RefactoredPluginLoader

    loader = RefactoredPluginLoader(plugins_root)
    parsers = loader.parser_registry.list_parsers()

    # Check YAML parser is registered
    yaml_parsers = [p for p in parsers if p['name'] == 'yaml']
    assert len(yaml_parsers) == 1
    assert yaml_parsers[0]['enabled']

@pytest.mark.asyncio
async def test_end_to_end_parsing(tmp_path):
    """Test complete parsing flow"""
    # Create test plugin
    plugin_dir = tmp_path / "test_plugin"
    plugin_dir.mkdir()

    (plugin_dir / "plugin.yaml").write_text("""
functions:
  - name: test
    description: Test function
    command: echo test
""")

    # Load plugin
    loader = RefactoredPluginLoader(tmp_path)
    plugins = await loader.load_all_plugins()

    # Verify function was parsed
    assert "test_plugin" in plugins
    assert "test" in plugins["test_plugin"]["functions"]
```

## Best Practices

### Error Handling

```python
async def parse(self, file: Path, ...) -> List[FunctionInfo]:
    functions = []

    try:
        with open(file, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        # Log parse errors
        logger.error(f"YAML parse error in {file}: {e}")
        return functions
    except FileNotFoundError:
        logger.error(f"File not found: {file}")
        return functions
    except Exception as e:
        logger.error(f"Unexpected error parsing {file}: {e}")
        return functions

    # Validate data structure
    if not isinstance(data, dict):
        logger.warning(f"Invalid YAML structure in {file}")
        return functions

    # Process functions with validation
    for func_data in data.get('functions', []):
        try:
            function_info = self._parse_function(func_data, ...)
            functions.append(function_info)
        except ValueError as e:
            logger.warning(f"Skipping invalid function in {file}: {e}")
            continue

    return functions
```

### Validation

```python
def _validate_function_data(self, data: dict) -> None:
    """Validate function data structure"""
    required_fields = ['name', 'description', 'command']

    for field in required_fields:
        if field not in data:
            raise ValueError(f"Missing required field: {field}")

    # Validate types
    if not isinstance(data['name'], str):
        raise ValueError("'name' must be a string")

    # Validate values
    if not data['name'].strip():
        raise ValueError("'name' cannot be empty")

    # Validate command safety (if needed)
    if any(danger in data['command'] for danger in ['rm -rf', 'dd if=']):
        raise ValueError("Potentially dangerous command detected")
```

### Performance

```python
class YAMLParser(FunctionParser):
    def __init__(self):
        self._cache = {}

    async def parse(self, file: Path, ...) -> List[FunctionInfo]:
        # Cache parsed results
        cache_key = (str(file), file.stat().st_mtime)

        if cache_key in self._cache:
            return self._cache[cache_key]

        functions = await self._do_parse(file, ...)
        self._cache[cache_key] = functions

        return functions

    async def _do_parse(self, file: Path, ...) -> List[FunctionInfo]:
        # Actual parsing logic
        pass
```

### Documentation

```python
@parser_metadata(
    name="yaml",
    version="1.0.0",
    supported_extensions=[".yaml", ".yml"],
    priority=100,
    description="Parse YAML-based plugin definitions"
)
class YAMLParser(FunctionParser):
    """
    YAML Plugin Parser

    Supports parsing plugin definitions from YAML files with the following format:

    ```yaml
    functions:
      - name: function_name
        description: Function description
        command: shell command or python code
        type: shell | python
        args: [arg1, arg2]
        options:
          option_name:
            description: Option description
            type: string | boolean | number
            default: value
        examples:
          - example command 1
          - example command 2
    ```

    Features:
    - Full YAML 1.2 support
    - Schema validation
    - Multi-function definitions
    - Rich metadata extraction

    Example:
        >>> parser = YAMLParser()
        >>> functions = await parser.parse(Path("plugin.yaml"), "myplugin")
        >>> print(functions[0].name)
        'hello'
    """
```

## Examples

### Complete YAML Parser

See the full example in `/docs/examples/custom_parser/yaml_parser.py`

### TOML Parser Example

```python
from pathlib import Path
from typing import List
import tomli

from gscripts.plugins.parsers import (
    FunctionParser,
    FunctionInfo,
    parser_metadata
)

@parser_metadata(
    name="toml",
    version="1.0.0",
    supported_extensions=[".toml"],
    priority=110,
    description="TOML configuration parser"
)
class TOMLParser(FunctionParser):
    def can_parse(self, file: Path) -> bool:
        return file.suffix.lower() == '.toml'

    async def parse(
        self,
        file: Path,
        plugin_name: str,
        subplugin_name: str = ""
    ) -> List[FunctionInfo]:
        functions = []

        try:
            with open(file, 'rb') as f:
                data = tomli.load(f)

            for func_name, func_data in data.get('functions', {}).items():
                function_info = FunctionInfo(
                    name=func_name,
                    description=func_data.get('description', ''),
                    command=func_data.get('command', ''),
                    type=func_data.get('type', 'shell'),
                    plugin_name=plugin_name,
                    subplugin_name=subplugin_name
                )
                functions.append(function_info)

        except Exception as e:
            print(f"Error parsing TOML: {e}")

        return functions
```

### XML Parser Example

```python
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List

from gscripts.plugins.parsers import (
    FunctionParser,
    FunctionInfo,
    parser_metadata
)

@parser_metadata(
    name="xml",
    version="1.0.0",
    supported_extensions=[".xml"],
    priority=120,
    description="XML plugin definition parser"
)
class XMLParser(FunctionParser):
    def can_parse(self, file: Path) -> bool:
        return file.suffix.lower() == '.xml'

    async def parse(
        self,
        file: Path,
        plugin_name: str,
        subplugin_name: str = ""
    ) -> List[FunctionInfo]:
        functions = []

        try:
            tree = ET.parse(file)
            root = tree.getroot()

            for func_elem in root.findall('.//function'):
                function_info = FunctionInfo(
                    name=func_elem.get('name', ''),
                    description=func_elem.findtext('description', ''),
                    command=func_elem.findtext('command', ''),
                    type=func_elem.get('type', 'shell'),
                    plugin_name=plugin_name,
                    subplugin_name=subplugin_name
                )
                functions.append(function_info)

        except Exception as e:
            print(f"Error parsing XML: {e}")

        return functions
```

## Troubleshooting

### Parser Not Discovered

**Problem:** Your parser isn't showing up in `gs parser list`

**Solutions:**
1. Check Entry Point configuration:
   ```bash
   python -c "import importlib.metadata; print(list(importlib.metadata.entry_points(group='gscripts.parsers')))"
   ```

2. Verify installation:
   ```bash
   uv pip list | grep gscripts
   ```

3. Check for import errors:
   ```bash
   python -c "from your_package import YAMLParser"
   ```

4. Run with verbose logging:
   ```bash
   export GS_LOG_LEVEL=DEBUG
   gs parser list
   ```

### Parser Not Selected

**Problem:** Parser is registered but not being used

**Solutions:**
1. Check priority (lower = higher):
   ```bash
   gs parser list
   ```

2. Verify `can_parse()` logic:
   ```bash
   gs parser test your_file.yaml
   ```

3. Check if disabled:
   ```bash
   gs parser info yaml
   ```

4. Override priority in config:
   ```json
   {
     "parsers": {
       "priority_overrides": {
         "yaml": 5
       }
     }
   }
   ```

### Parse Errors

**Problem:** Parser crashes or returns empty results

**Solutions:**
1. Add comprehensive error handling
2. Validate input data structure
3. Use try-except blocks
4. Log errors for debugging
5. Test with sample files first

### Import Errors

**Problem:** `ImportError` when loading parser

**Solutions:**
1. Ensure all dependencies are installed:
   ```bash
   uv pip install PyYAML
   ```

2. Check import paths in Entry Points:
   ```toml
   [project.entry-points."gscripts.parsers"]
   yaml = "yaml_parser:YAMLParser"  # module:class
   ```

3. Verify module structure:
   ```
   my_parser/
   ├── __init__.py
   └── yaml_parser.py
   ```

## Additional Resources

- [YAML Parser Example](../examples/custom_parser/)
- [FunctionParser API Reference](../api/parsers.md)
- [Global Scripts Plugin Development](./plugin-development.md)
- [Contributing Parsers](../contributing.md)

## Getting Help

- GitHub Issues: https://github.com/i-rtfsc/global_scripts/issues
- Discussions: https://github.com/i-rtfsc/global_scripts/discussions
- Documentation: https://github.com/i-rtfsc/global_scripts/docs

---

**Version:** 1.0.0
**Last Updated:** 2025-10-11
**License:** Apache 2.0
