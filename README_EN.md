# Global Scripts

[中文](README.md) | [English](README_EN.md)

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-5.2.0-brightgreen.svg)](https://github.com/i-rtfsc/global_scripts)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

> A modern, high-performance shell command management system with multi-type plugin architecture, async execution, and complete type safety.

## Introduction

Global Scripts is a powerful command-line tool management framework designed to simplify daily development workflows. Through its flexible plugin system, you can easily extend and customize commands to boost your development efficiency.

### Why Global Scripts?

- **Unified Management**: Centrally manage all your common commands and scripts
- **Plugin Architecture**: Support for Python, Shell, Config, and Hybrid plugin types
- **High Performance**: Async execution based on asyncio with intelligent caching
- **Type Safety**: Complete type annotations and data validation
- **Easy to Extend**: Simple plugin development API for quick custom command creation
- **Ready to Use**: Rich built-in plugin ecosystem covering Android development, system management, and more

## Core Features

### Architecture Advantages

- **Unified Data Model**: Type-safe data structures based on `dataclass`
- **Multi-Type Plugins**: Support for Python, Shell, Config, and Hybrid plugin types
- **Async First**: High-performance async execution engine based on `asyncio`
- **Direct Shell Execution**: Shell plugins execute commands directly without Python overhead
- **Smart Caching**: Automatic plugin config caching, reducing I/O overhead by 30%
- **Secure Execution**: Command whitelist, timeout control, process group management

### Developer Experience

- **Complete Type Annotations**: 80%+ type annotation coverage
- **Comprehensive Documentation**: Complete documentation system from quickstart to architecture
- **Easy to Test**: Unified ProcessExecutor for convenient unit testing
- **Simple Configuration**: JSON-based config with user/project level support
- **Multi-language Support**: Seamless Chinese/English interface switching
- **Dynamic Completion**: Real-time command completion powered by jq

### Performance Features

- **Code Optimization**: Eliminated 300+ lines of duplicate code
- **Smart Caching**: 72% cache hit rate
- **Fast Loading**: 100 plugins in < 3 seconds
- **Shell Integration**: Auto-generated completion and shortcuts

## Quick Start

### Prerequisites

- Python 3.8 or higher
- Bash, Zsh, or Fish Shell
- jq (required for command completion)

### Installation

Since Global Scripts uses UV for dependency management and the CLI is configured to run with UV, this is the strongly recommended approach:

```bash
# 1. Install UV (modern Python project manager)
curl -LsSf https://astral.sh/uv/install.sh | sh

# 2. Clone the repository
git clone https://github.com/i-rtfsc/global_scripts.git
cd global_scripts

# 3. UV will automatically sync dependencies and create virtual environment
uv sync

# 4. Run the installation script
uv run python scripts/setup.py

# 5. Reload shell configuration
source ~/.bashrc                    # for bash users
source ~/.zshrc                     # for zsh users
source ~/.config/fish/config.fish   # for fish users
```

For detailed installation instructions, see [Installation Guide](./docs/en/installation-en.md)

### Verify Installation

```bash
# Check version
gs version

# Check system health
gs doctor

# List plugins
gs plugin list

# Test completion (press Tab)
gs <Tab>
```

### Basic Usage

```bash
# Show help
gs help

# List all plugins
gs plugin list

# View plugin details
gs plugin info android

# Use plugin commands
gs android logcat clear
gs system status
```

## Plugin Ecosystem

Global Scripts comes with a rich set of built-in plugins covering multiple development scenarios:

### Android Plugin

Android development toolkit with device management, log viewing, app management, and more.

```bash
# List devices
gs android device devices

# Clear logcat
gs android logcat clear

# Check app version
gs android app version com.android.settings
```

### System Plugin

System management tools providing configuration management, logging, and more.

```bash
# Check system status
gs status

# Configuration management
gs system config list
gs system config install git

# Proxy management
gs system proxy on
gs system proxy status
```

### Grep Plugin

Advanced search tools with multiple search modes.

```bash
# Search in code
gs grep code "pattern" /path/to/search
```

### Spider Plugin

Web scraping tools supporting static and dynamic pages.

```bash
# Crawl a webpage
gs spider crawl https://example.com
```

For more plugins, see [CLI Reference](./docs/en/cli-reference-en.md)

## Documentation

Complete documentation system to help you get started and dive deep:

- [Quick Start](./docs/en/quickstart-en.md) - Master the basics in 5 minutes
- [Installation Guide](./docs/en/installation-en.md) - Detailed installation steps and troubleshooting
- [CLI Reference](./docs/en/cli-reference-en.md) - Complete command-line reference
- [Plugin Development](./docs/en/plugin-development-en.md) - Build plugins from scratch
- [Architecture Design](./docs/en/architecture-en.md) - Deep dive into system architecture
- [FAQ](./docs/en/faq-en.md) - Troubleshooting guide
- [Contributing Guide](./docs/en/contributing-en.md) - How to contribute to the project

## Examples

### Config Plugin - Simplest

Create `plugins/hello/plugin.json`:

```json
{
  "name": "hello",
  "version": "1.0.0",
  "description": {"zh": "问候插件", "en": "Hello plugin"},
  "commands": {
    "world": {
      "command": "echo 'Hello, World!'",
      "description": "Say hello to the world"
    }
  }
}
```

Usage: `gs hello world`

### Python Plugin - Recommended

Create `plugins/calc/plugin.py`:

```python
from gscripts.plugins.decorators import plugin_function
from gscripts.models import CommandResult

@plugin_function(
    name="add",
    description={"zh": "加法运算", "en": "Addition"}
)
def add_numbers(args):
    a, b = float(args[0]), float(args[1])
    return CommandResult(
        success=True,
        output=f"{a} + {b} = {a + b}"
    )
```

Usage: `gs calc add 10 20`

For more examples, see [Plugin Development Guide](./docs/en/plugin-development-en.md)

## Development

### Develop Custom Plugins

Global Scripts provides a powerful and flexible plugin API:

1. **Config Plugin**: Perfect for simple command wrappers
2. **Shell Plugin**: Integrate existing shell scripts
3. **Python Plugin**: Implement complex business logic
4. **Hybrid Plugin**: Mix multiple types

For detailed development guide, see [Plugin Development Documentation](./docs/en/plugin-development-en.md)

### Contributing

Contributions are welcome! Report issues or make suggestions:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

See [Contributing Guide](./docs/en/contributing-en.md) for details

## Architecture Overview

```
global_scripts/
├── src/gscripts/          # Core code
│   ├── models/            # Data models
│   ├── core/              # Core modules
│   ├── cli/               # Command-line interface
│   ├── plugins/           # Plugin system
│   ├── router/            # Command routing index
│   ├── shell_completion/  # Shell completion generation
│   ├── resources/         # Resource files
│   │   ├── config/        # System configuration
│   │   └── templates/     # Jinja2 templates
│   └── utils/             # Utility modules
├── plugins/               # Built-in plugins
│   ├── android/           # Android development tools
│   ├── system/            # System management tools
│   ├── grep/              # Search tools
│   └── spider/            # Web scraping tools
├── custom/                # Custom plugin directory
├── docs/                  # Documentation
└── scripts/               # Installation and maintenance scripts
```

## Performance

| Metric | Performance |
|--------|-------------|
| Plugin loading (100 plugins) | < 3s |
| Command response time | < 100ms |
| Cache hit rate | 72% |
| Memory usage | < 50MB |
| Type annotation coverage | 80%+ |

## License

This project is licensed under the Apache-2.0 License. See [LICENSE](LICENSE) file for details.

## Acknowledgments

Thanks to all contributors for their support and contributions to this project!

## Links

- [GitHub Repository](https://github.com/i-rtfsc/global_scripts)
- [Issue Tracker](https://github.com/i-rtfsc/global_scripts/issues)
- [Changelog](./docs/changelog.md)
- [Documentation](./docs/)

---

**Get Started**: [Quick Start Guide](./docs/en/quickstart-en.md)

**Need Help**: [FAQ](./docs/en/faq-en.md) | [Submit Issue](https://github.com/i-rtfsc/global_scripts/issues)
