# UV Usage Guide

This document introduces how to use UV to manage the Global Scripts project.

## What is UV?

[UV](https://github.com/astral-sh/uv) is an **extremely fast Python package manager** developed by Astral (creators of Ruff), written in Rust, and 10-100x faster than pip.

### Why Use UV?

- ⚡ **Blazingly Fast**: 10-100x faster than pip
- 🔒 **Dependency Locking**: Automatically generates `uv.lock` to ensure reproducible builds
- 🎯 **Modern**: Supports latest standards like PEP 621, PEP 660
- 🛠️ **Multi-functional**: Integrated package management, virtual environments, and project management
- 🌍 **Cross-platform**: Full support for Windows, macOS, and Linux

---

## Installing UV

### Method 1: Official Installation Script (Recommended)

```bash
# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Or using wget
wget -qO- https://astral.sh/uv/install.sh | sh
```

### Method 2: Using pip

```bash
pip install uv
```

### Method 3: Using Package Managers

```bash
# macOS (Homebrew)
brew install uv

# Arch Linux
pacman -S uv
```

### Verify Installation

```bash
uv --version
# Output: uv 0.x.x
```

---

## Quick Start

### 1. Initialize Project

```bash
# Clone the project
git clone https://github.com/i-rtfsc/global_scripts.git
cd global_scripts

# UV will automatically read pyproject.toml
# Sync dependencies (create .venv and install dependencies)
uv sync
```

This will:
1. Create a `.venv` virtual environment
2. Install dependencies based on `pyproject.toml`
3. Generate a `uv.lock` lockfile

### 2. Activate Virtual Environment

```bash
# macOS/Linux
source .venv/bin/activate

# Windows
.venv\Scripts\activate

# Or use uv run directly (no activation needed)
uv run python script.py
```

### 3. Install Project (Editable Mode)

```bash
# Install base version
uv pip install -e .

# Install performance-optimized version
uv pip install -e ".[performance]"

# Install full features (including Spider)
uv pip install -e ".[full]"

# Install development tools
uv sync --group dev
```

---

## Common Commands

### Dependency Management

```bash
# Sync dependencies (based on pyproject.toml and uv.lock)
uv sync

# Sync including development dependencies
uv sync --group dev

# Add new dependency
uv add package_name

# Add development dependency
uv add --dev package_name

# Remove dependency
uv remove package_name

# Update all dependencies
uv sync --upgrade

# Update specific dependency
uv add --upgrade package_name
```

### Running Scripts

```bash
# Run script in virtual environment (no activation needed)
uv run python script.py

# Run gs command
uv run gs version

# Run tests
uv run pytest
```

### Virtual Environment Management

```bash
# Create virtual environment
uv venv

# Specify Python version
uv venv --python 3.11

# Delete virtual environment
rm -rf .venv

# Recreate
uv sync
```

### Package Installation

```bash
# Install package (equivalent to pip install)
uv pip install package_name

# Install from requirements.txt
uv pip install -r requirements.txt

# View installed packages
uv pip list

# Uninstall package
uv pip uninstall package_name
```

---

## Global Scripts Specific Usage

### Basic Installation

```bash
# 1. Sync dependencies
uv sync

# 2. Install project (editable mode)
uv pip install -e .

# 3. Run setup script
uv run python scripts/setup.py
```

### Installing Optional Features

```bash
# Performance optimization (install aiofiles)
uv pip install -e ".[performance]"

# Spider plugin
uv pip install -e ".[spider]"

# Full features
uv pip install -e ".[full]"

# Development tools
uv sync --group dev
```

### Development Workflow

```bash
# 1. Install development dependencies
uv sync --group dev

# 2. Run tests
uv run pytest

# 3. Code formatting
uv run black src/

# 4. Code linting
uv run ruff check src/

# 5. Type checking
uv run mypy src/
```

### Adding New Plugin Dependencies

If your plugin requires specific Python packages:

```bash
# Add to project dependencies
uv add package_name

# Or add as optional dependency (recommended)
# Manually edit pyproject.toml:
# [project.optional-dependencies]
# myplugin = ["package_name>=1.0.0"]

# Then sync
uv sync
```

---

## pyproject.toml Configuration Explanation

Global Scripts' `pyproject.toml` structure:

```toml
[project]
name = "global-scripts"
version = "6.0.0"
requires-python = ">=3.8"

# Core dependencies - 3 required dependencies
dependencies = [
    "PyYAML>=6.0.1",
    "Jinja2>=3.1.2",
    "aiofiles>=0.8.0,<1.0",
]

[project.optional-dependencies]
# Performance optimization
performance = ["aiofiles>=0.8.0,<1.0"]

# Spider plugin
spider = [
    "requests>=2.25.0,<3.0",
    "beautifulsoup4>=4.9.0,<5.0",
    # ...
]

# Development tools
dev = [
    "pytest>=7.0.0,<8.0",
    "black>=22.0.0,<25.0",
    # ...
]

# UV-specific configuration
[tool.uv]
dev-dependencies = [
    "pytest>=7.0.0,<8.0",
    # ...
]
```

### Installing Optional Dependency Groups

```bash
# Install single group
uv pip install -e ".[performance]"
uv pip install -e ".[spider]"
uv pip install -e ".[dev]"

# Install multiple groups
uv pip install -e ".[performance,spider]"

# Install all
uv pip install -e ".[full]"
```

---

## UV vs PIP Comparison

| Feature | UV | PIP |
|---------|----|----|
| Speed | ⚡️ 10-100x faster | 🐢 Slow |
| Lock File | ✅ uv.lock | ❌ Requires pip-tools |
| Virtual Environment | ✅ Built-in | Requires venv |
| Dependency Resolution | ✅ Fast | 🐢 Slow |
| Caching | ✅ Intelligent | ⚠️  Basic |
| Platform Support | ✅ All platforms | ✅ All platforms |

### Command Comparison Table

| Operation | PIP | UV |
|-----------|-----|-----|
| Install package | `pip install package` | `uv pip install package` |
| Uninstall package | `pip uninstall package` | `uv pip uninstall package` |
| List packages | `pip list` | `uv pip list` |
| Freeze dependencies | `pip freeze > requirements.txt` | `uv pip freeze > requirements.txt` |
| Install requirements | `pip install -r requirements.txt` | `uv pip install -r requirements.txt` |
| Create virtual environment | `python -m venv .venv` | `uv venv` |
| Install project | `pip install -e .` | `uv pip install -e .` |

---

## Advanced Usage

### Using Chinese Mirrors

```bash
# Temporary use
uv pip install package --index-url https://pypi.tuna.tsinghua.edu.cn/simple

# Or set environment variable
export UV_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple
uv sync
```

### Cache Management

```bash
# View cache size
uv cache dir

# Clear cache
uv cache clean

# Clear specific package cache
uv cache clean package_name
```

### Specifying Python Version

```bash
# Create environment with specific Python version
uv venv --python 3.11
uv venv --python 3.12

# Use Python from pyenv
uv venv --python $(pyenv which python3.11)
```

### Lock Files

```bash
# Generate/update uv.lock
uv sync

# Only update lock file (don't install)
uv lock

# Install from lock file (ensure reproducibility)
uv sync --frozen
```

---

## Troubleshooting

### Issue 1: uv: command not found

**Solution**:
```bash
# Reinstall
curl -LsSf https://astral.sh/uv/install.sh | sh

# Add to PATH (usually added automatically)
export PATH="$HOME/.cargo/bin:$PATH"

# Or reload shell
source ~/.bashrc   # bash users
source ~/.zshrc    # zsh users
source ~/.config/fish/config.fish  # fish users
```

### Issue 2: Dependency Resolution Failed

**Solution**:
```bash
# Clear cache
uv cache clean

# Resync
uv sync

# If still failing, check pyproject.toml format
python3 -m json.tool < pyproject.toml
```

### Issue 3: Virtual Environment Not Activated

**Solution**:
```bash
# Solution 1: Manual activation
source .venv/bin/activate

# Solution 2: Use uv run (recommended)
uv run python script.py
```

### Issue 4: Slow Installation

**Cause**: Network issues

**Solution**:
```bash
# Use Chinese mirror
export UV_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple
uv sync

# Or Tsinghua mirror
export UV_INDEX_URL=https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple
uv sync
```

---

## Best Practices

### 1. Use uv run to Avoid Environment Activation

```bash
# Not recommended
source .venv/bin/activate
python script.py

# Recommended
uv run python script.py
```

### 2. Lock Dependencies to Ensure Reproducibility

```bash
# During development
uv sync  # Generate uv.lock

# Production deployment
uv sync --frozen  # Use locked versions
```

### 3. Group Optional Dependencies by Category

```toml
[project.optional-dependencies]
# Group by functionality
performance = [...]
spider = [...]
dev = [...]

# Combined usage
uv pip install -e ".[performance,spider]"
```

### 4. Use .python-version to Pin Python Version

```bash
# Create .python-version file
echo "3.11" > .python-version

# UV will automatically use this version
uv venv
```

---

## Reference Resources

- 📚 [UV Official Documentation](https://github.com/astral-sh/uv)
- 🚀 [UV Release Announcement](https://astral.sh/blog/uv)
- 📖 [PEP 621 (pyproject.toml)](https://peps.python.org/pep-0621/)
- 🔧 [Global Scripts Documentation](../README.md)

---

## Next Steps

- 📖 [Installation Guide](INSTALLATION.md) - Detailed installation steps
- 🔌 [Plugin Development](PLUGIN_DEVELOPMENT.md) - Develop your own plugins
- ⚙️  [Configuration Guide](CONFIGURATION.md) - Custom configuration
