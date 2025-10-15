# Installation Guide

## System Requirements

- Python 3.11+
- Git
- uv (Python package manager)

## Installation Steps

### 1. Install uv

If you haven't installed uv yet, please install it first:

#### macOS/Linux
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

#### Windows
```powershell
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

For other installation methods, please refer to the [uv official documentation](https://docs.astral.sh/uv/getting-started/installation/).

### 2. Clone the Repository

```bash
git clone https://github.com/yourusername/global_scripts-v6.git
cd global_scripts-v6
```

### 3. Run Setup Script

```bash
# Initialize project
python scripts/setup.py
```

The setup script will automatically:
- Create virtual environment
- Install dependencies
- Configure shell integration
- Initialize system configurations

### 4. Configure Shell Environment

The setup script will automatically create shell configuration files for you. Choose according to your shell type:

#### Bash Users
Add the following to `~/.bashrc` or `~/.bash_profile`:
```bash
source /path/to/global_scripts-v6/env.sh
```

#### Fish Users
Add the following to `~/.config/fish/config.fish`:
```fish
source /path/to/global_scripts-v6/env.fish
```

#### Zsh Users
Add the following to `~/.zshrc`:
```bash
source /path/to/global_scripts-v6/env.sh
```

### 5. Reload Shell Configuration

```bash
# Bash/Zsh users
source ~/.bashrc  # or source ~/.zshrc

# Fish users
source ~/.config/fish/config.fish
```

## Verify Installation

After installation, you can verify with the following commands:

```bash
# Check version
gs --version

# View help information
gs --help

# List available scripts
gs list
```

## Common Issues

### uv Command Not Found

If you encounter "uv: command not found", it may be because uv is not in your PATH. Solution:

1. Check if uv is installed:
   ```bash
   which uv
   ```

2. If uv is installed but not found, add uv's installation path to your PATH environment variable.

### Permission Issues

If you encounter permission errors during installation, try:

```bash
# Grant execution permissions
chmod +x scripts/setup.py
```

### Python Version Issues

Make sure your Python version is 3.11 or higher:

```bash
python --version
```

If the version is too low, please install a newer version of Python.

## Manual Installation

If the automated installation fails, you can install manually:

```bash
# Create virtual environment
uv venv

# Activate virtual environment
source .venv/bin/activate  # Linux/macOS
# or
.venv\Scripts\activate  # Windows

# Install dependencies
uv pip install -e .

# Create configuration directories
mkdir -p ~/.config/gscripts
```

## Next Steps

After successful installation, you can:

1. [Quick Start](quickstart.md) - Learn basic usage
2. [Plugin Development](plugin-development.md) - Learn how to write custom scripts
3. [FAQ](faq.md) - Find answers to common questions
