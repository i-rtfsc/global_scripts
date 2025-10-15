# System Dependencies Documentation

This document provides a detailed explanation of all system-level dependencies required to run Global Scripts.

## 📋 Table of Contents

- [Python Dependencies](#python-dependencies)
- [Shell Tools](#shell-tools)
- [Optional Tools](#optional-tools)
- [Platform-Specific Dependencies](#platform-specific-dependencies)
- [Dependency Installation Scripts](#dependency-installation-scripts)

---

## Python Dependencies

### Required Python Version

```bash
Python >= 3.7
```

### Core Python Packages

Global Scripts has **3 required Python dependencies**:

```bash
PyYAML>=6.0.1          # Parse system_config.yaml configuration files
Jinja2>=3.1.2          # Template engine, generate env.sh/env.fish
aiofiles>=0.8.0,<1.0   # Asynchronous file I/O (with synchronous fallback)
```

**Purpose Explanation**:
- **PyYAML**: Used to parse `system_config.yaml` configuration files
- **Jinja2**: Used for template engine, generating `env.sh` / `env.fish` environment files
- **aiofiles**: Used for asynchronous file I/O performance optimization (with synchronous fallback)

These dependencies will be automatically installed when running `uv sync`.

**Standard Library Dependencies**:

Global Scripts also uses the following Python standard libraries (no installation required):

- `os`, `sys`, `pathlib` - File system operations
- `json` - JSON processing
- `subprocess`, `asyncio` - Process management
- `logging`, `argparse` - Logging and command line
- `hashlib`, `shutil` - Utility functions
- `datetime`, `time` - Time handling
- `typing`, `dataclasses` - Type support

#### Spider Plugin (On-Demand)

```bash
requests>=2.25.0,<3.0           # HTTP client
beautifulsoup4>=4.9.0,<5.0      # HTML parsing
markdownify>=0.9.0,<1.0         # HTML to Markdown conversion
selenium>=4.0.0,<5.0            # Browser automation
parsel>=1.6.0,<2.0              # XPath/CSS selectors
```

**Installation Method**:
```bash
# Automatically install Spider dependencies
gs spider install_deps

# Or manually install
uv pip install -e ".[spider]"
```

---

## Shell Tools

### Required Tools

Global Scripts' shell scripts depend on the following system tools:

| Tool | Purpose | Check Command | Alternatives |
|------|---------|---------------|--------------|
| `bash/zsh/fish` | Shell script execution | `bash --version` | None |
| `python3` | Python script execution | `python3 --version` | None |
| `jq` | JSON processing (dynamic completion) | `jq --version` | None (core completion feature) |

#### jq Installation

```bash
# macOS
brew install jq

# Ubuntu/Debian
sudo apt-get install jq

# CentOS/RHEL
sudo yum install jq

# Arch Linux
sudo pacman -S jq

# Alpine Linux
apk add jq
```

**Explanation**:
- jq is a **core dependency** for dynamic completion, used to read router/index.json in real-time
- bash/zsh/fish completion all rely on jq for JSON parsing
- This is Global Scripts' most practical feature, making jq a must-install tool

---

## Optional Tools

These tools are used for specific plugins or enhanced features:

### Android Plugin

| Tool | Purpose | Check Command | Installation Method |
|------|---------|---------------|---------------------|
| `adb` | Android debugging | `adb version` | Android SDK Platform Tools |
| `fastboot` | Android flashing | `fastboot --version` | Android SDK Platform Tools |

```bash
# macOS
brew install android-platform-tools

# Ubuntu/Debian
sudo apt-get install android-tools-adb android-tools-fastboot

# Or download SDK Platform Tools
# https://developer.android.com/studio/releases/platform-tools
```

### Git/Gerrit Plugin

| Tool | Purpose | Check Command | Installation Method |
|------|---------|---------------|---------------------|
| `git` | Version control | `git --version` | System package manager |
| `git-review` | Gerrit integration | `git-review --version` | `pip install git-review` |

```bash
# macOS
brew install git git-review

# Ubuntu/Debian
sudo apt-get install git git-review

# Or use pip
pip install git-review
```

### System Plugin

#### Repo Tool (AOSP Source Code Management)

```bash
# Download repo
mkdir -p ~/bin
curl https://storage.googleapis.com/git-repo-downloads/repo > ~/bin/repo
chmod a+x ~/bin/repo

# Add to PATH
export PATH="$HOME/bin:$PATH"
```

#### Homebrew Mirror Management (macOS)

```bash
# Homebrew itself
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### Spider Plugin

In addition to Python dependencies, the Spider plugin may also require:

#### Selenium WebDriver

```bash
# Chrome WebDriver
brew install chromedriver  # macOS
# Or download from https://chromedriver.chromium.org/

# Firefox WebDriver (geckodriver)
brew install geckodriver  # macOS
# Or download from https://github.com/mozilla/geckodriver/releases
```

---

## Platform-Specific Dependencies

### macOS

```bash
# Recommended to use Homebrew for tool management
brew install jq git python@3.11

# Android development
brew install android-platform-tools

# Optional: proxy tools
brew install proxychains-ng
```

### Ubuntu/Debian

```bash
# Basic tools
sudo apt-get update
sudo apt-get install -y \
    jq \
    git \
    python3 \
    python3-pip \
    python3-venv

# Android development
sudo apt-get install -y \
    android-tools-adb \
    android-tools-fastboot

# Optional: build tools
sudo apt-get install -y \
    build-essential \
    curl \
    wget
```

### Arch Linux

```bash
# Basic tools
sudo pacman -S jq git python python-pip

# Android development
sudo pacman -S android-tools

# AUR helper (optional)
yay -S android-sdk-platform-tools
```

### CentOS/RHEL

```bash
# Enable EPEL
sudo yum install -y epel-release

# Basic tools
sudo yum install -y \
    jq \
    git \
    python3 \
    python3-pip

# Android tools require manual installation
# https://developer.android.com/studio/releases/platform-tools
```

---

## Dependency Installation Scripts

### One-Click Installation Script (macOS)

Save as `install_deps_macos.sh`:

```bash
#!/bin/bash
set -e

echo "🔧 Installing Global Scripts dependencies for macOS..."

# Check Homebrew
if ! command -v brew &>/dev/null; then
    echo "❌ Homebrew not found. Installing..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

# Install Python
echo "📦 Installing Python..."
brew install python@3.11

# Install jq
echo "📦 Installing jq..."
brew install jq

# Install Git
echo "📦 Installing Git..."
brew install git

# Optional: Android tools
read -p "Install Android tools? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    brew install android-platform-tools
fi

# Install UV
echo "📦 Installing UV..."
curl -LsSf https://astral.sh/uv/install.sh | sh

echo "✅ Dependencies installed successfully!"
echo "Run: source ~/.bashrc (or ~/.zshrc)"
```

### One-Click Installation Script (Ubuntu/Debian)

Save as `install_deps_ubuntu.sh`:

```bash
#!/bin/bash
set -e

echo "🔧 Installing Global Scripts dependencies for Ubuntu/Debian..."

# Update package list
sudo apt-get update

# Install basic tools
echo "📦 Installing basic tools..."
sudo apt-get install -y \
    jq \
    git \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    wget

# Optional: Android tools
read -p "Install Android tools? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    sudo apt-get install -y \
        android-tools-adb \
        android-tools-fastboot
fi

# Install UV
echo "📦 Installing UV..."
curl -LsSf https://astral.sh/uv/install.sh | sh

echo "✅ Dependencies installed successfully!"
echo "Run: source ~/.bashrc"
```

### Running Installation Scripts

```bash
# Download and run
chmod +x install_deps_*.sh
./install_deps_macos.sh      # macOS
./install_deps_ubuntu.sh     # Ubuntu/Debian
```

---

## Dependency Checking

Global Scripts provides built-in dependency checking commands:

```bash
# Check all dependencies
gs doctor

# Check dependencies for specific plugins
gs android doctor      # Android plugin dependencies
gs spider doctor       # Spider plugin dependencies
```

Example output:

```
🏥 Global Scripts System Health Check

Python Environment:
  ✅ Python 3.11.5
  ✅ pip 23.3.1
  ✅ UV 0.1.0

Required Tools:
  ✅ bash 5.2.15
  ✅ jq 1.6

Optional Tools:
  ✅ git 2.42.0
  ✅ adb 34.0.4
  ⚠️  chromedriver not found (optional for Spider plugin)

Python Packages:
  ✅ aiofiles 23.2.1
  ⚠️  requests not installed (optional for Spider plugin)

Overall Status: ✅ All critical dependencies satisfied
```

---

## Troubleshooting

### jq Not Found

```bash
# Check jq
command -v jq
jq --version

# If not installed
brew install jq  # macOS
sudo apt-get install jq  # Ubuntu
```

### Python Version Too Old

```bash
# Check version
python3 --version

# Upgrade Python
brew install python@3.11  # macOS
sudo apt-get install python3.11  # Ubuntu

# Use pyenv to manage multiple versions
curl https://pyenv.run | bash
pyenv install 3.11.5
pyenv global 3.11.5
```

### adb Not Found

```bash
# macOS
brew install android-platform-tools

# Ubuntu
sudo apt-get install android-tools-adb

# Manual installation
# Download https://developer.android.com/studio/releases/platform-tools
# Extract and add to PATH
export PATH="$HOME/platform-tools:$PATH"
```

---

## Summary

### Minimum Dependencies (Core Features)

```
✅ Python 3.7+
✅ bash/zsh/fish
✅ jq (JSON processing, required for completion)
```

### Recommended Dependencies (Complete Experience)

```
✅ Python 3.7+
✅ bash/zsh/fish
✅ jq (JSON processing, required for completion)
✅ git (version control)
✅ aiofiles (Python package, performance optimization)
```

### Optional Dependencies (Specific Plugins)

```
⭐️ adb/fastboot (Android plugin)
⭐️ repo (AOSP source code management)
⭐️ requests, beautifulsoup4, etc. (Spider plugin)
⭐️ chromedriver (Spider dynamic pages)
```

Global Scripts adopts a **progressive enhancement** strategy, allowing you to:
1. **Zero-configuration start** - Only Python is needed to use core features
2. **Expand on demand** - Install corresponding dependencies based on the plugins you use
3. **Graceful degradation** - Automatically degrade when optional dependencies are missing without throwing errors
