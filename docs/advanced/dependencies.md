# 系统依赖说明

本文档详细说明Global Scripts运行所需的所有系统级依赖。

## 📋 目录

- [Python依赖](#python依赖)
- [Shell工具](#shell工具)
- [可选工具](#可选工具)
- [平台特定依赖](#平台特定依赖)
- [依赖安装脚本](#依赖安装脚本)

---

## Python依赖

### 必需Python版本

```bash
Python >= 3.7
```

### 核心Python包

Global Scripts 有 **3个必需的Python依赖**：

```bash
PyYAML>=6.0.1          # 解析system_config.yaml配置文件
Jinja2>=3.1.2          # 模板引擎，生成env.sh/env.fish
aiofiles>=0.8.0,<1.0   # 异步文件I/O（有同步fallback）
```

**用途说明**:
- **PyYAML**: 用于解析 `system_config.yaml` 配置文件
- **Jinja2**: 用于模板引擎，生成 `env.sh` / `env.fish` 环境文件
- **aiofiles**: 用于异步文件I/O性能优化（有同步fallback）

这些依赖会在运行 `uv sync` 时自动安装。

**标准库依赖**:

Global Scripts 还使用以下 Python 标准库（无需安装）：

- `os`, `sys`, `pathlib` - 文件系统操作
- `json` - JSON处理
- `subprocess`, `asyncio` - 进程管理
- `logging`, `argparse` - 日志和命令行
- `hashlib`, `shutil` - 工具函数
- `datetime`, `time` - 时间处理
- `typing`, `dataclasses` - 类型支持

#### Spider插件（按需）

```bash
requests>=2.25.0,<3.0           # HTTP客户端
beautifulsoup4>=4.9.0,<5.0      # HTML解析
markdownify>=0.9.0,<1.0         # HTML转Markdown
selenium>=4.0.0,<5.0            # 浏览器自动化
parsel>=1.6.0,<2.0              # XPath/CSS选择器
```

**安装方式**:
```bash
# 自动安装Spider依赖
gs spider install_deps

# 或手动安装
uv pip install -e ".[spider]"
```

---

## Shell工具

### 必需工具

Global Scripts的shell脚本依赖以下系统工具：

| 工具 | 用途 | 检查命令 | 替代方案 |
|------|------|----------|----------|
| `bash/zsh/fish` | Shell脚本执行 | `bash --version` | 无 |
| `python3` | Python脚本执行 | `python3 --version` | 无 |
| `jq` | JSON处理（动态补全） | `jq --version` | 无（补全核心功能） |

#### jq安装

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

**说明**:
- jq是动态补全的**核心依赖**，用于实时读取router/index.json
- bash/zsh/fish补全都依赖jq进行JSON解析
- 这是Global Scripts最实用的功能，jq为必装工具

---

## 可选工具

这些工具用于特定插件或增强功能：

### Android插件

| 工具 | 用途 | 检查命令 | 安装方式 |
|------|------|----------|----------|
| `adb` | Android调试 | `adb version` | Android SDK Platform Tools |
| `fastboot` | Android刷机 | `fastboot --version` | Android SDK Platform Tools |

```bash
# macOS
brew install android-platform-tools

# Ubuntu/Debian
sudo apt-get install android-tools-adb android-tools-fastboot

# 或下载SDK Platform Tools
# https://developer.android.com/studio/releases/platform-tools
```

### Git/Gerrit插件

| 工具 | 用途 | 检查命令 | 安装方式 |
|------|------|----------|----------|
| `git` | 版本控制 | `git --version` | 系统包管理器 |
| `git-review` | Gerrit集成 | `git-review --version` | `pip install git-review` |

```bash
# macOS
brew install git git-review

# Ubuntu/Debian
sudo apt-get install git git-review

# 或使用pip
pip install git-review
```

### System插件

#### Repo工具（AOSP源码管理）

```bash
# 下载repo
mkdir -p ~/bin
curl https://storage.googleapis.com/git-repo-downloads/repo > ~/bin/repo
chmod a+x ~/bin/repo

# 添加到PATH
export PATH="$HOME/bin:$PATH"
```

#### Homebrew镜像管理（macOS）

```bash
# Homebrew本身
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### Spider插件

除了Python依赖外，Spider插件还可能需要：

#### Selenium WebDriver

```bash
# Chrome WebDriver
brew install chromedriver  # macOS
# 或从 https://chromedriver.chromium.org/ 下载

# Firefox WebDriver (geckodriver)
brew install geckodriver  # macOS
# 或从 https://github.com/mozilla/geckodriver/releases 下载
```

---

## 平台特定依赖

### macOS

```bash
# 推荐使用Homebrew管理工具
brew install jq git python@3.11

# Android开发
brew install android-platform-tools

# 可选：代理工具
brew install proxychains-ng
```

### Ubuntu/Debian

```bash
# 基础工具
sudo apt-get update
sudo apt-get install -y \
    jq \
    git \
    python3 \
    python3-pip \
    python3-venv

# Android开发
sudo apt-get install -y \
    android-tools-adb \
    android-tools-fastboot

# 可选：构建工具
sudo apt-get install -y \
    build-essential \
    curl \
    wget
```

### Arch Linux

```bash
# 基础工具
sudo pacman -S jq git python python-pip

# Android开发
sudo pacman -S android-tools

# AUR助手（可选）
yay -S android-sdk-platform-tools
```

### CentOS/RHEL

```bash
# 启用EPEL
sudo yum install -y epel-release

# 基础工具
sudo yum install -y \
    jq \
    git \
    python3 \
    python3-pip

# Android工具需要手动安装
# https://developer.android.com/studio/releases/platform-tools
```

---

## 依赖安装脚本

### 一键安装脚本（macOS）

保存为 `install_deps_macos.sh`:

```bash
#!/bin/bash
set -e

echo "🔧 Installing Global Scripts dependencies for macOS..."

# 检查Homebrew
if ! command -v brew &>/dev/null; then
    echo "❌ Homebrew not found. Installing..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

# 安装Python
echo "📦 Installing Python..."
brew install python@3.11

# 安装jq
echo "📦 Installing jq..."
brew install jq

# 安装Git
echo "📦 Installing Git..."
brew install git

# 可选：Android工具
read -p "Install Android tools? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    brew install android-platform-tools
fi

# 安装UV
echo "📦 Installing UV..."
curl -LsSf https://astral.sh/uv/install.sh | sh

echo "✅ Dependencies installed successfully!"
echo "Run: source ~/.bashrc (or ~/.zshrc)"
```

### 一键安装脚本（Ubuntu/Debian）

保存为 `install_deps_ubuntu.sh`:

```bash
#!/bin/bash
set -e

echo "🔧 Installing Global Scripts dependencies for Ubuntu/Debian..."

# 更新包列表
sudo apt-get update

# 安装基础工具
echo "📦 Installing basic tools..."
sudo apt-get install -y \
    jq \
    git \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    wget

# 可选：Android工具
read -p "Install Android tools? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    sudo apt-get install -y \
        android-tools-adb \
        android-tools-fastboot
fi

# 安装UV
echo "📦 Installing UV..."
curl -LsSf https://astral.sh/uv/install.sh | sh

echo "✅ Dependencies installed successfully!"
echo "Run: source ~/.bashrc"
```

### 运行安装脚本

```bash
# 下载并运行
chmod +x install_deps_*.sh
./install_deps_macos.sh      # macOS
./install_deps_ubuntu.sh     # Ubuntu/Debian
```

---

## 依赖检查

Global Scripts提供内置的依赖检查命令：

```bash
# 检查所有依赖
gs doctor

# 检查特定插件的依赖
gs android doctor      # Android插件依赖
gs spider doctor       # Spider插件依赖
```

输出示例：

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

## 故障排除

### jq未找到

```bash
# 检查jq
command -v jq
jq --version

# 如果未安装
brew install jq  # macOS
sudo apt-get install jq  # Ubuntu
```

### Python版本过低

```bash
# 检查版本
python3 --version

# 升级Python
brew install python@3.11  # macOS
sudo apt-get install python3.11  # Ubuntu

# 使用pyenv管理多版本
curl https://pyenv.run | bash
pyenv install 3.11.5
pyenv global 3.11.5
```

### adb未找到

```bash
# macOS
brew install android-platform-tools

# Ubuntu
sudo apt-get install android-tools-adb

# 手动安装
# 下载 https://developer.android.com/studio/releases/platform-tools
# 解压并添加到PATH
export PATH="$HOME/platform-tools:$PATH"
```

---

## 总结

### 最小依赖（核心功能）

```
✅ Python 3.7+
✅ bash/zsh/fish
✅ jq (JSON处理，补全必需)
```

### 推荐依赖（完整体验）

```
✅ Python 3.7+
✅ bash/zsh/fish
✅ jq (JSON处理，补全必需)
✅ git (版本控制)
✅ aiofiles (Python包，性能优化)
```

### 可选依赖（特定插件）

```
⭐️ adb/fastboot (Android插件)
⭐️ repo (AOSP源码管理)
⭐️ requests, beautifulsoup4等 (Spider插件)
⭐️ chromedriver (Spider动态页面)
```

Global Scripts采用**渐进增强**策略，让你可以：
1. **零配置开始** - 仅需Python即可使用核心功能
2. **按需扩展** - 根据使用的插件安装相应依赖
3. **优雅降级** - 缺少可选依赖时自动降级但不报错
