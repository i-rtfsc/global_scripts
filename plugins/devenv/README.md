# DevEnv Plugin - 开发环境管理工具

快速安装和配置开发工具的 Global Scripts 插件。

## 🎯 功能特性

- ✅ **一键安装**: 快速安装开发环境所需的所有工具
- 🎨 **预设环境**: 内置多种开发环境预设 (Android、Rust、C++、Agent等)
- 🔧 **工具分类**: 清晰的必选/可选工具分类
- 🖥️  **跨平台**: 支持 macOS (Homebrew) 和 Linux (APT)
- 📦 **80+ 工具**: 涵盖语言运行时、构建工具、容器、数据库等
- 🚀 **自动验证**: 安装后自动验证工具可用性

## 🛠️ 支持的工具分类

### 必选工具 (30+)
- **语言运行时**: JDK, Python, Node.js, Go, Rust
- **版本控制**: Git, Git LFS, GitHub CLI
- **Android开发**: ADB, Gradle
- **构建工具**: CMake, Make, Ninja
- **文本处理**: jq, yq, ripgrep, fd, bat, fzf, ack
- **网络工具**: curl, wget, httpie, nmap
- **终端工具**: tmux, fish
- **监控工具**: htop, btop, ncdu, duf
- **编辑器**: Neovim, VSCode
- **代码质量**: ShellCheck

### 可选工具 (50+)
- **容器**: Docker, Docker Compose, kubectl, k9s
- **数据库**: PostgreSQL, MySQL, Redis, SQLite
- **云平台**: AWS CLI, Google Cloud SDK
- **终端复用**: Screen, Zellij
- **Shell增强**: Zsh, Oh My Zsh, Starship, Zoxide
- **AI工具**: Ollama
- **DevOps**: Terraform, Ansible
- **其他**: Bazel, Flutter, Fastlane, Ruby 等

## 📖 使用指南

### 查看可用工具

```bash
# 列出所有工具
gs devenv list

# 仅列出必选工具
gs devenv list --required

# 仅列出可选工具
gs devenv list --optional
```

### 查看预设环境

```bash
# 列出所有预设
gs devenv presets

# 输出示例:
# ✅ [必选] essential         - 开发环境最基础的必选工具
# ✅ [必选] android-dev       - Android系统和应用开发完整环境
# ✅ [必选] rust-dev          - Rust开发完整工具链
# ✅ [必选] cpp-dev           - C/C++开发工具链
# ✅ [必选] agent-dev         - AI Agent开发工具集
# ✅ [必选] full-required     - 完整必选环境 (Android + Rust + C++ + Agent)
# ⭐ [可选] optional-container - Docker和Kubernetes工具 (可选)
# ⭐ [可选] optional-database  - 常用数据库客户端 (可选)
```

### 检查环境状态

```bash
# 检查所有必选工具
gs devenv status

# 检查单个工具
gs devenv status jdk

# 环境健康检查 (仅检查必选工具)
gs devenv check

# 完整环境检查 (包括可选工具)
gs devenv check --all
```

### 安装工具

#### 安装单个工具
```bash
# 安装 JDK
gs devenv install jdk

# 安装 Rust
gs devenv install cargo

# 安装 Docker
gs devenv install docker
```

#### 安装预设环境

```bash
# 安装核心必选工具
gs devenv install essential

# 安装 Android 开发环境
gs devenv install android-dev

# 安装完整必选环境 (推荐: 新机首次使用)
gs devenv install full-required

# 安装可选工具
gs devenv install optional-container   # Docker + K8s
gs devenv install optional-database    # 数据库客户端
gs devenv install optional-shell       # Shell 美化

# 安装完整环境 (包含所有工具)
gs devenv install full-dev

# 安装完整环境但跳过可选工具
gs devenv install full-dev --required-only
```

## 🚀 快速开始

### 新机器第一次setup

```bash
# 1. 安装核心工具和完整必选环境 (一键搞定!)
gs devenv install full-required

# 2. 按需安装可选工具
gs devenv install optional-container  # 如果需要 Docker
gs devenv install optional-shell      # 如果想美化 Shell

# 3. 验证安装
gs devenv check
```

### Android开发者

```bash
# 安装 Android 开发环境
gs devenv install android-dev

# 验证
gs devenv status
```

### Rust开发者

```bash
# 安装 Rust 工具链
gs devenv install rust-dev

# 验证
cargo --version
```

### Agent开发者

```bash
# 安装 Agent 开发环境
gs devenv install agent-dev

# 可选: 安装本地 LLM
gs devenv install ollama
```

## 📦 预设环境详解

### 必选预设

| 预设名 | 说明 | 包含工具数量 |
|--------|------|-------------|
| `essential` | 核心必选工具 | 11 |
| `android-dev` | Android开发 | 4 |
| `rust-dev` | Rust开发 | 1 |
| `cpp-dev` | C/C++开发 | 3 |
| `agent-dev` | Agent开发 | 5 |
| `full-required` | 完整必选环境 | 30+ |

### 可选预设

| 预设名 | 说明 | 包含工具数量 |
|--------|------|-------------|
| `optional-container` | 容器工具 | 4 |
| `optional-database` | 数据库客户端 | 4 |
| `optional-cloud` | 云平台CLI | 2 |
| `optional-shell` | Shell美化 | 4 |
| `optional-ai` | AI工具 | 1 |
| `optional-devops` | DevOps工具 | 2 |
| `full-dev` | 完整环境 (包含所有可选) | 所有 |

## 🎨 工具列表

<details>
<summary>点击展开完整工具列表</summary>

### 编程语言运行时 (6)
- ✅ **jdk** - OpenJDK 21
- ✅ **python3** - Python 3.11
- ✅ **node** - Node.js
- ✅ **go** - Go 1.21
- ❌ **ruby** - Ruby (可选)
- ✅ **cargo** - Rust Toolchain

### 版本控制 (3)
- ✅ **git** - Git
- ✅ **git-lfs** - Git LFS
- ✅ **gh** - GitHub CLI

### Android/Mobile开发 (4)
- ✅ **adb** - Android Platform Tools
- ✅ **gradle** - Gradle
- ❌ **flutter** - Flutter (可选)
- ❌ **fastlane** - Fastlane (可选)

### 构建工具 (4)
- ✅ **cmake** - CMake
- ✅ **make** - GNU Make
- ✅ **ninja** - Ninja
- ❌ **bazel** - Bazel (可选)

### 容器工具 (4) - 可选
- ❌ **docker** - Docker
- ❌ **docker-compose** - Docker Compose
- ❌ **kubectl** - Kubernetes CLI
- ❌ **k9s** - K9s

### 数据库工具 (4) - 可选
- ❌ **postgresql** - PostgreSQL Client
- ❌ **mysql** - MySQL Client
- ❌ **redis** - Redis CLI
- ❌ **sqlite** - SQLite

### 云平台CLI (2) - 可选
- ❌ **awscli** - AWS CLI
- ❌ **gcloud** - Google Cloud SDK

### 网络工具 (4)
- ✅ **curl** - cURL
- ✅ **wget** - Wget
- ✅ **httpie** - HTTPie
- ✅ **nmap** - Nmap

### 文本处理/搜索 (6)
- ✅ **jq** - JSON处理器
- ✅ **yq** - YAML处理器
- ✅ **ripgrep** - 快速搜索 (rg)
- ✅ **fd** - 快速文件查找
- ✅ **bat** - 代码高亮查看
- ✅ **fzf** - 模糊搜索
- ✅ **ack** - 代码搜索

### 终端增强 (3)
- ✅ **tmux** - Tmux
- ❌ **screen** - GNU Screen (可选)
- ❌ **zellij** - Zellij (可选)

### Shell增强 (5) - 可选
- ❌ **zsh** - Zsh
- ❌ **oh-my-zsh** - Oh My Zsh
- ✅ **fish** - Fish Shell
- ❌ **starship** - Starship
- ❌ **zoxide** - Zoxide

### 监控工具 (4)
- ✅ **htop** - htop
- ✅ **btop** - btop
- ✅ **ncdu** - ncdu
- ✅ **duf** - duf

### AI工具 (1) - 可选
- ❌ **ollama** - Ollama

### 编辑器 (2)
- ✅ **neovim** - Neovim
- ✅ **vscode** - Visual Studio Code

### 代码质量 (2)
- ✅ **shellcheck** - ShellCheck
- ❌ **hadolint** - Hadolint (可选)

### DevOps工具 (2) - 可选
- ❌ **terraform** - Terraform
- ❌ **ansible** - Ansible

</details>

## 🔧 技术实现

- **Python插件**: 使用 `@plugin_function` 装饰器
- **异步执行**: 基于 asyncio 的异步安装
- **平台检测**: 自动检测 macOS/Linux 和包管理器
- **配置驱动**: JSON配置文件定义工具和预设
- **错误处理**: 完善的错误处理和日志记录

## 📝 配置文件

- `config/tools.json` - 工具定义 (80+ 工具)
- `config/presets.json` - 预设环境配置

## 🤝 贡献

欢迎添加更多工具到配置文件! 编辑 `config/tools.json` 添加新工具。

## 📄 License

Apache 2.0

---

**作者**: Solo
**版本**: 1.0.0
**插件类型**: Python
**支持平台**: macOS, Linux
