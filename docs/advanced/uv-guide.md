# UV 使用指南

本文档介绍如何使用UV管理Global Scripts项目。

## 什么是UV？

[UV](https://github.com/astral-sh/uv) 是由Astral（Ruff的作者）开发的**极快的Python包管理器**，用Rust编写，比pip快10-100倍。

### 为什么使用UV？

- ⚡ **极快**: 比pip快10-100倍
- 🔒 **锁定依赖**: 自动生成`uv.lock`确保可重现构建
- 🎯 **现代化**: 支持PEP 621、PEP 660等最新标准
- 🛠️ **多功能**: 包管理、虚拟环境、项目管理一体化
- 🌍 **跨平台**: Windows, macOS, Linux全支持

---

## 安装UV

### 方式1: 官方安装脚本（推荐）

```bash
# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# 或使用wget
wget -qO- https://astral.sh/uv/install.sh | sh
```

### 方式2: 使用pip

```bash
pip install uv
```

### 方式3: 使用包管理器

```bash
# macOS (Homebrew)
brew install uv

# Arch Linux
pacman -S uv
```

### 验证安装

```bash
uv --version
# 输出: uv 0.x.x
```

---

## 快速开始

### 1. 初始化项目

```bash
# 克隆项目
git clone https://github.com/i-rtfsc/global_scripts.git
cd global_scripts

# UV会自动读取pyproject.toml
# 同步依赖（创建.venv并安装依赖）
uv sync
```

这会：
1. 创建`.venv`虚拟环境
2. 根据`pyproject.toml`安装依赖
3. 生成`uv.lock`锁定文件

### 2. 激活虚拟环境

```bash
# macOS/Linux
source .venv/bin/activate

# Windows
.venv\Scripts\activate

# 或使用uv run直接运行（不需要激活）
uv run python script.py
```

### 3. 安装项目（可编辑模式）

```bash
# 安装基础版本
uv pip install -e .

# 安装性能优化版本
uv pip install -e ".[performance]"

# 安装完整功能（包括Spider）
uv pip install -e ".[full]"

# 安装开发工具
uv sync --group dev
```

---

## 常用命令

### 依赖管理

```bash
# 同步依赖（根据pyproject.toml和uv.lock）
uv sync

# 同步并包含开发依赖
uv sync --group dev

# 添加新依赖
uv add package_name

# 添加开发依赖
uv add --dev package_name

# 移除依赖
uv remove package_name

# 更新所有依赖
uv sync --upgrade

# 更新特定依赖
uv add --upgrade package_name
```

### 运行脚本

```bash
# 在虚拟环境中运行脚本（不需要activate）
uv run python script.py

# 运行gs命令
uv run gs version

# 运行测试
uv run pytest
```

### 虚拟环境管理

```bash
# 创建虚拟环境
uv venv

# 指定Python版本
uv venv --python 3.11

# 删除虚拟环境
rm -rf .venv

# 重新创建
uv sync
```

### 包安装

```bash
# 安装包（等价于pip install）
uv pip install package_name

# 从requirements.txt安装
uv pip install -r requirements.txt

# 查看已安装的包
uv pip list

# 卸载包
uv pip uninstall package_name
```

---

## Global Scripts特定用法

### 基础安装

```bash
# 1. 同步依赖
uv sync

# 2. 安装项目（可编辑模式）
uv pip install -e .

# 3. 运行安装脚本
uv run python scripts/setup.py
```

### 安装可选功能

```bash
# 性能优化（安装aiofiles）
uv pip install -e ".[performance]"

# Spider插件
uv pip install -e ".[spider]"

# 完整功能
uv pip install -e ".[full]"

# 开发工具
uv sync --group dev
```

### 开发流程

```bash
# 1. 安装开发依赖
uv sync --group dev

# 2. 运行测试
uv run pytest

# 3. 代码格式化
uv run black src/

# 4. 代码检查
uv run ruff check src/

# 5. 类型检查
uv run mypy src/
```

### 添加新插件依赖

如果你的插件需要特定的Python包：

```bash
# 添加到项目依赖
uv add package_name

# 或添加为可选依赖（推荐）
# 手动编辑 pyproject.toml:
# [project.optional-dependencies]
# myplugin = ["package_name>=1.0.0"]

# 然后同步
uv sync
```

---

## pyproject.toml 配置说明

Global Scripts的`pyproject.toml`结构：

```toml
[project]
name = "global-scripts"
version = "6.0.0"
requires-python = ">=3.8"

# 核心依赖 - 3个必需依赖
dependencies = [
    "PyYAML>=6.0.1",
    "Jinja2>=3.1.2",
    "aiofiles>=0.8.0,<1.0",
]

[project.optional-dependencies]
# 性能优化
performance = ["aiofiles>=0.8.0,<1.0"]

# Spider插件
spider = [
    "requests>=2.25.0,<3.0",
    "beautifulsoup4>=4.9.0,<5.0",
    # ...
]

# 开发工具
dev = [
    "pytest>=7.0.0,<8.0",
    "black>=22.0.0,<25.0",
    # ...
]

# UV专用配置
[tool.uv]
dev-dependencies = [
    "pytest>=7.0.0,<8.0",
    # ...
]
```

### 安装可选依赖组

```bash
# 安装单个组
uv pip install -e ".[performance]"
uv pip install -e ".[spider]"
uv pip install -e ".[dev]"

# 安装多个组
uv pip install -e ".[performance,spider]"

# 安装全部
uv pip install -e ".[full]"
```

---

## UV vs PIP对比

| 功能 | UV | PIP |
|------|----|----|
| 速度 | ⚡️ 10-100倍 | 🐢 慢 |
| 锁定文件 | ✅ uv.lock | ❌ 需要pip-tools |
| 虚拟环境 | ✅ 内置 | 需要venv |
| 依赖解析 | ✅ 快速 | 🐢 慢 |
| 缓存 | ✅ 智能 | ⚠️  基础 |
| 平台支持 | ✅ 全平台 | ✅ 全平台 |

### 命令对照表

| 操作 | PIP | UV |
|------|-----|-----|
| 安装包 | `pip install package` | `uv pip install package` |
| 卸载包 | `pip uninstall package` | `uv pip uninstall package` |
| 列出包 | `pip list` | `uv pip list` |
| 冻结依赖 | `pip freeze > requirements.txt` | `uv pip freeze > requirements.txt` |
| 安装requirements | `pip install -r requirements.txt` | `uv pip install -r requirements.txt` |
| 创建虚拟环境 | `python -m venv .venv` | `uv venv` |
| 安装项目 | `pip install -e .` | `uv pip install -e .` |

---

## 高级用法

### 使用国内镜像

```bash
# 临时使用
uv pip install package --index-url https://pypi.tuna.tsinghua.edu.cn/simple

# 或设置环境变量
export UV_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple
uv sync
```

### 缓存管理

```bash
# 查看缓存大小
uv cache dir

# 清除缓存
uv cache clean

# 清除特定包缓存
uv cache clean package_name
```

### 指定Python版本

```bash
# 使用特定Python版本创建环境
uv venv --python 3.11
uv venv --python 3.12

# 使用pyenv的Python
uv venv --python $(pyenv which python3.11)
```

### 锁定文件

```bash
# 生成/更新uv.lock
uv sync

# 仅更新锁定文件（不安装）
uv lock

# 从锁定文件安装（确保可重现）
uv sync --frozen
```

---

## 故障排除

### 问题1: uv: command not found

**解决**:
```bash
# 重新安装
curl -LsSf https://astral.sh/uv/install.sh | sh

# 添加到PATH（通常会自动添加）
export PATH="$HOME/.cargo/bin:$PATH"

# 或重新加载shell
source ~/.bashrc   # bash用户
source ~/.zshrc    # zsh用户
source ~/.config/fish/config.fish  # fish用户
```

### 问题2: 依赖解析失败

**解决**:
```bash
# 清除缓存
uv cache clean

# 重新同步
uv sync

# 如果还是失败，检查pyproject.toml格式
python3 -m json.tool < pyproject.toml
```

### 问题3: 虚拟环境未激活

**解决**:
```bash
# 方案1: 手动激活
source .venv/bin/activate

# 方案2: 使用uv run（推荐）
uv run python script.py
```

### 问题4: 安装速度慢

**原因**: 网络问题

**解决**:
```bash
# 使用国内镜像
export UV_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple
uv sync

# 或清华镜像
export UV_INDEX_URL=https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple
uv sync
```

---

## 最佳实践

### 1. 使用uv run避免激活环境

```bash
# 不推荐
source .venv/bin/activate
python script.py

# 推荐
uv run python script.py
```

### 2. 锁定依赖确保可重现

```bash
# 开发时
uv sync  # 生成uv.lock

# 生产部署
uv sync --frozen  # 使用锁定的版本
```

### 3. 分组管理可选依赖

```toml
[project.optional-dependencies]
# 按功能分组
performance = [...]
spider = [...]
dev = [...]

# 组合使用
uv pip install -e ".[performance,spider]"
```

### 4. 使用.python-version固定Python版本

```bash
# 创建.python-version文件
echo "3.11" > .python-version

# UV会自动使用这个版本
uv venv
```

---

## 参考资源

- 📚 [UV官方文档](https://github.com/astral-sh/uv)
- 🚀 [UV发布公告](https://astral.sh/blog/uv)
- 📖 [PEP 621 (pyproject.toml)](https://peps.python.org/pep-0621/)
- 🔧 [Global Scripts文档](../README.md)

---

## 下一步

- 📖 [安装指南](INSTALLATION.md) - 详细安装步骤
- 🔌 [插件开发](PLUGIN_DEVELOPMENT.md) - 开发自己的插件
- ⚙️  [配置指南](CONFIGURATION.md) - 自定义配置
