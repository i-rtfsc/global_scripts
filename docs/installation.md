# Global Scripts - 安装指南

## 📋 目录

- [系统要求](#系统要求)
- [依赖说明](#依赖说明)
- [安装步骤](#安装步骤)
- [Shell环境配置](#shell环境配置)
- [验证安装](#验证安装)
- [可选功能安装](#可选功能安装)
- [故障排除](#故障排除)

---

## 系统要求

### 必需要求

- **Python**: 3.8 或更高版本
- **UV**: Python项目管理工具（必须）
- **操作系统**: macOS, Linux (Windows WSL2)
- **Shell**: bash, zsh, 或 fish
- **jq**: JSON处理工具（补全系统核心依赖）

#### 安装jq

```bash
# macOS (Homebrew)
brew install jq

# Ubuntu/Debian
sudo apt-get install jq

# Arch Linux
sudo pacman -S jq

# CentOS/RHEL
sudo yum install jq
```

**说明**:
- **jq**: 动态补全系统的核心依赖，用于实时读取plugin配置
- Global Scripts的补全是最实用的功能，jq为必装工具

---

## 依赖说明

### ✅ 核心依赖

Global Scripts 有3个必需的Python依赖（不是零依赖）：

- **PyYAML**: 用于解析 `system_config.yaml` 配置文件
- **Jinja2**: 用于模板引擎，生成 `env.sh` / `env.fish` 环境文件
- **aiofiles**: 用于异步文件I/O性能优化（有同步fallback）

这些依赖会在运行 `uv sync` 时自动安装。

### 可选依赖

| 依赖包 | 用途 | 是否必需 | 安装方式 |
|--------|------|----------|----------|
| `requests` | Spider插件HTTP请求 | ❌ 仅Spider插件需要 | `gs spider install_deps` |
| `beautifulsoup4` | Spider插件HTML解析 | ❌ 仅Spider插件需要 | `gs spider install_deps` |
| `markdownify` | Spider插件格式转换 | ❌ 仅Spider插件需要 | `gs spider install_deps` |
| `selenium` | Spider插件动态页面 | ❌ 仅Spider插件需要 | `gs spider install_deps` |
| `parsel` | Spider插件选择器 | ❌ 仅Spider插件需要 | `gs spider install_deps` |

---

## 安装步骤

**重要提示**：Global Scripts 的 CLI 写死使用 UV 运行（`uv run`），因此 UV 是必需的依赖项。

### 1. 安装 UV

```bash
# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# 或使用 pip 安装
pip install uv
```

### 2. 克隆仓库

```bash
git clone https://github.com/i-rtfsc/global_scripts.git
cd global_scripts
```

### 3. 同步依赖

```bash
# UV 会自动读取 pyproject.toml 并创建虚拟环境
uv sync
```

### 4. 运行安装脚本

```bash
# 使用 UV 运行安装脚本，配置 shell 环境
uv run python scripts/setup.py
```

### 5. 重新加载 Shell 配置

```bash
# Bash 用户
source ~/.bashrc

# Zsh 用户
source ~/.zshrc

# Fish 用户
source ~/.config/fish/config.fish
```

---

## Shell环境配置

安装完成后，安装脚本会自动配置你的Shell环境。如需手动配置：

### Bash

编辑 `~/.bashrc`:

```bash
# Global Scripts
export GS_ROOT="$HOME/.config/global-scripts"
source "$GS_ROOT/env.sh"

# 启用补全（如果已安装jq）
if command -v jq &>/dev/null; then
    source "$GS_ROOT/completions/gs.bash"
fi
```

### Zsh

编辑 `~/.zshrc`:

```bash
# Global Scripts
export GS_ROOT="$HOME/.config/global-scripts"
source "$GS_ROOT/env.sh"

# 启用补全（如果已安装jq）
if command -v jq &>/dev/null; then
    source "$GS_ROOT/completions/gs.zsh"
fi
```

### Fish

编辑 `~/.config/fish/config.fish`:

```fish
# Global Scripts
set -gx GS_ROOT "$HOME/.config/global-scripts"
source "$GS_ROOT/env.fish"

# 启用补全（如果已安装jq）
if command -q jq
    source "$GS_ROOT/completions/gs.fish"
end
```

---

## 验证安装

运行以下命令验证安装成功：

```bash
# 检查版本
gs version

# 检查系统健康状态
gs doctor

# 列出已安装的插件
gs plugin list

# 测试补全（按Tab键）
gs <Tab>
gs android <Tab>
gs system <Tab>
```

预期输出：

```
Global Scripts 1.0.0
Python: 3.x.x
Shell: bash/zsh/fish
Status: ✅ All systems operational
```

---

## 可选功能安装

### 性能优化（可选）

如需进一步的性能优化，可以安装额外的优化包：

```bash
# 安装 performance 组（如有定义）
uv pip install -e ".[performance]"
```

### Spider插件依赖

如果需要使用Spider插件爬取网页：

```bash
# 方式1: 使用gs命令自动安装
gs spider install_deps

# 方式2: 使用uv手动安装
uv pip install requests beautifulsoup4 markdownify selenium parsel

# 方式3: 安装完整功能
uv pip install -e ".[full]"
```

### 开发工具

如果需要参与开发：

```bash
# 安装开发依赖
uv sync --group dev

# 安装pre-commit hooks
pre-commit install
```

### UV 常用命令

```bash
# 同步依赖（根据pyproject.toml）
uv sync

# 安装开发依赖
uv sync --group dev

# 添加新依赖
uv add package_name

# 运行脚本
uv run python script.py

# 更新所有依赖
uv sync --upgrade

# 安装可选依赖组
uv pip install -e ".[performance]"  # 性能优化
uv pip install -e ".[full]"         # 完整功能
uv pip install -e ".[dev]"          # 开发工具
```

---

## 故障排除

### 问题1: 命令找不到 `gs: command not found`

**原因**: Shell环境未正确配置

**解决**:
```bash
# 检查环境变量
echo $GS_ROOT

# 如果为空，重新加载配置
source ~/.bashrc  # 或 ~/.zshrc

# 确认env.sh存在
ls -la ~/.config/global-scripts/env.sh
```

### 问题2: Python版本过低

**原因**: Python < 3.8

**解决**:
```bash
# 检查Python版本
python3 --version

# 升级Python（macOS）
brew install python@3.11

# 升级Python（Ubuntu）
sudo apt-get install python3.11
```

### 问题3: 补全不工作

**原因**: jq未安装或补全文件未加载

**解决**:
```bash
# 1. 安装jq
brew install jq  # macOS
sudo apt-get install jq  # Ubuntu

# 2. 重新生成补全文件
uv run python scripts/setup.py

# 3. 重新加载shell配置
source ~/.bashrc  # 或 ~/.zshrc
```

### 问题4: UV sync失败

**原因**: 网络问题或UV版本过旧

**解决**:
```bash
# 更新UV
pip install --upgrade uv

# 使用国内镜像（如果在中国）
uv sync --index-url https://pypi.tuna.tsinghua.edu.cn/simple

# 清除缓存重试
uv cache clean
uv sync
```

### 问题5: 插件加载失败

**原因**: plugin.json格式错误或缺失

**解决**:
```bash
# 检查插件状态
gs plugin list

# 查看详细错误
gs doctor

# 刷新插件索引
gs refresh

# 验证plugin.json格式
python3 -m json.tool plugins/android/plugin.json
```

---

## 下一步

安装完成后，查看以下文档继续使用：

- 📖 [快速开始](./quickstart.md) - 5分钟入门教程
- 🔌 [插件开发](./plugin-development.md) - 创建自己的插件
- 🎯 [命令参考](./cli-reference.md) - 完整命令列表
- ❓ [常见问题](./faq.md) - 问题排查指南

---

## 获取帮助

遇到问题？以下资源可以帮助你：

- 💬 [GitHub Issues](https://github.com/i-rtfsc/global_scripts/issues)
- 📚 [在线文档](https://github.com/i-rtfsc/global_scripts/tree/main/docs)
- ❓ 运行 `gs help` 获取内置帮助

