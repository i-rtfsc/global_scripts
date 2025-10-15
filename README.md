# Global Scripts

[中文](README.md) | [English](README_EN.md)

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-5.0.0-brightgreen.svg)](https://github.com/i-rtfsc/global_scripts)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

> 一个现代化、高性能的Shell命令管理系统，支持多类型插件架构、异步执行和完整的类型安全。

## 简介

Global Scripts 是一个强大的命令行工具管理框架，旨在简化日常开发工作流程。通过灵活的插件系统，您可以轻松扩展和自定义命令，提高开发效率。

### 为什么选择 Global Scripts？

- **统一管理**: 集中管理所有常用命令和脚本
- **插件化架构**: 支持Python、Shell、Config和混合四种插件类型
- **高性能**: 基于asyncio的异步执行，智能缓存优化
- **类型安全**: 完整的类型注解和数据验证
- **易于扩展**: 简单的插件开发API，快速创建自定义命令
- **开箱即用**: 内置丰富的插件生态，涵盖Android开发、系统管理等场景

## 核心特性

### 架构优势

- **统一数据模型**: 基于`dataclass`的类型安全数据结构
- **多类型插件**: 支持Python、Shell、Config、Hybrid四种插件类型
- **异步优先**: 基于`asyncio`的高性能异步执行引擎
- **Shell直接执行**: Shell插件不经过Python，直接执行Shell命令
- **智能缓存**: 自动缓存插件配置，减少30% I/O开销
- **安全执行**: 命令白名单、超时控制、进程组管理

### 开发体验

- **完整类型注解**: 80%+ 类型注解覆盖率
- **详尽文档**: 从快速入门到架构设计完整文档体系
- **易于测试**: 统一的ProcessExecutor，便于单元测试
- **简单配置**: JSON配置，支持用户/项目级别
- **多语言支持**: 中英文界面无缝切换
- **动态补全**: 基于jq的实时命令补全系统

### 性能特性

- **代码优化**: 消除300+行重复代码
- **智能缓存**: 72%缓存命中率
- **快速加载**: 100个插件<3秒
- **Shell集成**: 自动生成补全和快捷函数

## 快速开始

### 前置要求

- Python 3.8 或更高版本
- Bash、Zsh 或 Fish Shell
- jq (命令补全所需)

### 安装

由于Global Scripts使用UV管理依赖，CLI写死使用UV运行，强烈推荐使用此方式：

```bash
# 1. 安装UV（现代Python项目管理工具）
curl -LsSf https://astral.sh/uv/install.sh | sh

# 2. 克隆项目
git clone https://github.com/i-rtfsc/global_scripts.git
cd global_scripts

# 3. UV自动同步依赖并创建虚拟环境
uv sync

# 4. 运行安装脚本
uv run python scripts/setup.py

# 5. 重新加载Shell配置
source ~/.bashrc   # bash用户
source ~/.zshrc    # zsh用户
```

详细安装说明请查看 [安装指南](./docs/installation.md)

### 验证安装

```bash
# 查看版本
gs version

# 检查系统健康
gs doctor

# 列出插件
gs plugin list

# 测试补全（按Tab键）
gs <Tab>
```

### 基本使用

```bash
# 查看帮助
gs help

# 列出所有插件
gs plugin list

# 查看插件详情
gs plugin info android

# 使用插件命令
gs android logcat clear
gs status
```

## 插件生态

Global Scripts 内置了丰富的插件，覆盖多个开发场景：

### Android 插件

Android开发工具集，包含设备管理、日志查看、应用管理等功能。

```bash
# 查看设备列表
gs android device devices

# 清除logcat
gs android logcat clear

# 查看应用版本
gs android app version com.android.settings
```

### System 插件

系统管理工具，提供配置管理、repo同步等功能。

```bash
# 查看系统状态
gs status

# repo同步管理
gs system repo sync
gs system repo checkout
```

### Grep 插件

高级搜索工具，支持针对不同文件类型的搜索。

```bash
# 查看所有可用的grep命令
gs grep help

# 在C/C++文件中搜索
gs grep c "pattern"

# 在Java文件中搜索
gs grep java "pattern"

# 在Python文件中搜索
gs grep python "pattern"
```

### Spider 插件

网页爬取工具，支持简书、CSDN、博客园等平台。

```bash
# 检查依赖
gs spider check_deps

# 安装依赖
gs spider install_deps

# 爬取简书文章
gs spider jianshu crawl <url_or_username>

# 爬取CSDN文章
gs spider csdn crawl <url_or_username>

# 爬取博客园文章
gs spider cnblogs crawl <url_or_username>
```

更多插件请查看 [CLI命令参考](./docs/cli-reference.md)

## 文档

完整的文档体系帮助您快速上手和深入了解：

- [快速入门](./docs/quickstart.md) - 5分钟掌握基本使用
- [安装指南](./docs/installation.md) - 详细的安装步骤和故障排除
- [CLI命令参考](./docs/cli-reference.md) - 完整的命令行参考
- [插件开发](./docs/plugin-development.md) - 从零开发插件
- [架构设计](./docs/architecture.md) - 深入理解系统架构
- [常见问题](./docs/faq.md) - 问题排查指南
- [贡献指南](./docs/contributing.md) - 如何参与项目贡献

## 示例

### Config插件 - 最简单

创建 `plugins/hello/plugin.json`:

```json
{
  "name": "hello",
  "version": "1.0.0",
  "description": {
    "zh": "问候插件",
    "en": "Hello plugin"
  },
  "type": "json",
  "entry": "commands.json"
}
```

创建 `plugins/hello/commands.json`:

```json
{
  "name": "hello-commands",
  "description": {
    "zh": "Hello 插件命令定义",
    "en": "Hello plugin command definitions"
  },
  "commands": {
    "world": {
      "type": "command",
      "command": "echo 'Hello, World!'",
      "description": {
        "zh": "向世界问好",
        "en": "Say hello to the world"
      },
      "usage": "gs hello world",
      "examples": ["gs hello world"]
    }
  }
}
```

使用: `gs hello world`

### Python插件 - 推荐

创建 `plugins/calc/plugin.json`:

```json
{
  "name": "calc",
  "version": "1.0.0",
  "description": {
    "zh": "计算器插件",
    "en": "Calculator plugin"
  },
  "type": "python",
  "entry": "plugin.py"
}
```

创建 `plugins/calc/plugin.py`:

```python
import sys
from pathlib import Path
from typing import List

# 添加项目根目录到 Python 路径
project_root = Path(__file__).resolve().parents[2]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from gscripts.plugins.base import BasePlugin
from gscripts.plugins.decorators import plugin_function
from gscripts.core.config_manager import CommandResult

class CalcPlugin(BasePlugin):
    def __init__(self):
        self.name = "calc"

    @plugin_function(
        name="add",
        description={"zh": "加法运算", "en": "Addition"},
        usage="gs calc add <num1> <num2>",
        examples=["gs calc add 10 20", "gs calc add 3.5 2.5"]
    )
    async def add(self, args: List[str] = None) -> CommandResult:
        if not args or len(args) < 2:
            return CommandResult(False, error="需要两个数字参数")

        try:
            a, b = float(args[0]), float(args[1])
            return CommandResult(
                success=True,
                output=f"{a} + {b} = {a + b}"
            )
        except ValueError:
            return CommandResult(False, error="参数必须是数字")
```

使用: `gs calc add 10 20`

更多示例查看 [插件开发指南](./docs/plugin-development.md)

## 开发

### 开发自定义插件

Global Scripts 提供了强大而灵活的插件API：

1. **Config插件**: 适合简单的命令封装
2. **Shell插件**: 集成现有Shell脚本
3. **Python插件**: 实现复杂的业务逻辑
4. **Hybrid插件**: 混合使用多种类型

详细开发指南请查看 [插件开发文档](./docs/plugin-development.md)

### 贡献代码

欢迎贡献代码、报告问题或提出建议：

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

详见 [贡献指南](./docs/contributing.md)

## 架构概览

```
global_scripts/
├── src/gscripts/          # 核心代码
│   ├── models/            # 数据模型
│   ├── core/              # 核心模块
│   ├── cli/               # 命令行接口
│   ├── plugins/           # 插件系统
│   └── utils/             # 工具模块
├── plugins/               # 内置插件
│   ├── android/           # Android开发工具
│   ├── system/            # 系统管理工具
│   ├── grep/              # 搜索工具
│   └── spider/            # 爬虫工具
├── custom/                # 自定义插件目录
├── docs/                  # 文档
└── scripts/               # 安装和维护脚本
```

## 性能

| 指标 | 表现 |
|------|------|
| 插件加载(100个) | < 3秒 |
| 命令响应时间 | < 100ms |
| 缓存命中率 | 72% |
| 内存占用 | < 50MB |
| 类型注解覆盖 | 80%+ |

## 许可证

本项目采用 Apache-2.0 许可证。详见 [LICENSE](LICENSE) 文件。

## 致谢

感谢所有贡献者对本项目的支持和贡献！

## 链接

- [GitHub 仓库](https://github.com/i-rtfsc/global_scripts)
- [问题追踪](https://github.com/i-rtfsc/global_scripts/issues)
- [更新日志](./docs/changelog.md)
- [文档中心](./docs/)

---

**开始使用**: [快速入门指南](./docs/quickstart.md)

**需要帮助**: [常见问题](./docs/faq.md) | [提交Issue](https://github.com/i-rtfsc/global_scripts/issues)
