# 贡献指南

感谢您考虑为 Global Scripts 贡献！

[中文](contributing.md) | [English](contributing_EN.md)

## 目录

- [行为准则](#行为准则)
- [如何贡献](#如何贡献)
- [开发环境设置](#开发环境设置)
- [代码规范](#代码规范)
- [提交规范](#提交规范)
- [Pull Request流程](#pull-request流程)
- [插件贡献](#插件贡献)
- [文档贡献](#文档贡献)
- [Bug报告](#bug报告)
- [功能请求](#功能请求)

## 行为准则

### 我们的承诺

为了营造开放和友好的环境，我们承诺：

- 尊重不同的观点和经验
- 优雅地接受建设性批评
- 关注对社区最有利的事情
- 对其他社区成员表示同理心

### 不可接受的行为

- 使用性化的语言或图像
- 人身攻击或侮辱性评论
- 公开或私下骚扰
- 未经许可发布他人私人信息
- 其他不道德或不专业的行为

## 如何贡献

### 贡献类型

我们欢迎以下类型的贡献：

- **代码**: 修复bug、新功能、性能优化
- **插件**: 新的插件或改进现有插件
- **文档**: 改进文档、添加示例、修正错误
- **测试**: 增加测试覆盖率
- **Bug报告**: 报告问题和错误
- **功能请求**: 建议新功能
- **代码审查**: 审查其他人的PR

### 开始贡献

1. **Fork仓库**: 在GitHub上Fork本项目
2. **Clone到本地**: `git clone https://github.com/YOUR_USERNAME/global_scripts.git`
3. **创建分支**: `git checkout -b feature/your-feature-name`
4. **进行更改**: 编写代码、测试、文档
5. **提交更改**: `git commit -m "Add some feature"`
6. **推送到GitHub**: `git push origin feature/your-feature-name`
7. **创建Pull Request**: 在GitHub上创建PR

## 开发环境设置

### 前置要求

- Python 3.8+
- Git
- UV (推荐)
- jq (用于测试补全)

### 安装步骤

```bash
# 1. Clone仓库
git clone https://github.com/i-rtfsc/global_scripts.git
cd global_scripts

# 2. 安装UV（如果未安装）
curl -LsSf https://astral.sh/uv/install.sh | sh

# 3. 创建虚拟环境并安装依赖
uv sync --group dev

# 4. 激活虚拟环境
source .venv/bin/activate

# 5. 安装pre-commit hooks
pre-commit install

# 6. 运行安装脚本
python3 scripts/setup.py
```

### 验证安装

```bash
# 运行测试
pytest tests/ -v

# 检查代码风格
ruff check src/

# 类型检查
mypy src/

# 运行gs命令
gs version
gs doctor
```

## 代码规范

### Python代码风格

我们遵循 [PEP 8](https://pep8.org/) 和项目特定规范：

#### 1. 格式化

使用 **Black** 进行代码格式化：

```bash
# 格式化所有代码
black src/ tests/

# 检查格式
black --check src/ tests/
```

#### 2. Linting

使用 **Ruff** 进行代码检查：

```bash
# 检查代码
ruff check src/

# 自动修复
ruff check --fix src/
```

#### 3. 类型注解

使用 **MyPy** 进行类型检查：

```bash
mypy src/
```

**要求**:
- 所有公共函数必须有类型注解
- 使用typing模块的类型
- 复杂类型使用TypeAlias

示例：

```python
from typing import List, Dict, Optional
from gscripts.models import CommandResult

def execute_command(
    command: str,
    args: List[str],
    timeout: int = 30
) -> CommandResult:
    """执行命令

    Args:
        command: 命令名称
        args: 参数列表
        timeout: 超时时间（秒）

    Returns:
        命令执行结果
    """
    pass
```

#### 4. 文档字符串

使用 **Google风格** 文档字符串：

```python
def complex_function(param1: str, param2: int) -> Dict[str, Any]:
    """一行简短描述。

    更详细的描述，可以多行。

    Args:
        param1: 参数1的描述
        param2: 参数2的描述

    Returns:
        返回值的描述

    Raises:
        ValueError: 参数无效时抛出

    Examples:
        >>> complex_function("test", 42)
        {"result": "success"}
    """
    pass
```

#### 5. 命名规范

- **模块和包**: `lowercase_with_underscores`
- **类**: `CapitalizedWords`
- **函数和变量**: `lowercase_with_underscores`
- **常量**: `UPPERCASE_WITH_UNDERSCORES`
- **私有成员**: `_leading_underscore`

#### 6. 导入顺序

```python
# 1. 标准库
import os
import sys
from pathlib import Path

# 2. 第三方库
import aiofiles
from jinja2 import Template

# 3. 本地模块
from gscripts.models import CommandResult
from gscripts.core import PluginManager
```

### Shell脚本规范

#### 1. Shebang

```bash
#!/usr/bin/env bash
```

#### 2. 严格模式

```bash
set -euo pipefail
```

#### 3. 函数定义

```bash
# 好的做法
function_name() {
    local arg1="$1"
    local arg2="$2"

    # 参数验证
    if [[ -z "$arg1" ]]; then
        echo "Error: arg1 is required" >&2
        return 1
    fi

    # 函数逻辑
    echo "Processing..."
}
```

#### 4. 注释

```bash
# @plugin_function
# name: function-name
# description: Clear description
# usage: gs plugin function-name <args>

function_name() {
    # 实现
}
```

### JSON规范

#### 1. 格式化

使用2空格缩进：

```json
{
  "name": "plugin-name",
  "version": "1.0.0",
  "description": {
    "zh": "中文描述",
    "en": "English description"
  }
}
```

#### 2. 必需字段

plugin.json必须包含：

```json
{
  "name": "string (required)",
  "version": "string (required)",
  "description": "string or i18n object (required)",
  "author": "string (optional)",
  "enabled": "boolean (optional, default: true)"
}
```

## 提交规范

### Commit Message格式

使用 [Conventional Commits](https://www.conventionalcommits.org/) 规范：

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Type类型

- `feat`: 新功能
- `fix`: Bug修复
- `docs`: 文档更新
- `style`: 代码格式（不影响功能）
- `refactor`: 重构
- `perf`: 性能优化
- `test`: 测试相关
- `chore`: 构建/工具相关
- `ci`: CI配置

### 示例

```
feat(android): add device screenshot command

Add a new command to capture device screenshots with
optional file path parameter.

Closes #123
```

```
fix(plugin-loader): handle missing plugin.json gracefully

Previously, the loader would crash if plugin.json was missing.
Now it logs a warning and skips the plugin.

Fixes #456
```

### Commit最佳实践

- 每个commit做一件事
- 使用现在时态："Add feature" 而非 "Added feature"
- 首字母小写
- 不要以句号结尾
- Body部分解释"为什么"而非"是什么"
- 引用相关Issue

## Pull Request流程

### 创建PR前

1. **确保代码通过所有检查**:

```bash
# 运行测试
pytest tests/ -v

# 代码格式化
black src/ tests/

# Linting
ruff check --fix src/

# 类型检查
mypy src/
```

2. **更新文档**:
   - 如果添加了新功能，更新README和相关文档
   - 添加docstring
   - 更新CHANGELOG.md

3. **编写测试**:
   - 新功能必须有测试
   - Bug修复需要添加回归测试
   - 目标：保持80%+覆盖率

### PR模板

创建PR时请包含：

```markdown
## 描述
简要描述此PR的目的和内容。

## 类型
- [ ] Bug修复
- [ ] 新功能
- [ ] 重构
- [ ] 文档更新
- [ ] 其他（请说明）

## 更改内容
- 详细列出所有更改
- 使用清单列表

## 测试
- [ ] 添加了新的测试
- [ ] 所有测试通过
- [ ] 手动测试通过

## 文档
- [ ] 更新了README
- [ ] 更新了相关文档
- [ ] 添加了docstring

## 截图（如适用）
添加截图或录屏

## 相关Issue
Closes #issue_number
```

### PR审查流程

1. **自动检查**: CI会自动运行测试和代码检查
2. **人工审查**: 维护者会审查代码
3. **反馈**: 根据反馈进行修改
4. **合并**: 审查通过后合并到main分支

### 审查标准

- 代码风格符合规范
- 测试充分且通过
- 文档完整
- 没有破坏性更改（或已明确说明）
- 性能影响可接受
- 安全性考虑

## 插件贡献

### 新插件清单

- [ ] `plugin.json` 格式正确且完整
- [ ] 包含中英文描述
- [ ] 版本号遵循SemVer
- [ ] 所有函数有文档
- [ ] 添加使用示例
- [ ] 编写测试
- [ ] 添加README.md
- [ ] 添加LICENSE（如果是独立插件）

### 插件目录结构

```
plugins/yourplugin/
├── plugin.json          # 必需：插件元数据
├── README.md            # 推荐：插件文档
├── plugin.py            # Python插件
├── utils.sh             # Shell脚本
├── tests/               # 测试
│   └── test_yourplugin.py
└── docs/                # 详细文档（可选）
    └── guide.md
```

### 插件示例

参考现有插件：

- `plugins/android/` - 复杂插件示例
- `plugins/system/` - 系统级插件
- `examples/python-simple/` - 简单Python插件
- `examples/config-simple/` - Config插件

## 文档贡献

### 文档类型

- **用户文档**: README, 快速开始, 使用指南
- **开发者文档**: 架构设计, API参考, 插件开发
- **维护文档**: 贡献指南, 发布流程

### 文档规范

1. **使用Markdown**
2. **提供中英文版本**
3. **包含代码示例**
4. **添加目录（长文档）**
5. **链接相关文档**

### 文档检查清单

- [ ] 无拼写错误
- [ ] 代码示例可运行
- [ ] 截图清晰且最新
- [ ] 链接有效
- [ ] 格式一致
- [ ] 适当的标题层级

## Bug报告

### Bug报告模板

```markdown
## 描述
清晰简洁地描述bug。

## 复现步骤
1. 执行 '...'
2. 点击 '....'
3. 滚动到 '....'
4. 看到错误

## 预期行为
描述应该发生什么。

## 实际行为
描述实际发生了什么。

## 环境
- OS: [e.g. macOS 13.0]
- Python版本: [e.g. 3.11.0]
- Global Scripts版本: [e.g. 5.0.0]
- Shell: [e.g. bash 5.1]

## 日志
粘贴相关日志输出。

## 截图
如果适用，添加截图。

## 额外信息
其他相关信息。
```

### Bug报告最佳实践

- 搜索现有Issues，避免重复
- 使用清晰的标题
- 提供最小可复现示例
- 包含完整的错误信息
- 说明影响范围

## 功能请求

### 功能请求模板

```markdown
## 问题描述
这个功能解决什么问题？

## 建议的解决方案
详细描述你想要的功能。

## 替代方案
描述你考虑过的替代方案。

## 附加信息
其他相关信息或截图。

## 愿意贡献
- [ ] 我愿意实现这个功能
- [ ] 我愿意帮助测试
- [ ] 我愿意编写文档
```

### 功能请求指南

- 解释使用场景
- 说明为什么重要
- 考虑向后兼容性
- 提供示例
- 讨论实现方案

## 发布流程

### 版本号

遵循 [语义化版本](https://semver.org/):

- **MAJOR**: 不兼容的API更改
- **MINOR**: 向后兼容的新功能
- **PATCH**: 向后兼容的Bug修复

### 发布清单

- [ ] 更新版本号（VERSION文件）
- [ ] 更新CHANGELOG.md
- [ ] 运行完整测试套件
- [ ] 更新文档
- [ ] 创建Git tag
- [ ] 推送到GitHub
- [ ] 创建GitHub Release
- [ ] 发布公告

## 获取帮助

### 沟通渠道

- **GitHub Issues**: 报告问题、功能请求
- **GitHub Discussions**: 一般讨论、问题
- **Pull Requests**: 代码审查

### 联系维护者

- 创建Issue或Discussion
- 在PR中提及 `@maintainer`
- 查看 [README](../README.md) 中的联系方式

## 致谢

感谢所有贡献者！您的贡献让 Global Scripts 变得更好。

贡献者列表：[CONTRIBUTORS.md](./CONTRIBUTORS.md)

---

**准备好贡献了吗？** 查看 [Good First Issues](https://github.com/i-rtfsc/global_scripts/labels/good%20first%20issue)

**返回**: [文档首页](./README.md)
