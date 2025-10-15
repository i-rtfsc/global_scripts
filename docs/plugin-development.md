# 插件开发指南

完整的插件开发教程,从基础到进阶。

## 插件类型选择

Global Scripts 支持4种插件类型:

| 类型 | 适用场景 | 开发难度 | 灵活性 |
|------|---------|---------|-------|
| **Config** | 简单命令封装 | ⭐ | ⭐⭐ |
| **Shell** | Shell脚本集成 | ⭐⭐ | ⭐⭐⭐ |
| **Python** | 复杂逻辑处理 | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Hybrid** | 混合需求 | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |

## 快速开始:创建第一个插件

### 1. Config插件 (最简单)

**适用场景**: 封装已有命令

```bash
mkdir -p plugins/hello
cd plugins/hello
```

创建 `plugin.json`:
```json
{
  "name": "hello",
  "version": "1.0.0",
  "author": "Your Name",
  "description": {
    "zh": "问候插件",
    "en": "Hello plugin"
  },
  "type": "json",
  "entry": "commands.json",
  "enabled": true
}
```

创建 `commands.json`:
```json
{
  "name": "hello-commands",
  "description": {
    "zh": "Hello插件命令定义",
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
      "usage": "gs hello world"
    },
    "name": {
      "type": "command",
      "command": "echo 'Hello, {args}!'",
      "description": {
        "zh": "向指定对象问好",
        "en": "Say hello to someone"
      },
      "usage": "gs hello name <name>"
    }
  }
}
```

**使用**:
```bash
gs hello world
# 输出: Hello, World!

gs hello name Alice
# 输出: Hello, Alice!
```

### 2. Shell插件

**适用场景**: 需要Shell脚本逻辑

创建 `plugin.json`:
```json
{
  "name": "system-info",
  "version": "1.0.0",
  "author": "Your Name",
  "description": {
    "zh": "系统信息工具",
    "en": "System information utilities"
  },
  "enabled": true,
  "subplugins": [
    {
      "name": "hardware",
      "type": "shell",
      "entry": "info.sh",
      "description": {
        "zh": "硬件信息查询",
        "en": "Hardware information"
      }
    },
    {
      "name": "network",
      "type": "shell",
      "entry": "network.sh",
      "description": {
        "zh": "网络信息查询",
        "en": "Network information"
      }
    }
  ]
}
```

创建 `hardware/info.sh`:
```bash
#!/bin/bash

# @plugin_function
# name: cpu
# description:
#   zh: 显示CPU信息
#   en: Show CPU information
# usage: gs system-info hardware cpu
# examples:
#   - gs system-info hardware cpu

cpu() {
    if [[ "$(uname)" == "Darwin" ]]; then
        sysctl -n machdep.cpu.brand_string
    else
        cat /proc/cpuinfo | grep "model name" | head -1 | cut -d: -f2
    fi
}

# @plugin_function
# name: memory
# description:
#   zh: 显示内存信息
#   en: Show memory information
# usage: gs system-info hardware memory
# examples:
#   - gs system-info hardware memory

memory() {
    if [[ "$(uname)" == "Darwin" ]]; then
        vm_stat | head -5
    else
        free -h
    fi
}

# Shell注解函数路由
case "$1" in
    cpu) cpu ;;
    memory) memory ;;
    *) echo "Unknown command: $1" >&2; exit 1 ;;
esac
```

**使用**:
```bash
gs system-info hardware cpu
gs system-info hardware memory
```

### 3. Python插件 (推荐)

**适用场景**: 复杂逻辑、API调用、数据处理

创建 `plugin.json`:
```json
{
  "name": "calculator",
  "version": "1.0.0",
  "author": "Your Name",
  "description": {
    "zh": "计算器插件",
    "en": "Calculator plugin"
  },
  "type": "python",
  "entry": "plugin.py",
  "enabled": true
}
```

创建 `plugin.py`:
```python
#!/usr/bin/env python3
"""计算器插件"""

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


class CalculatorPlugin(BasePlugin):
    def __init__(self):
        self.name = "calculator"

    @plugin_function(
        name="add",
        description={"zh": "加法运算", "en": "Addition"},
        usage="gs calculator add <a> <b>",
        examples=[
            "gs calculator add 10 20",
            "gs calculator add 3.5 2.5"
        ]
    )
    async def add(self, args: List[str] = None) -> CommandResult:
        """加法运算"""
        if not args or len(args) < 2:
            return CommandResult(False, error="需要两个数字参数")

        try:
            a, b = float(args[0]), float(args[1])
            result = a + b
            return CommandResult(
                success=True,
                output=f"{a} + {b} = {result}"
            )
        except ValueError:
            return CommandResult(False, error="参数必须是数字")

    @plugin_function(
        name="multiply",
        description={"zh": "乘法运算", "en": "Multiplication"},
        usage="gs calculator multiply <a> <b>",
        examples=[
            "gs calculator multiply 5 6",
            "gs calculator multiply 2.5 4"
        ]
    )
    async def multiply(self, args: List[str] = None) -> CommandResult:
        """乘法运算"""
        if not args or len(args) < 2:
            return CommandResult(False, error="需要两个数字参数")

        try:
            a, b = float(args[0]), float(args[1])
            result = a * b
            return CommandResult(
                success=True,
                output=f"{a} × {b} = {result}"
            )
        except ValueError:
            return CommandResult(False, error="参数必须是数字")
```

**使用**:
```bash
gs calculator add 10 20
# 输出: 10.0 + 20.0 = 30.0

gs calculator multiply 5 6
# 输出: 5.0 × 6.0 = 30.0
```

## 高级功能

### 1. 子插件组织

对于复杂插件,使用子插件结构:

```
plugins/dev-tools/
├── plugin.json          # 主配置
├── git/                 # git子插件
│   ├── plugin.py
│   └── utils.sh
├── docker/              # docker子插件
│   └── plugin.py
└── kubernetes/          # k8s子插件
    └── plugin.py
```

`plugin.json`:
```json
{
  "name": "dev-tools",
  "version": "1.0.0",
  "description": {
    "zh": "开发工具集",
    "en": "Development tools"
  },
  "subplugins": [
    {
      "name": "git",
      "type": "python",
      "entry": "plugin.py",
      "description": {
        "zh": "Git版本控制",
        "en": "Git version control"
      }
    },
    {
      "name": "docker",
      "type": "python",
      "entry": "plugin.py",
      "description": {
        "zh": "Docker容器管理",
        "en": "Docker container management"
      }
    },
    {
      "name": "kubernetes",
      "type": "python",
      "entry": "plugin.py",
      "description": {
        "zh": "Kubernetes集群管理",
        "en": "Kubernetes cluster management"
      }
    }
  ]
}
```

### 2. 使用Python装饰器(面向对象)

```python
import sys
from pathlib import Path

# 添加项目根目录到 Python 路径
project_root = Path(__file__).resolve().parents[2]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from gscripts.plugins.base import BasePlugin
from gscripts.plugins.decorators import plugin_function
from gscripts.core.config_manager import CommandResult


class GitPlugin(BasePlugin):
    """Git工具子插件"""

    def __init__(self):
        super().__init__()
        self.config = self.load_config()

    @plugin_function(
        name="status",
        description={"zh": "查看仓库状态", "en": "Show repository status"},
        usage="gs dev-tools git status",
        examples=[
            "gs dev-tools git status",
            "gs dev-tools git status --short"
        ]
    )
    async def git_status(self, args):
        """执行git status"""
        return await self.execute_command("git status")

    @plugin_function(
        name="branches",
        description={"zh": "列出所有分支", "en": "List all branches"},
        usage="gs dev-tools git branches",
        examples=[
            "gs dev-tools git branches",
            "gs dev-tools git branches --remote"
        ]
    )
    async def list_branches(self, args):
        """列出分支"""
        result = await self.execute_command("git branch -a")
        # 处理输出
        branches = [b.strip() for b in result.output.split('\n') if b.strip()]
        return CommandResult(
            success=True,
            output='\n'.join(branches)
        )
```

### 3. 异步执行

```python
import asyncio
import sys
from pathlib import Path

# 添加项目根目录到 Python 路径
project_root = Path(__file__).resolve().parents[2]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from gscripts.plugins.decorators import plugin_function
from gscripts.core.config_manager import CommandResult


@plugin_function(
    name="parallel",
    description="并发执行多个命令"
)
async def run_parallel(args):
    """并发执行命令"""
    commands = [
        "ls -la",
        "df -h",
        "ps aux | head -10"
    ]

    # 并发执行
    tasks = [execute_command(cmd) for cmd in commands]
    results = await asyncio.gather(*tasks)

    # 合并结果
    output = '\n'.join([r.output for r in results if r.success])
    return CommandResult(success=True, output=output)


async def execute_command(cmd):
    """辅助函数:执行单个命令"""
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    return CommandResult(
        success=proc.returncode == 0,
        output=stdout.decode(),
        error=stderr.decode()
    )
```

### 4. 配置管理

```python
import sys
from pathlib import Path

# 添加项目根目录到 Python 路径
project_root = Path(__file__).resolve().parents[2]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from gscripts.plugins.base import BasePlugin
from gscripts.plugins.decorators import plugin_function
from gscripts.core.config_manager import CommandResult


class MyPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        # 加载插件配置
        self.config = self.load_config()

    def load_config(self):
        """从plugin.json加载额外配置"""
        config_file = self.plugin_dir / "config.json"
        if config_file.exists():
            import json
            with open(config_file) as f:
                return json.load(f)
        return {}

    @plugin_function(name="deploy")
    async def deploy(self, args):
        """使用配置进行部署"""
        api_key = self.config.get('api_key')
        server = self.config.get('server')

        if not api_key:
            return CommandResult(
                success=False,
                error="未配置API密钥"
            )

        # 执行部署...
```

### 5. 错误处理

```python
import sys
from pathlib import Path

# 添加项目根目录到 Python 路径
project_root = Path(__file__).resolve().parents[2]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from gscripts.plugins.decorators import plugin_function
from gscripts.core.config_manager import CommandResult


@plugin_function(name="safe-operation")
async def safe_operation(args):
    """安全的操作示例"""
    try:
        # 参数验证
        if len(args) < 1:
            return CommandResult(
                success=False,
                error="缺少必需参数",
                exit_code=2
            )

        # 执行操作
        result = await risky_operation(args[0])

        return CommandResult(
            success=True,
            output=result
        )

    except FileNotFoundError as e:
        return CommandResult(
            success=False,
            error=f"文件不存在: {e}",
            exit_code=1
        )
    except PermissionError:
        return CommandResult(
            success=False,
            error="权限不足",
            exit_code=13
        )
    except Exception as e:
        return CommandResult(
            success=False,
            error=f"未知错误: {e}",
            exit_code=1
        )
```

## 最佳实践

### 1. 命名规范

- 插件名: 小写,连字符分隔 (`git-tools`, `docker-utils`)
- 子插件: 小写,单个单词 (`container`, `image`)
- 函数名: 小写,连字符分隔 (`list-containers`, `build-image`)

### 2. 文档规范

**完整的装饰器参数**:

```python
@plugin_function(
    name="function-name",              # 必需: 函数名称
    description={                       # 必需: 函数描述(支持中英文)
        "zh": "中文描述",
        "en": "English description"
    },
    usage="gs plugin subplugin function-name <args>",  # 推荐: 使用方法
    examples=[                          # 推荐: 使用示例
        "gs plugin subplugin function-name arg1",
        "gs plugin subplugin function-name --flag value"
    ]
)
def my_function(args):
    """函数实现"""
    pass
```

**示例 - 完整注解**:

```python
@plugin_function(
    name="deploy",
    description={
        "zh": "部署应用到指定环境",
        "en": "Deploy application to specified environment"
    },
    usage="gs myapp deploy <environment> [options]",
    examples=[
        "gs myapp deploy production",
        "gs myapp deploy staging --skip-tests",
        "gs myapp deploy dev --verbose"
    ]
)
async def deploy_app(args):
    """部署应用"""
    # 实现逻辑
    pass
```

### 3. 错误消息

- 清晰具体
- 提供解决建议
- 使用正确的退出码

```python
return CommandResult(
    success=False,
    error="文件 'config.json' 不存在。请运行 'gs plugin init' 初始化配置。",
    exit_code=1
)
```

### 4. 性能优化

- 使用异步I/O
- 避免阻塞操作
- 合理使用缓存
- 并发执行独立任务

### 5. 安全考虑

- 验证所有输入
- 避免shell注入
- 使用白名单而非黑名单
- 敏感信息不要硬编码

## 测试插件

### 1. 手动测试

```bash
# 重新加载插件
gs refresh

# 测试插件
gs plugin info myplugin
gs myplugin function-name

# 查看日志
tail -f ~/.config/global-scripts/logs/gs.log
```

### 2. 单元测试

```python
import pytest
from gs_system.core.plugin_loader import PluginLoader


@pytest.mark.asyncio
async def test_myplugin_load():
    """测试插件加载"""
    loader = PluginLoader("plugins")
    plugin = await loader.load_plugin("myplugin")

    assert plugin is not None
    assert plugin.name == "myplugin"
    assert len(plugin.functions) > 0


@pytest.mark.asyncio
async def test_function_execution():
    """测试函数执行"""
    from myplugin.plugin import my_function

    result = await my_function(["arg1", "arg2"])

    assert result.success
    assert "expected output" in result.output
```

## 发布插件

### 1. 插件结构检查清单

- [ ] `plugin.json` 完整且格式正确
- [ ] 版本号遵循语义化版本
- [ ] 描述包含中英文
- [ ] 所有函数有文档
- [ ] 代码通过测试
- [ ] README.md 说明用法

### 2. 提交到官方插件库

1. Fork 官方仓库
2. 在 `plugins/` 下添加你的插件
3. 运行测试: `pytest tests/`
4. 提交 Pull Request

### 3. 第三方插件

用户可以将插件放在 `custom/` 目录:

```bash
custom/
└── myplugin/
    ├── plugin.json
    └── plugin.py
```

系统会自动扫描并加载。

## 常见问题

**Q: 插件不显示在列表中?**

A: 检查 `plugin.json` 的 `name` 字段,确保文件格式正确。

**Q: 函数执行失败?**

A: 查看日志文件 `~/.config/global-scripts/logs/gs.log`

**Q: 如何调试?**

A: 设置环境变量 `export GS_DEBUG=1` 启用详细日志。

**Q: Python导入错误?**

A: 确保 `PYTHONPATH` 包含项目根目录,或在函数中使用绝对导入。

## 示例插件

查看 `examples/` 目录获取完整示例:

- `examples/json-simple/` - 简单JSON插件
- `examples/shell-simple/` - 简单Shell插件
- `examples/python-simple/` - 简单Python插件
- `examples/hybrid-with-subplugins/` - 复杂混合插件

## 下一步

- 查看 [API文档](./api-reference.md) 了解可用API
- 阅读 [最佳实践](./best-practices.md) 学习经验
- 参考 [示例插件](./examples.md) 获取灵感
