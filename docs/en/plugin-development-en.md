# Plugin Development Guide

Complete plugin development tutorial, from basics to advanced.

## Choosing a Plugin Type

Global Scripts supports 4 plugin types:

| Type | Use Case | Development Difficulty | Flexibility |
|------|---------|---------|-------|
| **Config** | Simple command wrappers | ⭐ | ⭐⭐ |
| **Shell** | Shell script integration | ⭐⭐ | ⭐⭐⭐ |
| **Python** | Complex logic handling | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Hybrid** | Mixed requirements | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |

## Quick Start: Creating Your First Plugin

### 1. Config Plugin (Simplest)

**Use Case**: Wrapping existing commands

```bash
mkdir -p plugins/hello
cd plugins/hello
```

Create `plugin.json`:
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

Create `commands.json`:
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

**Usage**:
```bash
gs hello world
# Output: Hello, World!

gs hello name Alice
# Output: Hello, Alice!
```

### 2. Shell Plugin

**Use Case**: Need Shell scripting logic

Create `plugin.json`:
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

Create `hardware/info.sh`:
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

# Shell annotation function routing
case "$1" in
    cpu) cpu ;;
    memory) memory ;;
    *) echo "Unknown command: $1" >&2; exit 1 ;;
esac
```

**Usage**:
```bash
gs system-info hardware cpu
gs system-info hardware memory
```

### 3. Python Plugin (Recommended)

**Use Case**: Complex logic, API calls, data processing

Create `plugin.json`:
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

Create `plugin.py`:
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

**Usage**:
```bash
gs calculator add 10 20
# Output: 10.0 + 20.0 = 30.0

gs calculator multiply 5 6
# Output: 5.0 × 6.0 = 30.0
```

## Advanced Features

### 1. Subplugin Organization

For complex plugins, use a subplugin structure:

```
plugins/dev-tools/
├── plugin.json          # Main configuration
├── git/                 # git subplugin
│   ├── plugin.py
│   └── utils.sh
├── docker/              # docker subplugin
│   └── plugin.py
└── kubernetes/          # k8s subplugin
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

### 2. Using Python Decorators (Object-Oriented)

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

### 3. Asynchronous Execution

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

### 4. Configuration Management

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

### 5. Error Handling

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

## Best Practices

### 1. Naming Conventions

- Plugin names: lowercase, hyphen-separated (`git-tools`, `docker-utils`)
- Subplugins: lowercase, single word (`container`, `image`)
- Function names: lowercase, hyphen-separated (`list-containers`, `build-image`)

### 2. Documentation Standards

**Complete decorator parameters**:

```python
@plugin_function(
    name="function-name",              # Required: Function name
    description={                       # Required: Function description (supports Chinese and English)
        "zh": "中文描述",
        "en": "English description"
    },
    usage="gs plugin subplugin function-name <args>",  # Recommended: Usage instructions
    examples=[                          # Recommended: Usage examples
        "gs plugin subplugin function-name arg1",
        "gs plugin subplugin function-name --flag value"
    ]
)
def my_function(args):
    """函数实现"""
    pass
```

**Example - Complete annotation**:

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

### 3. Error Messages

- Clear and specific
- Provide solution suggestions
- Use correct exit codes

```python
return CommandResult(
    success=False,
    error="文件 'config.json' 不存在。请运行 'gs plugin init' 初始化配置。",
    exit_code=1
)
```

### 4. Performance Optimization

- Use asynchronous I/O
- Avoid blocking operations
- Use caching appropriately
- Execute independent tasks concurrently

### 5. Security Considerations

- Validate all inputs
- Avoid shell injection
- Use whitelists instead of blacklists
- Don't hardcode sensitive information

## Testing Plugins

### 1. Manual Testing

```bash
# Reload plugins
gs refresh

# Test plugin
gs plugin info myplugin
gs myplugin function-name

# View logs
tail -f ~/.config/global-scripts/logs/gs.log
```

### 2. Unit Testing

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

## Publishing Plugins

### 1. Plugin Structure Checklist

- [ ] `plugin.json` is complete and properly formatted
- [ ] Version number follows semantic versioning
- [ ] Description includes both Chinese and English
- [ ] All functions are documented
- [ ] Code passes tests
- [ ] README.md explains usage

### 2. Submitting to Official Plugin Repository

1. Fork the official repository
2. Add your plugin under `plugins/`
3. Run tests: `pytest tests/`
4. Submit a Pull Request

### 3. Third-Party Plugins

Users can place plugins in the `custom/` directory:

```bash
custom/
└── myplugin/
    ├── plugin.json
    └── plugin.py
```

The system will automatically scan and load them.

## Common Issues

**Q: Plugin doesn't appear in the list?**

A: Check the `name` field in `plugin.json`, ensure the file format is correct.

**Q: Function execution fails?**

A: Check the log file `~/.config/global-scripts/logs/gs.log`

**Q: How to debug?**

A: Set the environment variable `export GS_DEBUG=1` to enable verbose logging.

**Q: Python import errors?**

A: Ensure `PYTHONPATH` includes the project root directory, or use absolute imports in functions.

## Example Plugins

Check the `examples/` directory for complete examples:

- `examples/json-simple/` - Simple JSON plugin
- `examples/shell-simple/` - Simple Shell plugin
- `examples/python-simple/` - Simple Python plugin
- `examples/hybrid-with-subplugins/` - Complex hybrid plugin

## Next Steps

- Check the [API Reference](./api-reference.md) to learn about available APIs
- Read [Best Practices](./best-practices.md) to learn from experience
- Refer to [Example Plugins](./examples.md) for inspiration
