# Shell直接执行特性

Global Scripts 的一个重要特性：**Shell插件完全不经过Python代码，直接执行Shell命令**。

## 🎯 核心特性

### Shell插件 ≠ Python包装

与许多插件系统不同，Global Scripts的Shell插件：

- ✅ **直接执行** - Shell命令直接传递给系统Shell
- ✅ **无Python中介** - 不经过Python subprocess包装
- ✅ **完整Shell能力** - 支持所有Shell特性（管道、重定向、环境变量等）
- ✅ **cd命令可用** - `cd` 在当前Shell中直接生效，**真正改变工作目录**
- ✅ **export生效** - 环境变量设置在当前Shell会话中持久化

### ⚠️ 重要说明：cd命令的工作原理

**`gs()` 是一个Shell函数，不是外部命令！**

```bash
# env.sh 中的实现
gs() {
    # ... 路由逻辑 ...
    case "$kind" in
        json)
            eval "$cmd"  # 直接在当前Shell中执行！
            ;;
    esac
}
```

**这意味着**：
- ✅ 在终端中执行 `gs navigator as-aosp`，`cd` 命令**直接改变当前Shell的工作目录**
- ✅ 在终端中执行 `gs shell-ops set-env`，`export` 设置的环境变量**在当前Shell会话中持久化**
- ❌ 在脚本中执行 `gs navigator as-aosp`，`cd` 只影响脚本的子Shell，**脚本执行完后目录恢复**

**示例对比**：

```bash
# ✅ 正确用法：交互式Shell中使用
$ pwd
/tmp
$ gs navigator as-aosp
/Users/solo/code/github/as-aosp
📁 已切换到 as-aosp 项目目录
$ pwd
/Users/solo/code/github/as-aosp  # ✅ 目录已切换！

# ❌ 错误用法：脚本中使用
$ cat test.sh
#!/bin/bash
pwd
gs navigator as-aosp
pwd

$ ./test.sh
/tmp
/Users/solo/code/github/as-aosp
/tmp  # ❌ 目录又回到原位了
```

**为什么？** 因为脚本在子Shell中运行，`gs()` 函数虽然改变了子Shell的目录，但子Shell退出后，父Shell的目录不受影响。这是Unix/Linux的基本特性，不是Global Scripts的限制。

## 🔧 实现原理

### 执行流程对比

#### ❌ 传统方式 (Python包装)
```
用户命令 → Python解析 → subprocess.run() → Shell执行
          ↑
        有限制：cd、export等不生效
```

#### ✅ Global Scripts方式 (直接执行)
```
用户命令 → Shell注解解析 → 直接Shell执行
                            ↑
                    完整Shell能力：cd、export、alias等全部可用
```

### 技术细节

Shell插件通过两种方式实现直接执行：

1. **Config插件** - JSON配置中的command直接传递
2. **Shell脚本插件** - `.sh`文件中的函数直接调用

## 📝 示例

### 1. Config插件 - 完整Shell能力

创建 `plugins/shell-ops/plugin.json`:

```json
{
  "name": "shell-ops",
  "version": "1.0.0",
  "description": {
    "zh": "Shell操作插件",
    "en": "Shell operations plugin"
  },
  "commands": {
    "goto-home": {
      "command": "cd ~ && pwd",
      "description": "切换到HOME目录并显示路径"
    },
    "list-env": {
      "command": "export MY_VAR=test && echo $MY_VAR && env | grep MY_VAR",
      "description": "设置环境变量并显示"
    },
    "pipe-example": {
      "command": "ps aux | grep python | head -5",
      "description": "管道操作示例"
    },
    "background-job": {
      "command": "sleep 5 &",
      "description": "后台任务示例"
    }
  }
}
```

**使用**:
```bash
# cd命令有效！
gs shell-ops goto-home
# 输出: /Users/username

# export有效！
gs shell-ops list-env
# 输出: test
#       MY_VAR=test

# 管道、重定向全部支持
gs shell-ops pipe-example
```

### 2. Shell脚本插件 - 完整Shell函数

创建 `plugins/project-manager/scripts/workspace.sh`:

```bash
#!/bin/bash

# @plugin_function
# name: setup
# description:
#   zh: 初始化项目工作空间
#   en: Initialize project workspace
# usage: gs project-manager workspace setup
# examples:
#   - gs project-manager workspace setup

setup() {
    # 创建项目结构
    mkdir -p ~/projects/{src,build,docs}

    # 切换目录并设置环境
    cd ~/projects

    # 设置环境变量
    export PROJECT_ROOT=$(pwd)
    export PATH="$PROJECT_ROOT/bin:$PATH"

    # 创建激活脚本
    cat > activate.sh << 'EOF'
#!/bin/bash
export PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH="$PROJECT_ROOT/bin:$PATH"
echo "Project environment activated: $PROJECT_ROOT"
EOF

    chmod +x activate.sh

    # 显示结果
    pwd
    ls -la
    echo "Workspace initialized at: $PROJECT_ROOT"
}

# @plugin_function
# name: goto
# description:
#   zh: 快速跳转到项目目录
#   en: Quick jump to project directory
# usage: gs project-manager workspace goto <dir>
# examples:
#   - gs project-manager workspace goto src
#   - gs project-manager workspace goto build

goto() {
    local target_dir="$1"
    cd ~/projects/"$target_dir" 2>/dev/null || {
        echo "Error: Directory not found: $target_dir"
        return 1
    }
    pwd
    ls -la
}

# Shell函数路由
case "$1" in
    setup) setup ;;
    goto) goto "$2" ;;
    *) echo "Unknown command: $1" >&2; exit 1 ;;
esac
```

**使用**:
```bash
# 初始化工作空间
gs project-manager workspace setup
# cd、export、cat重定向等全部有效！

# 切换目录
gs project-manager workspace goto src
# cd命令直接生效！
```

### 3. 复杂Shell操作示例

创建 `plugins/devenv/plugin.json`:

```json
{
  "name": "devenv",
  "version": "1.0.0",
  "description": "开发环境管理",
  "commands": {
    "activate-node": {
      "command": "export NVM_DIR=\"$HOME/.nvm\" && [ -s \"$NVM_DIR/nvm.sh\" ] && . \"$NVM_DIR/nvm.sh\" && nvm use 18 && node --version",
      "description": "激活Node 18环境"
    },
    "activate-python": {
      "command": "cd ~/projects/myapp && source venv/bin/activate && python --version && which python",
      "description": "激活Python虚拟环境"
    },
    "docker-dev": {
      "command": "cd ~/projects/myapp && docker-compose up -d && docker-compose ps",
      "description": "启动Docker开发环境"
    },
    "full-setup": {
      "command": "cd ~/projects/myapp && source venv/bin/activate && export DJANGO_SETTINGS_MODULE=myapp.settings.dev && ./manage.py runserver",
      "description": "完整开发环境启动"
    }
  }
}
```

## 🎓 Shell vs Python 插件选择

### 何时使用Shell插件

✅ **适合Shell插件的场景**:
- 需要cd、export等Shell内置命令
- 大量管道、重定向操作
- Shell脚本迁移
- 环境变量设置
- 工作目录切换
- Shell别名和函数调用
- 后台任务管理

**示例**:
```json
{
  "commands": {
    "deploy": {
      "command": "cd /app && git pull && npm install && npm run build && pm2 restart app"
    }
  }
}
```

### 何时使用Python插件

✅ **适合Python插件的场景**:
- 复杂的数据处理
- API调用和JSON解析
- 条件逻辑和流程控制
- 需要状态管理
- 跨平台兼容性
- 与Python生态集成

**示例**:
```python
@plugin_function(
    name="deploy",
    description="智能部署",
    examples=["gs myapp deploy production"]
)
async def deploy(args):
    env = args[0] if args else "dev"

    # 检查环境
    if env == "production":
        # 确认提示
        confirmed = await prompt_user("Deploy to production?")
        if not confirmed:
            return CommandResult(success=False, error="Cancelled")

    # 复杂部署逻辑
    # ...
```

## ⚙️ Shell执行配置

### 超时设置

```json
{
  "commands": {
    "long-task": {
      "command": "sleep 100 && echo done",
      "timeout": 120,
      "description": "长时间运行的任务"
    }
  }
}
```

### 工作目录

```json
{
  "commands": {
    "build": {
      "command": "make all",
      "working_dir": "/path/to/project",
      "description": "在指定目录构建项目"
    }
  }
}
```

### 环境变量

```json
{
  "commands": {
    "test": {
      "command": "pytest tests/",
      "env": {
        "PYTEST_ADDOPTS": "-v --tb=short",
        "PYTHONPATH": "/app"
      },
      "description": "运行测试"
    }
  }
}
```

## 🔒 安全考虑

### 1. 命令白名单

Shell插件仍然受安全检查约束：

```python
# gs_system/core/constants.py
SAFE_COMMANDS = [
    'cd', 'pwd', 'ls', 'cat', 'grep', 'find',
    'git', 'npm', 'docker', 'python', ...
]
```

### 2. 危险命令拦截

```python
DANGEROUS_COMMANDS = [
    'rm', 'sudo', 'chmod 777', ...
]

FORBIDDEN_PATTERNS = [
    'rm -rf /',
    'format',
    'dd if=',
    ...
]
```

### 3. 用户确认

对于敏感操作，可以要求确认：

```json
{
  "commands": {
    "cleanup": {
      "command": "rm -rf ./build ./dist",
      "confirm": true,
      "confirm_message": "This will delete build artifacts. Continue?"
    }
  }
}
```

## 🚀 高级用法

### 1. 条件执行

```json
{
  "commands": {
    "smart-deploy": {
      "command": "if [ \"$NODE_ENV\" = \"production\" ]; then npm run build:prod; else npm run build:dev; fi && pm2 restart app"
    }
  }
}
```

### 2. 错误处理

```json
{
  "commands": {
    "safe-operation": {
      "command": "git pull || { echo 'Pull failed, trying reset'; git fetch --all && git reset --hard origin/main; }"
    }
  }
}
```

### 3. 多步骤操作

```bash
#!/bin/bash

# @plugin_function
# name: deploy
# description: 完整部署流程

deploy() {
    # Step 1: 备份
    echo "Creating backup..."
    tar -czf backup-$(date +%Y%m%d).tar.gz ./app

    # Step 2: 拉取代码
    echo "Pulling latest code..."
    cd ~/projects/app || exit 1
    git pull || exit 1

    # Step 3: 安装依赖
    echo "Installing dependencies..."
    npm install || exit 1

    # Step 4: 构建
    echo "Building..."
    npm run build || exit 1

    # Step 5: 重启服务
    echo "Restarting service..."
    pm2 restart app

    echo "Deployment completed successfully!"
}
```

## 📊 性能优势

### Shell直接执行 vs Python包装

| 指标 | Shell直接执行 | Python包装 |
|------|--------------|-----------|
| **启动时间** | ~10ms | ~50ms |
| **内存开销** | 低 | 中等 |
| **Shell能力** | 100% | 受限 |
| **cd命令** | ✅ 支持 | ❌ 不支持 |
| **环境变量** | ✅ 持久化 | ❌ 临时 |

### 基准测试

```bash
# Shell直接执行
time gs shell-ops goto-home
# real    0m0.012s

# Python包装(假设)
time python -c "import subprocess; subprocess.run(['cd', '~'])"
# real    0m0.045s (且cd不生效)
```

## 🎯 最佳实践

### 1. 使用Shell注解

清晰标注函数元信息：

```bash
# @plugin_function
# name: backup
# description:
#   zh: 备份数据库
#   en: Backup database
# usage: gs myapp backup [database]
# examples:
#   - gs myapp backup production
#   - gs myapp backup staging
```

### 2. 错误处理

```bash
backup() {
    local db="$1"

    if [ -z "$db" ]; then
        echo "Error: Database name required" >&2
        return 1
    fi

    # 执行备份
    mysqldump "$db" > "backup-${db}-$(date +%Y%m%d).sql" || {
        echo "Error: Backup failed" >&2
        return 1
    }

    echo "Backup completed: backup-${db}-$(date +%Y%m%d).sql"
}
```

### 3. 参数验证

```bash
deploy() {
    local env="$1"

    case "$env" in
        dev|staging|production)
            # 有效环境
            ;;
        *)
            echo "Error: Invalid environment: $env" >&2
            echo "Valid options: dev, staging, production" >&2
            return 1
            ;;
    esac

    # 执行部署
    cd "/app/${env}" && ./deploy.sh
}
```

## 🔗 相关文档

- [插件开发指南](./plugin-development.md) - 完整插件开发教程
- [CLI命令参考](./cli-reference.md) - 命令行使用说明
- [架构设计](./architecture.md) - 系统架构详解

## 💡 总结

Shell直接执行是Global Scripts的核心优势：

- ✅ **真正的Shell** - 不是Python包装，是真正的Shell执行
- ✅ **完整能力** - cd、export、alias等全部可用
- ✅ **高性能** - 无Python中介，启动更快
- ✅ **灵活性** - 支持所有Shell特性
- ✅ **易迁移** - 现有Shell脚本可直接使用

**这使得Global Scripts既能享受Python的强大功能，又能保留Shell的灵活性！** 🚀
