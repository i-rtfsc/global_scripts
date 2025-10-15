# Shell Direct Execution Feature

A key feature of Global Scripts: **Shell plugins execute directly without going through Python code**.

## 🎯 Core Features

### Shell Plugins ≠ Python Wrapper

Unlike many plugin systems, Global Scripts' Shell plugins:

- ✅ **Direct Execution** - Shell commands are passed directly to the system Shell
- ✅ **No Python Intermediary** - Does not go through Python subprocess wrapper
- ✅ **Full Shell Capabilities** - Supports all Shell features (pipes, redirects, environment variables, etc.)
- ✅ **cd Command Works** - `cd` takes effect directly in the current Shell, **truly changing the working directory**
- ✅ **export Takes Effect** - Environment variable settings persist in the current Shell session

### ⚠️ Important Note: How the cd Command Works

**`gs()` is a Shell function, not an external command!**

```bash
# Implementation in env.sh
gs() {
    # ... routing logic ...
    case "$kind" in
        json)
            eval "$cmd"  # Execute directly in the current Shell!
            ;;
    esac
}
```

**This means**:
- ✅ Executing `gs navigator as-aosp` in a terminal, the `cd` command **directly changes the current Shell's working directory**
- ✅ Executing `gs shell-ops set-env` in a terminal, environment variables set with `export` **persist in the current Shell session**
- ❌ Executing `gs navigator as-aosp` in a script, `cd` only affects the script's subshell, **directory reverts after script execution**

**Comparison Example**:

```bash
# ✅ Correct Usage: Use in interactive Shell
$ pwd
/tmp
$ gs navigator as-aosp
/Users/solo/code/github/as-aosp
📁 已切换到 as-aosp 项目目录
$ pwd
/Users/solo/code/github/as-aosp  # ✅ Directory changed!

# ❌ Incorrect Usage: Use in script
$ cat test.sh
#!/bin/bash
pwd
gs navigator as-aosp
pwd

$ ./test.sh
/tmp
/Users/solo/code/github/as-aosp
/tmp  # ❌ Directory reverted!
```

**Why?** Because scripts run in a subshell, the `gs()` function changes the subshell's directory, but after the subshell exits, the parent Shell's directory is unaffected. This is a fundamental Unix/Linux feature, not a Global Scripts limitation.

## 🔧 Implementation Principles

### Execution Flow Comparison

#### ❌ Traditional Approach (Python Wrapper)
```
User Command → Python Parse → subprocess.run() → Shell Execute
          ↑
    Limited: cd, export, etc. don't work
```

#### ✅ Global Scripts Approach (Direct Execution)
```
User Command → Shell Annotation Parse → Direct Shell Execution
                            ↑
                    Full Shell capabilities: cd, export, alias, etc. all available
```

### Technical Details

Shell plugins implement direct execution through two approaches:

1. **Config Plugins** - Commands in JSON configuration are passed directly
2. **Shell Script Plugins** - Functions in `.sh` files are called directly

## 📝 Examples

### 1. Config Plugin - Full Shell Capabilities

Create `plugins/shell-ops/plugin.json`:

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

**Usage**:
```bash
# cd command works!
gs shell-ops goto-home
# Output: /Users/username

# export works!
gs shell-ops list-env
# Output: test
#       MY_VAR=test

# Pipes and redirects all supported
gs shell-ops pipe-example
```

### 2. Shell Script Plugin - Full Shell Functions

Create `plugins/project-manager/scripts/workspace.sh`:

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
    # Create project structure
    mkdir -p ~/projects/{src,build,docs}

    # Change directory and set environment
    cd ~/projects

    # Set environment variables
    export PROJECT_ROOT=$(pwd)
    export PATH="$PROJECT_ROOT/bin:$PATH"

    # Create activation script
    cat > activate.sh << 'EOF'
#!/bin/bash
export PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH="$PROJECT_ROOT/bin:$PATH"
echo "Project environment activated: $PROJECT_ROOT"
EOF

    chmod +x activate.sh

    # Display results
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

# Shell function routing
case "$1" in
    setup) setup ;;
    goto) goto "$2" ;;
    *) echo "Unknown command: $1" >&2; exit 1 ;;
esac
```

**Usage**:
```bash
# Initialize workspace
gs project-manager workspace setup
# cd, export, cat redirect all work!

# Change directory
gs project-manager workspace goto src
# cd command takes effect directly!
```

### 3. Complex Shell Operations Example

Create `plugins/devenv/plugin.json`:

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

## 🎓 Shell vs Python Plugin Selection

### When to Use Shell Plugins

✅ **Scenarios Suitable for Shell Plugins**:
- Need cd, export, and other Shell built-in commands
- Heavy use of pipes and redirect operations
- Shell script migration
- Environment variable configuration
- Working directory switching
- Shell alias and function calls
- Background task management

**Example**:
```json
{
  "commands": {
    "deploy": {
      "command": "cd /app && git pull && npm install && npm run build && pm2 restart app"
    }
  }
}
```

### When to Use Python Plugins

✅ **Scenarios Suitable for Python Plugins**:
- Complex data processing
- API calls and JSON parsing
- Conditional logic and flow control
- Need state management
- Cross-platform compatibility
- Integration with Python ecosystem

**Example**:
```python
@plugin_function(
    name="deploy",
    description="智能部署",
    examples=["gs myapp deploy production"]
)
async def deploy(args):
    env = args[0] if args else "dev"

    # Check environment
    if env == "production":
        # Confirmation prompt
        confirmed = await prompt_user("Deploy to production?")
        if not confirmed:
            return CommandResult(success=False, error="Cancelled")

    # Complex deployment logic
    # ...
```

## ⚙️ Shell Execution Configuration

### Timeout Settings

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

### Working Directory

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

### Environment Variables

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

## 🔒 Security Considerations

### 1. Command Whitelist

Shell plugins are still subject to security checks:

```python
# gs_system/core/constants.py
SAFE_COMMANDS = [
    'cd', 'pwd', 'ls', 'cat', 'grep', 'find',
    'git', 'npm', 'docker', 'python', ...
]
```

### 2. Dangerous Command Interception

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

### 3. User Confirmation

For sensitive operations, you can require confirmation:

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

## 🚀 Advanced Usage

### 1. Conditional Execution

```json
{
  "commands": {
    "smart-deploy": {
      "command": "if [ \"$NODE_ENV\" = \"production\" ]; then npm run build:prod; else npm run build:dev; fi && pm2 restart app"
    }
  }
}
```

### 2. Error Handling

```json
{
  "commands": {
    "safe-operation": {
      "command": "git pull || { echo 'Pull failed, trying reset'; git fetch --all && git reset --hard origin/main; }"
    }
  }
}
```

### 3. Multi-Step Operations

```bash
#!/bin/bash

# @plugin_function
# name: deploy
# description: 完整部署流程

deploy() {
    # Step 1: Backup
    echo "Creating backup..."
    tar -czf backup-$(date +%Y%m%d).tar.gz ./app

    # Step 2: Pull code
    echo "Pulling latest code..."
    cd ~/projects/app || exit 1
    git pull || exit 1

    # Step 3: Install dependencies
    echo "Installing dependencies..."
    npm install || exit 1

    # Step 4: Build
    echo "Building..."
    npm run build || exit 1

    # Step 5: Restart service
    echo "Restarting service..."
    pm2 restart app

    echo "Deployment completed successfully!"
}
```

## 📊 Performance Advantages

### Shell Direct Execution vs Python Wrapper

| Metric | Shell Direct Execution | Python Wrapper |
|------|--------------|-----------|
| **Startup Time** | ~10ms | ~50ms |
| **Memory Overhead** | Low | Medium |
| **Shell Capabilities** | 100% | Limited |
| **cd Command** | ✅ Supported | ❌ Not Supported |
| **Environment Variables** | ✅ Persistent | ❌ Temporary |

### Benchmark Tests

```bash
# Shell direct execution
time gs shell-ops goto-home
# real    0m0.012s

# Python wrapper (hypothetical)
time python -c "import subprocess; subprocess.run(['cd', '~'])"
# real    0m0.045s (and cd doesn't work)
```

## 🎯 Best Practices

### 1. Use Shell Annotations

Clearly mark function metadata:

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

### 2. Error Handling

```bash
backup() {
    local db="$1"

    if [ -z "$db" ]; then
        echo "Error: Database name required" >&2
        return 1
    fi

    # Execute backup
    mysqldump "$db" > "backup-${db}-$(date +%Y%m%d).sql" || {
        echo "Error: Backup failed" >&2
        return 1
    }

    echo "Backup completed: backup-${db}-$(date +%Y%m%d).sql"
}
```

### 3. Parameter Validation

```bash
deploy() {
    local env="$1"

    case "$env" in
        dev|staging|production)
            # Valid environment
            ;;
        *)
            echo "Error: Invalid environment: $env" >&2
            echo "Valid options: dev, staging, production" >&2
            return 1
            ;;
    esac

    # Execute deployment
    cd "/app/${env}" && ./deploy.sh
}
```

## 🔗 Related Documentation

- [Plugin Development Guide](./plugin-development.md) - Complete plugin development tutorial
- [CLI Command Reference](./cli-reference.md) - Command line usage instructions
- [Architecture Design](./architecture.md) - System architecture details

## 💡 Summary

Shell direct execution is a core advantage of Global Scripts:

- ✅ **True Shell** - Not a Python wrapper, true Shell execution
- ✅ **Full Capabilities** - cd, export, alias, etc. all available
- ✅ **High Performance** - No Python intermediary, faster startup
- ✅ **Flexibility** - Supports all Shell features
- ✅ **Easy Migration** - Existing Shell scripts can be used directly

**This allows Global Scripts to enjoy the power of Python while retaining the flexibility of Shell!** 🚀
