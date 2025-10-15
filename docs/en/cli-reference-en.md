# CLI Command Reference

Complete command-line interface reference documentation for Global Scripts.

## Command Format

```bash
gs [system-command]
gs plugin [plugin-management-command] [arguments]
gs <plugin-name> <sub-plugin-name> <function-name> [arguments...]
```

## System Commands

### gs help

Display help information.

```bash
gs help
gs --help
gs -h
```

Output example:
```
🚀 Global Scripts 显示帮助信息
================================================================================

┌─────────────────────────┬──────────────┐
│ 命令                    │ 描述         │
├─────────────────────────┼──────────────┤
│ gs <名称> <命令> [用法] │ 基本信息     │
│ gs help                 │ 显示帮助信息 │
│ gs version              │ 显示版本信息 │
│ gs status               │ 显示系统状态 │
│ gs doctor               │ 系统诊断     │
│ gs refresh              │ 刷新系统     │
│ gs plugin list          │ 列出所有插件 │
└─────────────────────────┴──────────────┘
```

### gs version

Display version information.

```bash
gs version
gs --version
```

### gs status

Display system status information.

```bash
gs status
```

Output example:
```
🔧 显示系统状态
================================================================================

┌──────────┬───────────────────────────────────────────────────┐
│ 属性     │ 值                                                │
├──────────┼───────────────────────────────────────────────────┤
│ 状态     │ ✅ 已启用                                         │
│ 总插件数 │ 10                                                │
│ 已启用   │ 10                                                │
│ 已禁用   │ 0                                                 │
│ 总命令数 │ 191                                               │
└──────────┴───────────────────────────────────────────────────┘
```

### gs refresh

Refresh the plugin system and completion scripts.

```bash
gs refresh
```

Functions:
- Re-scan plugin directories
- Regenerate completion scripts
- Rebuild router index
- Reload configuration

### gs doctor

System health check.

```bash
gs doctor
```

Check items:
- Python version
- Required file existence
- Configuration file validity
- Plugin loading status
- Environment variable settings

## Plugin Management Commands

### gs plugin list

List all plugins.

```bash
gs plugin list
```

Output is in table format, containing plugin name, status, type, priority, version, command count, and description.

### gs plugin info

View detailed plugin information.

```bash
gs plugin info <plugin-name>
```

Example:
```bash
gs plugin info android
```

Output example:
```
🔌 插件详情: android
================================================================================

📋 基本信息:
┌──────────┬─────────────┐
│ 属性     │ 值          │
├──────────┼─────────────┤
│ 名称     │ android     │
│ 状态     │ ✅ 已启用   │
└──────────┴─────────────┘

📜 可用命令表格（包含命令、子插件、函数、类型、用法、描述）
```

### gs plugin enable

Enable a plugin.

```bash
gs plugin enable <plugin-name>
```

Example:
```bash
gs plugin enable gerrit
```

### gs plugin disable

Disable a plugin.

```bash
gs plugin disable <plugin-name>
```

Example:
```bash
gs plugin disable gerrit
```

## Plugin Command Execution

### Basic Format

```bash
gs <plugin-name> <sub-plugin-name> <function-name> [arguments...]
```

### Examples

#### Android Plugin

```bash
# Logcat management
gs android logcat clear
gs android logcat tail
gs android logcat filter TAG

# Device management
gs android device devices       # List connected devices
gs android device connect 192.168.1.100
gs android device screencap

# Application management
gs android app list-3rd
gs android app version com.example.app
gs android app clear com.example.app

# System management
gs android system selinux-disable
gs android system hidden-api-enable
```

#### System Plugin

```bash
# Log management (if plugin supports it)
gs system logging level DEBUG
gs system logging show
gs system logging clear
```

Note: For actual available commands, please use `gs plugin info <plugin-name>` to view.

## Shortcut Commands

The system automatically generates shell function shortcut commands:

```bash
# Format: gs-<plugin>-<sub-plugin>-<function>

# Original command:
gs android logcat clear

# Shortcut command:
gs-android-logcat-clear
```

## Completion Features

### Bash Completion

Press Tab key for auto-completion:

```bash
gs <Tab>          # Complete plugin names and system commands
gs plugin <Tab>   # Complete plugin management subcommands
gs android <Tab>  # Complete android sub-plugins
```

### Zsh Completion

Zsh users automatically get completion support with the same functionality as Bash.

### Fish Completion

Fish users automatically get completion support with the same functionality as Bash.

## Environment Variables

The following environment variables are automatically managed by the system and typically do not require manual user configuration:

### GS_ROOT

Project root directory, automatically set by the installation script.

```bash
# Automatically set, no manual configuration needed
echo $GS_ROOT
```

### GS_LANGUAGE

Interface language (optional).

```bash
# To switch language, set in shell configuration file
export GS_LANGUAGE="zh"  # or "en"
```

### GS_DEBUG

Enable debug mode (optional).

```bash
# Temporarily enable for debugging
export GS_DEBUG=1
```

### GS_LOG_LEVEL

Log level (optional).

```bash
# Possible values: ERROR/WARNING/INFO/DEBUG/VERBOSE/NANO
export GS_LOG_LEVEL="DEBUG"
```

## Exit Codes

| Exit Code | Meaning |
|-----------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Command usage error |
| 124 | Timeout |
| 126 | Execution error |
| 127 | Command not found |
| 130 | User interrupt (Ctrl+C) |

## Common Usage

### Daily Development

```bash
# View logs
gs android logcat tail

# List devices
gs android device devices

# Check app version
gs android app version com.example.app
```

### Plugin Management

```bash
# View all plugins
gs plugin list

# View plugin details
gs plugin info android

# Enable new plugin
gs plugin enable myplugin

# Refresh system
gs refresh
```

### Troubleshooting

```bash
# System check
gs doctor

# View status
gs status

# View plugin information
gs plugin info <plugin-name>
```

## More Information

- [Quickstart](./quickstart.md) - Quick start guide
- [Plugin Development](./plugin-development.md) - Plugin development guide
- [FAQ](./faq.md) - Frequently asked questions
