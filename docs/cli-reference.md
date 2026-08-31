# CLI 命令参考

Global Scripts 完整命令行接口参考文档。

## 命令格式

```bash
gs [系统命令]
gs plugin [插件管理命令] [参数]
gs <插件名> <子插件名> <函数名> [参数...]
```

## 系统命令

### gs help

显示帮助信息。

```bash
gs help
gs --help
gs -h
```

输出示例：
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

显示版本信息。

```bash
gs version
gs --version
```

### gs status

显示系统状态信息。

```bash
gs status
```

输出示例：
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

刷新插件系统和补全脚本。

```bash
gs refresh
```

作用：
- 重新扫描插件目录
- 重新生成补全脚本
- 重建 router 索引
- 重新加载配置

### gs doctor

系统健康检查。

```bash
gs doctor
```

检查项：
- Python 版本
- 必需文件存在性
- 配置文件有效性
- 插件加载状态
- 环境变量设置

## 插件管理命令

### gs plugin list

列出所有插件。

```bash
gs plugin list
```

输出为表格格式，包含插件名称、状态、类型、优先级、版本、命令数量和描述。

### gs plugin info

查看插件详细信息。

```bash
gs plugin info <插件名>
```

示例：
```bash
gs plugin info android
```

输出示例：
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

📜 GS 6.0 使用自适应信息面板和分组命令列表；插件列表使用自适应表格。

`gs6 android` 显示插件基本信息及按子插件分组的命令；`gs6 android device` 只显示 device 命令组。具体命令保持原始输出。

当 `plugin info` 后面的词组成完整命令路径时，会直接执行该命令。例如 `gs6 plugin info android app list-3rd` 等价于 `gs6 android app list-3rd`；后续参数会继续传给该命令。
```

### gs plugin enable

启用插件。

```bash
gs plugin enable <插件名>
```

示例：
```bash
gs plugin enable android
```

### gs plugin disable

禁用插件。

```bash
gs plugin disable <插件名>
```

示例：
```bash
gs plugin disable android
```

## 插件命令执行

### 基本格式

```bash
gs <插件名> <子插件名> <函数名> [参数...]
```

### 示例

#### Android 插件

```bash
# Logcat 管理
gs android logcat clear
gs android logcat tail
gs android logcat filter TAG

# 设备管理
gs android device devices       # 列出连接设备
gs android device connect 192.168.1.100
gs android device screencap

# 应用管理
gs android app list-3rd
gs android app version com.example.app
gs android app clear com.example.app

# 系统管理
gs android system selinux-disable
gs android system hidden-api-enable
```

#### System 插件

```bash
# 日志管理（如果插件支持）
gs system logging level DEBUG
gs system logging show
gs system logging clear
```

注意：实际可用命令请使用 `gs plugin info <插件名>` 查看。

## 快捷命令

系统自动生成 shell 函数快捷命令：

```bash
# 格式: gs-<插件>-<子插件>-<函数>

# 原命令:
gs android logcat clear

# 快捷命令:
gs-android-logcat-clear
```

## 补全功能

### Bash 补全

按 Tab 键自动补全：

```bash
gs <Tab>          # 补全插件名和系统命令
gs plugin <Tab>   # 补全插件管理子命令
gs android <Tab>  # 补全 android 的子插件
```

### Zsh 补全

Zsh 用户自动获得补全支持，功能同 Bash。

### Fish 补全

Fish 用户自动获得补全支持，功能同 Bash。

## 环境变量

以下环境变量由系统自动管理，通常不需要用户手动设置：

### GS_ROOT

项目根目录，由安装脚本自动设置。

```bash
# 自动设置，无需手动配置
echo $GS_ROOT
```

### GS_LANGUAGE

界面语言（可选）。

```bash
# 如需切换语言，可在 shell 配置文件中设置
export GS_LANGUAGE="zh"  # 或 "en"
```

### GS_DEBUG

启用调试模式（可选）。

```bash
# 用于调试时临时启用
export GS_DEBUG=1
```

### GS_LOG_LEVEL

日志级别（可选）。

```bash
# 可选值: ERROR/WARNING/INFO/DEBUG/VERBOSE/NANO
export GS_LOG_LEVEL="DEBUG"
```

## 退出码

| 退出码 | 含义 |
|-------|------|
| 0 | 成功 |
| 1 | 一般错误 |
| 2 | 命令使用错误 |
| 124 | 超时 |
| 126 | 执行错误 |
| 127 | 命令未找到 |
| 130 | 用户中断 (Ctrl+C) |

## 常见用法

### 日常开发

```bash
# 查看日志
gs android logcat tail

# 列出设备
gs android device devices

# 查看应用版本
gs android app version com.example.app
```

### 插件管理

```bash
# 查看所有插件
gs plugin list

# 查看插件详情
gs plugin info android

# 启用新插件
gs plugin enable myplugin

# 刷新系统
gs refresh
```

### 故障排查

```bash
# 系统检查
gs doctor

# 查看状态
gs status

# 查看插件信息
gs plugin info <插件名>
```

## 更多信息

- [快速入门](./quickstart.md) - 快速上手指南
- [插件开发](./plugin-development.md) - 插件开发指南
- [FAQ](./faq.md) - 常见问题解答
