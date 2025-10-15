# Android 插件

Android 开发与调试的综合工具集，提供设备管理、应用调试、性能分析、文件操作等全方位功能。

## 📋 目录

- [功能概览](#功能概览)
- [快速开始](#快速开始)
- [子插件详解](#子插件详解)
- [常用命令](#常用命令)
- [环境要求](#环境要求)
- [故障排除](#故障排除)

## 🚀 功能概览

本插件包含 **13 个子插件**，共 **90 个命令**，覆盖 Android 开发调试的各个方面：

| 子插件 | 命令数 | 主要功能 |
|--------|--------|----------|
| **app** | 7 | 应用管理：列表、版本、进程控制、数据清理 |
| **build** | 8 | 编译系统：make、ninja、完整编译、QSSI、vendor |
| **device** | 8 | 设备管理：连接、选择、截图、信息查询 |
| **dump** | 8 | 系统信息：电池、内存、CPU、Activity 等 |
| **frida** | 4 | 动态分析：JavaScript 注入、进程调试 |
| **fs** | 10 | 文件系统：文件传输、路径映射、库定位 |
| **input** | 15 | 输入操作：按键、触摸、滑动、屏幕录制 |
| **logcat** | 2 | 日志管理：日志清理、实时跟踪 |
| **perfetto** | 2 | 性能追踪：系统性能分析工具 |
| **proc** | 6 | 进程管理：进程搜索、监控、事件追踪 |
| **surface** | 3 | 显示管理：刷新率控制和显示信息 |
| **system** | 7 | 系统管理：SELinux、Hidden API、系统优化 |
| **winscope** | 5 | UI 分析：界面层次分析和调试 |

## 🎯 快速开始

### 基础设备操作

```bash
# 查看可用设备
gs android device devices

# 选择设备（多设备环境）
gs android device choose

# 连接网络设备
gs android device connect 192.168.1.100:5555

# 截图
gs android device screencap screenshot.png
```

### 应用管理

```bash
# 列出第三方应用
gs android app list-3rd

# 查看应用版本
gs android app version com.example.app

# 终止应用
gs android app kill com.example.app

# 清除应用数据
gs android app clear com.example.app

# 查看应用日志
gs android app log com.example.app
```

### 系统调试

```bash
# 查看内存信息
gs android dump meminfo

# 查看电池状态
gs android dump battery

# 查看当前焦点 Activity
gs android dump activity

# 实时日志
gs android logcat tail
```

## 🔧 子插件详解

### 🔨 build - 编译系统
Android 源码编译系统的完整集成，支持各种编译场景。

```bash
gs android build help                    # 显示构建选项帮助
gs android build status                 # 检查构建环境状态
gs android build modules                # 列出可编译的模块

# 编译命令
gs android build ninja-clean            # 清理ninja构建缓存
gs android build make [options]         # 使用make编译模块
gs android build build [options]        # 完整系统编译
gs android build qssi [options]         # 编译QSSI（高通特有）
gs android build vendor [options]       # 编译vendor分区
```

**编译选项：**
- `-t <target>` - 编译目标 (默认: sdk_pc_x86_64-userdebug)
- `-j <threads>` - 编译线程数 (默认: CPU核心数)
- `-m <module>` - 模块名 (仅make命令)
- `-c <0|1>` - 启用ccache (Linux默认1, macOS默认0)
- `-b <token>` - 飞书机器人通知token

**特性：**
- 智能线程数检测和ccache配置
- 完整的编译日志记录和管理
- 飞书机器人通知编译结果
- 自动ADB推送编译产物
- 支持多种Android编译场景

### 📱 app - 应用管理
专注于已安装应用的管理和调试。

```bash
gs android app list-3rd              # 列出第三方应用
gs android app list-system           # 列出系统应用  
gs android app version <package>     # 获取应用版本信息
gs android app kill <package>        # 终止应用进程
gs android app clear <package>       # 清除应用数据
gs android app log <package>         # 显示应用日志
gs android app version-settings      # 获取设置应用版本
```

### 📲 device - 设备管理
设备连接、选择和基础信息操作。

```bash
gs android device devices            # 列出所有设备
gs android device choose             # 交互式选择设备
gs android device current            # 显示当前选择的设备
gs android device clear              # 清除设备选择
gs android device connect <ip>       # 连接网络设备
gs android device disconnect <ip>    # 断开网络设备
gs android device screencap [file]   # 截取屏幕
gs android device size               # 获取屏幕尺寸
gs android device wait               # 等待设备连接
```

### 📊 dump - 系统信息
快速获取各种系统状态和信息。

```bash
gs android dump battery              # 电池信息
gs android dump build                # 系统构建信息
gs android dump meminfo [package]    # 内存信息
gs android dump cpuinfo              # CPU 信息
gs android dump activity             # 当前焦点 Activity
gs android dump packages [keyword]   # 已安装包列表
gs android dump appops <package>     # 应用权限操作
gs android dump top [n]              # 进程 CPU 占用
```

### 🔍 frida - 动态分析
JavaScript 脚本注入和动态调试工具。

```bash
gs android frida inject -p <process> -f <script.js>  # 注入脚本
gs android frida server <start|stop|status>          # 管理 frida-server
gs android frida scripts                             # 列出可用脚本
gs android frida status                              # 检查环境状态
```

**特性：**
- 智能文件搜索（当前目录 → 插件目录）
- 自动下载引导（frida-inject/frida-server）
- 内置多个预制 JavaScript 脚本

### 📁 fs - 文件系统
文件传输、路径映射和库文件定位。

```bash
gs android fs push <local> <remote>     # 推送文件到设备
gs android fs pull <remote> <local>     # 从设备拉取文件
gs android fs push_common <file> <name> # 推送到常见路径
gs android fs pull_common <name> <file> # 从常见路径拉取
gs android fs common                     # 显示路径映射
gs android fs resolve <name>            # 解析路径别名
gs android fs verify                     # 校验路径存在性
gs android fs exists <path>             # 检查路径是否存在
gs android fs find_apk <package>        # 查找 APK 路径
gs android fs locate_so <libname.so>    # 定位 .so 库
gs android fs ls <path>                 # 列出目录内容
```

### ⌨️ input - 输入操作
模拟用户输入、屏幕操作和录制功能。

```bash
# 基础输入
gs android input keyevent <code>        # 发送按键事件
gs android input tap <x> <y>            # 点击坐标
gs android input text <text>            # 输入文本
gs android input swipe <x1> <y1> <x2> <y2> [duration]  # 滑动手势
gs android input longpress <x> <y>      # 长按

# 快捷键
gs android input back                   # 返回键
gs android input home                   # 主页键
gs android input recent                 # 多任务键
gs android input menu                   # 菜单键
gs android input power                  # 电源键
gs android input volume_up              # 音量+
gs android input volume_down            # 音量-
gs android input enter                  # 回车
gs android input del                    # 删除
gs android input space                  # 空格

# 输入控制
gs android input disable               # 禁用触摸输入
gs android input enable                # 启用触摸输入

# 屏幕录制
gs android input screenrecord <file>   # 录制屏幕
```

### 📋 logcat - 日志管理
Android 系统日志的管理和监控。

```bash
gs android logcat clear               # 清除日志缓冲区
gs android logcat tail [level]       # 实时跟踪日志
gs android logcat filter <keyword>   # 按关键字过滤（采样）
```

### ⚡ perfetto - 性能追踪
基于 Perfetto 的系统性能分析工具。

```bash
gs android perfetto trace -f <config> <output>  # 自定义配置追踪
gs android perfetto default <output>            # 使用默认配置追踪
```

**特性：**
- 智能配置文件搜索（当前目录优先）
- 支持自定义 Protocol Buffer 配置
- 内置默认性能追踪配置

### 🔄 proc - 进程管理
进程搜索、监控和 Activity Manager 事件追踪。

```bash
gs android proc ps_grep <keyword>           # 按关键字搜索进程
gs android proc kill_grep <keyword>         # 按关键字杀进程
gs android proc am-proc-start <package>     # 监控进程启动事件
gs android proc am-proc-died <package>      # 监控进程死亡事件
gs android proc am-kill <package>           # 监控进程被杀事件
gs android proc am-anr <package>            # 监控 ANR 事件
```

### 🖥️ surface - 显示管理
SurfaceFlinger 相关的显示和刷新率控制。

```bash
gs android surface show_refresh_rate <0|1>    # 显示/隐藏刷新率
gs android surface set_refresh_rate <rate>    # 设置刷新率
gs android surface dump_refresh_rate          # 导出刷新率信息
```

### 🔧 system - 系统管理
系统级别的配置、优化和管理功能。

```bash
gs android system selinux-disable          # 禁用 SELinux
gs android system hidden-api-enable        # 启用 Hidden API
gs android system hidden-api-disable       # 禁用 Hidden API
gs android system settings-dump            # 导出系统设置
gs android system remove-dex2oat           # 清理 dex2oat 缓存
gs android system abx2xml <file>           # ABX 格式转 XML
gs android system imei                     # 获取设备 IMEI
```

### 🎨 winscope - UI 分析
Android UI 层次结构分析和调试工具。

```bash
gs android winscope start              # 启动 Winscope UI
gs android winscope aosp               # 启动 AOSP 版本
gs android winscope proxy              # 启动代理服务器
gs android winscope files              # 列出可用的分析文件
gs android winscope status             # 检查服务状态
```

**特性：**
- 跨平台浏览器启动支持
- 本地代理服务器模式
- 智能 HTML 文件搜索

## 🛠️ 环境要求

### 基础要求
- **ADB (Android Debug Bridge)** - 必须安装并配置到 PATH
- **Python 3.7+** - 插件运行环境
- **USB 调试已启用** - 设备端开启开发者选项

### 可选组件
- **Frida 二进制文件** - 用于动态分析功能
  - 下载地址：https://github.com/frida/frida/releases
  - 需要的文件：`frida-inject`, `frida-server`
  - 放置位置：`plugins/android/frida/`

- **Perfetto 配置** - 用于性能追踪
  - 支持自定义 Protocol Buffer 配置文件
  - 内置默认配置可直接使用

### 设备要求
- **Android 4.4+** - 基础功能支持
- **Root 权限** - 部分高级功能需要（Frida、系统级操作）
- **网络连接** - 无线调试功能需要

## 🔍 常用命令

### 设备诊断
```bash
# 完整设备信息检查
gs android dump build && gs android dump battery && gs android device size

# 内存和性能检查
gs android dump meminfo && gs android dump top 5

# 应用状态检查
gs android app version com.example.app && gs android app log com.example.app
```

### Android 源码编译流程
```bash
# 1. 检查编译环境
gs android build status

# 2. 查看可编译模块
gs android build modules

# 3. 编译特定模块
gs android build make -m framework -j 8

# 4. 完整系统编译
gs android build build -t sdk_pc_x86_64-userdebug -c 1

# 5. 高通QSSI编译
gs android build qssi -j 16 -b <feishu_token>
```

### 性能分析流程
```bash
# 1. 开始性能追踪
gs android perfetto default trace_output

# 2. 执行操作...

# 3. 分析 UI 层次
gs android winscope start

# 4. 查看实时日志
gs android logcat tail
```

### 应用调试流程
```bash
# 1. 查找目标应用
gs android app list-3rd | grep -i target

# 2. 查看应用信息
gs android app version com.target.app

# 3. 启动 Frida 调试
gs android frida inject -p com.target.app -f debug_script.js

# 4. 监控应用日志
gs android app log com.target.app
```

## 🚨 故障排除

### 常见问题

**1. 设备未找到**
```bash
# 检查 ADB 连接
adb devices

# 重启 ADB 服务
adb kill-server && adb start-server

# 检查插件设备状态
gs android device devices
```

**2. 权限被拒绝**
```bash
# 获取 Root 权限
adb root

# 重新挂载系统分区
adb remount

# 检查 SELinux 状态
gs android system selinux-disable
```

**3. Frida 相关问题**
```bash
# 检查 Frida 环境
gs android frida status

# 下载必需的二进制文件
# 访问：https://github.com/frida/frida/releases
# 下载对应架构的 frida-inject 和 frida-server
```

**4. 网络连接问题**
```bash
# 启用 TCP 连接
adb tcpip 5555

# 连接网络设备
gs android device connect <device_ip>:5555

# 验证连接
gs android device current
```

### 调试技巧

1. **使用设备选择功能** - 多设备环境下先用 `gs android device choose` 选择目标设备
2. **文件搜索优先级** - Frida 和 Perfetto 会优先搜索当前目录的配置文件
3. **日志过滤** - 使用 `gs android logcat filter` 进行关键字过滤而非阻塞式监听
4. **路径别名** - 使用 `gs android fs common` 查看常用路径映射，简化文件操作

## 📖 更多信息

- **插件开发文档** - 参考 `gs_system` 核心框架
- **子插件示例** - 查看各子插件的 `plugin.py` 实现
- **配置管理** - 设备选择等配置通过 `plugins.android.common` 持久化

---

**版本**: 6.0.0  
**作者**: Global Scripts Team  
**更新**: 2024年最新版本，支持 Android 14+