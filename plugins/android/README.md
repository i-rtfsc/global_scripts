# Android 插件

Android开发工具集，提供ADB管理、构建编译、动态分析、文件推送、源码搜索等全方位Android开发支持。

## 📋 概述

Android插件是Global Scripts v3系统的核心插件之一，专为Android开发者设计。它集成了Android开发过程中最常用的工具和工作流，让开发者能够更高效地进行Android应用和系统开发。

### 🎯 核心特性

- **智能设备管理**: 自动设备选择和缓存，支持多设备环境
- **完整ADB工具链**: 截屏、录屏、日志监控、应用管理等
- **构建系统支持**: AOSP编译、模块构建、ccache优化
- **动态分析工具**: Frida集成，支持Hook和实时调试
- **开发推送工具**: 快速部署系统组件和应用
- **源码搜索引擎**: 针对AOSP源码优化的搜索工具

## 🏗️ 插件架构

```
plugins/android/
├── android.meta              # 主插件元数据
├── android.sh                # 主插件入口
├── README.md                 # 插件文档
├── tests/                    # 测试套件
│   └── test_android.sh       # 自动化测试
├── adb/                      # ADB工具子模块
│   ├── adb.meta
│   ├── adb.sh
│   └── tests/
├── build/                    # 构建工具子模块
│   ├── build.meta
│   ├── build.sh
│   └── tests/
├── frida/                    # 动态分析子模块
│   ├── frida.meta
│   ├── frida.sh
│   └── tests/
├── push/                     # 推送工具子模块
│   ├── push.meta
│   ├── push.sh
│   └── tests/
└── grep/                     # 搜索工具子模块
    ├── grep.meta
    ├── grep.sh
    └── tests/
```

## 🚀 快速开始

### 安装依赖

确保系统已安装以下工具：

```bash
# 基础工具
adb           # Android Debug Bridge
fastboot      # Android刷机工具
python3       # Python 3.x

# 可选工具
ccache        # 编译缓存(Linux推荐)
frida-tools   # Frida动态分析工具
aapt          # Android资源打包工具
```

### 基础使用

```bash
# 查看连接的设备
gs-android-devices

# 连接网络设备
gs-android-connect 192.168.1.100

# 获取设备信息
gs-android-info

# 进入设备shell
gs-android-shell
```

## 📱 ADB工具模块

### 设备管理

```bash
# 查看设备列表
gs-android-devices

# 连接网络设备
gs-android-connect <IP地址> [端口]

# 获取设备详细信息
gs-android-info [设备ID]

# 设备shell
gs-android-shell [-d 设备ID] [命令]
```

### 屏幕捕获

```bash
# 截屏
gs-android-adb-screenshot [文件名] [设备ID]

# 录屏 (默认30秒)
gs-android-adb-screenrecord [文件名] [时长] [设备ID]
```

### 日志监控

```bash
# 监控应用日志
gs-android-adb-logcat -p com.example.app

# 监控系统日志
gs-android-adb-logcat -l I

# 过滤特定设备
gs-android-adb-logcat -d emulator-5554
```

### 应用管理

```bash
# 安装APK
gs-android-adb-install app.apk [-f] [--test]

# 卸载应用
gs-android-adb-uninstall com.example.app [-k]

# 清除应用数据
gs-android-adb-clear com.example.app

# 启动应用
gs-android-adb-start com.example.app [Activity]

# 强制停止应用
gs-android-adb-kill com.example.app
```

### 智能设备选择

插件实现了智能设备管理机制：

1. **自动选择**: 如果只有一个设备，自动使用该设备
2. **列表优先**: 多设备时自动选择列表中第一个
3. **设备缓存**: 输入设备ID后，后续命令会自动复用
4. **状态验证**: 自动验证设备连接状态

```bash
# 首次指定设备
gs-android-adb-screenshot myscreen emulator-5554

# 后续命令自动使用缓存的设备ID
gs-android-adb-logcat -p com.example.app
```

## 🔨 构建工具模块

### 环境设置

```bash
# 设置构建环境
gs-android-build-lunch sdk_phone_x86_64-userdebug

# 查看构建信息
gs-android-build-info
```

### 模块编译

```bash
# 编译单个模块
gs-android-build-module framework

# 指定并行数和ccache
gs-android-build-module services -j 16 --ccache true
```

### 全量编译

```bash
# 完整编译
gs-android-build-full

# 指定参数编译
gs-android-build-full -j 8 --target sdk_phone_x86_64-userdebug
```

### 编译清理

```bash
# 增量清理
gs-android-build-clean incremental

# 完全清理
gs-android-build-clean full
```

## 🔍 源码搜索模块

### 按语言搜索

```bash
# Java文件搜索
gs-android-grep-java "onCreate"

# C/C++文件搜索
gs-android-grep-cpp "main"

# Kotlin文件搜索
gs-android-grep-kotlin "fun "

# XML文件搜索
gs-android-grep-xml "android:name"
```

### 按文件类型搜索

```bash
# AndroidManifest.xml搜索
gs-android-grep-manifest "permission"

# 构建文件搜索
gs-android-grep-makefile "LOCAL_MODULE"

# 资源文件搜索
gs-android-grep-resource "string name"

# 全源码搜索
gs-android-grep-source "SystemProperties"
```

## 🔧 推送工具模块

### 文件推送

```bash
# 推送单个文件
gs-android-push-file local.so /system/lib64/local.so

# 推送并重启框架
gs-android-push-file framework.jar /system/framework/framework.jar --restart
```

### 系统组件推送

```bash
# 推送Framework
gs-android-push-framework [-t 构建目标] [--no-restart]

# 推送Services
gs-android-push-services [-o 输出目录] [-t 构建目标]

# 推送APK
gs-android-push-apk app.apk [-p 包名]
```

## 🎯 动态分析模块

### Frida Server管理

```bash
# 启动Frida Server
gs-android-frida-server start

# 检查运行状态
gs-android-frida-server status

# 停止Frida Server
gs-android-frida-server stop
```

### 脚本注入

```bash
# 注入脚本到进程
gs-android-frida-inject -p system_server -f hook.js

# 注入到应用进程
gs-android-frida-inject -p com.example.app -f trace.js
```

### 进程管理

```bash
# 查看可hook进程
gs-android-frida-ps

# 应用函数跟踪
gs-android-frida-trace com.example.app -t "java.io.*"
```

## ⚙️ 配置选项

### 环境变量

```bash
# Android SDK路径
export GS_ANDROID_SDK_PATH="/path/to/sdk"

# 调试模式
export GS_DEBUG_MODE=true

# 缓存目录
export GS_CACHE_DIR="$HOME/.gs_cache"
```

### 设备缓存

设备ID缓存文件位置: `$HOME/.gs_android_device_cache`

可手动编辑或删除此文件来重置设备选择。

## 🧪 测试

运行插件测试套件：

```bash
# 执行所有测试
./plugins/android/tests/test_android.sh

# 检查插件结构完整性
# 验证函数加载正确性
# 测试错误处理机制
```

## 🔧 开发指南

### 添加新功能

1. **确定子模块**: 根据功能分类选择合适的子模块
2. **遵循命名规范**: 使用`gs_android_<子模块>_<功能>`格式
3. **实现帮助系统**: 每个函数都要有对应的help函数
4. **错误处理**: 实现完善的参数验证和错误提示
5. **设备兼容**: 利用设备缓存和智能选择机制

### 函数命名规范

```bash
# 公开函数 (生成命令)
gs_android_adb_screenshot()     # → gs-android-adb-screenshot

# 私有函数 (内部使用)
_gs_android_adb_check_device()  # 不生成命令

# 帮助函数 (必需)
_show_android_adb_screenshot_help()
```

### 代码示例

```bash
gs_android_new_feature() {
    local param1="${1:-}"
    local param2="${2:-}"
    
    # 1. 帮助信息处理
    if [[ "$param1" == "--help" || "$param1" == "-h" ]]; then
        _show_android_new_feature_help
        return 0
    fi
    
    # 2. 参数验证
    if [[ -z "$param1" ]]; then
        echo "错误: 缺少必需参数" >&2
        echo "使用方式: gs-android-new-feature <参数1>" >&2
        return 1
    fi
    
    # 3. 依赖检查
    _gs_android_check_deps || return 2
    
    # 4. 核心功能实现
    echo "执行功能: $param1"
    
    # 5. 错误处理和返回
    return 0
}
```

## 📚 参考资料

- [Android Debug Bridge (ADB)](https://developer.android.com/studio/command-line/adb)
- [Android Open Source Project](https://source.android.com/)
- [Frida Dynamic Instrumentation](https://frida.re/)
- [Global Scripts v3 插件开发规范](../../../docs/技术规范/01-开发规范与标准.md)

## 🤝 贡献

1. Fork 项目
2. 创建功能分支
3. 遵循代码规范
4. 添加测试用例
5. 提交 Pull Request

## 📄 许可证

本插件采用 Apache License 2.0 许可证。详见 [LICENSE](../../../LICENSE) 文件。

---

**注意**: 使用本插件进行Android开发时，请确保遵守相关法律法规和设备使用政策。某些功能可能需要root权限或特定的系统版本支持。