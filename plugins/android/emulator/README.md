# Android Emulator 子插件

## 📱 功能简介

Android Emulator 子插件提供了在不打开 Android Studio 的情况下管理 Android 模拟器的快捷命令。

## 🎯 核心特性

- **快速启动/停止** - 无需打开 Android Studio
- **自动检测** - 自动查找 Android SDK emulator 路径
- **状态监控** - 实时查看模拟器运行状态
- **批量管理** - 支持管理多个模拟器

## 📋 可用命令

### 1. 列出所有模拟器
```bash
gs android emulator list
```

**输出示例**:
```
📱 Available Android Emulators:
  • Pixel_6_Pro_API_34 ⚪ Stopped
  • Pixel_5_API_33 🟢 Running

✅ Running emulators: emulator-5554
```

### 2. 启动模拟器
```bash
# 启动第一个可用的模拟器
gs android emulator start

# 启动指定的模拟器
gs android emulator start Pixel_6_Pro_API_34
```

**输出示例**:
```
🚀 Starting emulator 'Pixel_6_Pro_API_34' in background...
   Use 'gs android emulator status' to check status
```

**说明**:
- 模拟器会在后台启动
- 如果不指定名称，会启动第一个可用的 AVD
- 启动需要几秒到几十秒时间，取决于模拟器配置

### 3. 停止模拟器
```bash
# 停止所有正在运行的模拟器
gs android emulator stop

# 停止指定的模拟器
gs android emulator stop emulator-5554
```

**输出示例**:
```
✅ Stopped emulator-5554
```

### 4. 重启模拟器
```bash
# 重启第一个可用的模拟器
gs android emulator restart

# 重启指定的模拟器
gs android emulator restart Pixel_6_Pro_API_34
```

**说明**:
- 会先停止正在运行的模拟器
- 等待2秒后重新启动

### 5. 查看状态
```bash
gs android emulator status
```

**输出示例**:
```
📱 Emulator Status:
   Emulator Path: /Users/solo/Library/Android/sdk/emulator/emulator
   Total AVDs: 2
   Running: 1

📋 Available AVDs:
   • Pixel_6_Pro_API_34
   • Pixel_5_API_33

🟢 Running Emulators:
   • emulator-5554
```

### 6. 显示模拟器路径
```bash
gs android emulator path
```

**输出示例**:
```
Emulator: /Users/solo/Library/Android/sdk/emulator/emulator
```

## 🔧 技术实现

### 路径检测策略

插件会按以下优先级查找 emulator 路径：

1. **macOS**: `~/Library/Android/sdk/emulator/emulator`
2. **Linux**: `~/Android/Sdk/emulator/emulator`
3. **环境变量**: `$ANDROID_HOME/emulator/emulator`
4. **系统 PATH**: 使用 `which emulator`

### 状态检测

通过 `adb devices` 命令检测模拟器运行状态：
- 模拟器设备名称格式: `emulator-xxxx`
- 状态: `device` 表示正在运行

### 后台启动

使用异步进程启动模拟器，输出重定向到 `/dev/null`，避免阻塞终端。

## 📊 与其他子插件的关系

### vs. device 子插件

| 功能 | device | emulator |
|------|--------|----------|
| 管理对象 | 真实设备 + 模拟器 | 仅模拟器 |
| 连接设备 | ✅ | ❌ |
| 启动/停止 | ❌ | ✅ |
| 截屏 | ✅ | 使用 device 命令 |
| 设备选择 | ✅ | 使用 device 命令 |

**最佳实践**:
1. 使用 `emulator` 子插件启动/停止模拟器
2. 使用 `device` 子插件进行设备交互（截屏、连接等）

## 🚀 使用场景

### 场景1: 快速启动模拟器进行测试
```bash
# 启动模拟器
gs android emulator start

# 等待设备就绪
gs android device wait

# 安装 APK
adb install app.apk
```

### 场景2: 多模拟器管理
```bash
# 查看所有模拟器
gs android emulator list

# 启动特定模拟器
gs android emulator start Pixel_6_Pro_API_34

# 查看运行状态
gs android emulator status

# 停止所有模拟器
gs android emulator stop
```

### 场景3: 自动化脚本
```bash
#!/bin/bash
# 自动化测试脚本

# 启动模拟器
gs android emulator start Pixel_6_Pro_API_34

# 等待启动完成（检测到设备）
timeout=60
elapsed=0
while [ $elapsed -lt $timeout ]; do
    if adb devices | grep -q "emulator.*device"; then
        echo "✅ Emulator is ready"
        break
    fi
    sleep 2
    elapsed=$((elapsed + 2))
done

# 运行测试
./gradlew connectedAndroidTest

# 停止模拟器
gs android emulator stop
```

## ⚠️ 注意事项

### 1. 首次使用
- 确保已安装 Android SDK
- 在 Android Studio 中创建至少一个 AVD
- 设置 `ANDROID_HOME` 环境变量（可选）

### 2. 启动时间
- 冷启动通常需要 20-60 秒
- 使用快照可以加快启动速度
- 第一次启动会比较慢

### 3. 资源占用
- 模拟器会占用大量内存（2-4GB）
- 建议关闭不用的模拟器释放资源

### 4. 多模拟器
- 可以同时运行多个模拟器
- 每个模拟器有唯一的序列号（emulator-xxxx）
- 使用 `gs android device choose` 选择操作的模拟器

## 🐛 常见问题

### Q1: 提示找不到 emulator
**A**: 检查以下几点：
1. 确认 Android SDK 已安装
2. 设置 `ANDROID_HOME` 环境变量
3. 或将 `$ANDROID_HOME/emulator` 添加到 PATH

### Q2: 启动后没有反应
**A**: 模拟器在后台启动需要时间，使用以下命令监控：
```bash
# 查看状态
gs android emulator status

# 查看 adb 设备
adb devices

# 查看进程
ps aux | grep emulator
```

### Q3: 如何关闭卡住的模拟器
**A**:
```bash
# 使用插件停止
gs android emulator stop

# 如果失败，强制杀进程
pkill -9 -f "qemu.*avd"
```

## 📚 相关文档

- [Android Emulator 官方文档](https://developer.android.com/studio/run/emulator-commandline)
- [ADB 命令参考](https://developer.android.com/studio/command-line/adb)
- [Global Scripts Android 插件](../README.md)

## 🎉 总结

Android Emulator 子插件为开发者提供了快速、便捷的模拟器管理工具，无需打开 Android Studio 即可：

✅ 快速启动/停止模拟器
✅ 实时查看运行状态
✅ 支持多模拟器管理
✅ 适合自动化脚本集成

---

**作者**: Claude Code
**创建时间**: 2025-10-01
**版本**: v1.0.0
