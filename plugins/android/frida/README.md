# Android Frida 子插件

Android Frida 动态分析工具，支持JavaScript脚本注入和进程调试。

## 功能特性

- 🎯 JavaScript脚本注入到Android进程
- 🔧 frida-server管理（启动/停止/状态检查）
- 📜 智能脚本文件查找（优先当前目录，回退到插件目录）
- 📊 环境状态检查和二进制文件管理
- 🔍 可用脚本列表和描述显示

## 使用方法

### 基础命令

```bash
# 注入JavaScript脚本到进程
gs android frida inject -p <process> -f <script.js>

# 管理frida-server
gs android frida server <start|stop|status>

# 列出可用脚本
gs android frida scripts

# 检查环境状态
gs android frida status
```

### 详细示例

```bash
# 注入脚本到system_server进程
gs android frida inject -p system_server -f android-trace.js

# 注入脚本到指定应用
gs android frida inject -p com.example.app -f hook.js

# 启动frida-server
gs android frida server start

# 检查frida-server状态
gs android frida server status

# 停止frida-server
gs android frida server stop

# 列出所有可用的JavaScript脚本
gs android frida scripts

# 检查Frida环境完整性
gs android frida status
```

## 文件查找优先级

插件使用智能文件查找机制：

1. **优先级1**: 当前工作目录
   - 查找路径：`$(pwd)/script.js`
   
2. **优先级2**: 插件目录  
   - 查找路径：`/path/to/plugins/android/frida/script.js`

3. **绝对路径**: 直接使用指定的完整路径

## 环境准备

### 下载Frida二进制文件

首次使用需要从GitHub下载对应架构的Frida二进制文件：

**下载地址**: https://github.com/frida/frida/releases

**需要的文件**:
- `frida-inject` - 用于直接注入JavaScript脚本
- `frida-server` - 用于运行Frida服务器模式

**放置位置**: 
```
plugins/android/frida/
├── frida-inject      # ARM/ARM64版本
├── frida-server      # ARM/ARM64版本  
└── *.js              # JavaScript脚本
```

### Android设备要求

- 设备已获得ROOT权限
- ADB调试已开启
- 目标进程正在运行

## 内置JavaScript脚本

插件包含多个预置的JavaScript脚本：

- `android-app-info.js` - 应用信息收集
- `android-trace.js` - 系统调用追踪
- `android-binder-transactions.js` - Binder事务监控
- `android-database.js` - 数据库操作监控
- `android-broadcast.js` - 广播监控
- `android-click.js` - 点击事件监控
- `android-ui.js` - UI操作监控
- `android-settings-provider.js` - 设置提供者监控
- `android-system-property.js` - 系统属性监控

## 工作原理

### frida-inject 模式（推荐）

1. 将`frida-inject`和JavaScript脚本推送到设备
2. 直接在设备上执行注入，无需电脑端Frida环境
3. 简单高效，适合快速调试

### frida-server 模式

1. 在设备上运行`frida-server`
2. 电脑端通过网络连接进行控制
3. 支持更复杂的调试场景

## 故障排除

### 常见问题

**1. frida-inject 不存在**
```
下载frida-inject二进制文件并放置到插件目录
```

**2. 进程未找到**  
```
确认目标进程正在设备上运行
使用 gs android proc list 查看运行中的进程
```

**3. 权限被拒绝**
```
确认设备已获得ROOT权限
执行 adb root 获取ROOT权限
```

**4. 脚本文件未找到**
```
检查文件路径是否正确
使用 gs android frida scripts 查看可用脚本
```

### 调试技巧

1. 使用 `gs android frida status` 检查环境完整性
2. 使用 `gs android frida scripts` 查看可用脚本列表  
3. 检查设备日志：`adb logcat | grep frida`
4. 确认目标进程PID：`adb shell pidof <process_name>`

## 更多信息

- [Frida 官方文档](https://frida.re/docs/)
- [Frida JavaScript API](https://frida.re/docs/javascript-api/)
- [Android Hooking 指南](https://frida.re/docs/android/)