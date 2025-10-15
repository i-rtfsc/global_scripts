# Android FS 子插件使用说明

Android FS 子插件提供常用的 push/pull 文件操作，并内置多个常见系统文件/库的“别名”（COMMON_PATHS），让你不必记忆或输入冗长的设备路径。

## 功能概览
- push / pull：支持直接使用设备路径或“别名”。
- 别名辅助：列出别名、解析别名到设备真实路径、批量校验存在性。
- 查找与浏览：find_apk、locate_so、exists、ls。

建议先连接设备并选择默认设备：
- gs android device devices
- gs android device choose

---

## 快速开始
- 使用别名直接拉取 libgpuservice.so 到当前目录：
  - gs android fs pull libgpuservice .
- 使用别名推送 framework.jar（写系统分区通常需要 root+remount）：
  - gs android fs push ./framework.jar framework
- 查看所有内置别名：
  - gs android fs common
- 解析别名到设备上的真实路径：
  - gs android fs resolve libgui
- 校验所有内置别名在设备上的存在性：
  - gs android fs verify

---

## 常用命令与示例

### 1) push / pull（支持别名）
- 推送：
  - 用法：gs android fs push <local> <remote|alias>
  - 示例：
    - gs android fs push app.apk /sdcard/app.apk
    - gs android fs push ./framework.jar framework
- 拉取：
  - 用法：gs android fs pull <remote|alias> <local>
  - 示例：
    - gs android fs pull /sdcard/log.txt ./log.txt
    - gs android fs pull libgpuservice ./libgpuservice.so

说明：当第二个参数是已知别名时，会先解析为设备上真实存在的路径；若多个候选，取第一个存在的路径作为最终位置。若均不存在，push 会使用候选列表中的首个路径作为目标（常用于你要写入的“应当位置”）。

### 2) push_common / pull_common（别名专用）
- 推送到别名：
  - 用法：gs android fs push_common <local> <name>
  - 示例：gs android fs push_common ./framework.jar framework
- 从别名拉取：
  - 用法：gs android fs pull_common <name> <local>
  - 示例：gs android fs pull_common libgui ./libgui.so

### 3) 别名工具（COMMON_PATHS）
- 列出所有别名与候选路径：
  - gs android fs common
- 解析别名到“当前设备上真实存在”的路径：
  - gs android fs resolve <name>
- 批量校验所有别名是否存在：
  - gs android fs verify

### 4) 查找/浏览
- 判断设备路径是否存在：
  - gs android fs exists /system/bin/sh
- 列出文件或目录（简易 ls -l）：
  - gs android fs ls /system/lib64
- 查找某个包名对应 APK 路径：
  - gs android fs find_apk com.android.settings
- 在常见库目录中定位某个 .so：
  - gs android fs locate_so libgui.so

---

## 内置别名（节选）
> 完整列表请执行：gs android fs common

- framework -> /system/framework/framework.jar
- libgpuservice -> /system/lib64/libgpuservice.so, /system/lib/libgpuservice.so
- libgui -> /system/lib64/libgui.so, /system/lib/libgui.so
- libinputflinger -> /system/lib64/libinputflinger.so, /system/lib/libinputflinger.so
- libui, libbinder, libandroid_runtime.so 等
- systemui_apk、settings_apk、bootanimation 等资源类条目

说明：
- 同一别名可能包含多个候选路径（不同设备/版本路径差异），解析时会自动挑选“当前设备上存在”的那个。

---

## 常见场景
- 拉取 GPU Service 动态库：
  - gs android fs pull libgpuservice .
- 推送 framework.jar（需要 root + remount）：
  - gs android fs push ./framework.jar framework
  - 可先检查别名指向：gs android fs resolve framework
- 查找 APK 路径：
  - gs android fs find_apk com.android.settings
- 定位某个 .so：
  - gs android fs locate_so libandroid_runtime.so

---

## 权限与注意事项
- 写入 /system/ 等受保护路径通常需要：
  - adb root（设备允许）
  - adb remount（只读分区改为可写）
  - 这些步骤暂未在 fs 中自动执行，可在 device 子插件中添加或手工执行；如需，我可以为你补充 fs root / fs remount / chmod / chown 等便捷命令。
- APEX/分区差异：新系统中部分组件位于 APEX（/apex/...），路径可能因版本/ROM 定制不同而变化。
- SELinux：系统库替换可能需要正确的上下文与权限，当前插件不自动处理。

---

## 扩展别名
- 直接编辑本目录的 `plugin.py` 中的 `COMMON_PATHS` 字典，按现有格式新增/修改即可。
- 支持为一个别名配置多个候选路径，解析时会自动选择存在的路径。

如需我将 root/remount/权限设置等能力集成到 fs，请告诉我你的具体习惯流程，我可以继续完善。
