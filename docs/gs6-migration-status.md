# GS 6.0 插件迁移状态

[English](./en/gs6-migration-status-en.md)

GS 6.0 迁移使用源码仓库中的正式 `plugins/` 目录和正式插件名。版本隔离由
Rust 开发版入口与当前工作区环境完成；不创建 `plugins-v6/`，也不保留
`system6`、`grep6` 等版本后缀作为最终名称。
当前所有正式 GS6 插件统一标记为 `6.0.0-dev`，表示仍处于开发验收阶段，尚未替换全局 5.2。
`gs6 plugin` 的库存视图包含 15 个 GS6 正式插件，不再包含 legacy 展示项；`menubar` 按设计不进入 GS6，并在统计信息中标记为已移除。
注意：`scripts/setup.py` 是 5.2 legacy 安装器，会生成旧 router/env 文件；GS6 开发和验收不运行它。

## 已迁移并验证

| 插件 | GS 6.0 范围 | 状态 |
|---|---|---|
| system | 只读系统/提示符能力 | 已有 `plugin.toml`，E2E 通过 |
| grep | 安全 shell-free 搜索 | 已有 `plugin.toml`，E2E 通过 |
| spider | 目标识别与受控联网抓取 | 真实博客园抓取通过；20 秒/5 MiB/输出目录门禁有效 |
| multirepo | 状态、manifest、计划与显式 Git apply | 本地 bare 仓库真实 clone/checkout 通过；repo 后端仍要求手动执行计划 |
| vscode | 路径、profile、计划与显式启动 | 假 `code` 执行器验证启动参数通过，真实执行要求 `--yes` |
| dotfiles | 状态、内容、计划与安全 apply | 临时 HOME 安装/备份/卸载通过；Nvim 配置树与当前系统 22 个文件逐项一致 |
| alias | source/list/show/doctor | 已有 `plugin.toml`，E2E 通过 |
| navigator | T1 目录导航和只读命令 | 前门 E2E 通过，列表路径正确展开 `$HOME` |
| android | T2 Android device/logcat/dump/fs/emulator/input 迁移入口 | 已合并到正式 `plugins/android` 目录；只读命令已用真实 ADB 设备验证，危险操作保持 dry-run |
| devenv | T2 开发环境检查、计划与显式安装 | 假 brew 验证真实执行参数通过，安装要求 `--yes` |
| flyme | 兼容 5.2 的 build/flash/info 示例行为 | 已迁入正式插件目录并通过 T2 E2E |
| sync | Git 工作区状态、SCP 计划和显式文件同步 | 临时 Git 仓库到临时目标目录真实复制通过 |
| vps | SSH、反向隧道和 SSHFS 挂载管理 | 8 条命令已迁移；写操作均要求 `--dry-run` 或 `--yes` |
| identity | 模型账号/节点切换、Git 与 SSH 私有配置 | 28 条命令已迁移；发布包不包含任何私钥、API key 或私有配置 |
| sgm | App 构建部署、公司连接、Gerrit push 与 SSH 配置 | 14 条命令已迁移；公司资产和密钥不进入发布包 |

## 已完成的最终验收

- `plugins/android`: GS 6.0 `plugin.toml` 已与旧 `plugin.json` 并存；旧子插件
  （emulator/input/fs/app 等）继续保留用于 5.2 兼容，GS 6.0 入口已逐项实现核心能力。
  当前真实设备 `ac7dbd4` 已验证：`device devices/current/size`、`dump battery/build/activity/packages`、
  `fs exists/ls/verify/find_apk/locate_so`、`proc ps_grep`、`app list-system/version`、
  `logcat filter`、`frida status`、`emulator status`；`dump activity` 使用轻量焦点查询并兼容新版
  resumed-activity 输出。设备当前为 Android 14 automotive build；Frida arm64 二进制可用
  `scripts/fetch_frida_android_arm64.sh` 可从官方 Releases 获取；当前 arm64 资产已存在并纳入 staging 校验和。
  `fs exists` 仅接受安全绝对路径，拒绝 shell 元字符；有副作用的 input、emulator、build、screencap、screenrecord、Winscope 命令统一要求 `--dry-run` 或显式 `--yes`。本轮补充对 `app.kill/clear`、`proc.kill_grep`、SurfaceFlinger
  刷新率设置和 system 修改命令的 dry-run 门禁；`proc.ps_grep` 改为本地过滤，避免远端
  shell 拼接关键字。Perfetto 采集、Frida 注入和 Frida server 启停支持 dry-run 或显式 `--yes`；
  Frida status 保持只读可执行。
  本轮继续补齐 `logcat clear`、`fs push_common/pull_common` 和快捷按键的 dry-run/参数门禁；
  无设备时可通过离线前门测试验证；当前设备真实回归已完成。新增 `android doctor`
  汇总检查 adb、设备、SDK、emulator 以及 Winscope/Frida/Perfetto 资产；并补齐设备连接目标、
  `fs ls` 路径、`proc am-*` 包名的注入校验。代码迁移和 Android 设备真实回归均已完成。
  GS6 Android 设备选择状态已迁移到独立的 `GS_CACHE_DIR/android-gs6`（可用
  `GS6_ANDROID_STATE_DIR` 覆盖），不会再读取或写入 5.2 的
  `~/.config/global-scripts/config/android.json`；自动发现设备也不再隐式写入选择状态。
  Winscope 浏览器启动和代理启动支持显式 `--yes`，默认仍要求确认，避免 T2 调用遗留后台进程；
  `logcat clear` 已按用户授权开放真实执行，并已在设备 `ac7dbd4` 上验证，同时保留可选
  `--dry-run` 供自动验收使用；其余设备写操作
  仍按命令级风险逐项开放，保留参数校验和确认边界。
  ADB 网络设备的 `device connect/disconnect` 也已纳入 dry-run，离线 E2E 使用保留测试地址
  `192.0.2.1` 验证，不会改变本机 adb server 的连接状态。
  包名参数现统一使用白名单校验，覆盖 dump meminfo/appops、fs find_apk、proc am-*、
  app version/log/kill/clear，非法输入在启动 adb 前返回 2。
  `device screencap` 支持 `--yes` 真实保存 PNG，已在设备 `ac7dbd4` 上验证；`input screenrecord` 支持受时长限制的 `--yes` 真实录制，已验证 2 秒 MP4；`input text` 限制 500 字符并拒绝控制字符。
  Perfetto dry-run 会校验配置资产、当前目录内的 trace 输出路径和扩展名，并展示采集类别；
  Frida inject dry-run 会校验进程名和脚本资产，仅生成设备脚本路径，不上传或注入设备。
- `plugins/menubar`: GS 6.0 明确移除。旧 Python 菜单栏仅作为 5.2 legacy
  兼容代码保留，不迁移、不构建、不纳入 GS 6.0 验收。agent 状态灯永久删除。

## 验收规则

每个插件完成迁移前必须通过：

1. Rust manifest 校验；
2. GS 6.0 前门真实 E2E；
3. Python 全量非慢速测试；
4. SDK self-test；
5. 不修改全局 5.2 入口、用户配置和用户缓存。

CI 门禁同时执行 Rust workspace 测试、Rust 格式检查、仓库空白检查、GS6 前门验收和
Python SDK self-test；因此 Android 实机缺席不会阻塞其他 GS6 回归。
总验收还会对 14 个 Python GS6 入口执行 Python 3.8 AST 兼容性检查，避免在高版本 Python
上通过、但在 CI 最低版本上出现语法错误。
同时检查 Bash/Zsh/Fish/PowerShell 的 `completions` 和 `shell-init` 输出均走 Rust
`gs __complete`/原生进程调用，不引用 Python 旧 CLI 或旧 `router.json`。
`GS_CD_FILE` 仅接受临时目录内已存在、为空且非符号链接的普通文件，避免外部环境变量
误指向任意文件或覆盖已有内容。
总验收还会检查正式 `plugins/` 下每个目录名与 manifest `name` 一致、版本统一为
`6.0.0-dev`，并确认正式 manifest 数量为 15 个；examples 和 menubar 不计入发布面。

逐命令兼容性以 [GS6 命令兼容性审计](./gs6-command-parity.md) 为准。当前命令审计已归零；
后续仍需依靠真实 E2E、平台测试和副作用门禁判断功能是否存在回归，不能只看命令数量或
staging 是否通过。
验收按各插件实际命令契约检查 `plugin info`，不要求所有插件都提供同名 `doctor` 命令。
此外，总验收会实际执行每个正式插件的一个无副作用代表命令，验证运行时入口而非仅检查
manifest 文本。
设置 `GS_ROOT` 时，GS6 还会隔离用户插件目录和旧 `router.json`；只有显式设置
`GS_ALLOW_LEGACY=1` 才启用兼容回退，避免源码版 GS6 意外调用 5.2 插件。
隔离模式也会忽略环境中继承的 `GS_CACHE_DIR` 和 `ROUTER_INDEX` router 来源。
同理，`GS_PLUGIN_PATH` 在 GS6 隔离模式下不会覆盖源码插件根目录；需要外部插件时必须
显式开启 legacy 兼容模式。
兼容行为已通过独立前门测试验证：设置 `GS_ALLOW_LEGACY=1` 后，`GS_PLUGIN_PATH` 中的
外部插件可被发现；未设置时则保持隔离。
同一兼容开关也保留旧 `router.json` 的显式回退能力；默认 GS6 隔离模式不会读取该文件。

当前离线阶段门禁已全部通过；Android 真实设备回归此前也已通过
`scripts/verify_android_device.sh`，设备重新连接时可重复执行。

正式替换全局 `gs` 前请执行 [GS6 发布前检查清单](./gs6-release-checklist.md)，完成备份、
灰度和回滚验证；当前不会自动修改全局入口。
