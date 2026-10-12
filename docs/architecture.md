# 架构设计

Global Scripts（GS）6.0 的架构说明。协议细节见 [插件协议](./protocol.md)。

## 1. 范围与原则

GS 6.0 是**唯一运行时**。GS 5.2 的 Python 实现（`src/gscripts`、`router.json`
派发、`plugin.json`/`commands.json`）已整体退役，见
[ADR 005](./adr/005-retire-gs52-python-runtime.md)。

四条原则：

1. **单一事实来源**：每个插件目录只有一个 `plugin.toml`，它同时定义命令树、
   能力与元数据。没有 `plugin.json`、没有装饰器扫描、没有 `router.json` 索引。
2. **核心无副作用**：`gs-core` 只做纯逻辑（解析、发现、补全、绑定、能力检查、
   帧编解码），从不 spawn 进程，因此可以完整单测。
3. **默认拒绝**：插件要在 manifest 里显式声明它需要执行什么、读写哪里、
   读哪些环境变量。
4. **分层惰性**：发现只读 `plugin.toml`；命令树按需内联解析或走一次
   `describe`，因此 Tab 补全和 `gs help` 不会启动任何插件。

## 2. 分层

```
┌──────────────────────────────────────────────────────────────┐
│ 前门  rust/crates/gs                                         │
│   main.rs      入口 / 引导 / 分发                            │
│   dispatch.rs  T1 exec、T2/T3 invoke、cd/env 副作用           │
│   plugin.rs    gs plugin list|info|enable|disable|migrate     │
│   shell.rs     gs __complete / completions / shell-init       │
│   system.rs    gs status / doctor / refresh                   │
│   init.rs      gs init（读 config/init.toml 的步骤清单）       │
│   ui.rs        唯一的展示层（tabled + 颜色）                   │
└───────────────────────────┬──────────────────────────────────┘
                            │ 纯函数调用
┌───────────────────────────▼──────────────────────────────────┐
│ 核心  rust/crates/gs-core                                    │
│   manifest.rs  plugin.toml schema + 归一化命令模型            │
│   index.rs     惰性发现 / 命令索引 / 程序解析                  │
│   engine.rs    位置补全（Tab）                                │
│   exec.rs      T1 argv 绑定 + run 模板渲染                    │
│   rpc.rs       JSON-RPC 2.0 + LSP 帧 + 一次性通道              │
│   daemon.rs    T3 常驻插件守护进程                             │
│   cache.rs     describe / complete 磁盘缓存                    │
│   caps.rs      能力仲裁（默认拒绝）                            │
│   migrate.rs   plugin.json → plugin.toml（迁移工具）           │
│   init.rs      config/init.toml 的步骤模型                     │
└───────────────────────────┬──────────────────────────────────┘
                            │ stdio / socket
┌───────────────────────────▼──────────────────────────────────┐
│ 插件  plugins/<name>/  +  SDK  sdk/python/gs_plugin            │
│   T1 declarative：无进程，核心渲染 argv 直接执行               │
│   T2 script / T3 rpc：JSON-RPC over stdio                      │
│   T4 wasm：wasmtime 运行 .wasm                                 │
└──────────────────────────────────────────────────────────────┘
```

## 3. 目录结构

```
global_scripts/
├── rust/                      # Rust 前门与核心
│   └── crates/{gs,gs-core}/
├── plugins/<name>/            # 正式插件（每个一个 plugin.toml）
├── examples/                  # 插件示例（仅 GS_INCLUDE_EXAMPLES=1 时加载）
├── sdk/python/gs_plugin/      # T2/T3 插件 SDK（stdlib-only）
├── config/init.toml           # gs init 的装机步骤清单
├── config/gs.json             # 用户偏好（language / prompt_theme）
├── themes/prompt/             # 提示符主题
├── custom/                    # 私有区（.gitignore 排除）
├── scripts/                   # 安装 / 打包 / 验收工具
└── docs/                      # 文档（协议见 protocol.md）
```

## 4. 一次调用的路径

```
gs <args>
  │
  ├─ 前门命令？(version/help/status/doctor/init/plugin/completions/shell-init…)
  │     → 原生处理
  │
  ├─ <args[0]> 是插件名？
  │     → 读 plugins/<name>/plugin.toml
  │       ├─ T1  → exec.rs 绑定 argv、渲染 run（或 cd）→ 受 exec 能力约束地执行
  │       ├─ T2  → rpc.rs 起一次进程，describe/invoke
  │       ├─ T3  → daemon.rs 复用常驻进程
  │       └─ T4  → wasmtime 运行模块
  │
  └─ 都不是 → 明确报错（提示 gs help / gs plugin list）
```

**没有 Python 兜底，也没有 `router.json` 回退**：未知输入直接失败并给出下一步。

### 4.1 插件分层（tier）

| tier | 别名 | 核心行为 | 何时选它 |
|---|---|---|---|
| `declarative` | T1 | 起进程数为 0 | 纯 `git`/`echo` 之类的命令封装 |
| `script` | T2 | 每次调用启一个解释器 | 需要真正逻辑、调用不频繁 |
| `rpc` | T3 | 常驻进程复用 | 需要逻辑且频繁调用（省冷启动） |
| `wasm` | T4 | wasmtime 执行 | 想用沙箱或非 Python 实现 |

## 5. 关键设计

### 5.1 单一数据模型，跨 tier 同构

`plugin.toml` 里内联的命令树与 T2+ 运行时 `describe` 返回的结构**完全同构**
（都用 `CommandSpec`）。补全、帮助、参数校验因此对 tier 无感：同一个
`engine::complete` 服务所有插件。

### 5.2 补全（Tab）的热路径

每次按键都是一个新进程，所以：

- 发现只解析 `plugin.toml`（不启动插件）；
- T1 的 `enum`/`file`/`dir` 完全静态，零回调；
- T1 动态补全由核心执行 manifest 里的命令（受能力约束）；
- T2+ 的 `describe`/`complete` 批量到**一次**进程启动，并落盘缓存
  （键含 manifest 与 entry 的 mtime、协议版本、语言）。

### 5.3 能力与安全

`[capabilities]` 默认全拒绝。`exec`/`env` 由核心**强制**（核心控制 spawn 与子进程
环境）；`fs`/`net` 目前是建议性声明并回传给插件，真正的沙箱留给后续 OS 设施。

危险操作约定：写操作必须显式 `--dry-run` 或 `--yes`，`gs` 自身**从不**提权，
只打印 `sudo …` 让用户自己执行。

### 5.4 常驻插件（T3）

socket 路径带插件内容的 generation 哈希（改插件即换路径）、空闲超时退出、
“客户端中途消失即毒化该 daemon” 避免回包错投、不可用时自动退化为一次性通道。
细节见 [protocol.md §8](./protocol.md)。

### 5.5 展示层

所有输出集中在 `gs/src/ui.rs` 一个模块：`tabled` 出表格、`anstyle` 上色、
`indicatif` 出进度。规则：无 emoji、可 `NO_COLOR`、宽度自适应、非 TTY 时降级。

## 6. 扩展点

- **加一条命令**：改对应插件的 `plugin.toml`（T1）或插件脚本里的
  `@plugin.command`（T2/T3）。
- **加一个插件**：新建 `plugins/<name>/plugin.toml` + 入口脚本，参照
  [插件开发](./plugin-development.md) 与 [protocol.md 附录](./protocol.md)。
- **加一个前门命令**：在 `gs/src/main.rs` 的 `run()` 注册，实现放到对应模块。
- **装机步骤**：改 `config/init.toml`，`gs init` 自动反映。

## 7. 与 5.2 的关系

GS 5.2 的 Python 实现已从仓库退役（`src/gscripts`、`tests/`、`scripts/setup.py`、
`plugin.json`/`plugin.py`、`router.json` 派发路径）。仍在迁移自己老插件的用户
可以用 `gs plugin migrate <dir>` 把 `plugin.json` 转成 `plugin.toml`。
决策记录见 [docs/adr](./adr/)。

## 相关文档

- [插件协议](./protocol.md) — manifest / RPC / 缓存 / daemon 规范
- [插件开发](./plugin-development.md) — 从零写一个插件
- [安装](./installation.md) · [快速开始](./quickstart.md)
- [迁移状态](./migration-status.md)
