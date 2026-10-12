# Global Scripts

[中文](README.md) | [English](README_EN.md)

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Version](https://img.shields.io/badge/version-6.0.0--dev-brightgreen.svg)](https://github.com/i-rtfsc/global_scripts)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE)

> 用一个 `gs` 管住你的开发机：命令封装、Android 工具链、dotfiles、装机编排，
> 全部由 `plugin.toml` 描述，Rust 前门调度。

## 简介

Global Scripts（GS）6.0 是一个命令与插件系统。你输入 `gs <插件> <命令> [参数]`，
Rust 前门读该插件的 `plugin.toml`，按声明的分层（tier）执行：

- **T1 声明式**：整条命令就是一段 `run` 模板，核心直接渲染 argv 执行，**不起进程**；
- **T2 脚本 / T3 常驻**：插件以 JSON-RPC over stdio 应答，T3 复用常驻进程省冷启动；
- **T4 wasm**：用 wasmtime 跑沙箱模块。

命令树、参数、补全规则、能力声明都在同一个 `plugin.toml` 里——没有第二份清单，
也没有隐藏的加载器。

## 特性

- **单一事实来源**：一个插件一个 `plugin.toml`；补全、帮助、校验共用同一模型。
- **补全快**：发现只读 manifest，T1 静态补全零回调，T2+ 只启动一次并落盘缓存。
- **能力默认拒绝**：`exec` / `env` / `fs` / `net` 都要显式声明，`exec`/`env` 由核心强制。
- **安全默认**：写操作必须 `--dry-run` 或 `--yes`；`gs` 自己从不提权，只打印 `sudo …`。
- **可脚本化**：`--format=json` 的计划输出，方便接 CI。
- **无 emoji、可 `NO_COLOR`**：表格输出在管道里自动降级。

## 安装

### 从源码

```bash
git clone https://github.com/i-rtfsc/global_scripts.git
cd global_scripts

# 1. 构建 Rust 前门
cargo build --release --manifest-path rust/Cargo.toml -p gs

# 2. 生成 staging 树（dist/gs）
bash scripts/stage_release.sh

# 3. 安装到 ~/.local（不复制、不要 sudo）
bash scripts/install_gs.sh --yes
```

### 从发布包

下载对应平台的 `gs-<target>.zip`，解压后执行

```bash
bash scripts/install_gs.sh --yes
```

安装器只放两样东西：`~/.local/bin/gs` 的符号链接，以及
`~/.local/share/global-scripts/<version>/` 的实体目录。要装到别的前缀用
`GS_PREFIX=…`；要换命令名用 `--name`。卸载用 `scripts/uninstall_gs.sh --yes`。

## 系统要求

- **Rust**：1.75+（仅从源码构建时需要）
- **Python 3.8+**：T2/T3 插件需要（`gs doctor` 会检查它）
- **Shell**：bash / zsh / fish（PowerShell 实验支持）
- 不需要 `jq`、不需要 `uv`、不需要任何第三方 Python 包。

## 快速开始

```bash
gs help                       # 前门命令一览
gs plugin list                # 插件与命令数
gs doctor                     # 体检：manifest / entry / 插件运行时 / shell 集成
gs android device devices     # 跑一条插件命令
gs init --list                # 看装机步骤清单（config/init.toml）
```

开启补全与 `cd` 集成（三选一，加进对应 rc 文件）：

```bash
source <(gs shell-init bash)
source <(gs shell-init zsh)
gs shell-init fish > ~/.config/fish/conf.d/gs.fish
```

## 内置插件

| 插件 | 说明 |
|---|---|
| `android` | 设备、logcat、dump、emulator、fs、frida、perfetto、winscope、构建 |
| `dotfiles` | nvim / vim / tmux / git / fish / zsh 的安装、备份、恢复、体检 |
| `system` | 镜像源、代理、提示符主题 |
| `identity` | 模型账号与节点切换、Git 与 SSH 私有配置 |
| `multirepo` | AOSP 多仓 manifest 的 plan / apply / sync |
| `sync` | Git 工作区到目标目录的受控同步 |
| `devenv` | 开发环境检查与显式安装 |
| `vscode` / `vps` / `spider` / `grep` / `navigator` / `alias` | 编辑器、VPS、网页正文抓取、检索、目录导航、别名检查 |

`gs plugin info <插件>` 看某个插件的完整命令面。

## 文档

| 文档 | 内容 |
|---|---|
| [插件协议](./docs/protocol.md) | manifest / RPC / 缓存 / daemon 规范 |
| [架构设计](./docs/architecture.md) | 分层、执行路径、设计取舍 |
| [插件开发](./docs/plugin-development.md) | 从零写一个插件 |
| [安装指南](./docs/installation.md) · [快速开始](./docs/quickstart.md) | 安装与上手 |
| [文档索引](./docs/readme.md) | 全部文档 |

## 许可证

Apache-2.0，见 [LICENSE](./LICENSE)。
