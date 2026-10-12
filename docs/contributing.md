# 贡献指南

## 开发环境

只需要两样东西：

- **Rust** 1.75+（`rustup` 安装即可）
- **Python 3.8+**（跑 T2/T3 插件、以及 `scripts/` 下的工具）

不需要 `uv`、不需要 `jq`、不需要建虚拟环境。

```bash
git clone https://github.com/i-rtfsc/global_scripts.git
cd global_scripts
cargo build --manifest-path rust/Cargo.toml -p gs
```

## 目录导览

```
rust/crates/gs-core/   # 纯逻辑核心（manifest/发现/补全/RPC/缓存/能力）
rust/crates/gs/        # 前门二进制
plugins/<name>/        # 插件（每个一个 plugin.toml）
sdk/python/gs_plugin/  # T2/T3 插件 SDK
scripts/               # 安装、打包、验收工具
docs/                  # 文档（协议见 docs/protocol.md）
```

代码之外的行为规范都在 [插件协议](./protocol.md) 与 [架构设计](./architecture.md)。

## 日常命令

```bash
# 编译
cargo build --manifest-path rust/Cargo.toml -p gs

# 单元 + 集成测试
cd rust && cargo test --workspace

# 格式与 lint（CI 会卡）
cargo fmt --all -- --check
cargo clippy --workspace --all-targets

# 用源码树跑 gs（不碰已安装版本）
export GS_ROOT=$PWD
./rust/target/debug/gs doctor
./rust/target/debug/gs plugin list

# 端到端验收（会 stage 到 dist/gs 并跑全套契约）
bash scripts/stage_release.sh
bash scripts/verify_gs.sh

# 逐插件体检（清单/元数据/分组/冒烟）
python3 scripts/audit_plugins.py
```

## 改代码时的约定

### Rust

- 逻辑放 `gs-core`，副作用（spawn、写文件、打印）放 `gs` 前门；
  `gs-core` 保持纯函数，方便单测。
- 模块加载路径固定：前门按 `main.rs` 的 `run()` → 对应模块（`plugin.rs` /
  `shell.rs` / `system.rs` / `init.rs` / `dispatch.rs`）。
- 展示统一走 `ui.rs`，不要在别处直接拼颜色或表格。
- 输出不用 emoji；颜色遵循 `NO_COLOR`。

### 插件

- 一个目录一个 `plugin.toml`，目录名必须等于 `name`。
- 危险操作必须提供互斥的 `--dry-run` / `--yes`。
- 外部程序写进 `[capabilities].exec`，环境变量写进 `env`。
- 加命令 / 加插件的完整流程见 [插件开发](./plugin-development.md)。

## 提交规范

用 Conventional Commits 前缀，说明写清楚“为什么”：

```
feat(android): add device screencap dry-run
fix(shell): keep cd effects when the wrapper is missing
refactor(core): split the front door into modules
docs(protocol): specify the completion directive
```

仓库使用 Gerrit 风格的 `Change-Id:` trailer，提交时补一行即可。

## 加一个新插件（最短路径）

```bash
mkdir plugins/myplugin
$EDITOR plugins/myplugin/plugin.toml      # 见 docs/protocol.md §2
# T1：直接在 plugin.toml 里写 [[commands]]
# T2/T3：再写一个入口脚本，entry 指向它
export GS_ROOT=$PWD
./rust/target/debug/gs doctor
./rust/target/debug/gs plugin info myplugin
python3 scripts/audit_plugins.py
```

`audit_plugins.py` 会对新插件做清单/元数据/分组/冒烟检查；如果它没有冒烟命令，
记得在脚本的 `SMOKE` 表里补一条只读命令。

## 加一条前门命令

1. 在 `rust/crates/gs/src/main.rs` 的 `run()` 里注册；
2. 实现放到对应模块（`system.rs` / `plugin.rs` / `shell.rs` / `init.rs`）；
3. 如果它是补全要展示的，同步更新 `shell.rs` 里的 `SYSTEM_CMDS`；
4. `cargo test --workspace` 与 `bash scripts/verify_gs.sh`。

## 文档

- 协议变更 → 改 [docs/protocol.md](./protocol.md)（唯一规范）；
- 重要取舍 → 加一篇 [ADR](./adr/)；
- 用户可见行为 → 更新 [命令参考](./cli-reference.md) 与 [变更日志](./changelog.md)。

## 相关文档

- [插件协议](./protocol.md) · [架构设计](./architecture.md) · [插件开发](./plugin-development.md)
