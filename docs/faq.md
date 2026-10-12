# 常见问题

## 关于 6.0 与 5.2

**5.2 的 Python 实现还在吗？**
不在了。`src/gscripts/`、`tests/`、`scripts/setup.py`、`plugin.json`/`plugin.py`
以及 `router.json` 派发路径都已从仓库退役（见
[ADR 005](./adr/005-retire-gs52-python-runtime.md)）。git 历史里仍可查到。

**我还有自己的老插件，能用吗？**
可以转换：

```bash
gs plugin migrate /path/to/old-plugin --write
```

它读 `plugin.json`（及 `commands.json`）生成 6.0 的 `plugin.toml`。

**为什么现在还需要 Python?**
因为部分插件是 T2/T3 分层，用 Python 实现。核心和前门是 Rust；`gs doctor` 会
检查 `python3` 是否在 `PATH` 上。不需要 `uv`，也不需要 `jq`。

## 日常使用

**`gs` 撞名 Ghostscript 了。**
`~/.local/bin/gs` 在 `PATH` 里更靠前会遮蔽它。要调用 Ghostscript 用
`/usr/bin/gs`，或重装时 `--name gsp`。

**为什么有些命令明明是 `cd`，却没换目录？**
需要 shell 集成：`source <(gs shell-init bash)`（zsh 同理，fish 写到
`~/.config/fish/conf.d/gs.fish`）。没有集成时 `cd` 命令只会打印目标路径。

**怎么关掉颜色？**
`NO_COLOR=1` 或 `GS_COLOR=0`。管道里会自动降级。

**输出语言怎么切成英文？**
`export GS_LANGUAGE=en`（或 `GS_LANG`；未设置时看 `LC_ALL`/`LANG`）。

## 插件系统

**一个插件的“事实来源”是什么？**
它目录里的 `plugin.toml`。命令树、参数、补全规则、能力声明都在里面；没有第二份清单。

**manifest 里能内联命令树，为什么不直接写代码？**
内联（T1）意味着核心可以零进程执行和补全，`gs help`/Tab 都不会启动插件。
需要真正的逻辑时再用 T2/T3。

**T2 和 T3 怎么选？**
调用不频繁用 T2（每次起一个进程）；调用频繁用 T3（常驻进程复用，省解释器冷启动）。

**补全为什么快？**
发现只读 manifest；T1 静态补全零回调；T2+ 的 `describe`/`complete` 合并成一次
进程启动并落盘缓存。

**插件能随便执行命令吗？**
不能。`[capabilities]` 默认全拒绝，`exec`/`env` 由核心强制；未声明的程序会被拒绝执行。

**为什么危险操作要 `--dry-run` 或 `--yes`？**
所有写操作都必须二选一，避免误触。`gs` 自己从不提权，需要 root 时只打印
`sudo …` 让用户执行。

## 开发与验收

**怎么跑测试？**

```bash
cd rust && cargo test --workspace        # Rust 单元 + 集成
bash scripts/verify_gs.sh                # 端到端验收（需要先构建）
python3 scripts/audit_plugins.py         # 每个插件的清单/元数据/冒烟
```

**`gs doctor` 报某插件 manifest 无效怎么办？**
按报错的文件与行号修，`doctor` 会一次列出全部问题；`gs refresh` 也能复扫。

## 相关文档

- [插件协议](./protocol.md) · [架构设计](./architecture.md) · [安装指南](./installation.md)
