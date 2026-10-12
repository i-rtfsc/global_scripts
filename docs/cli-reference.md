# 命令参考

## 前门命令

这些命令由 Rust 前门原生处理，不经过插件。

| 命令 | 说明 |
|---|---|
| `gs` / `gs help` | 帮助：前门命令 + 插件列表 |
| `gs version` | 版本 |
| `gs status` | 插件库存与命令总数 |
| `gs doctor` | 体检：manifest / entry / 插件运行时 / shell 集成 |
| `gs refresh` | 重新扫描 manifest（并报告无效项） |
| `gs plugin list` | 插件与命令数 |
| `gs plugin info <插件> [组]` | 某插件的命令面（可按组聚焦） |
| `gs plugin enable\|disable <插件>` | 改该插件 `plugin.toml` 的 `enabled` |
| `gs plugin migrate <目录>` | 把旧 `plugin.json` 转成 `plugin.toml` |
| `gs init [步骤]` | 按 `config/init.toml` 初始化这台机器 |
| `gs completions [shell]` | 生成补全脚本（`--install` 直接落盘） |
| `gs shell-init <shell>` | 生成带 `cd`/`export` 集成的外壳函数 |
| `gs __complete <词…>` | 补全后端（供上面两个生成的脚本调用） |

### `gs init`

```bash
gs init --list                    # 列步骤与状态
gs init --dry-run                 # 全部只检查
gs init <步骤>                    # 只跑一步
gs init --group=<组>              # 只跑一组
gs init --only=<步骤,…> --skip=<步骤,…>
gs init --without=<组,…>
gs init --yes <步骤>              # 真正执行（否则只打印 sudo 命令）
```

## 插件命令

插件命令统一是

```
gs <插件> <动词> [对象] [参数]
```

组名用 `.`（`device.logcat`）或空格（`device logcat`）都可以。列举几个：

```bash
gs android device devices
gs android logcat clear --dry-run
gs android build build --dry-run
gs dotfiles install nvim --dry-run
gs dotfiles doctor
gs system proxy on --dry-run
gs system repo tsinghua --dry-run
gs system prompt themes
gs multirepo plan mini-aosp --backend=git
gs multirepo apply-plan plan.json --yes
gs sync status
gs identity claude show
gs vps status
gs vscode paths
gs spider classify https://www.jianshu.com/p/…
gs grep python 'def _search'
gs navigator list
gs alias sources bash
```

完整列表用 `gs plugin list`，单个插件用 `gs plugin info <插件>`。

## 通用约定

- **计划 vs 执行**：写操作必须二选一：`--dry-run`（只打印计划）或 `--yes`（真执行）；
  两者都给或都不给都会报错。
- **JSON 计划**：支持 `--format=json` 的命令会输出稳定 schema 的计划，
  字段含 `schema_version`、`mode`、`check` 等，便于 CI 消费。
- **`--dry-run` 文案**：中文环境统一包含“不会…”字样，便于断言。
| 退出码 | 含义 |
|---|---|
| 0 | 成功 |
| 1 | 运行失败 / 检查未通过 |
| 2 | 用法错误（参数、选项、缺少必需 flag） |
| 127 | 找不到要执行的程序 |

## 环境变量

| 变量 | 作用 |
|---|---|
| `GS_ROOT` | 插件树与 config 的根（staging/安装时由 `gs-launch` 设置） |
| `GS_COMMAND_NAME` | 生成补全/外壳函数时使用的命令名 |
| `GS_LANGUAGE` / `GS_LANG` / `LANG` | 输出语言（`zh` / `en`） |
| `GS_COLOR=0`、`NO_COLOR` | 关闭颜色 |
| `GS_CACHE_DIR` | describe / complete 缓存目录 |
| `GS_PLUGIN_PATH` | 额外插件根（`:` 分隔） |
| `GS_INCLUDE_EXAMPLES=1` | 额外加载 `examples/` |
| `GS_ALLOW_EXTERNAL_PLUGINS=1` | 设置了 `GS_ROOT` 时仍加载用户插件目录 |
| `GS_DAEMON_IDLE_MS` | T3 常驻进程空闲退出时间（默认 30000） |
| `GS_CD_FILE` / `GS_ENV_FILE` | 外壳函数交给 `gs` 的副作用文件 |

## 相关文档

- [插件协议](./protocol.md) · [架构设计](./architecture.md) · [安装指南](./installation.md)
