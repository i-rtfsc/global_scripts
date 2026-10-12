# 插件开发

完整的字段与协议规范在 [插件协议](./protocol.md)。本文是动手教程。

## 1. 三种插件

| 你想要的 | 用哪个分层 | 起进程 |
|---|---|---|
| 把一条现成命令包成 `gs xxx` | T1 声明式 | 0 |
| 需要真正的判断/循环/解析 | T2 脚本 | 每次 1 个 |
| 上一条，但要频繁调用 | T3 常驻 | 常驻复用 |

本文先给 T1，再给 T2。

## 2. 一个 T1 插件（零进程）

```
plugins/gitx/
└── plugin.toml
```

```toml
name    = "gitx"
version = "1.0.0"
tier    = "declarative"
category = "development"
description = { zh = "Git 快捷封装", en = "Git shortcuts" }

[groups.co]
zh = "分支操作"
en = "Branch operations"

[capabilities]
exec = ["git", "code"]

[[commands]]
name    = "co"
summary = { zh = "切换分支", en = "Checkout branch" }
usage   = "gs gitx co <branch>"
run     = "git checkout {branch}"

  [[commands.args]]
  name = "branch"
  type = "string"
  required = true
  [commands.args.complete]
  kind    = "dynamic"
  command = "git branch --format=%(refname:short)"
```

要点：

- `run` 是 **argv 模板**：核心按空白切词，`{branch}` 展开为一个独立参数，
  因此分支名里有空格也不会被拆开，也没有 shell 注入面；
- 需要管道/重定向/`&&` 时加 `shell = true`，整行交给系统 shell，占位符做转义替换；
- 想让调用方 shell 换目录，用 `cd = "$HOME/code/foo"` 代替 `run`；
- `exec` 白名单是强制的：`run` 的第一个词必须在这里。

## 3. 一个 T2 插件

```
plugins/hello/
├── plugin.toml
└── hello.py
```

`plugin.toml`：

```toml
name    = "hello"
version = "1.0.0"
tier    = "script"
runtime = "python"
entry   = "hello.py"

[capabilities]
exec = ["echo"]
env  = ["GS_ROOT"]
```

`hello.py`：

```python
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk" / "python"))
from gs_plugin import Plugin  # noqa: E402

plugin = Plugin(name="hello")


@plugin.command(
    name="greet",
    summary={"zh": "打招呼", "en": "Greet"},
    usage="gs hello greet <who>",
    args=[{"name": "who", "type": "string", "required": True}],
)
def greet(ctx):
    ctx.emit_output("stdout", "hello {}\n".format(ctx.args.get("who")))
    return 0


@plugin.completer(source="colors")
def colors(params):
    return ["red", "green", "blue"]


if __name__ == "__main__":
    plugin.run()
```

要点：

- 不需要 `plugin.toml` 里再写命令树：`describe` 会从装饰器生成，核心与 manifest
  内联的结构同构；
- 处理函数返回 `int` 退出码，或返回 dict 合并进结果（`stdout`/`stderr`/`env`/`exec`）；
- 用 `ctx.emit_progress/log/output` 报告进度，长任务不必等结束；
- 需要核心代跑一条命令时返回 `{"exit_code": 0, "exec": ["git", "status"]}`，
  仍然受 `exec` 能力约束。

改成分层 `rpc`（常驻）只需要把 `tier = "script"` 改成 `tier = "rpc"`。

## 4. 补全

| 场景 | 写法 |
|---|---|
| 固定取值 | `complete = { kind = "enum", values = [...] }` |
| 文件 / 目录 | `complete = { kind = "file", pattern = "*.apk" }` / `kind = "dir"` |
| T1 动态 | `complete = { kind = "dynamic", command = "…" }`（核心执行，受能力约束） |
| T2+ 动态 | `complete = { kind = "dynamic", source = "colors" }` → 调 `@plugin.completer(source="colors")` |

## 5. 调试

```bash
# 用源码目录直接跑，不污染已安装版本
export GS_ROOT=$PWD
cargo build --manifest-path rust/Cargo.toml -p gs
./rust/target/debug/gs doctor
./rust/target/debug/gs plugin info hello
./rust/target/debug/gs hello greet world
./rust/target/debug/gs __complete hello greet
```

改完 plugin.toml 不用重启任何东西；T2+ 的 describe 缓存按键含 mtime，会自动失效。

## 6. 提交前自检

```bash
python3 scripts/audit_plugins.py          # 清单/元数据/分组/冒烟
bash scripts/verify_gs.sh                 # 端到端契约
cd rust && cargo test --workspace
```

## 7. 规则清单

- 一个插件目录 = 一个 `plugin.toml`；不要把命令另写进 `plugin.json`。
- 目录名必须等于 manifest 的 `name`。
- 危险操作提供 `--dry-run` 与 `--yes`，两者互斥且必须给一个。
- 不打印 emoji；颜色遵循 `NO_COLOR`。
- 需要外部命令就写进 `exec`，需要环境变量就写进 `env`。
- 命令名用「动词 + 对象」，分组用点号（`device.logcat`），并在 `[groups]` 写组描述。

## 相关文档

- [插件协议](./protocol.md) · [架构设计](./architecture.md) · [命令参考](./cli-reference.md)
