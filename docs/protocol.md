# GS 6.0 插件协议

本文是 GS 6.0 插件协议的**规范**（manifest、命令模型、RPC 与副作用）。
Rust 核心（`rust/crates/gs-core`）、`gs` 前门（`rust/crates/gs`）与 Python
SDK（`sdk/python/gs_plugin`）都以本文为准；代码里出现的 `§n` 编号指本文。

如果不是要写新插件，可以先看 [插件开发指南](./plugin-development.md)。

---

## 1. 分层与发现

| 层 | 位置 | 职责 |
|---|---|---|
| 前门 | `rust/crates/gs` | 解析 argv、分发、进程与副作用 |
| 核心 | `rust/crates/gs-core` | manifest 模型、发现、补全引擎、能力仲裁、RPC/缓存 |
| SDK | `sdk/python/gs_plugin` | 写 T2/T3 插件的 stdlib 辅助库 |
| 插件 | `plugins/<name>/` | 每个目录一个 `plugin.toml` + 实现 |

**唯一事实来源是 `plugin.toml`。** 核心不读 `plugin.json`、`commands.json`，
也不扫描 Python 装饰器；发现即"读每个 `<root>/<plugin>/plugin.toml`"。

发现的根目录按优先级（先出现的遮蔽后面的同名插件）：

1. `$GS_PLUGIN_PATH`（`:` 分隔，显式覆盖）；
2. `$GS_ROOT/plugins`；`$GS_ROOT/examples` 仅在 `GS_INCLUDE_EXAMPLES=1` 时加入；
3. `~/.config/global-scripts/plugins`（用户自装插件）。

设置了 `$GS_ROOT` 时默认只使用 2（开发检出与用户已装插件隔离）；要显式放行
用户插件，设 `GS_ALLOW_EXTERNAL_PLUGINS=1`。

### 1.1 分层（tier）

`tier` 决定核心"如何执行"这个插件，而不是它的能力：

| tier | 别名 | 核心行为 |
|---|---|---|
| `declarative` | T1 | **从不启动进程**。命令树与执行模板都在 manifest 里，核心自己渲染 argv。 |
| `script` | T2 | 每次调用起一个解释器进程，用 JSON-RPC over stdio 应答。 |
| `rpc` | T3 | 常驻进程：握手一次并复用（见 §8）。 |
| `wasm` | T4 | 通过 `wasmtime` 运行 `.wasm` 模块（能力 = WASI 授权）。 |

`describe_cache` 缺省由 tier 推导：T1 → `manifest`，其余 → `runtime`。
取值 `manifest`（树内联）、`static`（内联但 tier 是 T2+）、`runtime`
（运行时取一次并缓存）。

---

## 2. `plugin.toml`

未知字段被忽略，保证新 manifest 仍能被旧核心加载。最小可运行示例：

```toml
name    = "gitx"
version = "1.0.0"
tier    = "declarative"

[capabilities]
exec = ["git"]

[[commands]]
name = "co"
summary = { zh = "切换分支", en = "Checkout branch" }
run  = "git checkout {branch}"

  [[commands.args]]
  name = "branch"
  type = "string"
  [commands.args.complete]
  kind = "dynamic"          # T1: 核心执行下面这条命令取候选
  command = "git branch --format=%(refname:short)"
```

### 2.1 顶层字段

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `name` | string | 必填 | 插件名；必须与目录名一致 |
| `version` | string | `""` | 语义化版本 |
| `tier` | enum | 必填 | `declarative`/`script`/`rpc`/`wasm` |
| `runtime` | string | `""` | T2/T3 解释器：`python`/`bash`/`node`…；T1 必须为空 |
| `entry` | string | `""` | T2/T3 的入口脚本；T4 的 `.wasm`；T1 必须为空 |
| `description` | i18n | — | `{ zh = "…", en = "…" }` |
| `author` / `homepage` / `license` / `category` | string | `""` | 元数据 |
| `keywords` | string[] | `[]` | 元数据 |
| `groups` | table | `{}` | 点号命名空间的组描述，见 §3.3 |
| `priority` | int | `50` | 补全排序（越大越靠前） |
| `enabled` | bool | `true` | `gs plugin enable/disable` 改这一项 |
| `protocol` | int | `1` | 协议版本 |
| `describe_cache` | enum | 由 tier 推导 | 见 §1.1 |
| `capabilities` | table | 全拒绝 | 见 §4 |
| `commands` | table[] | `[]` | 见 §3 |

### 2.2 tier 校验（不满足直接拒绝加载）

- `declarative`：禁止 `runtime`/`entry`；每条命令必须**恰好**有 `run` 或 `cd`。
- `script`/`rpc`：必须有 `runtime` 与 `entry`，且 `entry` 文件存在。
- 任何 tier：`name` 非空，每条命令 `name` 非空。

---

## 3. 命令模型

### 3.1 `[[commands]]`

| 字段 | 类型 | 说明 |
|---|---|---|
| `name` | string | 命令名；用 `.` 表示子命令路径，如 `device.logcat` |
| `summary` | i18n | 一行说明（命令用 `summary`，参数用 `description`） |
| `usage` | string | 用法示例（帮助里展示） |
| `examples` | string[] | 例子 |
| `run` | string | **T1**：argv 模板，`{arg}` 为占位符 |
| `shell` | bool | **T1**：把 `run` 当整行 shell（`sh -c`），用于管道/重定向/`&&` |
| `cd` | string | **T1**：导航命令的目标目录（与 `run` 互斥） |
| `hidden` | bool | 从补全中隐藏 |
| `args` | table[] | 见 §3.2 |

### 3.2 `[[commands.args]]`

| 字段 | 类型 | 说明 |
|---|---|---|
| `name` | string | 参数名（`{name}` 占位符、RPC 里的键） |
| `type` | string | `string`/`int`/`float`/`bool`/`enum`/`path`/`flag` |
| `required` | bool | 必填 |
| `variadic` | bool | 可重复的末尾位置参数 |
| `description` | i18n | 说明 |
| `default` | any | 默认值 |
| `flag` | string | 选项形如 `--serial` / `-s`；空 = 位置参数 |
| `complete` | table | 补全规则，见 §3.3 |

`bool`/`flag` 类型不消费后续值；其余参数消费一个值。

### 3.3 补全规则 `[commands.args.complete]`

| `kind` | 行为 |
|---|---|
| `none` | 不补全（默认） |
| `enum` | 用 `values` 静态列表 |
| `file` | 让 shell 做文件补全，可带 `pattern`（如 `*.apk`） |
| `dir` | 让 shell 做目录补全 |
| `dynamic` | 运行时解析：**T1** 执行 `command`（受 `exec` 能力约束），输出每行一个候选；`filter` 可给正则，取第一个捕获组。**T2/T3/T4** 以 `source` 调插件 `complete`（见 §6.3） |

点号命名空间的组描述放在顶层 `groups`：

```toml
[groups.device]
zh = "设备管理"
en = "Device management"
```

没有 `groups` 声明时 `gs <plugin>` 只能显示组名，`gs doctor` 会给出警告。

---

## 4. 能力 `[capabilities]`

**默认拒绝**：字段缺省等于空白名单。核心在**替插件做事之前**检查。

| 字段 | 形式 | 6.0 强制程度 |
|---|---|---|
| `exec` | `["adb","fastboot"]`，`["*"]` 为不限制 | **强制**：核心控制 spawn，不在白名单直接拒绝 |
| `env` | 环境变量名列表 | **强制**：核心只把白名单变量放进子进程环境 |
| `fs` | `"<mode>:<path>"`，mode ∈ `read`/`write`/`rw`，路径可用 `$HOME`/`$PROJECT`/`$PLUGIN_DIR` | 建议性：真正的沙箱需要 OS 设施，6.0 只做提示 |
| `net` | `false` / `true` / `["host:port", …]` | 建议性：能力会原样回传给插件，由 SDK 自律 |

`exec` 门禁作用在：T1 的 `run`（exec 形式的第一个词，`shell = true` 时的行首第一个词）、
T1 动态补全的 `command`、以及插件通过 invoke 结果请求的 `exec`（§6.4）。

---

## 5. T1（declarative）执行模型

T1 从不启动插件进程，核心自己完成绑定与渲染（`gs-core::exec`）。

1. **绑定**：按 `args` 把 argv 绑成 `name → 值列表`。
2. **渲染 `run`**（exec 形式）：
   - 模板按空白切成 argv；
   - 单独的 `{name}` 占位符展开为**独立的 argv 元素**（值里有空格也不会被拆开），
     因而没有 shell 注入面；
   - 形如 `prefix-{name}` 的内联占位符做文本替换。
3. `shell = true` 时整行交给系统 shell（`sh -c` / `cmd /C`），占位符做**文本**
   替换且值经过 shell 转义；行首第一个词仍受 `exec` 能力约束。

### 5.1 `cd`（导航）

`cd` 命令不是 exec，而是"让调用方的 shell 换目录"：

- shell 集成（`gs shell-init <shell>`）在调用前设置 `$GS_CD_FILE`（一个临时空文件）；
- 核心把解析后的绝对路径写进该文件；
- wrapper 读到非空内容后执行真正的 `cd`；
- 未装集成时只打印目标路径并提示安装方法。

同样的机制承载环境变量副作用：`$GS_ENV_FILE` 每行 `S<TAB>键<TAB>值` 表示设置，
`U<TAB>键` 表示取消。

---

## 6. T2/T3 RPC

### 6.1 帧格式

LSP 风格：`Content-Length: <字节数>\r\n\r\n<UTF-8 JSON 体>`。未知报文头忽略，
只有 `Content-Length` 有意义。

请求/响应是 JSON-RPC 2.0：

```json
{"jsonrpc":"2.0","id":1,"method":"invoke","params":{…}}
{"jsonrpc":"2.0","id":1,"result":{…}}
{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"…"}}
```

错误码沿用 JSON-RPC：`-32601`（方法不存在）、`-32602`（参数非法）、
`-32603`（内部错误）。

### 6.2 `describe`

请求：`{"jsonrpc":"2.0","id":1,"method":"describe","params":{}}`

结果：

```json
{"protocol":1,"name":"sync","commands":[{"name":"status","summary":{"zh":"…"},
 "usage":"gs sync status","examples":["…"],"args":[…],"hidden":false}]}
```

`commands[].args[]` 与 manifest 的 `[[commands.args]]` 同构，所以补全、帮助、
校验对 tier 无感。Python SDK 的 `@plugin.command(...)` 装饰器就是生成这个结构。

### 6.3 `complete`

请求参数：

```json
{"command":"classify","arg":"url","source":"targets","current":"",
 "args":{},"cwd":"/path/to/plugin","locale":"zh","env":{"GS_ROOT":"…"}}
```

结果：

```json
{"values":[{"value":"https://a","description":"可选说明"}],"ttl":30}
```

- `values[]` 也可以是纯字符串，SDK 会归一化；
- `ttl`（秒）可选：给了就落盘缓存（§7），不给就每次现算。

### 6.4 `invoke`

请求参数：

```json
{"command":"status","args":{"path":"…"},"cwd":"/current/dir",
 "env":{…白名单环境…},"context":{"locale":"zh","tty":true},
 "capabilities":{"exec":["git"],"env":["PATH"]}}
```

结果：

```json
{"exit_code":0,"stdout":"…","stderr":"…","env":{"KEY":"VALUE"},
 "exec":["git","status"]}
```

| 键 | 含义 |
|---|---|
| `exit_code` | 退出码；`gs` 原样返回 |
| `stdout` / `stderr` | 非流式时由核心补齐输出（已流式则忽略） |
| `env` | 要注入调用方 shell 的环境变量（写 `$GS_ENV_FILE`） |
| `exec` | 请求核心**代为执行**一条命令（argv 数组，受 `exec` 能力约束，`exec(2)` 替换进程） |

### 6.5 事件（通知）

插件可在应答前后发通知给用户看进度，核心会把它们转成终端输出：

```json
{"jsonrpc":"2.0","method":"event","params":{"type":"output","stream":"stdout","chunk":"…"}}
{"jsonrpc":"2.0","method":"event","params":{"type":"log","level":"info","message":"…"}}
{"jsonrpc":"2.0","method":"event","params":{"type":"progress","pct":50,"stage":"build","message":"…"}}
```

`type = "output"` 会立即写向对应流（真流式），因此长任务不需要等进程结束。

---

## 7. 缓存

缓存目录 = `$GS_CACHE_DIR`，否则 `~/.config/global-scripts/cache`。两类：

| 文件 | 键 | 失效 |
|---|---|---|
| `cache/describe/<plugin>.json` | `(plugin.toml mtime, entry mtime, protocol, locale)` | 任一输入变化即失效 |
| `cache/complete/<plugin>.json` | `(command, arg, source, locale)` | 插件给的 `ttl` 秒后过期 |

缓存是**尽力而为**：任何 IO/解析错误都退化成都市未命中或静默跳过，
缓存永远不能阻断补全。

---

## 8. T3 常驻 daemon

`tier = "rpc"` 的插件只启动一次，之后经 Unix socket 复用，省掉解释器冷启动
（实测 `python3` 冷启动约占一次调用的 63ms）。

生命周期：

- socket 路径包含插件文件内容的 `generation` 哈希 → 改插件即换路径，旧 daemon 自然老死；
- 空闲 `GS_DAEMON_IDLE_MS`（默认 30s）后退出，释放解释器内存；
- 客户端在请求未完成时消失会**毒化**该 daemon（回包会串给下一位调用者），
  于是它直接退出，下次调用重新拉起；
- 插件 stdio 是单管道对，没有请求复用，因此并发调用排队串行；
- daemon 不可用时自动退化为一次性通道（§6.1 同样的帧）。

---

## 9. 补全 directive

`gs __complete` 输出的最后一行是 `:<bits>`（Cobra 风格），告诉 shell 是否还要做
文件/目录补全：

| bit | 值 | 含义 |
|---|---|---|
| `NO_SPACE` | 2 | 单一匹配后不加空格 |
| `NO_FILE` | 4 | 不要再做文件补全（候选已完整） |
| `FILTER_DIRS` | 16 | 改为目录补全 |
| `DEFAULT` | 0 | 交回 shell 默认（文件）补全 |

候选行格式为 `值<TAB>说明`；说明只有 zsh/fish 展示，bash 只用值。

---

## 10. 版本与兼容

- `protocol` 目前为 `1`：manifest schema + describe/complete/invoke + 事件。
- 未知 manifest 字段被忽略，新增可选字段不会破坏旧核心。
- 若未来出现不兼容变更，`protocol` 递增，核心拒绝高于自己支持的版本并给出提示。

---

## 附：最小 T2 插件

`plugins/demo/plugin.toml`

```toml
name  = "demo"
tier  = "script"
runtime = "python"
entry   = "demo.py"

[capabilities]
exec = ["echo"]
```

`plugins/demo/demo.py`

```python
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk" / "python"))
from gs_plugin import Plugin  # noqa: E402

plugin = Plugin(name="demo")

@plugin.command(name="greet", summary={"zh": "打招呼", "en": "Greet"},
                args=[{"name": "who", "type": "string", "required": True}])
def greet(ctx):
    ctx.emit_output("stdout", "hello {}\n".format(ctx.args.get("who")))
    return 0

if __name__ == "__main__":
    plugin.run()
```
