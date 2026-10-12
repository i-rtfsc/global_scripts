# 插件系统重构方案

> 状态:提案(部分实施)  ·  作者:Solo + Codex  ·  日期:2026-10-01
>
> 说明:本文是改造方案的记录。文中提到的「5.2 兼容路径」已在
> [ADR 005](./adr/005-retire-gs52-python-runtime.md) 中整体退役,相应条目
> 只保留为历史背景;`gs init` 编排与 P1 渲染已落地。
>
> 目标读者:项目作者本人。本文只描述**打算怎么改、改完怎么用**,不含实施代码。

---

## 0. 一句话结论

三条硬规则:

**规则 1 · 动词永远紧跟在插件名后面。**

```
gs <plugin> <verb> [object] [args]
```

| ✅ 对 | ❌ 错 |
|---|---|
| `gs tmux apply theme` | `gs tmux theme apply` |
| `gs lang install rust` | `gs lang rust install` |
| `gs gpu install driver` | `gs gpu driver install` |
| `gs docker install` | `gs docker install-docker` |

动词只用一张小词表(§3.3),含义单一,不出现"同一个意思在 A 插件是 install、在 B 插件是 apply"。

**规则 2 · 按领域拆插件,不做一个万能插件。**
`~/new-system` 的 26 步拆到 **7 个新插件 + 现有插件的扩展**,每个插件只管一个领域
(磁盘 / GPU / 容器 / 语言 / AI / 网络 ……),而不是塞进一个叫"装机"的大插件。
已定:`devenv` 拆解、`multirepo` 并入 `android`、镜像源归 `system`、编辑器归 `vscode`、
目录定义与 `navigator` 共用 —— 详见 §7.6 与 §7.7。最终 **13 → 22 个公开插件**(私有 sgm/flyme 照旧只在 custom/)。
跨插件的"按顺序装完一台机器"由**核心编排命令**完成(名字见 §11,不是插件)。

**规则 3 · 三层职责不混。**

| 层 | 你的诉求 | 代表命令 |
|---|---|---|
| 快捷命令 `shortcuts` | ① 快捷命令 / 脚本函数 | `gs shortcuts list` · `gs shortcuts apply` |
| 工具插件(每工具一个) | ② 配置(nvim / tmux / git / 终端) | `gs nvim install` · `gs tmux apply` · `gs fish install` |
| 装机(领域插件) | ② 安装 | `gs lang install rust` · `gs gpu install cuda` · `gs disk mount` |

三层共享同一套动词、同一套门禁(`--dry-run` / `--yes`)、同一套分组 UI。
`dotfiles` 作为"一个插件管所有配置"的形态**取消**,按工具拆成 `nvim`/`vim`/`tmux`/`git`/`fish`/`zsh`
(§7.7.6);它的文件搬运/合并/备份机制下沉为共享库。

---

## 1. 现状盘点(先看清问题)

### 1.1 现有 13 个公开插件、226 条命令(另有 2 个私有插件)

| 插件 | 命令数 | 主要分组 | 现在实际在干的事 |
|---|---:|---|---|
| android | 96 | input 18 / fs 11 / device 10 / dump 8 / system 7 / app 7 … | 日常操作(读设备、装应用、抓日志) |
| identity | 28 | ssh 6 / claude 5 / gpt 5 / git 5 / router 3 | 私有账号与密钥切换 |
| grep | 18 | 顶层 | 代码搜索 |
| system | 16 | brew 5 / proxy 4 / repo 4 / prompt 3 | 系统状态 + 镜像/代理/提示符 |
| sgm / multirepo / dotfiles / vps / spider / devenv / vscode / alias / flyme / sync / navigator | 3–14 | 混合 | 见下 |

### 1.2 七个具体问题(都带证据)

**P1 · 分组标题渲染不出来,像一条畸形命令**
`gs android` 现在长这样:

```
│ doctor                                    │ gs android doctor                  │ Check the Andro… │
│ app  Application management               │                                    │                  │
│ list-3rd                                  │ gs android app list-3rd            │ List third-part… │
│ build  Android system builds              │                                    │                  │
```

分组名和描述被塞进"命令"列,用两个空格拼起来,后面两列空着 —— 视觉上和普通命令行同构,
扫读时会把 `app Application management` 当成一条命令。这就是你说的"没有特殊的分割"。
根因:`print_plugin_overview` 用**同一张表**同时渲染"分组标题"和"命令",只是把标题塞进第一列。

**P2 · 同一件事分散在多个插件里**

| 关注点 | 现在在哪 |
|---|---|
| 安装软件包 | `devenv install`、`system brew`、(新)new-system |
| 配置文件 | `dotfiles install`(zsh/vim/nvim/tmux/git/fish) |
| 镜像源 | `system repo`、`system brew`、new-system `01-mirrors` |
| 终端提示符 | `system prompt`、`dotfiles fish`(tide 配置) |
| 代理 | `system proxy`、new-system `v2rayN` |

用户要装个 tmux 并配好,得知道"安装归 devenv、配置归 dotfiles、插件归 TPM"三件事。

**P3 · "快捷命令"没有提供者**
`alias` 插件只有 4 条命令,全是**只读检查**(`sources`/`list`/`show`/`doctor`),
它读你现有的 alias 文件,**不提供**任何快捷命令。而你真正在用的快捷命令散落在:
`~/.config/fish/gs-config/03-gs-abbreviations.fish`(103 条缩写)、`00-gs-functions.fish`
(get_ip/mkcd/extract/ff/…)、你自己的 `.bashrc`/`.zshrc`。没有单一事实来源,也没法跨 shell 复用。

**P4 · 文件配置与安装步骤分家**
`dotfiles` 只搬文件,`devenv` 只装包,`new-system` 两样都做但自成体系。
结果是"装 tmux"和"配 tmux"是两条互不知情的路径。

**P5 · 危险等级没有统一表达**
现在靠约定俗成:`dotfiles` 用 `--dry-run|--yes`,`android` 用 `--dry-run|--yes`,
`devenv` 用 `--dry-run|--yes`,但**没有任何元数据**能告诉 UI/文档"这条命令会写系统盘"。
分组描述里只有名字,没有风险/是否需要 root/前置条件。

**P6 · 没有"新机器装机"这一层**
`~/new-system` 38 个脚本(其中 26 步在编排里)、12 个分组、约 8000 行,能跑 `--list/--dry-run/--only/--skip/--without`,
但它和 `gs` 完全无关:不在插件清单里,没有 `gs doctor` 覆盖,补全也没有。

**P7 · 元数据不足以驱动 UI**
`plugin.toml` 的 `[groups]` 只有 zh/en 描述。缺:组内顺序、风险等级、是否 root、
适用平台、组级前置条件 —— 所以 UI 只能退化成"把描述塞进第一列"。

### 1.3 `~/new-system` 现状(它其实已经很接近我们想要的样子)

```
~/new-system
├── install-workflow.sh      编排器:STEPS 表(id|分组|脚本|说明)+ --only/--skip/--without/--group
├── lib/common.sh            日志/确认/root 切换/apt 封装(约 200 行)
├── config/*.conf            路径与开关(system/storage/mirrors/models)
├── config/tmux/             tmux 主题资源
└── scripts/NN-*.sh          38 个脚本(26 个进编排,其余为独立工具;都可单跑、幂等、带 --dry-run)
```

它已经具备:`步骤顺序`、`分组`、`dry-run`、`幂等`、`备份`、`前置检查`、
`root/普通用户切换`、`失败即停 + 单步重跑`。**这些正是装机层需要的全部语义**,
所以移植策略是"翻译清单",不是"重写脚本"。

它和 `gs` 的差别只有两点:new-system 面向"一次性装机 + sudo",`gs` 面向"日常调用 + 用户态"。

---

## 2. 目标与非目标

**目标**

1. 快捷命令、配置、装机三件事各有归属,且**同一套动词和门禁**。
2. `gs android` 这类大插件能一眼看懂结构(分组标题、组内命令、组描述)。
3. `~/new-system` 的能力进入 `gs`,保留原有用法与幂等性。
4. 快捷命令**单一事实来源**,能同时导出到 bash / zsh / fish。
5. 不破坏现有公开插件(sgm/flyme 私有插件不受影响;5.2 兼容路径已在 ADR 005 退役)。

**非目标(本方案不做)**

- 不改核心协议(framed JSON-RPC / T1–T4 分层不动)。
- 不把 `~/new-system` 的脚本重写成 Rust。
- 不做 GUI/TUI。
- 不一次性重命名所有插件(渐进迁移)。

---

## 3. 新模型:三层 + 一套动词

### 3.1 三层各自负责什么

```
┌──────────────────────────────────────────────────────────────────┐
│ L1 shortcuts   快捷命令/函数/缩写  → 生成 shell 代码,零运行时         │
│    声明式(不写文件也能跑),apply 后写进 shell 的受管区块               │
├──────────────────────────────────────────────────────────────────┤
│ L2 工具插件    配置 + 该工具的一切  → 装软件 + 落配置 + 备份/回滚       │
│    每个工具一个插件:nvim · vim · tmux · git · fish · zsh · vscode     │
├──────────────────────────────────────────────────────────────────┤
│ L3 领域插件    装机与环境          → 装包/驱动/挂载/服务,幂等 + sudo    │
│    每个领域一个插件:disk · gpu · docker · lang · ai · net · tmux …    │
│    跨领域顺序编排 = 核心命令(不是插件,见 §7)                          │
└──────────────────────────────────────────────────────────────────┘
```

判断归属的一句话规则:

- **不改文件、只在你的 shell 里生效** → shortcuts
- **改的是某个工具的配置文件/设置** → 该工具的插件(`gs nvim install`、`gs tmux apply`)
- **装东西、改系统状态(包/驱动/挂载/服务)** → 对应领域插件(`gs <领域> install …`)

### 3.2 统一动词表(所有插件遵守)

| 动词 | 语义 | 门禁 | 例子 |
|---|---|---|---|
| `list` / `status` | 只读展示 | 无 | `gs disk list`、`gs shortcuts status` |
| `doctor` | 只读体检,给修复建议 | 无 | `gs gpu doctor` |
| `install` / `uninstall` | 落地/撤掉 | 必须 `--dry-run` 或 `--yes` | `gs nvim install --yes` |
| `run` | 执行任务(可有副作用) | 按风险,见 §6 | `gs init --group=langs` |
| `apply` | 把声明写进目标(shell/配置) | 必须 `--dry-run` 或 `--yes` | `gs shortcuts apply --yes` · `gs tmux apply theme` |
| `backup` / `restore` / `backups` | 备份与回滚 | `--yes` | `gs nvim restore --backup=<名字> --yes` |
| `show` | 查看源内容/定义 | 无 | `gs shortcuts show ll` |

**统一收益**:用户不必记"这个插件用 plan/apply、那个用 install/uninstall"。
(现状:dotfiles 刚从 plan/apply 统一成 install/uninstall,其余插件还没跟上。)

### 3.3 动词词表与词序(硬规范)

```
gs <plugin> <verb> [object] [args…]
             ↑ 必须出自下表
```

| 动词 | 含义 | 类别 | 例子 |
|---|---|---|---|
| `list` | 列清单 | 只读 | `gs lang list` · `gs disk list` |
| `status` | 看当前状态 | 只读 | `gs gpu status` · `gs docker status` |
| `show` | 看定义/内容 | 只读 | `gs shortcuts show ll` · `gs tmux show` |
| `doctor` | 体检 + 修复建议 | 只读 | `gs android doctor` · `gs disk doctor` |
| `install` | 装上(幂等) | 写 | `gs lang install rust` · `gs nvim install` |
| `uninstall` | 卸掉 | 写 | `gs nvim uninstall` |
| `apply` | 把声明落到目标(配置/shell) | 写 | `gs shortcuts apply` · `gs tmux apply theme` |
| `set` | 改一个设置项 | 写 | `gs system set mirror apt` |
| `enable` / `disable` | 开关 | 写 | `gs docker enable gpu` |
| `backup` / `restore` / `backups` | 备份与回滚 | 写 | `gs nvim restore --backup=<名字>` |
| `run` | 按清单跑(编排专用) | 看步骤风险 | `gs init --group=langs` |

**只允许两种形状**(动词永远紧贴它作用的对象):

```
① 无子域:  gs <plugin> <verb> <object> …      gs lang   install rust
② 有子域:  gs <plugin> <domain> <verb> …      gs android app   kill <package>
                                              gs system  proxy on
```

反面例子(禁止,也是现有插件要逐步改掉的地方):

```
gs lang rust install        ← 动词跑到了名词后面
gs tmux theme apply         ← 同上(应为 gs tmux apply theme)
gs android device devices   ← 第三个词是名词,应为 device list
gs docker install-docker    ← 动词与对象粘连
```

五条执行细则:

1. 动词固定在"插件名(或子域名)之后、宾语之前";宾语可以是位置参数,也可以是枚举参数:
   `gs lang install rust` 的 `rust` 是 `install` 命令的枚举参数(而不是路径里的一段),
   这样 `gs lang install` 单独敲出来还能列可选值。
2. 插件名只能是**名词/领域**(`disk`/`gpu`/`lang`/`tmux`),动词不进插件名。
3. 子域只在"一个插件里确实有多个平级世界"时使用(android 的 device/app/logcat、system 的 proxy/repo/mirror);
   子域名同样是名词。
4. **老写法不保留**(决议):改名就是改名,不提供别名/转发层。命令不存在时报错信息里可以带上新名字
   (只在改名表里查一次,用于提示,不是兼容层)。
5. `plugin.toml` 可选新增 `verb` / `object` 字段(供 UI 排序与补全分组);缺省时按命令名解析。

---

## 4. 清单格式(`plugin.toml` 扩展)

### 4.1 分组元数据(解决 P1/P5/P7)

```toml
[groups.app]
summary     = { zh = "应用管理",               en = "Application management" }
detail      = { zh = "安装、卸载、查看第三方/系统应用与日志", en = "…" }
order       = 10            # 组在 UI 里的排序(可选,默认按名称)
risk        = "read"        # read | write | destructive
requires    = ["device"]    # 需要先选设备(供 UI 提示 / doctor 校验)
platform    = ["linux", "darwin"]

[groups.system]
summary     = { zh = "系统修改", en = "System changes" }
risk        = "destructive"
root        = false
```

### 4.2 装机类命令(兼容现有 commands 结构)

```toml
# 形状 ①:gs lang install rust
[[commands]]
name       = "install"
summary    = { zh = "安装语言运行时", en = "Install a language runtime" }
usage      = "gs lang install <runtime> <--dry-run|--yes>"
risk       = "write"        # read | write | destructive
root       = "either"       # no | yes | either(自动切回普通用户)
idempotent = true

  [[commands.args]]
  name     = "runtime"
  type     = "enum"
  required = true
  complete = { kind = "enum", values = ["rust", "go", "java", "python", "node"] }

# 形状 ②(有子域时):gs android device list
[[commands]]
name    = "device.list"
summary = { zh = "列出设备", en = "List devices" }
risk    = "read"
```

> 也可以一个对象一条命令(`name = "install.rust"` / `"install.go"` …),好处是每个对象能单独写
> `examples` 与不同 `root`;代价是命令条目变多。两种都符合词序规范,按插件复杂度选。

> 落地时优先**复用现有 `commands` 字段**,新增的 `risk/root/order/idempotent` 都是可选,
> 老 manifest 不受影响(未知字段本来就忽略)。

### 4.3 快捷命令(shortcuts 新插件)

```toml
[[shortcuts]]
name    = "ll"
kind    = "abbr"            # abbr | alias | function
summary = { zh = "详细列表", en = "Long listing" }
when    = "interactive"     # interactive | always
fish    = "eza -la --git"
bash    = "ls -la --color=auto"
zsh     = "ls -la --color=auto"

[[shortcuts]]
name    = "mkcd"
kind    = "function"
summary = { zh = "建目录并进入", en = "mkdir + cd" }
fish    = '''
mkdir -p $argv[1]; and cd $argv[1]
'''
bash    = '''
mkdir -p "$1" && cd "$1"
'''
zsh     = '''
mkdir -p "$1" && cd "$1"
'''
```

**决议:独立文件 + source(不去改你的 rc 文件本身)。**
`gs shortcuts apply` 把每个 shell 的渲染结果写成独立文件:

```
~/.config/global-scripts/shortcuts/
├── shortcuts.bash     # alias / 函数体
├── shortcuts.zsh      # 同上
└── shortcuts.fish     # abbr / function
```

你的 rc 里只有一行(由 `gs shortcuts setup` 打印,你自己贴一次):

```fish
# ~/.config/fish/config.fish
test -f ~/.config/global-scripts/shortcuts/shortcuts.fish; and source ~/.config/global-scripts/shortcuts/shortcuts.fish
```

```bash
# ~/.bashrc / ~/.zshrc
[ -f ~/.config/global-scripts/shortcuts/shortcuts.bash ] && . ~/.config/global-scripts/shortcuts/shortcuts.bash
```

好处:`gs` 永不直接编辑你的 rc(不会弄坏你的配置),升级/回退只是重写这三个文件;
`gs shortcuts status` 检测漂移(文件与声明是否一致、rc 里那行是否还在),
`gs shortcuts doctor` 提示冲突(名字被占用、某 shell 语法不合法)。

---

## 5. UI/交互改造(直接解决你看到的那行)

### 5.1 分组要"真的是分组"

目标效果(`gs android`):

```
╭─ android ───────────────────────────────────────────────────────────╮
│ android 96 条命令 · 14 组 · 版本 6.0.0-dev                           │
╰─────────────────────────────────────────────────────────────────────╯

  app · 应用管理                                          read
  ────────────────────────────────────────────────────────────────────
    list-3rd            gs android app list-3rd            列出第三方应用
    list-system         gs android app list-system         列出系统应用
    version             gs android app version <pkg>       查看应用版本

  build · Android 系统构建                              destructive
  ────────────────────────────────────────────────────────────────────
    make                gs android build make --dry-run …  执行 make
```

要点:

1. 分组标题**独占一行**,带缩进、加粗组名 + 描述,右侧显示 `risk`;
2. 组与组之间用一条分隔线(或空行)隔开,不再和命令行同构;
3. 命令行**只显示叶子名**(`list-3rd`),完整用法放第二列,避免 `app.` 前缀重复 96 次;
4. 组按 `order`(没有则按名称)排序,顶层命令(`doctor` 等)单独一组放最前;
5. 终端窄时自动降级:隐藏第三列(说明),组标题仍然独占一行。

### 5.2 两级导航

- `gs android` → 分组总览(每组一行:名字、描述、命令数、risk)
- `gs android app` → 只展开 `app` 组(现在已有类似行为,继续保留)
- `gs android app <Tab>` → 只补全该组命令

### 5.3 让元数据成为硬性要求

`gs doctor` / manifest 校验里增加(可分级为警告):

1. 分组没有 `summary` → 警告;
2. 命令名含 `.` 却没有对应 `[groups.<prefix>]` → 警告;
3. `risk` 缺失的危险命令(名字含 `kill/clear/format/flash/rm`)→ 警告。

---

## 6. 执行模型与安全

### 6.1 三档门禁(与现有约定一致,只是写进元数据)

| risk | 默认行为 | 落地条件 |
|---|---|---|
| `read` | 直接执行 | — |
| `write` | 打印计划 | `--yes`(或交互确认) |
| `destructive` | 打印计划 + 二次强调 | `--dry-run` **或** `--yes`,并且不提供 `--force` 之类旁路 |

### 6.2 sudo 策略(移植 new-system 的关键)

现状:`new-system` 直接 `sudo bash install-workflow.sh`。**决议:方案 A —— `gs` 永不自己提权。**

- **A. `gs` 不自己提权**:步骤声明 `root = "yes"` 时,
  `gs` 打印需要执行的 sudo 命令,由用户复制执行;`--yes` 时也只在用户已经以 root 运行时才真跑。
  好处:不引入"`gs` 偷偷 sudo"的信任问题。
- ~~B. `gs init --sudo`:内部 `sudo -v` 先验证缓存,再 `sudo` 执行单步~~ —— 不采用。
- ~~C. 后端服务(systemd unit)~~ —— 不采用。

细节与"以 root 运行时如何还原目标用户"见 §7.7.8。

### 6.3 幂等与备份(沿用 new-system 的约定)

- 每步必须幂等:已装则跳过,已挂载则保留,内容相同不重写;
- 改系统文件前生成 `.bak.<时间戳>`;
- `gs init --list` 显示每一步的"已装/未装/需要重启";
- 失败即停,并提示 `gs init --only=<id>` 重跑;
- 大型下载(如 AOSP `repo sync`)独立成步骤,默认不纳入 `run`。

---

## 7. `~/new-system` 移植方案

### 7.1 按领域拆成插件(不是一个大 provision)

`new-system` 是"一台新机器要做的所有事",但 `gs` 里应该按**领域**落到不同插件。
拆分后每个插件都小、可独立使用,而且命令天然满足 §3.3 的动词词序。

| 插件 | 方式 | domain | 承载的 new-system 步骤 |
|---|---|---|---|
| `system` | **扩展现有** | 镜像源、基础包、无线 | 01-mirrors · 20-base · 23-wifi |
| `devenv` | **拆解** | (取消插件) | 目录/预设按领域拆走,逻辑下沉为共享安装库(§7.7.1) |
| `multirepo` | **并入 android** | repo manifest 工作流 | 成为 `gs android repo …`,manifests 一并搬走(§7.7.2) |
| `vscode` | **扩展现有** | 编辑器 | 36-vscode · 37-vscode-tunnel |
| `android` | **扩展现有** | 设备 + AOSP 编译环境 | 40-deps · 41-workspace · 42-build-env · 43-tools · 45-emulator · 47-adb-service · 48-mac-adb |
| `navigator` | **改数据源** | 目录跳转(已有) | 12-workspaces(共享目录定义,见 §7.6-C) |
| `dotfiles` | **拆解** | (取消插件) | 按工具拆成 `nvim`/`vim`/`tmux`/`git`/`fish`/`zsh`;搬运/合并/备份机制下沉为共享库(§7.7.6) |
| `alias` | **升级** | → `shortcuts`(提供而不只是检查) | — |
| `disk` | **新增** | 磁盘、挂载、工作区(**只读 + 挂载,不含格式化**) | 00-inventory · 10-storage · 12-workspaces |
| `gpu` | **新增** | NVIDIA / CUDA | 13-nvlink · 21-nvidia · 26-nvidia-container · 22-cuda |
| `docker` | **新增** | 容器运行时 | 25-docker |
| `lang` | **新增** | 语言运行时 | 30-rust · 31-go · 32-java · 33-python · 34-node |
| `tmux` | **新增** | 终端复用(装 + 主题 + 插件) | 39-tmux · tmux-theme.sh |
| `nvim` / `vim` / `git` / `fish` / `zsh` | **新增** | 各工具的配置与设置 | 原 `plugins/dotfiles/<tool>/` 的资源 |
| `ai` | **新增** | 训练 / 推理环境 | 50-ai-stack · 51-inference · 52-serve-model |
| `net` | **新增** | 代理客户端、门户登录 | 38-v2rayn · auto-network/portal-autologin |

合计:**接管/扩展 5 个现有插件 + 拆解 3 个 + 新增 13 个插件**,最终 **13 → 22 个公开插件**(私有 sgm/flyme 照旧只在 custom/)。
每个插件就是一个 `plugins/<name>/` 目录,沿用现有 plugin.toml/脚本结构,没有任何"超级插件"。

### 7.2 步骤 → 命令映射(旧脚本 → gs 命令)

| new-system 步骤(id) | gs 命令(动词在前) |
|---|---|
| 00-inventory | `gs disk list` |
| 01-mirrors | `gs system set mirror --all` |
| 10-storage | `gs disk mount` |
| 12-workspaces | `gs disk create workspaces` |
| 13-nvlink | `gs gpu check nvlink` |
| 20-base | `gs system install base` |
| 21-nvidia | `gs gpu install driver` |
| 22-cuda | `gs gpu install cuda` |
| 23-wifi | `gs system install wifi` |
| 25-docker | `gs docker install` |
| 26-nvidia-container | `gs gpu install container` |
| 30-rust … 34-node | `gs lang install rust\|go\|java\|python\|node` |
| 36-vscode | `gs vscode install [--cli-only]` |
| 37-vscode-tunnel | `gs vscode setup tunnel` |
| 38-v2rayn | `gs net install proxy` |
| 39-tmux | `gs tmux install` |
| 40-aosp-deps … 45-emulator | `gs android setup deps` / `gs android repo init` / `gs android setup env` / `gs android install tools` / `gs android repo sync` / `gs android start emulator` |
| 47-adb-server / 48-mac-adb | `gs android install adb-service` / `gs android setup adb-mac` |
| 50-ai-stack | `gs ai install train` |
| 51-inference / 52-serve-model | `gs ai install infer` / `gs ai serve` |
| (*每个插件自己的状态*) | `gs <plugin> status` / `gs <plugin> doctor` |

### 7.3 跨插件的顺序编排(核心命令,不是插件)

"按顺序装完一台机器"是**编排**问题,不应该变成某个插件。做法是一条核心命令读一份
**步骤清单**,清单里指向各插件的命令:

```toml
# init.toml(核心资源,不属任何插件)
[[steps]]
id = "mirror-repo"
group = "mirrors"
run = ["system", "set", "mirror", "--all"]
desc = { zh = "配置国内软件源", en = "Configure mirrors" }
root = true

[[steps]]
id = "docker"
group = "docker"
run = ["docker", "install"]
desc = { zh = "安装 Docker", en = "Install Docker" }
root = true
```

用户看到的能力:

```
gs init --list                      # 步骤清单(id/分组/说明/是否已装)
gs init --dry-run             # 预览默认流程(不需要 root)
gs init --group=base,langs    # 按分组跑
gs init --only=docker          # 只跑某一步(步骤名自解释,不沿用旧编号)
gs init --skip=gpu-driver      # 跳过某步(步骤名或插件名都行)
gs init --without=android     # 跳过整组
```

要点:

1. **能力在插件里,顺序在清单里** —— 新增一步只需要写一行清单,不用改插件;
2. 步骤名是**自解释的新名字**(`mirror-repo`/`base-tools`/`gpu-driver`…),**不沿用 `~/new-system` 的编号**;
   分组名同样用词(`mirror`/`base`/`langs`/`gpu`…);
3. `gs init` 与 `gs <plugin>` 是同一套实现:编排只是依次调用插件命令,单独跑某步与走编排完全等价;
4. 每个步骤标 `root`/`risk`,由编排决定是否提示 sudo(策略见 §6.2)。

### 7.4 与现有插件的重叠怎么处理

一句话总结:**镜像源进 `system`、AOSP 源码进 `android`、目录定义三方共用、
代理新归 `net`、软件安装与文件配置分开**。完整分析见 §7.6。

### 7.5 目录落位与双仓策略

**决议:不把 `~/new-system` 的脚本搬进本仓库,而是把"能力"移植进来。**
该仓只留在 `~/new-system`(作为你自己的参考资料),`global_scripts` 仓库里不出现它的
任何脚本、`lib/`、`config/` 副本 —— 移植的是**行为**,不是文件。

单个领域插件的目录(以 gpu 为例)—— 全部是 gs 自己的实现:

```
plugins/gpu/
├── plugin.toml         # 命令清单(动词在前)+ risk/root/idempotent 元数据
├── gpu.py              # T2 脚本:按命令查状态、装驱动、装 CUDA、体检
├── assets/             # 需要分发的静态资源(如 pin 的 apt key、模板)
└── README.md
```

移植方式是**逐条对照实现**:每落一个插件,拿 `~/new-system` 对应脚本做"行为基准"
(同样的路径/参数/幂等判定/失败信息),但代码是 gs 自己的(复用 §7.6-G 的共享安装库)。
验收时用"同样的机器状态 → 两种实现结果一致"来对照,而不是共用代码。

| 方案 | 做法 | 结论 |
|---|---|---|
| C. 双仓并存(gs 调 `~/new-system` 的脚本) | 用 `GS_NEW_SYSTEM_ROOT` 指过去 | ❌ 不采用 |
| G. 把脚本搬进 gs 仓库 | `plugins/<领域>/steps/` 放副本 | ❌ 不采用 |
| **P. 只移植能力** | 插件用自己的实现复刻行为,`~/new-system` 保持原样不动 | ✅ 采用 |

### 7.6 与现有 13 个公开插件的融合(重点)

只加新插件是不够的 —— 现在仓库里已经有 **四个真实重叠**,不处理就会出现"同一个东西两条路"。

#### A. 安装职责重复:`devenv` 已经是通用安装器

`devenv` 现有 `list / status / check / presets / install <tool|preset> / validate` ——
它本来就在做"检查 + 安装工具",而 `~/new-system` 的 20/25/30–36/39 是同一件事的具体版本。

**归属规则**:

| 场景 | 用谁 |
|---|---|
| 临时补装一个不在清单里的工具 | `gs devenv install <tool>`(保持) |
| 装一整套环境(装 + 配 + 状态 + 该领域特殊逻辑) | 领域插件 `gs lang install rust` / `gs docker install` |
| 首次把一台机器装到可用 | `gs init`(步骤里可以引用 devenv 的 preset) |

关键:**底层只有一份安装实现**(apt/brew/镜像/幂等判断)。现在 `~/new-system/lib/common.sh`
和 `devenv` 各有一套 apt 封装,融合时必须合并成一份共享库,否则镜像源、幂等策略、失败信息会三处不一致。
同理,`devenv presets` 与 `init --group` 不该是两个概念:后者可以**包含**前者。

#### B. repo/manifest 重复:`multirepo` 与 AOSP 是同一件事(决议:合并)

`multirepo` 有 `manifest / projects / init --backend=git|repo / sync / checkout / inspect / plan`,
而且**它自带的清单就是 `mini-aosp.xml`** —— 它本来就是为 AOSP 场景写的。
所以决议是**把 `multirepo` 整个并进 `android`**,成为 `repo` 子域:

```
gs android repo init aosp --backend=repo --branch=android-17.0.0_r1 --depth=1
gs android repo sync aosp --jobs=4
gs android repo checkout aosp
```

`android` 因此同时拥有"源码(repo)"与"编译(build/setup)"两个子域,`repo sync` 的限流、
断点续传、manifest 解析只有一份实现。旧命令 `gs multirepo …` **直接移除**(§7.7.2)。

#### C. 目录定义重复:`navigator` 硬编码的目录 vs Disk 创建的目录

`navigator` 现在硬编码了 house/as-aosp/aosp/lineage/flyme/miui/oppo/vivo 等目录;
new-system 的 `12-create-workspaces.sh` 也在创建 `/mnt/build-ssd/...` 之类的工作区。
两处各写一份,改名或换盘就会对不上。

**做法:一份 `workspaces.conf` 作为唯一事实来源**(名字、路径、用途、是否创建):

| 谁 | 怎么用它 |
|---|---|
| `gs disk create workspaces` | 按它建目录 / 打印缺失 |
| `gs navigator list` / `gs navigator aosp` | 按它列目录、按它跳转(不再硬编码) |
| `gs android repo sync` | 按它找 AOSP 工作区 |

#### D. 同域多使用者:必须先定"单一 owner"

| 领域 | 现在的所有者 | 建议 owner | 兼容做法 |
|---|---|---|---|
| 代理 | `system proxy` + (新)v2rayN 客户端 | **`net`**:`gs net proxy on|off|status|config` + `gs net client install` | 旧 `gs system proxy …` 移除 |
| 提示符 | `system prompt` + dotfiles 的 `gs-config/01-gs-prompt` | **`shortcuts`**(提示符属于 shell 外观层)或保留 `system` | 待定,见 §11.2 |
| git 身份 | `identity git`(切换身份) + dotfiles `.gitconfig`(文件) | **文件归 `git` 插件**(`gs git apply`)、切换归 identity | 两边 `--help` 互相指路 |
| ssh | `identity ssh`(6) + 私有 `sgm ssh`(6) | identity 管"我的账号/密钥",sgm 管"公司/gerrit 连接" | 现状可接受,补交叉引用 |
| AOSP 源码 vs 编译 | `multirepo` + `android` | **都归 `android`**:源码 = `repo` 子域,编译 = `build`/`setup` 子域 | 见 B |

#### E. 逐插件对照表(改造后每个插件变成什么样)

| 现有插件 | 改动 | 具体 |
|---|---|---|
| `system` | 扩 + 瘦 | 新增 `set mirror`(apt/pip/npm/cargo + 现有 repo/brew);`proxy` 移交 `net`(旧命令移除);`prompt` 移交 `shortcuts` |
| `devenv` | **拆解** | 工具目录/预设按领域拆走;apt/brew 逻辑下沉为共享安装库;`gs devenv …` 直接移除 |
| `multirepo` | **并入 android** | 变为 `gs android repo init/sync/checkout/list/…`;`mini-aosp.xml` 搬进 `plugins/android/manifests/` |
| `vscode` | 扩 | + `install`(桌面/CLI)、`setup tunnel` |
| `android` | 扩 + 词序对齐 | + `setup` 组(deps/workspace/env/emulator)、`adb` 组(service/udev/mac-helper);`device devices` → `device list` 等 |
| `navigator` | 改数据源 | 目录定义改为读 `workspaces.conf` |
| `dotfiles` | **拆解** | 按工具拆成 `nvim`/`vim`/`tmux`/`git`/`fish`/`zsh`;机制下沉为共享库 |
| `alias` | 升级为 `shortcuts` | 从"检查我的 alias"变成"提供并导出快捷命令" |
| `grep` / `spider` / `vps` / `sync` / `identity` | 基本不动 | 仅动词对齐 + 交叉引用 |

#### F. 工具插件的样子(装 + 配都在它自己身上)

既然每个工具一个插件,就不存在"软件归 A、配置归 B"的跨插件拆分了:

```
gs tmux install        # 装 tmux 与 TPM
gs tmux apply          # 落 tmux.conf + 主题 + 插件列表(复用共享的文件搬运库)
gs tmux status         # 软件版本 / 配置是否同步 / 主题是否生效
gs tmux backup|restore # 回滚(共享库提供)
```

规则一句话:**这个工具的一切(装、配、状态、回滚)都在它自己的插件里**;
跨工具的东西只有两类 —— shell 快捷命令(`shortcuts`)和领域安装(`lang`/`gpu`/…)。

#### G. 融合后的共享底座(避免三套实现)

1. **安装库**:apt/brew/镜像/幂等/`sudo` 判断只有一份(合并 `new-system/lib/common.sh` 与 `devenv`);
2. **工作区定义**:一份 `workspaces.conf`,disk / navigator / android / ai 共用;
3. **步骤清单**:`init.toml` 只引用插件命令,不复制逻辑;
4. **门禁与备份**:`risk`/`root`/`--dry-run|--yes`/`.bak` 由核心统一执行,插件只声明;
5. **镜像源**:一处配置(apt/pip/npm/cargo/repo/brew),`system set mirror` 与各安装步骤共用。

### 7.7 六条决议的落地(2026-10-01 定)

> 决议:`devenv` 拆掉 · `multirepo` 并入 `android` · 目录定义统一到 `workspaces.conf` ·
> 代理新设 `net` · 提示符迁入 `shortcuts` · git/ssh 按"文件 vs 切换 vs 公司连接"分工。

#### 7.7.1 `devenv` 拆掉(它的能力去哪)

它现在的资产是两张表 + 6 条命令:

```
plugins/devenv/config/tools.json     # 工具目录(required/optional/分类/安装方式)
plugins/devenv/config/presets.json   # 预设(essential / android-dev / …)
```

| devenv 资产 | 去向 |
|---|---|
| `install <tool>` 的 apt/brew 逻辑 | 下沉为**共享安装库**(见 §7.6-G),由各领域插件调用 |
| `tools.json` 的工具条目 | 按领域拆:`git/jq/ripgrep/fd/bat/fzf/tmux/htop/curl/wget`→`system`;**语言**→`lang`;**docker**→`docker`;**vscode**→`vscode`;**AOSP 依赖**→`android` |
| `presets.json: essential` | → `gs system install base`(基础 CLI 工具集) |
| `presets.json: android-dev` 等 | → 对应领域插件的 `setup`(`gs android setup deps`) |
| `list` / `status` / `check` | → 各领域插件的 `list` / `status` / `doctor` |
| `validate` | → `gs doctor`(全局体检里加一节"环境完整性") |
| `install` 的 `--dry-run/--yes` 门禁 | 保留为全局规则(`risk` 元数据) |

兼容:**不保留入口**(决议:旧命令不保留)。`gs devenv …` 直接不存在;命令名报错时按改名表提示
"已拆分为 `gs <领域> …`"即可。(仓库里的 `devenv validate` 出现在验收脚本 §7.7.4,一并迁移。)

#### 7.7.2 `multirepo` 并入 `android`

它现在的资产同样先搬过来:

```
plugins/multirepo/manifests/mini-aosp.xml   →  plugins/android/manifests/
plugins/multirepo/multirepo.py              →  plugins/android/repo.py(T2 脚本,保持逻辑)
```

命令映射(全部落到 android 的 `repo` 子域,满足 `<plugin> <domain> <verb>` 词序):

| 旧命令 | 新命令 |
|---|---|
| `gs multirepo list` | `gs android repo list` |
| `gs multirepo manifest [name]` | `gs android repo show [name]` |
| `gs multirepo projects [m]` | `gs android repo projects [m]` |
| `gs multirepo inspect [m]` | `gs android repo inspect [m]` |
| `gs multirepo status` / `diff` | `gs android repo status` / `gs android repo diff` |
| `gs multirepo init [m] --backend=…` | `gs android repo init [m] --backend=…` |
| `gs multirepo sync [m]` | `gs android repo sync [m]` |
| `gs multirepo checkout` | `gs android repo checkout` |
| `gs multirepo plan/verify-plan/apply-plan` | `gs android repo plan` / `verify-plan` / `apply-plan`(阶段名保留,门禁不变) |

兼容:**不保留**(决议:旧命令不保留),`gs multirepo …` 直接消失;报错时按改名表提示新命令。

副作用要认:android 会从 96 条涨到 ~109 条、17 个组。这正是 §5「分组必须真的是分组」必须**先做**的原因
——否则 `gs android` 会彻底不可读。分组规划:

```
device · app · dump · logcat · fs · proc · input · emulator · surface · system · winscope · frida
repo    ← 原 multirepo(源码/manifest)
build   ← AOSP 编译(原 build 组)
setup   ← 编译环境搭建(deps/ccache/env/tools)
adb     ← adb server / udev / Mac 侧助手
```

#### 7.7.3 目录定义统一到 `workspaces.conf`

唯一事实来源(建议放 `config/workspaces.conf`,与 new-system 的 `config/*.conf` 风格一致):

```ini
# 名字 | 路径 | 用途 | 是否自动创建
code      = ~/code                 | 日常代码        | yes
aosp      = /mnt/build-ssd/aosp    | AOSP 源码       | yes
ccache    = /mnt/build-ssd/ccache  | 编译缓存        | yes
models    = /mnt/models            | 模型权重        | yes
```

使用者:`gs disk create workspaces`(建)、`gs navigator …`(跳)、`gs android repo sync`(找 AOSP 工作区)、
`gs ai …`(找 models)。**`navigator` 里那份硬编码目录表删除。**

#### 7.7.4 验收脚本与测试的迁移

`scripts/verify_gs.sh` 现在直接引用旧插件,拆分/合并后要同步改:

| 现在 | 改成 |
|---|---|
| `gs devenv validate` | `gs doctor`(环境完整性一节) |
| `gs devenv install definitely-missing-tool`(门禁检查) | `gs lang install definitely-missing-tool`(同样应拒绝) |
| `'devenv:validate'` 契约项 | `'system:doctor'`(或删除,由 `gs doctor` 覆盖) |
| `gs multirepo list / manifest / plan / apply-plan` | `gs android repo list / show / plan / apply-plan`(**旧写法删除,不做转发**) |
| `'multirepo:verify-plan'` 契约项 | `'android:repo.verify-plan'`(同上) |

因为决议是"旧命令不保留",验收脚本里凡是引用旧名字的地方都要**直接改写**(不是加兼容),
`gs doctor` 里也不再有任何"遗留入口仍然可用"的检查项。

#### 7.7.5 插件总数变化

```
现在 13 个(公开):alias android devenv dotfiles grep identity multirepo navigator spider sync system vps vscode
             (+2 私有:sgm flyme,代码只在 custom/userspace/,不进仓库/发布包)
改造后 22 个(公开):android shortcuts grep identity navigator spider sync system vps vscode
              nvim vim tmux git fish zsh
              disk gpu docker lang ai net
             (-devenv -multirepo -dotfiles,alias→shortcuts,+13 新插件)
```

`gs android` 变重(设备 + 源码 + 编译 + 环境),这是"按你的分类方式"的必然结果;
靠 §5 的分组渲染 + `<domain> <verb>` 词序把它压回可读。

#### 7.7.6 `dotfiles` 拆成"每个工具一个插件"(与 tmux 独立的逻辑一致)

既然 tmux 独立,那 nvim/vim/git/fish/zsh 没有理由挤在一个 `dotfiles` 里。资产落位:

```
plugins/dotfiles/nvim/   →  plugins/nvim/{files/,nvim.py,plugin.toml}
plugins/dotfiles/vim/    →  plugins/vim/…
plugins/dotfiles/tmux/   →  plugins/tmux/…      (与 new-system 的 39-tmux 合并)
plugins/dotfiles/git/    →  plugins/git/…
plugins/dotfiles/fish/   →  plugins/fish/…      (含 gs-config/ 与 fisher/tide 流程)
plugins/dotfiles/zsh/    →  plugins/zsh/…
plugins/dotfiles/dotfiles.py 里的搬运/合并/备份 →  sdk 里的共享库(见 §7.6-G)
```

每个工具插件统一给同一套动词(§3.3):

```
gs nvim install [--yes]      # 装 nvim + 落 init.vim/lua + 可选装插件管理器
gs nvim status               # 软件版本 / 配置文件是否同步 / 差异
gs nvim backup / restore     # 备份与回滚(共享库提供)
gs tmux install              # 装 tmux + TPM
gs tmux apply theme          # 应用主题与插件列表
gs fish install              # 装 fish + config.fish + gs-config + fisher 插件
gs git apply                 # 落 .gitconfig(身份切换仍归 identity)
```

**分工要点**:

- 文件搬运/合并/`.bak`/回滚 → **共享库**(从 dotfiles.py 抽出,所有工具插件复用);
- shell 里的缩写/函数 → **不在工具插件里**,统一进 `shortcuts`(所以 fish 的
  `gs-config/03-gs-abbreviations.fish` 那一百多条要走 `gs shortcuts apply` 导出,而不是 fish 私有);
- 工具自身的设置项(git config、tmux 插件列表、tide 主题) → 该工具插件的 `apply`。

> `vim` 只有一个 `.vimrc`,如果嫌太碎,可以并入 `nvim` 插件(`gs nvim apply vimrc`);
> 但按"每工具一个"的一致性,默认仍单独列出。

#### 7.7.7 仓库策略:`~/new-system` 保持独立,只移植能力(决议)

**`~/new-system` 只留在 `~/new-system`;`global_scripts` 仓库里不放它的任何脚本副本。**

| 项 | 处理 |
|---|---|
| `scripts/NN-*.sh` | **不搬**。按 §7.5 的"逐条对照实现"把行为写进对应插件的 `*.py` |
| `lib/common.sh`(日志/root 切换/apt 封装) | 行为等价地**重写**进 gs 的共享库(与 devenv 的安装逻辑合并成一份),不复制文件 |
| `config/*.conf`(路径与开关) | 换算成 gs 自己的配置:`workspaces.conf`(§7.7.3)+ 各插件 `plugin.toml` 里的默认值 |
| `config/tmux/` 主题资源 | 需要分发的静态资源放 `plugins/tmux/assets/`(那是 gs 自己的资产,不是 new-system 的副本) |
| `README.md` / `install-workflow.sh` | 不搬。信息拆进各插件 README 与 `gs init` 的步骤说明 |
| `~/new-system` 本身 | **保持原样不动**(你的参考资料);gs 不依赖它存在,CI/验收也不读它 |

对实现的约束:

1. 插件代码里**不允许**出现 `~/new-system` 路径或 `source ../new-system/...`;
2. 每完成一个插件,用"同样的机器状态跑旧脚本 vs 跑 `gs <插件>`"来对照结果(路径、包、幂等判定一致);
3. `~/new-system` 之后怎么处置(归档/删除)由你决定,与 gs 无关。

#### 7.7.8 sudo 策略:只由你自己执行(决议)

`gs` **永不自己提权**(§6.2 的 A 方案)。遇到 `root = true` 的步骤:

```
$ gs gpu install driver
需要 root 权限。请执行:
    sudo gs gpu install driver
或直接跑该步骤脚本:
    sudo bash ~/.local/share/global-scripts/<version>/plugins/gpu/steps/21-nvidia.sh
```

要点:

1. `gs` 只打印,不调用 `sudo`、不缓存凭据、不弹密码框;
2. 用户以 `sudo gs …` 运行时,核心必须用 `SUDO_USER` 还原"目标用户"的
   `HOME`/`GS_ROOT`/`GS_CACHE_DIR`,避免把配置写到 `/root`(new-system 的
   `resolve_target_user`/`target_home`/`run_as_user` 逻辑原样保留);
3. 需要同时"root 装 + 用户配"的步骤(如 rustup):脚本内部自己 `run_as_user` 切回,
   行为与 new-system 今天一致;
4. `--dry-run` 永远不需要 root(只读),这是默认验收路径。

#### 7.7.9 "旧命令不保留"要一并清理的地方

硬切意味着没有兼容层可以兜底,所以这些地方必须在同一批里改完:

| 位置 | 要做什么 |
|---|---|
| `scripts/verify_gs.sh` | 全部旧命令改写(§7.7.4);删掉任何"遗留入口可用"的检查 |
| 改名对照表 | 当初由 `scripts/audit_command_parity.py` 维护;该脚本已随 5.2 退役删除,对照关系改为记录在本文与各自插件的 README 里 |
| `README.md` / `docs/cli-reference.md` / `docs/installation.md` / 各插件 README | 所有示例改成新命令;删除已不存在的插件章节 |
| `plugin.toml` 的 `[groups]` 与命令名 | 这次一并改到位(别留"旧名 + 新名"两份) |
| 升级说明 | 放一张**改名对照表**(旧 → 新),让用户一次性改自己的脚本 |
| shell 补全 / `shell-init` | 不用改(都是运行时生成) |

---

## 8. 分期计划

| 阶段 | 内容 | 产出 | 风险 |
|---|---|---|---|
| **P0** | 本文档定稿 + 评审 | 决策记录 | — |
| **P1** | UI 分组渲染 + 动词统一(不动插件内容) | `gs android` 变清晰;`doctor` 开始校验 groups | 低 |
| **P2** | `shortcuts` 插件(v2):声明、导出、status/doctor | 103 条缩写 + 常用函数迁进去,三 shell 共用 | 中(涉及写 shell 配置) |
| **P3** | 动词对齐(`install`/`apply`/`set`)+ 工具插件拆分(nvim/vim/tmux/git/fish/zsh) | `gs nvim install` · `gs tmux apply` | 中 |
| **P4** | 6 个领域插件 + 核心编排命令 `gs init` + new-system 移植(先 C 后 G) | `gs lang install rust` · `gs init --group=langs` | 中(依赖 sudo 策略) |
| **P5** | 收尾:补全、文档、验收脚本(5.2 兼容层已直接删除,见 ADR 005) | 全量验收绿 | 低 |

每阶段独立可发布,任意阶段可停。

---

## 9. 改造之后怎么用(场景演练)

**新机器到手(现在:clone new-system + 读 README)**

```bash
gs init --list                            # 步骤清单:每步属于哪个插件、是否已完成
gs init --dry-run                   # 预览默认流程(不需要 root)
gs init --group=sys,langs           # 装基础工具链与各语言
gs init --only=docker                # 只补一步(按步骤名)
gs system status && gs disk status       # 各领域自己的状态
```

**装并配好 tmux(现在:三条命令、两个仓库)**

```bash
gs tmux install --dry-run                # 装 tmux + TPM
gs tmux install --yes                    # 装软件 + TPM
gs tmux apply --yes                      # 落 tmux.conf + 主题 + 插件列表
gs tmux status                           # 三项:软件 / 配置 / 主题
```

**只想要某个领域(不必跑整套流程)**

```bash
gs lang list                             # 支持哪些语言、当前版本
gs lang install rust --dry-run
gs lang install rust --yes
gs gpu install cuda --dry-run            # GPU 领域同理
```

**快捷命令(现在:三份 alias 文件各写一遍)**

```bash
gs shortcuts list                        # 看内置 + 自定义(按分组)
gs shortcuts show ll                     # 看某个命令的定义与各 shell 展开
gs shortcuts add mygit --kind=function --fish='…' --bash='…'   # 自己加
gs shortcuts apply --dry-run             # 预览会写进哪些 shell 文件
gs shortcuts apply --yes                 # 写进受管区块(带备份)
gs shortcuts doctor                      # 检测冲突(比如缩写被占用)
```

**日常使用(不变)**

```bash
gs android app list-3rd                  # 设备日常操作
gs android app                           # 只看 app 组
gs grep python 'def _search'
```

**出问题**

```bash
gs doctor                    # 全局:插件清单、SDK、T3 守护进程、shell 集成
gs android doctor            # 插件级:adb/设备/资产
gs init --list                # 装机清单:哪些步骤已完成 / 待做 / 需要重启
gs disk doctor               # 领域级:挂载/fstab/工作区
gs gpu status                # 驱动版本、CUDA、容器支持
gs shortcuts status          # 我的 shell 是否被改过
```

---

## 10. 验收与测试

| 层 | 验收方式 |
|---|---|
| UI | 快照测试:同一份 manifest 渲染结果比对;窄终端(60 列)不折行 |
| 全插件 | `python3 scripts/audit_plugins.py`:逐插件清单/元数据/分组/只读冒烟 + 冷热启动耗时,有问题非零退出 |
| shortcuts | 在隔离 HOME 里 `apply` → 用 bash/zsh/fish 各起一个会话,断言缩写/函数可用、重复 apply 幂等、删掉重来可恢复 |
| 工具插件 | 每个工具各自一遍:隔离 HOME + 合并语义 + 备份 + restore(`gs nvim install/apply/restore`) |
| 领域插件 | 每个插件:同一命令重复执行幂等、`--dry-run` 不写盘、`status` 与真实状态一致;真实执行只在临时机/容器里跑无副作用步骤 |
| 编排 `gs init` | `--list` 覆盖全部步骤;`--only=<步骤名>` 与直接调插件命令等价;`--dry-run` 全程退出 0 |
| 全局 | `scripts/verify_gs.sh` 增加三层各自的冒烟项 |

---

## 11. 命名与决议汇总

### 11.1 编排命令叫什么(替代 `provision`)—— 已定:`init`

| 候选 | 用法 | 优点 | 问题 |
|---|---|---|---|
| `setup` | `gs init --group=langs` | 最直白,一眼能猜 | 与安装脚本同名不同物,容易混 |
| `bootstrap` | `gs bootstrap run --group=langs` | 语义最准:把新机器引导到可用 | 略长、容易拼错 |
| `init` | `gs init --group=langs` | 最短,动词感强,像 `git init` / `terraform init` | 可能被理解成"初始化 gs 自己" |
| `machine` | `gs machine setup` / `gs machine status` | 明确指"这台机器" | 要两层才读得顺 |
| `runbook` | `gs runbook run` | 强调"照清单跑" | 偏运维黑话 |

**决议:用 `init`。**
`provision` 的问题在于它把"业务动作"当成了命名,而且它**不该是插件**——装什么由领域插件负责,
编排只是一条读清单的核心命令。选 `init` 的理由:最短、动词性最强、不需要第二个词就能读通:

```
gs init --list                  # 步骤清单
gs init --group=sys,langs       # 按分组装
gs init --only=docker           # 只补一步(步骤名自解释)
gs init --without=android       # 跳过整组
```

### 11.2 插件边界 —— 已定

1. **tmux 独立 → 顺推所有工具独立**:既然 tmux 单独成插件,`nvim`/`vim`/`git`/`fish`/`zsh`
   同样各自独立;`dotfiles` 作为"一个插件管所有配置"的形态取消(§7.7.6)。
2. **`net` 独立**:命令为 `gs net proxy on|off|status|config` 与 `gs net client install`;
   旧 `gs system proxy …` **移除**(决议:旧命令不保留)。

### 11.3 融合相关的决定(§7.6 的四类重叠)—— 已定

| # | 问题 | 决议 |
|---|---|---|
| 1 | `devenv` 的去向 | **拆掉**:目录/预设按领域拆走,逻辑下沉为共享安装库;`gs devenv …` 直接移除(§7.7.1) |
| 2 | AOSP 源码同步归谁 | **并入 `android`**:`gs android repo …`;`gs multirepo …` 直接移除(§7.7.2) |
| 3 | 目录定义 | **统一到 `workspaces.conf`**,disk / navigator / android / ai 共用(§7.7.3) |
| 4 | 代理的单一 owner | **新设 `net`**(`gs net proxy on|off|status|config`);旧 `gs system proxy …` 移除(§7.6-D) |
| 5 | 提示符的 owner | **迁入 `shortcuts`**(提示符属于 shell 外观层),原 `system prompt …` 移除 |
| 6 | git/ssh 身份 | **按分工**:文件归 `git` 插件、身份切换归 `identity`、公司/gerrit 连接归私有插件 `sgm` |

### 11.4 其余待定

全部已定:

| 问题 | 决议 |
|---|---|
| `~/new-system` 与本仓的关系 | **只移植能力,不搬文件**:该仓保持原样留在 `~/new-system`,本仓不出现它的副本(§7.7.7) |
| sudo 策略 | **`gs` 永不自己提权**,只打印要执行的 sudo 命令(§7.7.8) |
| shortcuts 落点 | **独立文件 + source**:生成 `~/.config/global-scripts/shortcuts/shortcuts.{bash,zsh,fish}`,你的 rc 里只加一行 source(§4.3) |
| 格式化磁盘 | **不进 `gs`**:不可恢复操作留在 `~/new-system`(或纯手工),仅在文档里提示风险 |
| 旧命令 | **不保留**:`gs multirepo …`/`gs devenv …`/旧写法直接消失,不设别名与转发;报错信息可按改名表提示新命令 |
| `alias` 插件 | 升级为 `shortcuts`(新名字),`alias` 不保留 |

仍可选(不影响开工):`gs i nvim` 这类一次性极简别名要不要做。

---

## 附:本方案对现有行为的影响

- 现有公开插件的命令**不删不改名**(P1 只改渲染,P3/P4 只加新命令)。
- `install/uninstall` 成为全项目标准动词(源自 `dotfiles` 那轮统一),`android` 等逐步对齐措辞。
- `plugin.toml` 新增字段全部可选,老 manifest 继续可用(未知字段本来就被忽略)。
- 5.2 兼容路径(`scripts/setup.py`、legacy router)已被 ADR 005 整体删除,不再是约束。
