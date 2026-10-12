# 安装指南

## 系统要求

| 项 | 要求 | 说明 |
|---|---|---|
| Rust | 1.75+ | 仅**从源码构建**时需要 |
| Python | 3.8+ | T2/T3 插件需要（`gs doctor` 会检查） |
| Shell | bash / zsh / fish | PowerShell 实验支持 |
| 平台 | macOS / Linux | Windows 通过 WSL2 |

不需要 `jq`、不需要 `uv`、不需要安装任何第三方 Python 包——插件 SDK 是
stdlib-only，随发布包一起分发。

## 安装步骤

### 方式一：从源码

```bash
git clone https://github.com/i-rtfsc/global_scripts.git
cd global_scripts

# 1. 构建 Release 前门
cargo build --release --manifest-path rust/Cargo.toml -p gs

# 2. 生成 staging 树（产出 dist/gs）
bash scripts/stage_release.sh

# 3. 安装（默认 ~/.local，不需要 sudo）
bash scripts/install_gs.sh --yes
```

### 方式二：从发布包

```bash
# 解压对应平台的包后
bash scripts/install_gs.sh --yes
```

发布包布局：

```
gs-<target>/
├── gs                  # 原生二进制
├── gs-launch           # 入口脚本（设置 GS_ROOT 后 exec gs）
├── plugins/            # 正式插件
├── sdk/python/         # 插件 SDK
├── config/             # init.toml / gs.json
├── themes/prompt/      # 提示符主题
└── SHA256SUMS
```

### 安装器做了什么

- 把整棵树放进 `$PREFIX/share/global-scripts/<version>/`；
- 建立 `$PREFIX/bin/gs` → `<version>/gs-launch` 的符号链接；
- 生成补全文件与 `~/.config/global-scripts/shell/gs-env.{bash,zsh,fish}`，
  并在 `~/.bashrc` / `~/.zshrc` / `~/.config/fish/config.fish` 里引用它。

可选开关：

| 环境变量 / 参数 | 作用 |
|---|---|
| `GS_PREFIX=/opt/gs` | 换安装前缀（默认 `~/.local`） |
| `--name gsp` | 换命令名（默认 `gs`） |
| `GS_LINK_PRIVATE_ASSETS=0` | 不链接 `custom/userspace` 下的私有资产 |
| `GS_INCLUDE_PRIVATE=1` | 打包私有插件（只用于你自己的私有构建） |

安装器**从不**复制私钥、token 或公司配置；私有资产只做符号链接。

## Shell 集成

想用 `cd` 与 `export` 副作用，需要装一层很薄的外壳函数（它把 `$GS_CD_FILE` /
`$GS_ENV_FILE` 交给 `gs`，读回结果再 `eval`）：

```bash
# bash
echo 'source <(gs shell-init bash)' >> ~/.bashrc
# zsh
echo 'source <(gs shell-init zsh)'  >> ~/.zshrc
# fish
gs shell-init fish > ~/.config/fish/conf.d/gs.fish
```

补全单独安装：

```bash
gs completions bash --install     # 或 zsh / fish；不带参数则装全部
```

## 验证安装

```bash
gs version
gs doctor        # manifest / entry / 插件运行时 / shell 集成
gs plugin list
```

`doctor` 的“插件运行时”一行会告诉你 T2/T3 插件需要的解释器是否在 `PATH` 上。

### 私有插件

`sgm`、`flyme` 这类私有插件不在公开仓库也不在发布包里，只存在于私有目录
`custom/userspace/<名字>/`（`custom/` 被 `.gitignore` 排除）。运行
`scripts/install_gs.sh --yes` 时它们会被复制进已安装树的 `plugins/`，本机 `gs`
照常列出并执行；第三方拿到的发布包不含它们。

## 升级与卸载

```bash
bash scripts/install_gs.sh --yes     # 重复执行即升级
bash scripts/uninstall_gs.sh --yes   # 只删 gs，其它入口不动
```

升级时 `~/.local/bin/gs` 若指向别的目标会先被改名为 `gs.backup-<时间戳>`。

## 与 Ghostscript 同名

很多系统自带 `gs`（Ghostscript）。安装后 `~/.local/bin/gs` 在 `PATH` 中更靠前，
因此会遮蔽它。仍要调用 Ghostscript 时用绝对路径 `/usr/bin/gs`，或用
`--name gsp` 换一个命令名。

## 故障排除

| 现象 | 原因 / 处理 |
|---|---|
| `gs: command not found` | `~/.local/bin` 不在 `PATH`，或需要重开终端 |
| `env: 'command': No such file or directory` | 旧的 fish 集成残留，重装 `gs shell-init fish` |
| 插件命令报找不到解释器 | 装 `python3`，然后 `gs doctor` 复核 |
| 补全不生效 | `gs completions <shell> --install` 后重开终端 |
| `gs <插件>` 报 plugin.toml 无效 | 按提示的行号修 manifest，`gs doctor` 汇总所有问题 |

## 相关文档

- [快速开始](./quickstart.md) · [架构设计](./architecture.md) · [插件协议](./protocol.md)
