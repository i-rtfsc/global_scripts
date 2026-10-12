# 快速开始

## 1. 确认装好了

```bash
gs version
gs doctor
```

`doctor` 会告诉你 manifest 是否有效、entry 是否存在、插件运行时是否可用、
shell 集成是否已引用。

## 2. 认识三个入口

```bash
gs help              # 前门命令
gs plugin list       # 插件与命令数
gs plugin info system   # 某个插件的完整命令面
```

命令形式统一为：

```
gs <插件> <动词> [对象] [参数]
```

子命令用 `.` 分组，空格写法等价：

```bash
gs android device logcat        # 等价于 gs android device.logcat
gs system proxy status
```

## 3. 跑几条只读命令

```bash
gs navigator list               # 目录导航表
gs system proxy status          # 代理状态
gs android device devices       # 已连接设备（需要 adb）
gs dotfiles status nvim         # dotfiles 与 $HOME 的差异
gs identity ssh status          # SSH 资产状态
```

危险操作会先给你看计划：

```bash
gs android build build --dry-run
gs system repo tsinghua --dry-run
gs multirepo plan mini-aosp --backend=git
```

真正执行要显式 `--yes`。`gs` 自己从不提权，需要 root 时它只打印 `sudo …` 让你自己跑。

## 4. 打开补全与 cd 集成

```bash
source <(gs shell-init bash)     # bash
source <(gs shell-init zsh)      # zsh
gs shell-init fish > ~/.config/fish/conf.d/gs.fish   # fish

gs completions bash --install    # 补全
```

装好后 `gs and<Tab>` 会列出插件与命令，带说明。

## 5. 装机编排

`gs init` 按 `config/init.toml` 的清单逐项检查/执行：

```bash
gs init --list                   # 看步骤与当前状态
gs init --dry-run                # 全部只做检查
gs init base-tools               # 只跑某一步
gs init --group=mirror           # 只跑某组
```

状态会区分“就绪 / 需要 sudo / 插件尚未创建”；需要 sudo 的步骤只会打印命令，
由你自己执行。

## 6. 下一步

- 想写插件：[插件开发](./plugin-development.md) + [插件协议](./protocol.md)
- 想懂内部：[架构设计](./architecture.md)
- 常见问题：[FAQ](./faq.md)
