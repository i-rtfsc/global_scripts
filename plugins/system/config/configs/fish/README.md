# Fish Shell Configuration

Global Scripts 提供的现代化 Fish Shell 配置系统。

## 📦 功能特性

- ✅ 模块化配置结构
- ✅ 跨平台支持 (macOS/Linux)
- ✅ 丰富的实用函数
- ✅ 完整的 Git 工作流缩写
- ✅ FZF 深度集成
- ✅ 40+ 工具集成
- ✅ Tide 提示符配置（Rainbow 双行风格 + user@IP 显示）
- ✅ 智能路径管理

## 🚀 快速开始

### 1. 安装配置文件

```bash
gs system config install fish
```

这会将以下文件安装到 `~/.config/fish/`:
- `config.fish` - 主配置文件（带生成时间戳和 env.fish 自动加载）
- `apply-tide-config.fish` - Tide 完整配置脚本
- `conf.d/` - 模块化配置目录
  - `00-functions.fish` - 实用工具函数
  - `01-prompt.fish` - Tide 提示符自定义（user@IP 显示）
  - `02-fzf.fish` - FZF 集成
  - `03-abbreviations.fish` - 命令缩写
  - `04-integrations.fish` - 工具集成
  - `05-greeting.fish` - 欢迎信息
- `setup-plugins.fish` - 插件安装脚本

**注意**：安装时会自动添加时间戳和 Global Scripts 环境变量：
```fish
#!/usr/bin/env fish
# Global Scripts - Fish Shell Configuration
# Generated automatically by: gs system config install fish
# Generated at: 2025-10-16 18:38:11
# Source: plugins/system/config/configs/fish/
#
# ============================================

# ... 配置内容 ...

# ============================================
# Global Scripts Environment
# ============================================
source /Users/solo/code/github/global_scripts/env.fish
```

### 2. 应用 Tide 配置（推荐）

在**真实的 Fish shell 终端**中执行：

```fish
# 应用完整的 Tide 配置
source ~/.config/fish/apply-tide-config.fish

# 重启 Fish shell
exec fish
```

这将应用：
- ✅ Rainbow 双行风格（圆角分隔符 + 框架）
- ✅ 24小时制时间显示
- ✅ Many icons（丰富图标）
- ✅ 虚拟环境检测（Python, Node.js, Go, Docker 等）
- ✅ user@IP 显示（而不是 hostname）
- ✅ 命令执行时长显示（>1秒）

**配置效果**：

**左侧提示符**:
- 🍎 OS 图标
- 📁 当前目录
- 🌿 Git 状态
- ➜ 命令提示符

**右侧提示符**（智能显示）:
- ✓/✗ 命令状态
- ⏱ 执行时长（>1秒才显示）
- 🐍 Python 虚拟环境（venv/conda）
- ⬢ Node.js 版本（检测到 package.json 时）
- 🐹 Go 版本（检测到 go.mod 时）
- 🐳 Docker 容器
- 📌 direnv 环境
- 👤 user@192.168.1.100
- 📋 后台任务数
- 🕐 当前时间

### 3. 验证配置

```fish
# 查看右侧提示符配置
set -S | grep tide_right_prompt_items

# 应该看到 10 个元素：
# status, cmd_duration, python, node, go, docker, direnv, context, jobs, time
```

测试虚拟环境显示：
```fish
# 激活 Python 虚拟环境
cd ~/your_project
source .venv/bin/activate.fish

# 你应该在右侧提示符看到：🐍 3.11.13 (.venv)
```

测试命令执行时长：
```fish
# 运行一个耗时命令
sleep 2

# 下一个提示符右侧应该显示：2s
```

### 4. 安装 Fish 插件（可选）

运行安装脚本来安装推荐的 Fisher 插件：

```fish
fish ~/.config/fish/setup-plugins.fish
```

或手动安装：

```fish
# 1. 安装 Fisher 插件管理器
curl -sL https://raw.githubusercontent.com/jorgebucaran/fisher/main/functions/fisher.fish | source
fisher install jorgebucaran/fisher

# 2. 安装推荐插件
fisher install IlanCosman/tide@v6           # 现代提示符
fisher install jethrokuan/z                 # 目录跳转
fisher install PatrickF1/fzf.fish          # FZF 集成
fisher install franciscolourenco/done      # 命令完成通知
fisher install laughedelic/pisces          # 自动闭合括号
fisher install gazorby/fish-abbreviation-tips  # 缩写提示
fisher install edc/bass                     # Bash 脚本支持
```

## 📖 核心功能

### 实用函数

```fish
get_ip          # 获取本地 IP 地址（跨平台）
mkcd <dir>      # 创建目录并进入
extract <file>  # 智能解压各种格式
ll              # 增强的 ls 命令
ff              # 使用 FZF 搜索文件
pkillf          # 搜索并终止进程
backup <file>   # 快速备份文件
reload          # 重新加载 Fish 配置
sysinfo         # 显示系统信息
```

### FZF 集成

```fish
fcd             # FZF 目录搜索并跳转
fe              # FZF 文件搜索并编辑
fh              # FZF 命令历史搜索
fgb             # FZF Git 分支切换
fgl             # FZF Git 日志查看
fkill           # FZF 进程搜索并终止
fps             # FZF 包搜索
```

### Git 缩写

```fish
g               # git
ga              # git add
gaa             # git add --all
gc              # git commit -v
gcm             # git commit -m
gco             # git checkout
gd              # git diff
gf              # git fetch
gl              # git pull
glog            # git log --oneline --graph
gp              # git push
gst             # git status (注意：gs 被 Global Scripts 占用)
gsta            # git stash
```

完整的 Git 缩写列表请查看 `conf.d/03-abbreviations.fish`

### Docker 缩写

```fish
d               # docker
dps             # docker ps
dpsa            # docker ps -a
dc              # docker-compose
dcup            # docker-compose up -d
dcdown          # docker-compose down
```

## 🎨 Tide 提示符配置

### 配置文件说明

Tide 配置分为三个部分：

1. **~/.config/fish/fish_variables** - Tide 主配置存储位置
   - 包含所有 `tide configure` 生成的配置
   - 使用 Universal Variables (SETUVAR) 格式
   - 159 个配置变量（颜色、图标、分隔符等）

2. **~/.config/fish/apply-tide-config.fish** - 完整配置脚本
   - 包含原始的 `tide configure` 命令：
     ```fish
     tide configure --auto --style=Rainbow --prompt_colors='True color' \
       --show_time='24-hour format' --rainbow_prompt_separators=Round \
       --powerline_prompt_heads=Round --powerline_prompt_tails=Round \
       --powerline_prompt_style='Two lines, character and frame' \
       --prompt_connection=Disconnected --powerline_right_prompt_frame=Yes \
       --prompt_connection_andor_frame_color=Light --prompt_spacing=Compact \
       --icons='Many icons' --transient=No
     ```
   - 可一键应用所有配置
   - 便于版本控制和迁移

3. **~/.config/fish/conf.d/01-prompt.fish** - 自定义扩展
   - 只包含自定义功能（如 user@IP 显示）
   - 不会与 Tide 主配置冲突
   - 每次启动 Fish 自动加载

### 右侧提示符显示说明

#### 总是显示的项目
- **status**: ✓ 或 ✗ (命令成功/失败)
- **context**: user@192.168.1.100 (用户@IP)
- **time**: 18:30 (当前时间)

#### 条件显示的项目（仅在检测到时显示）

| 项目 | 显示条件 | 示例 |
|------|----------|------|
| **cmd_duration** | 命令执行超过 1 秒 | `2s` |
| **python** | 在 Python 虚拟环境中 | `🐍 3.11.13 (.venv)` |
| **node** | 目录包含 package.json | `⬢ v20.10.0` |
| **go** | 目录包含 go.mod | `🐹 go1.21.0` |
| **docker** | 在 Docker 容器内 | `🐳 container-name` |
| **direnv** | direnv 已加载 | `direnv` |
| **jobs** | 有后台任务运行 | `1&` |

### 自定义右侧提示符

#### 添加更多语言检测

```fish
# 添加 Rust, Java, PHP
set -U tide_right_prompt_items status cmd_duration python node go rustc java php context jobs time
exec fish
```

#### 添加云服务检测

```fish
# 添加 AWS, GCloud, Kubectl
set -U tide_right_prompt_items status cmd_duration python node aws gcloud kubectl context jobs time
exec fish
```

#### 调整命令执行时长阈值

```fish
# 设置为 3 秒（只有超过 3 秒的命令才显示时长）
set -U tide_cmd_duration_threshold 3000

# 或设置为 500 毫秒（半秒）
set -U tide_cmd_duration_threshold 500
```

### 可用的所有检测项

#### 编程语言
- `python` - Python (venv, conda)
- `node` - Node.js
- `go` - Go
- `rustc` - Rust
- `java` - Java
- `php` - PHP
- `ruby` - Ruby
- `elixir` - Elixir
- `crystal` - Crystal
- `zig` - Zig
- `bun` - Bun

#### 容器 & DevOps
- `docker` - Docker 容器
- `kubectl` - Kubernetes context
- `terraform` - Terraform workspace
- `pulumi` - Pulumi stack

#### 云服务
- `aws` - AWS profile
- `gcloud` - Google Cloud project

#### 其他工具
- `direnv` - direnv 环境
- `nix_shell` - Nix shell
- `toolbox` - Toolbox
- `distrobox` - Distrobox
- `shlvl` - Shell 层级
- `private_mode` - 私密模式
- `vi_mode` - Vi 模式

### 推荐配置方案

#### 方案一：平衡型（推荐）

适合大多数开发者，包含常用语言和工具：

```fish
set -U tide_right_prompt_items status cmd_duration python node go docker direnv context jobs time
exec fish
```

#### 方案二：前端开发

```fish
set -U tide_right_prompt_items status cmd_duration node bun docker context jobs time
exec fish
```

#### 方案三：后端开发

```fish
set -U tide_right_prompt_items status cmd_duration python go java docker kubectl context jobs time
exec fish
```

#### 方案四：DevOps

```fish
set -U tide_right_prompt_items status cmd_duration docker kubectl terraform aws gcloud context jobs time
exec fish
```

#### 方案五：极简主义

```fish
set -U tide_right_prompt_items status cmd_duration context time
exec fish
```

#### 方案六：全功能配置

显示所有可能的环境：

```fish
set -U tide_right_prompt_items status cmd_duration python node go rustc java php ruby bun docker kubectl terraform aws gcloud direnv context jobs time
exec fish
```

## 🎯 自定义

### 修改提示符样式

如果想重新配置 Tide 样式，运行：

```fish
tide configure
```

然后重新应用自定义扩展：

```fish
source ~/.config/fish/conf.d/01-prompt.fish
exec fish
```

### 添加个人配置

创建 `~/.config/fish/local.fish` 文件，添加个人自定义配置：

```fish
# 个人环境变量
set -gx MY_VAR "value"

# 个人别名
abbr -a -g myalias 'my command'

# 个人函数
function my_function
    # your code
end
```

### 禁用欢迎信息

编辑 `conf.d/05-greeting.fish`，注释掉整个函数，或者使用：

```fish
function fish_greeting
    # 留空以禁用
end
```

## 🔧 工具集成

配置已集成以下工具（如果已安装）：

- **Python**: Conda, Pyenv
- **Node.js**: NVM
- **Rust**: Cargo
- **Go**: Go workspace
- **包管理**: Homebrew
- **目录管理**: Direnv, Zoxide
- **现代工具**: Bat, Exa, Ripgrep, Delta
- **DevOps**: Kubectl, Terraform, AWS CLI
- **其他**: Tmux, Starship, GPG, SSH Agent

## 📝 配置文件说明

### config.fish
主配置文件，负责：
- 生成时间戳记录
- 环境变量设置
- PATH 管理
- 颜色配置
- 模块加载
- Global Scripts 环境变量加载

### apply-tide-config.fish
完整的 Tide 配置脚本，包含原始 tide configure 命令。

### conf.d/00-functions.fish
实用工具函数库，包含文件操作、进程管理、系统信息等常用函数。

### conf.d/01-prompt.fish
提示符自定义扩展，提供 user@IP 显示功能。

### conf.d/02-fzf.fish
FZF 集成配置，包括颜色主题、预览设置和大量 FZF 辅助函数。

### conf.d/03-abbreviations.fish
命令缩写定义，涵盖通用命令、Git、Docker、Python、网络等。

### conf.d/04-integrations.fish
第三方工具集成，自动检测并配置常用开发工具。

### conf.d/05-greeting.fish
启动欢迎信息，显示系统信息和随机技巧。

## ⚠️ 注意事项

1. **命令冲突**: `gs` 命令被 Global Scripts 使用，Git status 请使用 `gst`

2. **插件安装**: 不要在 `config.fish` 中自动安装插件，这会导致资源耗尽。请使用 `setup-plugins.fish` 脚本。

3. **性能**: 配置已经过优化，延迟加载不常用的工具集成。

4. **跨平台**:
   - `get_ip` 函数自动检测平台并使用合适的命令
   - `ll` 函数在 macOS 使用 `-G`，Linux 使用 `--color=auto`

5. **备份**: 安装配置前，现有配置会自动备份到 `~/.config/global-scripts/backups/config/`，只保留最新 2 份备份

6. **Tide 配置**:
   - 使用 `-U` (universal) 而不是 `-g` (global) 设置变量，确保配置持久化
   - 必须在真实的 Fish shell 中执行配置命令，不能通过脚本或 `fish -c` 命令
   - 必须使用 `exec fish` 重启 Fish shell 使配置生效

7. **环境检测**:
   - 环境检测是智能的：只有检测到对应环境时才会显示图标
   - 不会影响性能：未检测到的 item 不会执行任何操作

## 🔄 更新配置

重新运行安装命令即可更新：

```bash
gs system config install fish
```

**注意**: 更新后需要重新应用 Tide 配置：

```fish
source ~/.config/fish/apply-tide-config.fish
exec fish
```

## 🐛 故障排除

### Tide 提示符报错：Unknown command

**症状**：
```
fish: Unknown command: _tide_item_python
fish: Unknown command: _tide_item_rustc
fish: Unknown command: _tide_item_java
```

**原因**：某些 `_tide_item_*` 函数未正确加载或系统中不可用。

**解决方案 1**：移除报错的检测项

```fish
# 如果 rustc, java 等报错，移除它们
set -U tide_right_prompt_items status cmd_duration python node go docker context jobs time
exec fish
```

**解决方案 2**：重新安装 Tide

```fish
fisher remove IlanCosman/tide
fisher install IlanCosman/tide@v6
source ~/.config/fish/apply-tide-config.fish
exec fish
```

### 配置不生效

**症状**：修改了配置但没有变化

**解决方案**：

```fish
# 1. 删除所有相关配置
set -e tide_right_prompt_items
set -e _tide_right_items

# 2. 重新应用配置
source ~/.config/fish/apply-tide-config.fish

# 3. 确保重启 Fish
exec fish
```

### 虚拟环境不显示

**症状**：激活了 Python venv 但右侧提示符没有显示

**解决方案**：

```fish
# 1. 检查是否在虚拟环境中
echo $VIRTUAL_ENV

# 2. 检查 python item 是否在配置中
set -S | grep tide_right_prompt_items | grep python

# 3. 检查 _tide_item_python 函数是否存在
functions -q _tide_item_python && echo "存在" || echo "不存在"

# 4. 如果函数不存在，重新安装 Tide
fisher remove IlanCosman/tide
fisher install IlanCosman/tide@v6
source ~/.config/fish/apply-tide-config.fish
exec fish
```

### IP 地址不显示

**症状**：context 显示 hostname 而不是 IP

**解决方案**：

测试 `get_ip` 函数：

```fish
get_ip
```

如果返回空值，检查网络配置：

```fish
# macOS
ifconfig | grep inet

# Linux
ip addr show
```

如果 `get_ip` 正常但还是不显示 IP，检查自定义函数：

```fish
functions _tide_item_context
```

### 插件安装失败

如果自动安装脚本失败，可以手动安装每个插件：

```fish
fisher install <plugin-name>
```

### 提示符不显示

检查 Tide 是否已安装：

```fish
fisher list | grep tide
```

如果未安装，运行：

```fish
fisher install IlanCosman/tide@v6
source ~/.config/fish/apply-tide-config.fish
exec fish
```

### 配置文件语法错误

检查配置文件语法：

```fish
fish -n ~/.config/fish/config.fish
```

如果有错误，会显示行号和错误信息。

## 📚 更多资源

- [Fish Shell 文档](https://fishshell.com/docs/current/)
- [Fisher 插件管理器](https://github.com/jorgebucaran/fisher)
- [Tide 提示符](https://github.com/IlanCosman/tide)
- [FZF](https://github.com/junegunn/fzf)

## 🤝 贡献

欢迎提交改进建议和 Pull Requests！

---

**最后更新**: 2025-10-16
**适用版本**: Tide v6, Fish 3.0+
