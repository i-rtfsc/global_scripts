# Fish Shell Configuration

Global Scripts 提供的现代化 Fish Shell 配置系统，采用模块化设计，易于管理和扩展。

## 📦 功能特性

- ✅ 模块化配置结构（独立的 `gs-config/` 目录）
- ✅ 跨平台支持 (macOS/Linux)
- ✅ 丰富的实用函数
- ✅ 完整的 Git/Docker 工作流缩写
- ✅ FZF 深度集成
- ✅ 40+ 开发工具集成
- ✅ Tide 提示符配置（Rainbow 双行风格 + user@IP 显示）
- ✅ 智能备份与恢复机制

## 🚀 快速开始

### 1. 安装配置

```bash
# 安装 Fish 配置
gs dotfiles fish install

# 查看安装状态
gs dotfiles fish status

# 强制安装（覆盖现有配置）
gs dotfiles fish install --force
```

安装后的目录结构：
```
~/.config/fish/
├── config.fish              # 主配置文件（自动生成）
├── gs-config/               # Global Scripts 配置模块目录
│   ├── 00-gs-functions.fish      # 实用工具函数
│   ├── 01-gs-prompt.fish         # Tide 提示符自定义
│   ├── 02-gs-fzf.fish            # FZF 集成
│   ├── 03-gs-abbreviations.fish  # 命令缩写
│   ├── 04-gs-integrations.fish   # 工具集成
│   └── 05-gs-greeting.fish       # 欢迎信息
├── apply-tide-config.fish   # Tide 完整配置脚本
└── setup-plugins.fish       # Fisher 插件安装脚本
```

**注意**：
- `gs-config/` 是 Global Scripts 专用目录，不会与 fish 自带的 `functions/` 目录冲突
- 所有配置文件都带有 `gs-` 前缀，方便识别
- 安装时会自动备份现有配置

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
- ✅ 多语言虚拟环境检测（Python, Node.js, Go 等）
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
- 🐍 Python 虚拟环境
- ⬢ Node.js 版本
- 🐹 Go 版本
- 🐳 Docker 容器
- 👤 user@192.168.1.100
- 🕐 当前时间

### 3. 安装 Fish 插件（可选）

```fish
# 方式一：使用安装脚本
fish ~/.config/fish/setup-plugins.fish

# 方式二：手动安装
curl -sL https://git.io/fisher | source && fisher install jorgebucaran/fisher
fisher install IlanCosman/tide@v6           # 现代提示符
fisher install jethrokuan/z                 # 目录跳转
fisher install PatrickF1/fzf.fish          # FZF 集成
fisher install franciscolourenco/done      # 命令完成通知
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
gst             # git status（注意：gs 被 Global Scripts 占用）
gsta            # git stash
```

完整列表请查看 `gs-config/03-gs-abbreviations.fish`

### Docker 缩写

```fish
d               # docker
dps             # docker ps
dpsa            # docker ps -a
dc              # docker-compose
dcup            # docker-compose up -d
dcdown          # docker-compose down
```

## 🎨 自定义配置

### 添加个人配置

创建 `~/.config/fish/local.fish` 文件：

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

### 自定义右侧提示符

```fish
# 添加更多语言检测
set -U tide_right_prompt_items status cmd_duration python node go rustc context jobs time
exec fish

# 添加云服务检测
set -U tide_right_prompt_items status cmd_duration python node aws gcloud kubectl context jobs time
exec fish

# 极简配置
set -U tide_right_prompt_items status cmd_duration context time
exec fish
```

### 可用的检测项

**编程语言**: python, node, go, rustc, java, php, ruby, elixir, bun

**容器 & DevOps**: docker, kubectl, terraform, pulumi

**云服务**: aws, gcloud

**其他工具**: direnv, nix_shell, toolbox, vi_mode

## 🔧 配置管理

### 备份配置

```bash
# 备份当前配置
gs dotfiles fish backup

# 查看备份列表（会在 restore 时显示）
gs dotfiles fish status
```

备份位置：`~/.config/global-scripts/backups/dotfiles/fish/`

备份内容：
- 主配置文件 `config.fish`
- 整个 `gs-config/` 目录
- 所有额外文件（apply-tide-config.fish, README.md 等）

特性：
- 自动保留最新 3 次备份
- 超过 3 次自动删除最旧的备份

### 恢复配置

```bash
# 恢复配置（会列出可选备份）
gs dotfiles fish restore
```

系统会显示：
```
可用备份:
  1. 20251017_095037 (2025-10-17 09:50:37)
  2. 20251017_093904 (2025-10-17 09:39:04)

输入备份编号 (默认=1):
```

### 卸载配置

```bash
# 卸载配置（自动备份）
gs dotfiles fish uninstall
```

卸载操作：
- 自动备份后删除 `config.fish`
- 删除 `gs-config/` 目录中的所有 `*-gs-*.fish` 文件
- 不删除其他 fish 配置文件

## 🔄 更新配置

```bash
# 重新安装即可更新
gs dotfiles fish install

# 如果使用了 Tide，需要重新应用配置
fish -c "source ~/.config/fish/apply-tide-config.fish && exec fish"
```

## ⚠️ 注意事项

1. **命令冲突**: `gs` 命令被 Global Scripts 使用，Git status 请使用 `gst`

2. **目录独立**: `gs-config/` 与 fish 自带的 `functions/`、`conf.d/` 目录完全独立，不会冲突

3. **文件识别**: 所有配置文件带有 `gs-` 前缀，方便识别哪些是 Global Scripts 的配置

4. **自动备份**:
   - 安装/卸载时自动备份
   - 只保留最新 3 次备份
   - 备份包含完整的配置目录

5. **Tide 配置**:
   - 必须在真实的 Fish shell 中执行配置命令
   - 使用 `-U` (universal) 变量确保配置持久化
   - 必须使用 `exec fish` 重启使配置生效

## 🐛 故障排除

### Tide 提示符报错

如果遇到 `Unknown command: _tide_item_xxx` 错误：

```fish
# 方法一：移除报错的检测项
set -U tide_right_prompt_items status cmd_duration python node context jobs time
exec fish

# 方法二：重新安装 Tide
fisher remove IlanCosman/tide
fisher install IlanCosman/tide@v6
source ~/.config/fish/apply-tide-config.fish
exec fish
```

### 配置不生效

```fish
# 清除缓存并重新加载
set -e tide_right_prompt_items
set -e _tide_right_items
source ~/.config/fish/apply-tide-config.fish
exec fish
```

### 虚拟环境不显示

```fish
# 检查虚拟环境
echo $VIRTUAL_ENV

# 检查 python item 是否在配置中
set -S | grep tide_right_prompt_items

# 检查 _tide_item_python 函数
functions -q _tide_item_python && echo "存在" || echo "不存在"
```

## 📚 更多资源

- [Fish Shell 文档](https://fishshell.com/docs/current/)
- [Fisher 插件管理器](https://github.com/jorgebucaran/fisher)
- [Tide 提示符](https://github.com/IlanCosman/tide)
- [FZF](https://github.com/junegunn/fzf)
- [Global Scripts 文档](https://github.com/i-rtfsc/global_scripts)

---

**最后更新**: 2025-10-17
**适用版本**: Fish 3.0+, Tide v6
