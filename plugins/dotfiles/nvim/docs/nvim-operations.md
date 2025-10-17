# Neovim 操作指南

## 📋 目录
1. [弹出窗口文字复制](#弹出窗口文字复制)
2. [Lazy 插件管理](#lazy-插件管理)
3. [Mason LSP 服务器管理](#mason-lsp-服务器管理)

---

## 弹出窗口文字复制

### 问题
使用 `:checkhealth`, `:Lazy`, `:Mason` 等命令时会弹出窗口，无法直接复制文字。

### 💡 系统剪贴板已启用

我们的配置已经启用系统剪贴板（`clipboard = "unnamedplus"`），所以复制非常简单！

### 解决方案

#### 方法1：使用 `y` 直接复制（最简单，推荐）⭐⭐⭐⭐⭐

```
:checkhealth        # 打开窗口
v                   # 可视模式
jjj                 # 选择3行
y                   # 直接按 y 复制
:q                  # 退出

Cmd + V             # 在任何应用粘贴！
```

**为什么可以直接用 `y`？**

因为配置文件中设置了 `clipboard = "unnamedplus"`，所有复制操作自动同步到系统剪贴板。

#### 方法2：使用 `"+y` 明确指定系统剪贴板 ⭐⭐⭐

```
v                   # 可视模式
jjj                 # 选择3行
"+y                 # 复制到系统剪贴板
```

**`"+y` 按键详解：**
```
第1步：Shift + '  →  "  (双引号)
第2步：Shift + =  →  +  (加号)
第3步：y          →  y  (复制命令)
```

**完整操作示例：**
```
:Mason              # 打开 Mason 窗口
↓↓↓                 # 移动到想复制的内容
v                   # 进入可视模式（左下角显示 -- VISUAL --）
jjj                 # 向下选择3行（文本高亮）

方法1（推荐）:
y                   # 直接按 y，复制完成

方法2（手动指定）:
按 Shift + '        # 输入 "
按 Shift + =        # 输入 +
按 y                # 复制完成

:q                  # 退出窗口
Cmd + V             # 在其他应用粘贴
```

#### 方法3：使用鼠标（部分终端支持）⭐⭐

某些终端（如 iTerm2, WezTerm）支持：
```
1. 按住 Option (Alt) 键
2. 鼠标拖动选择文本
3. Cmd+C 复制
```

#### 方法4：禁用 Noice（如果觉得太复杂）⭐

编辑配置文件禁用 Noice：
```bash
nvim ~/.config/nvim/gs-runtime/lua/plugins.lua

# 找到 noice.nvim 部分（第870行左右）
# 将 enabled = true 改为 enabled = false
```

重启 nvim 后，弹出窗口会恢复传统样式，更容易复制。

### 快捷复制技巧

不进可视模式直接复制：
```
yy               # 复制当前行
3yy              # 复制3行
y$               # 复制到行尾
yiw              # 复制当前单词
yf;              # 复制到下一个分号
```

### 验证系统剪贴板是否工作

```bash
nvim test.txt    # 打开文件
i                # 插入模式
Hello World      # 输入内容
Esc              # 退出插入模式
yy               # 复制行
:q!              # 退出

# 在终端粘贴
Cmd + V          # 如果出现 "Hello World"，配置成功！
```

---

## Lazy 插件管理

### 打开 Lazy 管理器
```
:Lazy
```

### Lazy 界面说明

```
┌─────────────────────────────────────┐
│ ● Plugin Name         [已安装] ✓     │ ← 已加载的插件（绿色圆点）
│ ○ Another Plugin      [未加载]       │ ← 懒加载插件（空心圆点）
└─────────────────────────────────────┘
```

### 插件状态

| 符号 | 状态 | 说明 |
|-----|------|------|
| ● | 已加载 | 插件已经启动 |
| ○ | 未加载 | 插件还未启动（懒加载） |
| ✓ | 已安装 | 插件文件已下载 |
| ✗ | 未安装 | 插件需要安装 |
| ➜ | 安装中 | 正在下载 |

### 什么是懒加载（Lazy Loading）？

为了提升 nvim 启动速度，某些插件只在需要时才加载：

**懒加载插件示例：**
- **flash.nvim** - 只在按 `s` 键时才加载
- **trouble.nvim** - 只在按 `<leader>xx` 时才加载
- **nvim-cmp** - 只在进入插入模式时才加载

### 如何启动懒加载插件？

#### 方法1：触发快捷键（推荐）

每个插件都有触发条件，触发后自动加载：

| 插件 | 触发方式 |
|-----|---------|
| flash.nvim | 按 `s` (跳转) |
| trouble.nvim | 按 `<leader>xx` (诊断) |
| nvim-cmp | 进入插入模式（按 `i`） |
| telescope.nvim | 按 `<leader>ff` (查找文件) |
| nvim-tree | 按 `<leader>ee` (文件树) |

#### 方法2：在 Lazy 界面手动启动

```
:Lazy                    # 打开 Lazy
移动光标到插件名         # 使用 j/k
按 l (小写L)             # 手动加载插件
```

#### 方法3：全部加载

```
:Lazy load <插件名>      # 加载单个插件
:Lazy load all           # 加载所有插件（不推荐，失去性能优势）
```

### Lazy 常用快捷键

在 `:Lazy` 界面中：

| 快捷键 | 功能 |
|--------|------|
| `U` | 更新所有插件 |
| `S` | 同步插件（安装缺失、删除多余） |
| `C` | 清理未使用的插件 |
| `L` | 查看插件日志 |
| `l` (小写) | 手动加载选中插件 |
| `X` | 查看错误详情 |
| `d` | 查看插件详情 |
| `?` | 显示帮助 |
| `q` | 退出 |

### 常见操作流程

**更新所有插件：**
```
:Lazy     # 打开
按 U      # 更新
等待完成
按 q      # 退出
```

**查看插件错误：**
```
:Lazy     # 打开
找到有 ✗ 的插件
按 X      # 查看错误详情
```

---

## Mason LSP 服务器管理

### 打开 Mason 管理器
```
:Mason
```

### Mason 界面说明

```
┌─────────────────────────────────────┐
│ ✓ lua_ls        [已安装]             │
│ ○ jdtls         [未安装]             │
│ ● pyright       [运行中]             │
└─────────────────────────────────────┘
```

### LSP 服务器状态

| 符号 | 状态 | 说明 |
|-----|------|------|
| ✓ | 已安装 | LSP 已安装可用 |
| ○ | 未安装 | 需要手动安装 |
| ● | 运行中 | 当前文件正在使用此 LSP |
| ✗ | 安装失败 | 需要检查错误 |

### 我们已配置的 LSP 服务器（14个）

#### 自动安装列表（在 plugins.lua 中配置）

```lua
ensure_installed = {
  "lua_ls",          -- Lua
  "pyright",         -- Python
  "ts_ls",           -- TypeScript/JavaScript
  "eslint",          -- JS/TS 代码检查
  "rust_analyzer",   -- Rust
  "gopls",           -- Go
  "clangd",          -- C/C++
  "jdtls",           -- Java
  "html",            -- HTML
  "cssls",           -- CSS
  "tailwindcss",     -- Tailwind CSS
  "jsonls",          -- JSON
  "yamlls",          -- YAML
  "bashls",          -- Bash
  "dockerls",        -- Docker
}
```

### 如何安装 Java LSP（jdtls）

#### 方法1：Mason 界面手动安装（推荐）

```
1. 打开 Mason
:Mason

2. 搜索 Java LSP
按 / 进入搜索
输入 java
按 Enter

3. 找到 jdtls
移动光标到 jdtls

4. 安装
按 i (install)

5. 等待安装完成
看到 ✓ 表示成功

6. 退出
按 q
```

#### 方法2：命令行直接安装

```
:MasonInstall jdtls
```

#### 方法3：让 Mason 自动安装

首次打开 `.java` 文件时，Mason 会自动检测并安装 jdtls：

```
nvim Test.java        # 打开 Java 文件
# 等待几秒，底部会显示安装进度
# 安装完成后 LSP 自动启动
```

### Mason 常用快捷键

在 `:Mason` 界面中：

| 快捷键 | 功能 |
|--------|------|
| `i` | 安装光标下的包 |
| `X` | 卸载光标下的包 |
| `u` | 更新光标下的包 |
| `U` | 更新所有已安装包 |
| `/` | 搜索包 |
| `g?` | 显示帮助 |
| `q` | 退出 |
| `<CR>` (Enter) | 查看包详情 |

### 常见操作流程

**安装新的 LSP 服务器：**
```
:Mason               # 打开
按 /                 # 搜索
输入 java            # 搜索 Java
找到 jdtls
按 i                 # 安装
等待完成
按 q                 # 退出
```

**更新所有 LSP：**
```
:Mason               # 打开
按 U                 # 更新所有
等待完成
按 q                 # 退出
```

**检查 LSP 状态：**
```
:LspInfo             # 查看当前文件的 LSP 状态
:Mason               # 查看所有 LSP 安装状态
:checkhealth mason   # 健康检查
```

### Java LSP 特殊配置

**⚠️ 重要提示：jdtls 需要 Java 21+**

从 jdtls v1.51.0 (2025-10) 开始，需要 Java 21 或更高版本。

#### 检查 Java 版本

```bash
java -version        # 需要显示 Java 21 或更高
```

#### 安装 Java 21

**macOS 用户：**
```bash
# 使用 Homebrew 安装 Java 21
brew install openjdk@21

# 创建系统符号链接（需要 sudo）
sudo ln -sfn /usr/local/opt/openjdk@21/libexec/openjdk.jdk \
  /Library/Java/JavaVirtualMachines/openjdk-21.jdk

# 添加到 PATH（可选，根据你的 shell 选择）
# Zsh
echo 'export PATH="/usr/local/opt/openjdk@21/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc

# Bash
echo 'export PATH="/usr/local/opt/openjdk@21/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Fish
fish_add_path /usr/local/opt/openjdk@21/bin
```

**其他平台：**
```bash
# 使用 SDKMAN（跨平台）
curl -s "https://get.sdkman.io" | bash
sdk install java 21.0.8-tem
```

#### 多版本 Java 管理（使用 jEnv）

如果你的项目需要使用不同版本的 Java，推荐使用 jEnv：

**1. 安装 jEnv：**
```bash
# macOS
brew install jenv

# 配置 shell（根据你的 shell 选择）
# Zsh
echo 'export PATH="$HOME/.jenv/bin:$PATH"' >> ~/.zshrc
echo 'eval "$(jenv init -)"' >> ~/.zshrc
source ~/.zshrc

# Bash
echo 'export PATH="$HOME/.jenv/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(jenv init -)"' >> ~/.bashrc
source ~/.bashrc

# Fish
set -Ux fish_user_paths $HOME/.jenv/bin $fish_user_paths
echo 'status --is-interactive; and source (jenv init -|psub)' >> ~/.config/fish/config.fish
```

**2. 添加 Java 版本到 jEnv：**
```bash
# 查找已安装的 Java 版本
ls -la /usr/local/opt/ | grep openjdk

# 添加 Java 11（如果有）
jenv add /usr/local/opt/openjdk@11/libexec/openjdk.jdk/Contents/Home

# 添加 Java 21
jenv add /usr/local/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home

# 查看已添加的版本
jenv versions
```

**3. 设置 Java 版本：**
```bash
# 全局使用 Java 21（供 Neovim jdtls 使用）
jenv global 21

# 在特定项目目录使用 Java 11
cd ~/my-java11-project
jenv local 11

# 验证当前版本
java -version
```

**4. jEnv 常用命令：**
```bash
jenv versions              # 查看所有可用版本
jenv version               # 查看当前使用的版本
jenv global <version>      # 设置全局版本
jenv local <version>       # 设置当前目录版本
jenv shell <version>       # 设置当前 shell 会话版本
jenv remove <version>      # 移除版本
```

#### 安装完 Java 后重启 nvim

```vim
:q                   # 退出 nvim
nvim Test.java       # 重新打开
:LspInfo             # 查看 jdtls 是否启动
```

**预期结果：**
- `:LspInfo` 显示 `Client: jdtls (id: 1, bufnr: 1)`
- 不再出现 "jdtls requires at least Java 21" 错误

### LSP 不工作的排查步骤

```
1. 检查 LSP 是否安装
:Mason
找到对应的 LSP，看是否有 ✓

2. 检查 LSP 是否附加到当前文件
:LspInfo
应该看到 "Client: jdtls (id: 1, bufnr: 1)"

3. 检查依赖环境
:checkhealth
查看是否有错误提示

4. 重启 LSP
:LspRestart

5. 查看日志
:Lazy log          # 查看插件日志
:messages          # 查看所有消息
```

---

## 💡 实用技巧

### 主题切换

配置已经包含多个主题，包括类似 VSCode/IDEA 的 One Dark 主题。

#### 方法1：实时预览切换主题（推荐）⭐⭐⭐⭐⭐

```vim
# 在 Neovim 中按
<leader>ft          # 即：空格 → f → t

# 会弹出主题列表，可以：
# - 使用 ↑↓ 或 Ctrl+j/k 选择
# - Enter 应用主题
# - Esc 取消
```

**可用主题：**
- **Tokyo Night** - 当前默认主题，深色护眼
- **One Dark (Atom 官方移植版)** - 最接近 Atom/VSCode/IDEA 的经典主题 ⭐ 推荐
- **One Dark (Lua 现代版)** - Lua 实现的 One Dark，备选方案
- **Catppuccin** - 柔和的配色
- **Kanagawa** - 日式配色
- **Nightfox** - 多变体主题
- **Dracula** - 经典 Dracula 主题

#### 方法2：永久切换到 One Dark 主题（Atom 官方版）

**Step 1：编辑配置文件**
```bash
nvim ~/.config/nvim/gs-runtime/lua/plugins.lua
```

**Step 2：找到主题配置部分（约第30行）**

注释掉 Tokyo Night，取消注释 One Dark (Atom 官方版)：
```lua
-- Tokyo Night 主题（当前激活）
-- {
--   "folke/tokyonight.nvim",
--   lazy = false,
--   priority = 1000,
--   config = function()
--     require("tokyonight").setup({
--       style = "night",
--       ...
--     })
--     vim.cmd([[colorscheme tokyonight]])
--   end,
-- },

-- One Dark 主题（Atom 官方移植版）⭐⭐⭐⭐⭐ 强烈推荐
-- 最接近 Atom/VSCode/IDEA 的 One Dark 配色
{
  "joshdick/onedark.vim",
  lazy = false,
  priority = 1000,
  config = function()
    -- 启用 24-bit 真彩色（推荐）
    vim.cmd([[
      if (has("termguicolors"))
        set termguicolors
      endif
    ]])

    -- 可选配置
    -- vim.g.onedark_terminal_italics = 1        -- 启用斜体注释
    -- vim.g.onedark_hide_endofbuffer = 1        -- 隐藏缓冲区结束符号 ~

    vim.cmd([[colorscheme onedark]])
  end,
},
```

**Step 3：重启 Neovim**
```vim
:qa                  # 退出所有窗口
nvim                 # 重新打开
```

首次使用 One Dark 时，Lazy 会自动下载该主题插件，等待几秒即可。

#### One Dark 主题说明

配置提供了两个 One Dark 版本：

**1. joshdick/onedark.vim（推荐）⭐⭐⭐⭐⭐**
- 官方地址：https://github.com/joshdick/onedark.vim
- 特点：最接近 Atom 编辑器原版 One Dark (https://github.com/atom/one-dark-syntax)
- 兼容性：支持 Vim 和 Neovim
- 配置：简单，开箱即用

**可选配置项**：
```lua
vim.g.onedark_terminal_italics = 1        -- 启用斜体注释
vim.g.onedark_hide_endofbuffer = 1        -- 隐藏缓冲区结束符号 ~
```

**2. navarasu/onedark.nvim（备选）**
- 官方地址：https://github.com/navarasu/onedark.nvim
- 特点：Lua 实现，现代化，配置选项更丰富
- 兼容性：仅支持 Neovim
- 样式：7 种样式可选（dark, darker, cool, deep, warm, warmer, light）

**推荐使用 joshdick/onedark.vim**，因为它最接近 Atom 原版。如果遇到兼容性问题，可以切换到 navarasu/onedark.nvim。

### 快速验证所有插件是否正常

```bash
# 在 nvim 中执行
:checkhealth         # 检查整体健康
:checkhealth lazy    # 检查 Lazy
:checkhealth mason   # 检查 Mason
:checkhealth lsp     # 检查 LSP
:checkhealth treesitter  # 检查 Treesitter
```

### 同时查看多个窗口

```
:Lazy               # 打开 Lazy
:vsplit             # 垂直分屏
:Mason              # 在新窗口打开 Mason
Ctrl+w w            # 切换窗口
```

### 保存当前配置状态

```
:Lazy snapshot save my-config     # 保存插件版本快照
:Lazy snapshot restore my-config  # 恢复到快照版本
```

---

## 🔍 参考资源

- **Lazy.nvim 文档**: `:help lazy.nvim`
- **Mason 文档**: `:help mason.nvim`
- **LSP 配置**: `:help lspconfig`
- **快捷键查找**: 按 `<leader>fk` (Space → f → k)

---

**有问题？**
- 查看新手教程：`~/.config/nvim/README-NVIM.md`
- 查看技术文档：`~/.config/nvim/README.md`
- 在 nvim 中打开：`:e ~/.config/nvim/README-OPERATIONS.md`
