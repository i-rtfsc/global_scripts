# Neovim 配置 - Global Scripts

现代化的 Neovim 配置，基于 Lua + lazy.nvim，提供完整的 LSP、代码补全、文件管理等功能。

## ✨ 特性

- 🚀 **lazy.nvim** - 现代化插件管理器，懒加载优化启动速度
- 🧠 **LSP 支持** - 14+ 语言服务器：Python, JS/TS, Rust, Go, C/C++, Java 等
- 🎨 **Treesitter** - 增强语法高亮和代码导航
- 🔍 **Telescope** - 强大的模糊查找器
- 📂 **文件浏览器** - nvim-tree 集成
- 💡 **智能补全** - nvim-cmp + LSP + snippets
- 🌿 **Git 集成** - gitsigns 实时显示改动
- 🎯 **快速跳转** - flash.nvim 导航增强
- 📋 **系统剪贴板** - 自动同步，无需额外配置

## 📚 文档导航

### 新手入门

如果你是第一次使用 Vim/Neovim，从这里开始：

**[📖 新手完整教程 (nvim-tutorial.md)](docs/nvim-tutorial.md)**

包含内容：
- Vim 基础概念（模式切换、移动、编辑）
- 快捷键详解（`<leader>` = 空格键）
- 复制粘贴操作（系统剪贴板集成）
- 常见使用场景
- 学习路线建议

### 日常操作

已经熟悉 Vim 基础？查看操作指南：

**[🔧 日常操作指南 (nvim-operations.md)](docs/nvim-operations.md)**

包含内容：
- 弹出窗口文字复制方法
- Lazy 插件管理（更新、安装、懒加载）
- Mason LSP 服务器管理
- 常见问题排查

### 快捷键完整参考

需要查找特定快捷键？查看完整快捷键文档：

**[⌨️ 快捷键完整参考 (nvim-keymaps.md)](docs/nvim-keymaps.md)**

包含内容：
- 所有自定义快捷键（LSP、Git、文件操作等）
- Vim 系统默认快捷键
- 按功能分类组织（导航、编辑、搜索、诊断等）
- 中英文双语说明
- 快速查询表

## 🚀 快速开始

### 安装

```bash
# 使用 Global Scripts 安装
gs dotfiles nvim install

# 强制重新安装
gs dotfiles nvim install --force
```

### 首次启动

```bash
# 打开 Neovim
nvim

# 等待插件自动安装（首次启动）
# 安装完成后重启 Neovim
:q
nvim
```

### 基础操作

```bash
# 模式切换
Esc         # 回到普通模式
i           # 进入插入模式（开始输入）
v           # 进入可视模式（选择文本）
:           # 进入命令模式

# 文件操作
空格 f f    # 查找文件
空格 f g    # 全局搜索
空格 e e    # 打开文件浏览器

# 保存和退出
:w          # 保存
:q          # 退出
:wq         # 保存并退出
```

## 📦 已安装插件

### 核心功能
- **folke/tokyonight.nvim** - Tokyo Night 主题（默认）
- **joshdick/onedark.vim** - One Dark 主题（Atom 官方移植版，可选）
- **nvim-treesitter/nvim-treesitter** - 语法高亮增强
- **neovim/nvim-lspconfig** - LSP 配置
- **williamboman/mason.nvim** - LSP/工具包管理器

> 💡 **主题切换**：按 `<leader>ft` (空格 f t) 实时预览和切换主题
>
> **One Dark 主题**：配置使用 Atom 官方移植版 (joshdick/onedark.vim)，最接近原版配色
>
> 详见：[操作指南 - 主题切换](docs/nvim-operations.md#主题切换)

### 编辑增强
- **hrsh7th/nvim-cmp** - 自动补全
- **windwp/nvim-autopairs** - 自动括号配对
- **numToStr/Comment.nvim** - 快速注释
- **kylechui/nvim-surround** - 快速包围

### 导航和查找
- **nvim-telescope/telescope.nvim** - 模糊查找
- **nvim-tree/nvim-tree.lua** - 文件浏览器
- **folke/flash.nvim** - 快速跳转

### Git 集成
- **lewis6991/gitsigns.nvim** - Git 改动显示

### UI 增强
- **nvim-lualine/lualine.nvim** - 状态栏
- **akinsho/bufferline.nvim** - 缓冲区标签
- **folke/which-key.nvim** - 快捷键提示
- **goolord/alpha-nvim** - 启动页

### 诊断和调试
- **folke/trouble.nvim** - 诊断列表增强
- **folke/todo-comments.nvim** - TODO 高亮

## 🔧 已配置 LSP 服务器

自动安装以下 LSP 服务器（通过 Mason）：

| 语言 | LSP 服务器 |
|------|-----------|
| Lua | lua_ls |
| Python | pyright |
| JavaScript/TypeScript | ts_ls, eslint |
| Rust | rust_analyzer |
| Go | gopls |
| C/C++ | clangd |
| Java | jdtls |
| HTML | html |
| CSS | cssls, tailwindcss |
| JSON | jsonls |
| YAML | yamlls |
| Bash | bashls |
| Docker | dockerls |

## ⌨️ 常用快捷键

> **注意**：`<leader>` = 空格键

### 文件操作
| 快捷键 | 功能 |
|--------|------|
| `<leader>ff` | 查找文件 |
| `<leader>fg` | 全局搜索 |
| `<leader>fb` | 切换缓冲区 |
| `<leader>ee` | 打开/关闭文件浏览器 |

### LSP 功能
| 快捷键 | 功能 |
|--------|------|
| `gd` | 跳转到定义 |
| `gR` | 查看引用 |
| `K` | 显示文档 |
| `<leader>ca` | 代码操作 |
| `<leader>rn` | 重命名 |
| `[d` / `]d` | 上/下一个错误 |

### Git 操作
| 快捷键 | 功能 |
|--------|------|
| `]c` / `[c` | 下/上一个改动 |
| `<leader>gs` | Stage 改动 |
| `<leader>gp` | 预览改动 |
| `<leader>gb` | Git blame |

完整快捷键列表请查看：**[⌨️ 快捷键完整参考](docs/nvim-keymaps.md)**

## 📋 复制粘贴

配置已启用系统剪贴板（`clipboard = "unnamedplus"`），复制操作自动同步到系统剪贴板。

**最简单的方法：**
```
v          # 可视模式
jjj        # 选择3行
y          # 复制（自动到系统剪贴板）

Cmd + V    # 在任何应用粘贴！
```

详细说明：[操作指南 - 弹出窗口文字复制](docs/nvim-operations.md#弹出窗口文字复制)

## 🔍 健康检查

```bash
# 检查 Neovim 配置状态
:checkhealth

# 检查特定模块
:checkhealth lazy      # 插件管理器
:checkhealth mason     # LSP 管理器
:checkhealth lsp       # LSP 配置
```

## 🆘 常见问题

### 如何切换主题？
按 `<leader>ft` (空格 → f → t) 可以实时预览和切换主题。

如需永久切换到 **One Dark 主题（Atom 官方移植版）**：
```vim
# 编辑配置文件
nvim ~/.config/nvim/gs-runtime/lua/plugins.lua

# 找到主题配置部分（约第30行）
# 注释掉 Tokyo Night，取消注释 joshdick/onedark.vim
# 重启 Neovim 即可

# 详细步骤见：docs/nvim-operations.md#主题切换
```

**One Dark 主题说明**：
- 使用 **joshdick/onedark.vim** - Atom 官方 One Dark 的 Neovim 移植版
- 最接近原版 Atom One Dark 配色：https://github.com/atom/one-dark-syntax
- 也提供了 navarasu/onedark.nvim（Lua 实现）作为备选方案

### 插件未加载？
1. 打开 `:Lazy` 查看插件状态
2. 按 `S` 同步插件
3. 重启 Neovim

### LSP 不工作？
1. 打开 `:Mason` 检查 LSP 是否安装
2. 查看 `:LspInfo` 确认 LSP 是否附加
3. 按 `<leader>rs` 重启 LSP

### 无法复制到系统剪贴板？
1. 检查配置：`:echo &clipboard`（应显示 `unnamedplus`）
2. 直接使用 `y` 复制（无需 `"+y`）
3. 查看 [复制粘贴操作](docs/nvim-operations.md#弹出窗口文字复制)

## 📂 配置文件位置

```
~/.config/nvim/
├── init.vim                    # 启动入口
└── gs-runtime/
    └── lua/
        ├── init.lua           # Lua 配置入口
        ├── options.lua        # 编辑器选项
        ├── plugins.lua        # 插件配置
        └── keymaps.lua        # 快捷键映射
```

## 🔄 配置管理

### 备份配置

```bash
# 备份当前配置
gs dotfiles nvim backup

# 查看备份列表
gs dotfiles nvim status
```

### 恢复配置

```bash
# 恢复配置（会列出可选备份）
gs dotfiles nvim restore
```

### 卸载配置

```bash
# 卸载配置（自动备份）
gs dotfiles nvim uninstall
```

## 🔗 参考资源

- **Neovim 官方文档**: https://neovim.io/doc/
- **lazy.nvim**: https://github.com/folke/lazy.nvim
- **Mason**: https://github.com/williamboman/mason.nvim
- **Telescope**: https://github.com/nvim-telescope/telescope.nvim

---

**有问题？**
- 📖 查看 [新手教程](docs/nvim-tutorial.md)
- 🔧 查看 [操作指南](docs/nvim-operations.md)
- ⌨️ 查看 [快捷键参考](docs/nvim-keymaps.md)
- 💬 在 Neovim 中输入 `:help` 查看帮助
- 🔍 按 `<leader>fk` (空格 f k) 搜索快捷键
