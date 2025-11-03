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

## 🚀 快速开始（小白专用）

### 第一步：安装配置

```bash
# 方法1：使用 Global Scripts 安装（推荐）
gs dotfiles nvim install

# 方法2：强制重新安装（如果之前装过）
gs dotfiles nvim install --force
```

**说明**：
- 命令会自动备份你原有的配置
- 安装lazy.nvim插件管理器
- 复制所有配置文件到 `~/.config/nvim/`

### 第二步：首次启动

```bash
# 1. 打开 Neovim
nvim

# 2. 等待 5-10 分钟，让插件自动安装
#    你会看到一个窗口显示安装进度
#    等待所有插件显示 ✓ 标记

# 3. 安装完成后，输入（按每个键，不是一起按）：
:q
# 然后按 Enter 键退出

# 4. 重新打开 Neovim
nvim

# 5. 现在可以正常使用了！
```

### 第三步：最基础的操作（必须掌握！）

#### 1️⃣ Vim 模式切换（最重要！）

Neovim 有几种模式，理解模式是使用 Vim 的关键：

```
【普通模式】- 默认模式，用于移动和命令
- 按 Esc 键随时回到这个模式
- 在这个模式下可以用快捷键

【插入模式】- 用于输入文本
- 在普通模式按 i 键进入
- 现在可以像普通编辑器一样输入文字
- 按 Esc 回到普通模式

【可视模式】- 用于选择文本
- 在普通模式按 v 键进入
- 用 h j k l 或方向键选择文字
- 选好后按 y 复制，按 d 剪切
- 按 Esc 回到普通模式

【命令模式】- 用于执行命令
- 在普通模式按 : 键进入
- 输入命令（比如 :w 保存）
- 按 Enter 执行命令
```

**实战示例**：编辑一个文件
```
步骤详解：
1. nvim test.txt                # 打开文件
2. 现在你在【普通模式】
3. 按 i 键                      # 进入【插入模式】
4. 输入 "Hello World"          # 打字
5. 按 Esc 键                    # 回到【普通模式】
6. 输入 :wq                     # 进入【命令模式】并输入保存退出命令
7. 按 Enter                     # 执行命令，文件保存并退出
```

#### 2️⃣ 基本移动（在普通模式下）

```
用键盘移动光标：
h - 左移一个字符  ←
j - 下移一行      ↓
k - 上移一行      ↑
l - 右移一个字符  →

或者：直接用方向键 ↑↓←→ 也可以！

快速移动：
0     - 跳到行首
$     - 跳到行尾
gg    - 跳到文件开头
G     - 跳到文件结尾
w     - 跳到下一个单词开头
b     - 跳到上一个单词开头
```

#### 3️⃣ 文件操作快捷键

**查找文件**（最常用！）
```
完整步骤：
1. 确保在【普通模式】（按 Esc）
2. 按空格键（会有提示出现）
3. 按 f 键
4. 再按 f 键
5. 出现搜索框，输入文件名
6. 用 Ctrl+j / Ctrl+k 上下选择
7. 按 Enter 打开文件
```
**快捷键**：`空格` `f` `f`

**全局搜索内容**
```
完整步骤：
1. 确保在【普通模式】
2. 按空格键
3. 按 f 键
4. 按 g 键
5. 输入要搜索的内容
6. 按 Enter 查看结果
```
**快捷键**：`空格` `f` `g`

**打开文件浏览器**（像 VSCode 的侧边栏）
```
完整步骤：
1. 确保在【普通模式】
2. 按空格键
3. 按 e 键两次
4. 左边出现文件树
5. 用 j k 上下移动
6. 按 Enter 打开文件
```
**快捷键**：`空格` `e` `e`

或者直接按：`Ctrl` + `e`（更快！）

#### 4️⃣ 保存和退出

```
保存文件：
1. 按 Esc（进入普通模式）
2. 输入 :w
3. 按 Enter

退出 Neovim：
1. 按 Esc
2. 输入 :q
3. 按 Enter

保存并退出：
1. 按 Esc
2. 输入 :wq
3. 按 Enter

强制退出（不保存）：
1. 按 Esc
2. 输入 :q!
3. 按 Enter
```

### 第四步：使用浮动终端（超级实用！）✨

#### 什么是浮动终端？

浮动终端就是**在 Neovim 里弹出一个终端窗口**，可以运行命令，而不需要退出 Neovim！

#### 最简单的使用方法

```
【打开终端】
1. 确保在【普通模式】（按 Esc）
2. 同时按 Ctrl + \（反斜杠键，通常在 Enter 上面）
3. 屏幕中间弹出一个漂亮的终端窗口 🎈
4. 可以直接输入命令（比如 ls, pwd, python test.py）

【关闭终端】
1. 再次按 Ctrl + \
2. 终端隐藏（但内容保留！下次打开还在）

【永久关闭终端】
1. 在终端窗口按 Esc（退出终端模式）
2. 输入 :q
3. 按 Enter
```

**一键快捷键**：`Ctrl` + `\` （最重要！记住这个！）

#### 实战示例1：运行 Python 代码

```
场景：你正在编辑 test.py，想运行看结果

完整步骤：
1. 正在编辑 test.py 文件
2. 按 Ctrl + \（终端弹出）
3. 输入：python test.py
4. 按 Enter（看到运行结果）
5. 再按 Ctrl + \（终端隐藏）
6. 继续编辑代码
7. 修改后再按 Ctrl + \（终端还在，历史命令也在！）
8. 按 ↑ 方向键（调出上一条命令 python test.py）
9. 按 Enter 再次运行
```

#### 实战示例2：查看文件和目录

```
完整步骤：
1. 按 Ctrl + \（打开终端）
2. 输入 ls -la（查看当前目录所有文件）
3. 输入 pwd（查看当前路径）
4. 输入 cd ..（切换到上级目录）
5. 完成后按 Ctrl + \（关闭终端）
```

#### 不同布局的终端

**底部终端**（像 VSCode）
```
操作：按 空格 t h
效果：终端出现在底部，占据屏幕下方
用途：适合查看长输出，比如日志
```

**右侧终端**
```
操作：按 空格 t v
效果：终端出现在右侧
用途：适合一边写代码一边看终端
```

**浮动终端**（默认，最推荐）
```
操作：按 Ctrl + \
或：按 空格 t f
效果：终端浮在中间
用途：快速运行命令，不占用屏幕空间
```

### 第五步：常见问题（新手必看）

#### Q1: 我按了键但没反应？

**原因**：你可能在错误的模式

**解决**：
1. 狂按 Esc 键几次（确保进入普通模式）
2. 然后再试一次快捷键

#### Q2: 我不小心进入了奇怪的模式，怎么退出？

**解决**：
1. 按 Esc 键（多按几次也没关系）
2. 如果还是不行，按 Ctrl + c
3. 实在不行，输入 :q! 强制退出重开

#### Q3: 终端打开了，但我打字没反应？

**原因**：终端需要在插入模式才能输入

**解决**：
1. 终端打开后，直接输入就行（默认是插入模式）
2. 如果不行，按 i 键进入插入模式

#### Q4: 怎么复制终端的内容到其他地方？

**方法**：
1. 在终端窗口按 Esc（进入普通模式）
2. 按 v 进入可视模式
3. 用 j k 选择要复制的行
4. 按 y 复制（自动复制到系统剪贴板）
5. 在任何地方 Cmd+V (Mac) 或 Ctrl+V (Linux) 粘贴

#### Q5: 我想同时看代码和终端怎么办？

**方法1：用底部终端**
```
1. 按 空格 t h（终端出现在底部）
2. 按 Esc（退出终端模式）
3. 按 Ctrl + k（光标跳到上面的代码窗口）
4. 现在可以编辑代码，底部的终端一直显示
5. 需要在终端输入时，按 Ctrl + j（跳回终端）
6. 按 i（进入插入模式，可以输入命令）
```

**方法2：用右侧终端**
```
1. 按 空格 t v（终端出现在右侧）
2. 按 Esc
3. 按 Ctrl + h（光标跳到左边的代码）
4. 一边写代码，一边看右边的终端输出
```

### 第六步：学习更多

#### 新手学习路线

**Day 1 - 基础操作（今天就掌握）**
- ✅ 模式切换（Esc, i, v, :）
- ✅ 基本移动（h j k l）
- ✅ 保存退出（:w :q :wq）
- ✅ 浮动终端（Ctrl + \）

**Day 2 - 文件管理**
- ✅ 查找文件（空格 f f）
- ✅ 全局搜索（空格 f g）
- ✅ 文件浏览器（空格 e e）

**Day 3 - 编辑技巧**
- ✅ 复制粘贴（y p）
- ✅ 撤销重做（u Ctrl+r）
- ✅ 多光标编辑（Ctrl+n）

**Day 4+ - 高级功能**
- ✅ 代码调试（空格 d b）
- ✅ Git 操作（空格 g g）
- ✅ Harpoon 快速跳转（空格 h a）

#### 重要文档（按顺序阅读）

1. **[新手完整教程](docs/nvim-tutorial.md)** ← 新手必读
   - Vim 基础概念详解
   - 每个操作的详细步骤
   - 大量实战示例

2. **[高级功能使用指南](docs/nvim-advanced-features.md)** ← 本文档重点
   - 浮动终端完整教程（每一步都有说明）
   - 多光标编辑、调试器、Git工具
   - 所有新功能的详细使用方法

3. **[日常操作指南](docs/nvim-operations.md)**
   - 复制粘贴技巧
   - 插件管理
   - 常见问题排查

4. **[快捷键完整参考](docs/nvim-keymaps.md)**
   - 所有快捷键速查表
   - 按功能分类
   - 中英文对照

#### 快速查询快捷键

**忘记快捷键了？**
```
操作：空格 f k
效果：搜索所有快捷键，输入功能名称即可查找
```

**查看某个键的功能**
```
操作：空格（等一会）
效果：自动显示所有 空格 开头的快捷键提示
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
- **mg979/vim-visual-multi** - 多光标编辑（VSCode 体验）
- **ThePrimeagen/refactoring.nvim** - 代码重构工具

### 导航和查找
- **nvim-telescope/telescope.nvim** - 模糊查找
- **nvim-tree/nvim-tree.lua** - 文件浏览器
- **folke/flash.nvim** - 快速跳转
- **ThePrimeagen/harpoon** - 快速切换常用文件
- **stevearc/aerial.nvim** - 代码大纲/符号视图
- **mbbill/undotree** - 可视化撤销历史

### 调试和测试
- **mfussenegger/nvim-dap** - 调试器（Debug Adapter Protocol）
- **rcarriga/nvim-dap-ui** - 调试 UI 界面
- **jay-babu/mason-nvim-dap.nvim** - Mason DAP 集成
- **nvim-neotest/neotest** - 测试运行器（支持 pytest, jest, go test）

### Git 集成
- **lewis6991/gitsigns.nvim** - Git 改动显示
- **NeogitOrg/neogit** - Git 客户端（类似 Magit）
- **sindrets/diffview.nvim** - Git diff 可视化查看

### 终端集成
- **akinsho/toggleterm.nvim** - 浮动终端

### UI 增强
- **nvim-lualine/lualine.nvim** - 状态栏
- **akinsho/bufferline.nvim** - 缓冲区标签
- **folke/which-key.nvim** - 快捷键提示
- **goolord/alpha-nvim** - 启动页

### Markdown 支持
- **iamcco/markdown-preview.nvim** - Markdown 实时预览

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
| `<leader>gg` | 打开 Neogit |
| `<leader>gdo` | 打开 Diffview |
| `<leader>gdh` | 文件历史 |

### 调试功能
| 快捷键 | 功能 |
|--------|------|
| `<leader>db` | 切换断点 |
| `<leader>dc` | 开始/继续调试 |
| `<leader>di` | 单步进入 |
| `<leader>do` | 单步跳过 |
| `<leader>du` | 打开调试 UI |

### 测试运行
| 快捷键 | 功能 |
|--------|------|
| `<leader>tt` | 运行最近的测试 |
| `<leader>tT` | 运行当前文件测试 |
| `<leader>td` | 调试最近的测试 |
| `<leader>ts` | 切换测试摘要 |

### 其他功能
| 快捷键 | 功能 |
|--------|------|
| `<C-\>` | 切换终端 |
| `<leader>ha` | Harpoon: 添加文件 |
| `<leader>hh` | Harpoon: 打开菜单 |
| `<leader>h1-4` | Harpoon: 跳转到文件 1-4 |
| `<leader>ao` | 切换代码大纲 |
| `<leader>u` | 切换撤销树 |
| `<C-n>` | 多光标: 选择下一个 |
| `<leader>mp` | Markdown 预览 |

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
