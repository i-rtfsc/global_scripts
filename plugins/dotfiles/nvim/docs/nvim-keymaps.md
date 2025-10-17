# Neovim 快捷键完整参考 | Complete Keymap Reference

> **说明**：`<leader>` = 空格键 (Space)
> **Note**: `<leader>` = Space key

## 📑 目录 | Table of Contents

- [模式切换 | Mode Switching](#模式切换--mode-switching)
- [基础移动 | Basic Movement](#基础移动--basic-movement)
- [文件操作 | File Operations](#文件操作--file-operations)
- [编辑操作 | Editing Operations](#编辑操作--editing-operations)
- [复制粘贴 | Copy & Paste](#复制粘贴--copy--paste)
- [搜索查找 | Search & Find](#搜索查找--search--find)
- [LSP 功能 | LSP Features](#lsp-功能--lsp-features)
- [代码导航 | Code Navigation](#代码导航--code-navigation)
- [文件浏览器 | File Explorer](#文件浏览器--file-explorer)
- [Git 集成 | Git Integration](#git-集成--git-integration)
- [诊断和调试 | Diagnostics & Debugging](#诊断和调试--diagnostics--debugging)
- [快速跳转 | Quick Jump](#快速跳转--quick-jump)
- [补全和代码片段 | Completion & Snippets](#补全和代码片段--completion--snippets)
- [窗口和缓冲区 | Windows & Buffers](#窗口和缓冲区--windows--buffers)
- [主题和UI | Theme & UI](#主题和ui--theme--ui)

---

## 模式切换 | Mode Switching

| 快捷键 | 模式 | 功能说明 | Description |
|--------|------|----------|-------------|
| `Esc` | 任何模式 → 普通模式 | 退出当前模式，回到普通模式 | Exit current mode, return to normal mode |
| `i` | 普通模式 → 插入模式 | 在光标前插入 | Insert before cursor |
| `I` | 普通模式 → 插入模式 | 在行首插入 | Insert at beginning of line |
| `a` | 普通模式 → 插入模式 | 在光标后插入 | Append after cursor |
| `A` | 普通模式 → 插入模式 | 在行尾插入 | Append at end of line |
| `o` | 普通模式 → 插入模式 | 在下方新建一行并插入 | Open line below and insert |
| `O` | 普通模式 → 插入模式 | 在上方新建一行并插入 | Open line above and insert |
| `v` | 普通模式 → 可视模式 | 字符选择模式 | Visual character mode |
| `V` | 普通模式 → 可视行模式 | 整行选择模式 | Visual line mode |
| `Ctrl+v` | 普通模式 → 可视块模式 | 块选择模式（列编辑） | Visual block mode |
| `:` | 普通模式 → 命令模式 | 进入命令行模式 | Enter command-line mode |

---

## 基础移动 | Basic Movement

### 字符移动 | Character Movement

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| `h` | 左移一个字符 | Move left |
| `j` | 下移一行 | Move down |
| `k` | 上移一行 | Move up |
| `l` | 右移一个字符 | Move right |
| `w` | 移动到下一个单词开头 | Move to next word |
| `b` | 移动到上一个单词开头 | Move to previous word |
| `e` | 移动到当前/下一个单词结尾 | Move to end of word |
| `0` | 移动到行首 | Move to beginning of line |
| `^` | 移动到行首第一个非空字符 | Move to first non-blank character |
| `$` | 移动到行尾 | Move to end of line |

### 页面移动 | Page Movement

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| `gg` | 跳转到文件开头 | Go to beginning of file |
| `G` | 跳转到文件末尾 | Go to end of file |
| `Ctrl+d` | 向下滚动半页 | Scroll down half page |
| `Ctrl+u` | 向上滚动半页 | Scroll up half page |
| `Ctrl+f` | 向下滚动一整页 | Scroll down full page |
| `Ctrl+b` | 向上滚动一整页 | Scroll up full page |
| `{数字}G` | 跳转到指定行号 | Go to line number |
| `:{数字}` | 跳转到指定行号 | Go to line number |

---

## 文件操作 | File Operations

### 保存和退出 | Save & Quit

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| `:w` | 保存文件 | Write (save) file |
| `:w {filename}` | 另存为 | Save as |
| `:q` | 退出（未修改） | Quit (if no changes) |
| `:q!` | 强制退出（不保存） | Force quit (discard changes) |
| `:wq` | 保存并退出 | Write and quit |
| `:x` | 保存并退出（仅当有修改时保存） | Exit (save if modified) |
| `ZZ` | 保存并退出 | Write and quit |
| `ZQ` | 不保存退出 | Quit without saving |

### Telescope 文件查找 | Telescope File Finding

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| `<leader>ff` | 查找文件（模糊搜索） | Find files (fuzzy search) |
| `<leader>fr` | 最近打开的文件 | Recent files (oldfiles) |
| `<leader>fb` | 查找并切换缓冲区 | Find buffers |
| `<leader>fh` | 搜索帮助文档 | Search help tags |
| `<leader>fm` | 查找书签/标记 | Find marks |
| `<leader>fk` | 查找快捷键 | Find keymaps |

**Telescope 窗口内快捷键** | **Inside Telescope Window**:
- `Ctrl+k` / `Ctrl+j` - 上下移动选择 | Move selection up/down
- `Ctrl+q` - 将选中项发送到 quickfix 列表 | Send to quickfix list
- `Enter` - 打开选中文件 | Open selected file
- `Esc` - 关闭 Telescope | Close Telescope

---

## 编辑操作 | Editing Operations

### 删除和修改 | Delete & Change

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| `x` | 删除光标下的字符 | Delete character under cursor |
| `X` | 删除光标前的字符 | Delete character before cursor |
| `dd` | 删除整行 | Delete line |
| `D` | 删除光标到行尾 | Delete to end of line |
| `d0` | 删除光标到行首 | Delete to beginning of line |
| `dw` | 删除一个单词 | Delete word |
| `cw` | 修改一个单词（删除并进入插入模式） | Change word |
| `cc` | 修改整行 | Change line |
| `C` | 修改到行尾 | Change to end of line |
| `r{char}` | 替换单个字符 | Replace single character |
| `R` | 进入替换模式 | Enter replace mode |
| `u` | 撤销 | Undo |
| `Ctrl+r` | 重做 | Redo |
| `.` | 重复上一次操作 | Repeat last command |

### 注释 | Comments (Comment.nvim)

| 快捷键 | 模式 | 功能说明 | Description |
|--------|------|----------|-------------|
| `gcc` | 普通模式 | 切换当前行注释 | Toggle line comment |
| `gc{motion}` | 普通模式 | 注释指定范围（如 `gcap` 注释段落） | Comment with motion |
| `gc` | 可视模式 | 切换选中内容的注释 | Toggle comment for selection |
| `gbc` | 普通模式 | 切换块注释 | Toggle block comment |

### 包围操作 | Surround (nvim-surround)

| 快捷键 | 模式 | 功能说明 | Description |
|--------|------|----------|-------------|
| `ys{motion}{char}` | 普通模式 | 添加包围（如 `ysiw"` 用引号包围单词） | Add surround |
| `ds{char}` | 普通模式 | 删除包围（如 `ds"` 删除引号） | Delete surround |
| `cs{old}{new}` | 普通模式 | 修改包围（如 `cs"'` 引号改单引号） | Change surround |
| `S{char}` | 可视模式 | 用指定字符包围选中内容 | Surround selection |

**常用包围字符** | **Common Surround Characters**:
- `"` - 双引号 | Double quotes
- `'` - 单引号 | Single quotes
- `` ` `` - 反引号 | Backticks
- `(` 或 `)` - 圆括号 | Parentheses
- `[` 或 `]` - 方括号 | Square brackets
- `{` 或 `}` - 花括号 | Curly braces
- `<` 或 `>` - 尖括号 | Angle brackets
- `t` - HTML/XML 标签 | HTML/XML tags

---

## 复制粘贴 | Copy & Paste

> **重要**：配置已启用系统剪贴板（`clipboard = "unnamedplus"`），所有复制操作自动同步到系统剪贴板！
> **Important**: System clipboard is enabled (`clipboard = "unnamedplus"`), all yank operations sync to system clipboard!

### 复制 | Yank (Copy)

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| `yy` | 复制当前行（自动到系统剪贴板） | Yank line (to system clipboard) |
| `y{motion}` | 复制指定范围（如 `yaw` 复制单词） | Yank with motion |
| `yw` | 复制一个单词 | Yank word |
| `y$` | 复制到行尾 | Yank to end of line |
| `y0` | 复制到行首 | Yank to beginning of line |
| `yG` | 复制到文件末尾 | Yank to end of file |
| `ygg` | 复制到文件开头 | Yank to beginning of file |
| `y` | 可视模式下复制选中内容 | Yank selection (visual mode) |

### 粘贴 | Paste

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| `p` | 在光标后粘贴 | Paste after cursor |
| `P` | 在光标前粘贴 | Paste before cursor |
| `Cmd+V` | 在 macOS 任何应用中粘贴 | Paste in any macOS app |

### 快速复制示例 | Quick Copy Examples

```vim
" 复制3行到系统剪贴板
vjjy          " v (可视模式) + jj (选3行) + y (复制)

" 然后在任何应用按 Cmd+V 即可粘贴
```

---

## 搜索查找 | Search & Find

### 文件内搜索 | In-File Search

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| `/pattern` | 向下搜索 | Search forward |
| `?pattern` | 向上搜索 | Search backward |
| `n` | 跳转到下一个匹配 | Next match |
| `N` | 跳转到上一个匹配 | Previous match |
| `*` | 搜索光标下的单词（向下） | Search word under cursor (forward) |
| `#` | 搜索光标下的单词（向上） | Search word under cursor (backward) |
| `:noh` | 清除搜索高亮 | Clear search highlight |

### 全局搜索 | Global Search (Telescope)

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| `<leader>fg` | 实时全局搜索（live grep） | Live grep in workspace |
| `<leader>fc` | 搜索光标下的字符串 | Find string under cursor |

---

## LSP 功能 | LSP Features

> **LSP** = Language Server Protocol，提供智能代码补全、跳转、重构等功能

### 代码导航 | Code Navigation

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| `gd` | 跳转到定义（Telescope） | Go to definition (Telescope) |
| `gD` | 跳转到声明 | Go to declaration |
| `gR` | 查看所有引用（Telescope） | Show references (Telescope) |
| `gi` | 查看实现（Telescope） | Show implementations (Telescope) |
| `gt` | 查看类型定义（Telescope） | Show type definitions (Telescope) |
| `K` | 显示悬浮文档（函数签名、参数说明） | Show hover documentation |
| `Ctrl+o` | 跳转回退（返回跳转前位置） | Jump back |
| `Ctrl+i` | 跳转前进 | Jump forward |

### 代码操作 | Code Actions

| 快捷键 | 模式 | 功能说明 | Description |
|--------|------|----------|-------------|
| `<leader>ca` | 普通/可视 | 显示可用的代码操作（修复、重构等） | Show code actions |
| `<leader>rn` | 普通模式 | 智能重命名（变量、函数等） | Smart rename |

### 诊断 | Diagnostics

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| `<leader>d` | 显示当前行诊断信息（错误、警告） | Show line diagnostics |
| `<leader>D` | 显示缓冲区所有诊断（Telescope） | Show buffer diagnostics (Telescope) |
| `[d` | 跳转到上一个诊断 | Go to previous diagnostic |
| `]d` | 跳转到下一个诊断 | Go to next diagnostic |

### LSP 管理 | LSP Management

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| `<leader>rs` | 重启 LSP 服务器 | Restart LSP server |
| `:LspInfo` | 查看 LSP 状态 | Show LSP info |
| `:Mason` | 打开 LSP 包管理器 | Open Mason (LSP package manager) |

---

## 代码导航 | Code Navigation

### Treesitter 增量选择 | Treesitter Incremental Selection

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| `Ctrl+Space` | 初始化选择 / 扩大选择范围 | Init selection / Increment selection |
| `Backspace` | 缩小选择范围 | Decrement selection |

### Treesitter 文本对象 | Treesitter Text Objects

**选择** | **Select**:

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| `af` | 选择整个函数（包括签名） | Select function outer |
| `if` | 选择函数内部 | Select function inner |
| `ac` | 选择整个类 | Select class outer |
| `ic` | 选择类内部 | Select class inner |

**跳转** | **Jump**:

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| `]m` | 跳转到下一个函数开始 | Go to next function start |
| `]]` | 跳转到下一个类开始 | Go to next class start |
| `]M` | 跳转到下一个函数结束 | Go to next function end |
| `][` | 跳转到下一个类结束 | Go to next class end |
| `[m` | 跳转到上一个函数开始 | Go to previous function start |
| `[[` | 跳转到上一个类开始 | Go to previous class start |
| `[M` | 跳转到上一个函数结束 | Go to previous function end |
| `[]` | 跳转到上一个类结束 | Go to previous class end |

---

## 文件浏览器 | File Explorer

> **nvim-tree** - 侧边栏文件浏览器

### 打开和关闭 | Open & Close

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| `<leader>ee` | 切换文件浏览器 | Toggle file explorer |
| `<leader>ef` | 在当前文件位置打开浏览器 | Toggle explorer on current file |
| `<leader>ec` | 折叠所有目录 | Collapse file explorer |
| `<leader>er` | 刷新文件浏览器 | Refresh file explorer |
| **`Ctrl+e`** | 快速聚焦到文件浏览器（⭐推荐） | Focus file explorer - Like VSCode! |

> **提示**：`Ctrl+e` 类似 VSCode 的体验，快速跳转到文件树，如果未打开会自动打开。
> **Tip**: `Ctrl+e` is like VSCode - quickly jump to file tree, opens automatically if closed.

### 浏览器内快捷键 | Inside Explorer

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| `Enter` | 打开文件或展开/折叠目录 | Open file or expand/collapse directory |
| `a` | 新建文件 | Create new file |
| `d` | 删除文件/目录 | Delete file/directory |
| `r` | 重命名文件 | Rename file |
| `x` | 剪切文件 | Cut file |
| `c` | 复制文件 | Copy file |
| `p` | 粘贴文件 | Paste file |
| `y` | 复制文件名 | Copy filename |
| `Y` | 复制相对路径 | Copy relative path |
| `gy` | 复制绝对路径 | Copy absolute path |
| `R` | 刷新 | Refresh |
| `H` | 切换隐藏文件显示 | Toggle hidden files |
| `q` | 关闭浏览器 | Close explorer |

---

## Git 集成 | Git Integration

> **gitsigns** - 实时显示 Git 改动，提供暂存、预览等功能

### Git 改动导航 | Git Change Navigation

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| `]c` | 跳转到下一个改动 | Go to next git change |
| `[c` | 跳转到上一个改动 | Go to previous git change |

### Git 操作 | Git Actions

| 快捷键 | 模式 | 功能说明 | Description |
|--------|------|----------|-------------|
| `<leader>gs` | 普通/可视 | 暂存当前 hunk | Stage hunk |
| `<leader>gr` | 普通/可视 | 重置当前 hunk | Reset hunk |
| `<leader>gS` | 普通模式 | 暂存整个文件 | Stage buffer |
| `<leader>gu` | 普通模式 | 撤销上次暂存 | Undo stage hunk |
| `<leader>gR` | 普通模式 | 重置整个文件 | Reset buffer |
| `<leader>gp` | 普通模式 | 预览改动 | Preview hunk |
| `<leader>gb` | 普通模式 | 显示 Git blame（作者信息） | Git blame line |
| `<leader>gd` | 普通模式 | 显示 diff | Diff this |
| `<leader>gD` | 普通模式 | 显示 diff（与HEAD~比较） | Diff this ~ |

---

## 诊断和调试 | Diagnostics & Debugging

> **Trouble** - 更好的诊断列表界面

### Trouble 快捷键 | Trouble Keymaps

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| `<leader>xx` | 切换诊断列表（所有文件） | Toggle diagnostics (workspace) |
| `<leader>xX` | 切换诊断列表（当前文件） | Toggle buffer diagnostics |
| `<leader>cs` | 切换符号列表 | Toggle symbols |
| `<leader>cl` | 切换 LSP 定义/引用列表 | Toggle LSP definitions/references |
| `<leader>xL` | 切换位置列表 | Toggle location list |
| `<leader>xQ` | 切换快速修复列表 | Toggle quickfix list |

### TODO 注释 | TODO Comments

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| `<leader>fT` | 搜索所有 TODO/FIXME/NOTE 等 | Find todos (Telescope) |

**支持的标签** | **Supported Tags**:
- `TODO:` - 待办事项 | To-do items
- `FIXME:` - 需要修复的问题 | Issues to fix
- `HACK:` - 临时解决方案 | Temporary workarounds
- `WARN:` - 警告 | Warnings
- `PERF:` - 性能问题 | Performance issues
- `NOTE:` - 注释说明 | Notes

---

## 快速跳转 | Quick Jump

> **Flash** - 超快速光标跳转导航

| 快捷键 | 模式 | 功能说明 | Description |
|--------|------|----------|-------------|
| `s` | 普通/可视/操作 | Flash 跳转（输入字符快速定位） | Flash jump |
| `S` | 普通/可视/操作 | Treesitter Flash（语法结构跳转） | Flash Treesitter |
| `r` | 操作模式 | 远程 Flash | Remote Flash |
| `R` | 操作/可视 | Treesitter 搜索 | Treesitter Search |

**使用方法** | **Usage**:
1. 按 `s` 进入 Flash 模式
2. 输入1-2个字符
3. 输入高亮标签字符跳转到目标位置

---

## 补全和代码片段 | Completion & Snippets

> **nvim-cmp** - 自动补全引擎
> **LuaSnip** - 代码片段引擎

### 补全窗口快捷键 | Completion Window

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| `Ctrl+k` | 选择上一项 | Select previous item |
| `Ctrl+j` | 选择下一项 | Select next item |
| `Ctrl+b` | 文档向上滚动 | Scroll docs up |
| `Ctrl+f` | 文档向下滚动 | Scroll docs down |
| `Ctrl+Space` | 触发补全 | Trigger completion |
| `Ctrl+e` | 关闭补全窗口 | Abort completion |
| `Enter` | 确认选中项 | Confirm selection |
| `Tab` | 下一项 / 展开代码片段 / 跳到下一占位符 | Next item / Expand snippet / Next placeholder |
| `Shift+Tab` | 上一项 / 跳到上一占位符 | Previous item / Previous placeholder |

### 补全来源 | Completion Sources

- `[LSP]` - 语言服务器补全 | LSP completions
- `[Snippet]` - 代码片段 | Snippets
- `[Buffer]` - 当前缓冲区单词 | Current buffer words
- `[Path]` - 文件路径 | File paths

---

## 窗口和缓冲区 | Windows & Buffers

### 窗口分割 | Window Split

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| `:sp {file}` | 水平分割窗口 | Horizontal split |
| `:vsp {file}` | 垂直分割窗口 | Vertical split |
| `Ctrl+w h` | 跳转到左侧窗口 | Move to left window |
| `Ctrl+w j` | 跳转到下方窗口 | Move to bottom window |
| `Ctrl+w k` | 跳转到上方窗口 | Move to top window |
| `Ctrl+w l` | 跳转到右侧窗口 | Move to right window |
| `Ctrl+w w` | 循环切换窗口 | Cycle through windows |
| `Ctrl+w q` | 关闭当前窗口 | Close current window |

### 窗口大小调整 | Window Resize

**精细调整（2 像素）| Fine Adjustment (2 pixels)**:

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| `Ctrl+Up` | 增加窗口高度 | Increase height |
| `Ctrl+Down` | 减少窗口高度 | Decrease height |
| `Ctrl+Left` | 减少窗口宽度 | Decrease width |
| `Ctrl+Right` | 增加窗口宽度 | Increase width |

**快速调整（10 像素）⭐ | Quick Adjustment (10 pixels)**:

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| **`Shift+Up`** | 快速增加高度 | Quickly increase height |
| **`Shift+Down`** | 快速减少高度 | Quickly decrease height |
| **`Shift+Left`** | 快速减少宽度 | Quickly decrease width |
| **`Shift+Right`** | 快速增加宽度 | Quickly increase width |

**快速命令 | Quick Commands**:

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| **`<leader>=`** | 平均分配所有窗口大小 | Equalize all window sizes |
| `<leader>\|` | 设置窗口宽度为 80 | Set window width to 80 |
| `<leader>_` | 设置窗口高度为 20 | Set window height to 20 |
| `Ctrl+w =` | 平均分配窗口大小（原生） | Equalize sizes (native) |

> **使用场景示例** | **Usage Example**:
> ```
> # 打开文件浏览器后，中间的编辑窗口太小
> Ctrl+e              # 聚焦到文件树
> Ctrl+w l            # 跳回编辑窗口
> Shift+Right Right   # 快速增加宽度（按2次 = 增加20像素）
>
> # 或者直接平均分配
> <leader>=           # 空格 → = （所有窗口等宽）
> ```

### 缓冲区切换 | Buffer Navigation

**最快速切换（推荐）⭐ | Fastest (Recommended)**:

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| **`Tab`** | 下一个缓冲区 | Next buffer (like browser tabs!) |
| **`Shift+Tab`** | 上一个缓冲区 | Previous buffer |
| **`<leader>bp`** | Pick 模式选择缓冲区 | Pick buffer (shows labels) |

> **重要**：`Tab` 只在**普通模式**下切换文件，在**插入模式**下是补全功能！
> **Important**: `Tab` switches files in **normal mode** only. In **insert mode**, it's for completion!

**备用方案 | Alternative**:

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| `Alt+l` | 下一个缓冲区 | Next buffer |
| `Alt+h` | 上一个缓冲区 | Previous buffer |

**数字快速跳转 | Jump by Number**:

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| `<leader>1` | 跳转到第 1 个缓冲区 | Go to buffer 1 |
| `<leader>2` | 跳转到第 2 个缓冲区 | Go to buffer 2 |
| `<leader>3-9` | 跳转到第 3-9 个缓冲区 | Go to buffer 3-9 |

**缓冲区管理 | Buffer Management**:

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| `<leader>bd` | 删除当前缓冲区 | Delete current buffer |
| `<leader>bc` | Pick 并关闭缓冲区 | Pick and close buffer |
| `<leader>bo` | 关闭其他所有缓冲区 | Close other buffers |
| `<leader>br` | 关闭右侧所有缓冲区 | Close buffers to the right |
| `<leader>bl` | 关闭左侧所有缓冲区 | Close buffers to the left |

**Telescope 查找 | Telescope Search**:

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| `<leader>fb` | 模糊搜索缓冲区 | Find buffers (fuzzy search) |

**命令行方式 | Command Line**:

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| `:bn` | 下一个缓冲区 | Next buffer |
| `:bp` | 上一个缓冲区 | Previous buffer |
| `:bd` | 删除当前缓冲区 | Delete current buffer |
| `:ls` | 列出所有缓冲区 | List all buffers |

> **完整工作流示例** | **Complete Workflow Example**:
> ```
> # 1. 打开多个文件
> nvim file1.py file2.js file3.lua
>
> # 2. 快速切换（推荐）
> Tab           # file1 → file2
> Tab           # file2 → file3
> Shift+Tab     # file3 → file2
>
> # 3. 直接跳转
> 空格 2        # 跳到第2个文件
>
> # 4. Pick 模式（最直观）
> 空格 b p      # 显示字母标签，输入字母跳转
>
> # 5. 模糊搜索
> 空格 f b      # Telescope 搜索文件名
> ```

---

## 主题和UI | Theme & UI

### 主题切换 | Theme Switching

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| `<leader>ft` | 实时预览并切换主题（⭐推荐） | Color schemes (Telescope) - Recommended |

**可用主题** | **Available Themes**:
- **One Dark** (Atom 官方移植版) - 当前默认 | Current default
- **One Dark** (Lua 现代版) - 备选方案 | Alternative
- **Tokyo Night** - 深色护眼主题 | Dark theme

**使用方法** | **Usage**:
1. 按 `空格 → f → t`
2. 用 `↑↓` 或 `Ctrl+j/k` 选择主题
3. 按 `Enter` 应用，按 `Esc` 取消

### 其他UI快捷键 | Other UI Keymaps

| 快捷键 | 功能说明 | Description |
|--------|----------|-------------|
| `:Lazy` | 打开插件管理器 | Open Lazy plugin manager |
| `:Mason` | 打开 LSP/工具管理器 | Open Mason LSP manager |
| `:checkhealth` | 检查 Neovim 健康状态 | Check Neovim health |

---

## 常用命令速查 | Common Commands Quick Reference

### 文件保存和退出 | Save & Quit

```vim
:w              " 保存 | Save
:wq             " 保存并退出 | Save and quit
:q              " 退出 | Quit
:q!             " 强制退出不保存 | Force quit
```

### 搜索替换 | Search & Replace

```vim
:%s/old/new/g       " 全局替换 | Global replace
:%s/old/new/gc      " 全局替换（逐个确认）| Global replace with confirm
:s/old/new/g        " 当前行替换 | Replace in current line
```

### 行操作 | Line Operations

```vim
:5              " 跳转到第5行 | Go to line 5
:5,10d          " 删除5-10行 | Delete lines 5-10
:5,10y          " 复制5-10行 | Yank lines 5-10
```

---

## 学习建议 | Learning Tips

### 新手优先掌握 | Beginners Should Master First

1. **模式切换**: `Esc`, `i`, `v`
2. **基础移动**: `h/j/k/l`, `w/b`, `0/$`, `gg/G`
3. **文件操作**: `:w`, `:q`, `:wq`, `<leader>ff`
4. **编辑**: `dd`, `yy`, `p`, `u`, `Ctrl+r`
5. **搜索**: `/`, `n`, `N`, `<leader>fg`

### 进阶技巧 | Advanced Tips

1. **LSP 导航**: `gd`, `gR`, `K`, `<leader>ca`
2. **Git 集成**: `]c/[c`, `<leader>gs`, `<leader>gp`
3. **代码对象**: `af/if`, `ac/ic`, `]m/[m`
4. **快速跳转**: `s` (Flash)
5. **Trouble 诊断**: `<leader>xx`

### 练习方法 | Practice Methods

1. 使用 `:help {command}` 查看命令帮助
2. 按 `<leader>fk` 搜索快捷键
3. 尝试 `vimtutor` 命令（Vim 内置教程）
4. 每天练习一个新的快捷键
5. 查看 [新手教程](nvim-tutorial.md) 了解详细用法

---

## 帮助系统 | Help System

| 命令 | 功能说明 | Description |
|------|----------|-------------|
| `:help` | 打开帮助首页 | Open help home |
| `:help {topic}` | 搜索特定主题帮助 | Search help for topic |
| `:help gd` | 查看 `gd` 命令帮助 | Help for `gd` command |
| `<leader>fk` | Telescope 搜索快捷键 | Search keymaps (Telescope) |
| `Ctrl+]` | 在帮助文档中跳转到标签 | Jump to tag in help |
| `Ctrl+o` | 返回上一位置 | Jump back |
| `:q` | 关闭帮助窗口 | Close help window |

---

## 附录：完整快捷键列表 | Appendix: Complete Keymap List

### 所有 Leader 键组合 | All Leader Key Combinations

```
文件查找 | File Finding:
  <leader>ff - 查找文件 | Find files
  <leader>fr - 最近文件 | Recent files
  <leader>fg - 全局搜索 | Live grep
  <leader>fc - 搜索光标下字符串 | Find string under cursor
  <leader>fb - 查找缓冲区 | Find buffers
  <leader>fh - 帮助标签 | Help tags
  <leader>fm - 查找书签 | Find marks
  <leader>fk - 查找快捷键 | Find keymaps
  <leader>ft - 切换主题 | Color schemes
  <leader>fT - 查找 TODO | Find todos

文件浏览器 | File Explorer:
  <leader>ee - 切换文件浏览器 | Toggle explorer
  <leader>ef - 当前文件位置打开浏览器 | Explorer on current file
  <leader>ec - 折叠浏览器 | Collapse explorer
  <leader>er - 刷新浏览器 | Refresh explorer
  Ctrl+e     - 快速聚焦文件浏览器 | Focus file explorer (Like VSCode!)

Buffer 切换 | Buffer Navigation:
  Tab        - 下一个 buffer | Next buffer (⭐ 最常用)
  Shift+Tab  - 上一个 buffer | Previous buffer (⭐ 最常用)
  Alt+l      - 下一个 buffer (备用) | Next buffer (alternative)
  Alt+h      - 上一个 buffer (备用) | Previous buffer (alternative)
  <leader>1-9 - 跳转到第 N 个 buffer | Jump to buffer N
  <leader>bp - Pick 选择 buffer | Pick buffer
  <leader>bc - Pick 并关闭 buffer | Pick and close buffer
  <leader>bd - 删除当前 buffer | Delete current buffer
  <leader>bo - 关闭其他 buffer | Close other buffers
  <leader>br - 关闭右侧 buffer | Close buffers to the right
  <leader>bl - 关闭左侧 buffer | Close buffers to the left

窗口调整 | Window Resize:
  Ctrl+方向键  - 精细调整窗口 (+/-2) | Fine adjustment
  Shift+方向键 - 快速调整窗口 (+/-10) | Quick adjustment (⭐ 推荐)
  <leader>=   - 平均分配窗口大小 | Equalize window sizes
  <leader>|   - 设置宽度为 80 | Set width to 80
  <leader>_   - 设置高度为 20 | Set height to 20

LSP 功能 | LSP Features:
  <leader>ca - 代码操作 | Code actions
  <leader>rn - 重命名 | Rename
  <leader>d  - 行诊断 | Line diagnostics
  <leader>D  - 缓冲区诊断 | Buffer diagnostics
  <leader>rs - 重启 LSP | Restart LSP

Git 操作 | Git Actions:
  <leader>gs - 暂存 hunk | Stage hunk
  <leader>gr - 重置 hunk | Reset hunk
  <leader>gS - 暂存文件 | Stage buffer
  <leader>gu - 撤销暂存 | Undo stage hunk
  <leader>gR - 重置文件 | Reset buffer
  <leader>gp - 预览改动 | Preview hunk
  <leader>gb - Git blame | Git blame
  <leader>gd - Diff | Diff this
  <leader>gD - Diff ~ | Diff this ~

诊断和调试 | Diagnostics:
  <leader>xx - 诊断列表 | Diagnostics (Trouble)
  <leader>xX - 缓冲区诊断 | Buffer diagnostics (Trouble)
  <leader>cs - 符号列表 | Symbols (Trouble)
  <leader>cl - LSP 列表 | LSP list (Trouble)
  <leader>xL - 位置列表 | Location list (Trouble)
  <leader>xQ - 快速修复列表 | Quickfix list (Trouble)
```

---

**有问题？** | **Questions?**
- 📖 查看 [新手教程](nvim-tutorial.md) | See [Tutorial](nvim-tutorial.md)
- 🔧 查看 [操作指南](nvim-operations.md) | See [Operations Guide](nvim-operations.md)
- 💬 输入 `:help` 查看 Neovim 帮助 | Type `:help` for Neovim help
- ⌨️ 按 `<leader>fk` 搜索快捷键 | Press `<leader>fk` to search keymaps
