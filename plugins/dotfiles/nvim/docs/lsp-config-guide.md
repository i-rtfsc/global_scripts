# LSP 配置完整指南

## 概述

本 Neovim 配置采用**模块化架构**，每个语言的 LSP 配置都在独立文件中，通过 `ftplugin` 机制自动加载。

### 优点

- ✅ **配置解耦** - 每个语言独立配置，易于维护
- ✅ **自动加载** - 打开文件时自动加载对应 LSP
- ✅ **统一风格** - 所有文件统一使用 4 个空格缩进
- ✅ **避免冲突** - 中间文件不污染项目（Java 等）
- ✅ **易于扩展** - 添加新语言只需创建对应文件

---

## 目录结构

```
~/.config/nvim/gs-runtime/
├── lua/
│   ├── lsp/                    # LSP 配置目录
│   │   ├── java.lua            # Java LSP (jdtls)
│   │   ├── python.lua          # Python LSP (pyright)
│   │   ├── rust.lua            # Rust LSP (rust-analyzer)
│   │   ├── go.lua              # Go LSP (gopls)
│   │   ├── typescript.lua      # TypeScript/JavaScript LSP (ts_ls + eslint)
│   │   ├── clang.lua           # C/C++ LSP (clangd)
│   │   ├── lua.lua             # Lua LSP (lua_ls)
│   │   └── common.lua          # 通用 LSP (HTML/CSS/JSON/YAML等)
│   └── plugins.lua             # 主插件配置
└── ftplugin/                   # 文件类型插件（自动加载）
    ├── java.lua                # 打开 .java 时加载
    ├── python.lua              # 打开 .py 时加载
    ├── rust.lua                # 打开 .rs 时加载
    ├── go.lua                  # 打开 .go 时加载
    ├── typescript.lua          # 打开 .ts 时加载
    ├── javascript.lua          # 打开 .js 时加载
    ├── c.lua                   # 打开 .c 时加载
    ├── cpp.lua                 # 打开 .cpp 时加载
    ├── lua.lua                 # 打开 .lua 时加载
    ├── html.lua                # 打开 .html 时加载
    ├── css.lua                 # 打开 .css 时加载
    ├── json.lua                # 打开 .json 时加载
    ├── yaml.lua                # 打开 .yaml 时加载
    └── sh.lua                  # 打开 .sh 时加载
```

---

## 加载机制

### 工作原理

```
打开文件 → 检测文件类型 → 加载 ftplugin → 加载 LSP 配置 → LSP 启动
```

**示例：打开 Python 文件**

```
1. nvim main.py
2. Neovim 检测到文件类型是 python
3. 自动执行 ftplugin/python.lua
4. ftplugin/python.lua 执行 require("lsp.python")
5. lua/lsp/python.lua 配置 pyright
6. pyright LSP 启动
7. LSP 功能可用（跳转、补全等）
```

---

## 语言配置详解

### 1. Java (jdtls)

**配置文件：** `lua/lsp/java.lua`
**加载文件：** `ftplugin/java.lua`
**中间文件位置：** `~/.local/share/eclipse/项目名/`

**特点：**
- 工作区隔离（每个项目独立）
- 支持 Maven/Gradle
- 自动组织导入
- 代码重构功能

**快捷键：**
| 快捷键 | 功能 |
|--------|------|
| `<leader>jo` | 组织导入 |
| `<leader>jv` | 提取变量 |
| `<leader>jc` | 提取常量 |
| `<leader>jm` | 提取方法 |
| `<leader>ju` | 更新配置 |

**详细文档：** [Java LSP 配置指南](java-lsp-config.md)

### 2. Python (pyright)

**配置文件：** `lua/lsp/python.lua`
**加载文件：** `ftplugin/python.lua`

**特点：**
- 类型检查
- 自动导入建议
- 诊断级别可配置

**配置选项：**
```lua
typeCheckingMode = "basic"  -- "off", "basic", "strict"
```

**快捷键：**
| 快捷键 | 功能 |
|--------|------|
| `<leader>pi` | 组织导入 |
| `gd` | 跳转到定义 |
| `gr` | 查看引用 |

### 3. Rust (rust-analyzer)

**配置文件：** `lua/lsp/rust.lua`
**加载文件：** `ftplugin/rust.lua`

**特点：**
- Clippy 集成
- 宏展开
- Cargo 集成

**快捷键：**
| 快捷键 | 功能 |
|--------|------|
| `<leader>rh` | Rust hover actions |
| `<leader>rc` | Rust runnables |
| `<leader>rm` | 展开宏 |

### 4. Go (gopls)

**配置文件：** `lua/lsp/go.lua`
**加载文件：** `ftplugin/go.lua`

**特点：**
- 保存时自动格式化
- 自动组织导入
- Inlay hints 支持

**快捷键：**
| 快捷键 | 功能 |
|--------|------|
| `<leader>go` | 组织导入 |
| `<leader>gf` | 格式化文件 |

**自动功能：**
- 保存时自动 `gofmt`
- 保存时自动组织导入

### 5. TypeScript/JavaScript (ts_ls + eslint)

**配置文件：** `lua/lsp/typescript.lua`
**加载文件：** `ftplugin/typescript.lua` 和 `ftplugin/javascript.lua`

**特点：**
- TypeScript 类型检查
- ESLint 自动修复
- Inlay hints

**快捷键：**
| 快捷键 | 功能 |
|--------|------|
| `<leader>to` | 组织导入 |
| `<leader>tr` | 重命名文件 |
| `<leader>ti` | 添加缺失导入 |
| `<leader>tu` | 移除未使用代码 |

**自动功能：**
- 保存时 ESLint 自动修复

### 6. C/C++ (clangd)

**配置文件：** `lua/lsp/clang.lua`
**加载文件：** `ftplugin/c.lua` 和 `ftplugin/cpp.lua`

**特点：**
- Clang-tidy 集成
- 头文件/源文件切换
- 编译数据库支持

**快捷键：**
| 快捷键 | 功能 |
|--------|------|
| `<leader>ch` | 切换源文件/头文件 |
| `<leader>ct` | 类型层次结构 |
| `<leader>cs` | 符号信息 |

### 7. Lua (lua_ls)

**配置文件：** `lua/lsp/lua.lua`
**加载文件：** `ftplugin/lua.lua`

**特点：**
- Neovim API 支持
- 自动识别 `vim` 全局变量

### 8. 通用语言 (common.lua)

**配置文件：** `lua/lsp/common.lua`
**支持的语言：**
- HTML (html)
- CSS (cssls)
- TailwindCSS (tailwindcss)
- JSON (jsonls)
- YAML (yamlls)
- Bash (bashls)
- Docker (dockerls)

**特点：**
- 简化配置
- Schema 支持（JSON/YAML）
- 基础LSP功能

---

## 通用快捷键

所有语言都支持的基础快捷键：

### 代码导航
| 快捷键 | 功能 |
|--------|------|
| `gd` | 跳转到定义 |
| `gD` | 跳转到声明 |
| `gi` | 跳转到实现 |
| `gr` | 查看引用 |
| `K` | 显示文档 |

### 代码操作
| 快捷键 | 功能 |
|--------|------|
| `<leader>ca` | 代码操作 |
| `<leader>rn` | 重命名 |

### 诊断
| 快捷键 | 功能 |
|--------|------|
| `<leader>d` | 显示当前行诊断 |
| `[d` | 上一个诊断 |
| `]d` | 下一个诊断 |
| `<leader>rs` | 重启 LSP |

---

## 缩进设置

所有语言统一使用 **4 个空格** 缩进：

```lua
vim.opt_local.shiftwidth = 4    -- 缩进宽度
vim.opt_local.tabstop = 4       -- Tab 宽度
vim.opt_local.expandtab = true  -- 使用空格
```

这包括：
- ✅ Python (4 spaces)
- ✅ Java (4 spaces)
- ✅ JavaScript/TypeScript (4 spaces，不是 2)
- ✅ Go (4 spaces，不是 tabs)
- ✅ Rust (4 spaces)
- ✅ C/C++ (4 spaces)
- ✅ Lua (4 spaces)
- ✅ 所有其他语言 (4 spaces)

---

## 如何修改配置

### 修改某个语言的 LSP 配置

**示例：修改 Python LSP**

1. 打开配置文件：
```bash
nvim ~/.config/nvim/gs-runtime/lua/lsp/python.lua
```

2. 修改设置，例如改变类型检查级别：
```lua
settings = {
  python = {
    analysis = {
      typeCheckingMode = "strict",  -- 从 "basic" 改为 "strict"
    },
  },
}
```

3. 保存并重启 Neovim 或重启 LSP：
```vim
:LspRestart
```

### 修改某个语言的编辑器设置

**示例：修改 Python 缩进（虽然已经是 4 了）**

1. 打开 ftplugin 文件：
```bash
nvim ~/.config/nvim/gs-runtime/ftplugin/python.lua
```

2. 修改设置：
```lua
vim.opt_local.shiftwidth = 2  -- 改为 2（如果你真的想要）
vim.opt_local.textwidth = 100 -- 改变行宽
```

3. 保存，重新打开 Python 文件生效

### 添加新语言支持

**步骤：**

1. 创建 LSP 配置文件：
```bash
nvim ~/.config/nvim/gs-runtime/lua/lsp/kotlin.lua
```

2. 参考其他语言配置，编写配置：
```lua
local lspconfig = require("lspconfig")
local cmp_nvim_lsp = require("cmp_nvim_lsp")

local on_attach = function(client, bufnr)
  -- 键位映射
end

local capabilities = cmp_nvim_lsp.default_capabilities()

lspconfig.kotlin_language_server.setup({
  on_attach = on_attach,
  capabilities = capabilities,
})
```

3. 创建 ftplugin 文件：
```bash
nvim ~/.config/nvim/gs-runtime/ftplugin/kotlin.lua
```

4. 加载 LSP 配置：
```lua
require("lsp.kotlin")

vim.opt_local.shiftwidth = 4
vim.opt_local.tabstop = 4
vim.opt_local.expandtab = true
```

5. 重启 Neovim，打开 Kotlin 文件测试

---

## 常见问题

### Q1: LSP 没有启动？

**检查步骤：**

```vim
" 1. 查看 LSP 状态
:LspInfo

" 2. 查看日志
:LspLog

" 3. 检查 LSP 是否安装
:Mason
```

**解决方法：**
```bash
# 在 Neovim 中安装 LSP
:Mason
# 搜索对应的 LSP，按 i 安装
```

### Q2: 跳转功能不工作？

**原因：** LSP 可能没有附加到 buffer

**解决：**
```vim
" 查看当前 buffer 的 LSP 状态
:LspInfo

" 如果没有附加，重启 LSP
:LspRestart

" 或重新打开文件
:e %
```

### Q3: Java 无法跳转且生成很多中间文件？

**解决：** 参考 [Java LSP 配置指南](java-lsp-config.md)

关键点：
- Java LSP 使用专门配置文件
- 中间文件存放在 `~/.local/share/eclipse/`
- 使用 `.gitignore` 忽略项目中的临时文件

### Q4: 如何禁用某个语言的 LSP？

**方法1：** 移除对应的 ftplugin 文件
```bash
rm ~/.config/nvim/gs-runtime/ftplugin/python.lua
```

**方法2：** 注释掉 ftplugin 中的 `require` 行
```lua
-- require("lsp.python")  -- 注释掉这行
```

### Q5: LSP 太慢？

**优化方法：**

1. 检查是否是大文件：
```vim
:echo line('$')  " 查看行数
```

2. 对大文件禁用某些功能：
```lua
-- 在对应的 lsp/*.lua 中添加
if vim.api.nvim_buf_line_count(0) > 10000 then
  return  -- 大文件不启动 LSP
end
```

### Q6: 如何更改所有语言的缩进为 2 个空格？

**方法1：** 修改全局默认（`lua/options.lua`）
```lua
opt.shiftwidth = 2
opt.tabstop = 2
```

**方法2：** 批量修改所有 ftplugin
```bash
# 使用 sed 批量替换
cd ~/.config/nvim/gs-runtime/ftplugin
sed -i '' 's/shiftwidth = 4/shiftwidth = 2/g' *.lua
sed -i '' 's/tabstop = 4/tabstop = 2/g' *.lua
```

---

## 诊断配置

### 诊断符号

```lua
Error = " "   -- 错误
Warn = " "    -- 警告
Hint = "󰠠 "   -- 提示
Info = " "    -- 信息
```

### 诊断显示

- ✅ 虚拟文本 - 在行尾显示错误信息
- ✅ 符号列 - 左侧显示诊断符号
- ✅ 下划线 - 错误位置下划线
- ✅ 浮动窗口 - `<leader>d` 查看详细信息

---

## 性能优化建议

1. **大文件** - 禁用部分 LSP 功能
2. **慢速 LSP** - 调整 `updatetime`
3. **多项目** - 定期清理 LSP 工作区缓存

```bash
# 清理所有 LSP 缓存
rm -rf ~/.local/share/nvim/lsp.log
rm -rf ~/.cache/nvim/lsp/

# 清理 Java 工作区
rm -rf ~/.local/share/eclipse/
```

---

## 相关文档

- [Java LSP 配置指南](java-lsp-config.md) - Java 专门配置
- [高级功能使用指南](nvim-advanced-features.md) - 调试、Git 等功能
- [快捷键完整参考](nvim-keymaps.md) - 所有快捷键

---

## 总结

### 配置架构优势

- 📁 **模块化** - 每个语言独立文件
- 🚀 **自动化** - 打开文件自动加载
- 🎯 **统一性** - 所有语言 4 空格缩进
- 🔧 **易维护** - 修改单个语言不影响其他
- 🧹 **整洁性** - 中间文件不污染项目

### 文件位置速查

| 语言 | LSP 配置 | ftplugin | LSP 名称 |
|------|----------|----------|----------|
| Java | `lua/lsp/java.lua` | `ftplugin/java.lua` | jdtls |
| Python | `lua/lsp/python.lua` | `ftplugin/python.lua` | pyright |
| Rust | `lua/lsp/rust.lua` | `ftplugin/rust.lua` | rust-analyzer |
| Go | `lua/lsp/go.lua` | `ftplugin/go.lua` | gopls |
| TypeScript | `lua/lsp/typescript.lua` | `ftplugin/typescript.lua` | ts_ls |
| JavaScript | `lua/lsp/typescript.lua` | `ftplugin/javascript.lua` | ts_ls |
| C | `lua/lsp/clang.lua` | `ftplugin/c.lua` | clangd |
| C++ | `lua/lsp/clang.lua` | `ftplugin/cpp.lua` | clangd |
| Lua | `lua/lsp/lua.lua` | `ftplugin/lua.lua` | lua_ls |
| HTML | `lua/lsp/common.lua` | `ftplugin/html.lua` | html |
| CSS | `lua/lsp/common.lua` | `ftplugin/css.lua` | cssls |
| JSON | `lua/lsp/common.lua` | `ftplugin/json.lua` | jsonls |
| YAML | `lua/lsp/common.lua` | `ftplugin/yaml.lua` | yamlls |
| Shell | `lua/lsp/common.lua` | `ftplugin/sh.lua` | bashls |

---

**需要帮助？** 运行 `:LspInfo` 查看状态或查看 `:help lsp`
