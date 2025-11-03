# Java LSP (jdtls) 配置指南

## 问题说明

### 遇到的问题
1. **Java 无法跳转** - LSP 功能不工作
2. **生成大量中间文件** - `.settings/`, `*.prefs` 等文件污染项目
3. **配置耦合** - 所有 LSP 配置都在 `plugins.lua` 里，难以维护

### 解决方案
我们创建了独立的 Java LSP 配置，使用 `ftplugin` 机制自动加载。

---

## 目录结构

新的配置文件结构：

```
~/.config/nvim/gs-runtime/
├── lua/
│   ├── lsp/
│   │   └── java.lua              # Java LSP 专门配置
│   ├── plugins.lua                # 主插件配置（jdtls 已移除）
│   └── ...
└── ftplugin/
    └── java.lua                   # Java 文件类型插件（自动加载）
```

---

## 配置说明

### 1. Java LSP 配置 (`lua/lsp/java.lua`)

**关键配置项：**

#### 工作区目录（中间文件存放位置）

**方案1：用户目录（默认，推荐）**
```lua
local workspace_dir = home .. "/.local/share/eclipse/" .. project_name
```
- ✅ **优点**：不污染项目目录
- ✅ **优点**：所有中间文件集中管理
- ✅ **优点**：不需要 `.gitignore`
- ⚠️ **注意**：不同项目的工作区隔离

**方案2：项目 build 目录**
```lua
local workspace_dir = vim.fn.getcwd() .. '/build/eclipse-workspace'
```
- ✅ **优点**：随项目一起，易于清理（`clean` 命令）
- ⚠️ **缺点**：需要在 `.gitignore` 中忽略
- ⚠️ **缺点**：每个项目都要配置

**切换方法：**
在 `lua/lsp/java.lua` 文件中：
```lua
-- 使用方案1（默认）
local workspace_dir = home .. "/.local/share/eclipse/" .. project_name

-- 使用方案2：注释掉上面，取消注释下面
-- local workspace_dir = vim.fn.getcwd() .. '/build/eclipse-workspace'
```

#### Java 特定快捷键

| 快捷键 | 功能 | 说明 |
|--------|------|------|
| `<leader>jo` | 组织导入 | 自动整理 import 语句 |
| `<leader>jv` | 提取变量 | 提取选中代码为变量 |
| `<leader>jc` | 提取常量 | 提取选中代码为常量 |
| `<leader>jm` | 提取方法 | 提取选中代码为方法 |
| `<leader>ju` | 更新配置 | 刷新 jdtls 配置 |

---

### 2. 文件类型插件 (`ftplugin/java.lua`)

**功能：**
- 自动加载 Java LSP 配置
- 设置 Java 特定的编辑器选项
- 只在打开 `.java` 文件时加载

**配置内容：**
```lua
require("lsp.java")              -- 加载 Java LSP

-- Java 代码风格
vim.opt_local.shiftwidth = 4     -- 缩进4个空格
vim.opt_local.tabstop = 4
vim.opt_local.expandtab = true   -- 使用空格而非Tab

vim.opt_local.textwidth = 120    -- 行宽120字符
vim.opt_local.colorcolumn = "120"
```

---

### 3. 主配置修改 (`lua/plugins.lua`)

**变更：**
```lua
-- 旧配置（已移除）
-- lspconfig.jdtls.setup(default_config)

-- 新配置（添加了注释说明）
-- Java
-- 注意：Java LSP (jdtls) 使用专门的配置文件
-- 配置文件位置：lua/lsp/java.lua
-- 通过 ftplugin/java.lua 自动加载
-- 不要在这里配置 jdtls！
```

---

## 使用方法

### 安装配置

```bash
# 重新安装配置（自动备份）
gs dotfiles nvim install --force

# 启动 Neovim
nvim

# 打开任意 Java 文件
nvim Main.java

# jdtls 会自动启动（首次可能需要几分钟）
```

### 测试 LSP 功能

**1. 测试跳转功能**
```
在 Java 文件中：
1. 光标移到某个类名或方法名上
2. 按 gd（跳转到定义）
3. 应该跳转到定义位置
4. 按 Ctrl+o 返回
```

**2. 测试自动补全**
```
1. 输入一个类名的前几个字母
2. 按 Ctrl+Space（触发补全）
3. 应该出现补全菜单
4. 用 Ctrl+j/k 选择，Enter 确认
```

**3. 测试代码操作**
```
1. 选中一段代码（可视模式）
2. 按 空格 j v（提取变量）
3. 输入变量名
4. 代码自动重构
```

---

## 清理中间文件

### 已存在的中间文件

**如果项目中已经有这些文件：**

```bash
# 进入项目目录
cd /path/to/your/java/project

# 删除 Eclipse 相关文件
rm -rf .settings/
rm -f .classpath .project .factorypath
find . -name "*.prefs" -type f -delete

# 提交 .gitignore
git add .gitignore
git commit -m "chore: add .gitignore for Java project"
```

### 配置 .gitignore

**复制模板到项目：**

```bash
# 方法1：直接复制模板
cp ~/.config/nvim/java-gitignore-template /path/to/your/java/project/.gitignore

# 方法2：追加到现有 .gitignore
cat ~/.config/nvim/java-gitignore-template >> /path/to/your/java/project/.gitignore

# 方法3：手动编辑
nvim /path/to/your/java/project/.gitignore
# 然后添加以下内容：
```

```gitignore
# Eclipse / jdtls
.settings/
.classpath
.project
*.prefs

# Maven
target/

# Gradle
.gradle/
build/
```

---

## 高级配置

### 配置多个 Java 版本

在 `lua/lsp/java.lua` 中：

```lua
settings = {
  java = {
    configuration = {
      runtimes = {
        {
          name = "JavaSE-11",
          path = "/Library/Java/JavaVirtualMachines/jdk-11.jdk/Contents/Home",
        },
        {
          name = "JavaSE-17",
          path = "/Library/Java/JavaVirtualMachines/jdk-17.jdk/Contents/Home",
          default = true,
        },
      },
    },
  },
}
```

### 配置 Lombok 支持

在 `lua/lsp/java.lua` 中，取消注释：

```lua
cmd = {
  "java",
  -- ... 其他参数 ...
  "-javaagent:" .. lombok_path,  -- 取消注释这行
  -- ... 其他参数 ...
}
```

### 配置代码格式化

```lua
settings = {
  java = {
    format = {
      enabled = true,
      settings = {
        url = "file:///path/to/eclipse-formatter.xml",
        profile = "GoogleStyle",
      },
    },
  },
}
```

---

## 常见问题

### Q1: jdtls 没有启动？

**检查步骤：**

```bash
# 1. 检查 jdtls 是否安装
ls ~/.local/share/nvim/mason/packages/jdtls

# 2. 如果没有，在 Neovim 中安装
:Mason
# 搜索 jdtls，按 i 安装

# 3. 重新打开 Java 文件
:e %
```

### Q2: LSP 功能不工作？

**调试方法：**

```vim
" 在 Neovim 中查看 LSP 状态
:LspInfo

" 查看 LSP 日志
:LspLog

" 重启 LSP
:LspRestart
```

### Q3: 中间文件还在生成？

**检查配置：**

```bash
# 1. 确认使用的是用户目录配置
nvim ~/.config/nvim/gs-runtime/lua/lsp/java.lua

# 2. 查找这一行（应该没有注释）
# local workspace_dir = home .. "/.local/share/eclipse/" .. project_name

# 3. 查看工作区目录
ls ~/.local/share/eclipse/
# 应该看到项目名称的目录

# 4. 删除项目中的旧中间文件
cd /path/to/project
rm -rf .settings/ .classpath .project
find . -name "*.prefs" -delete
```

### Q4: 如何完全卸载 jdtls 工作区？

```bash
# 删除所有 jdtls 工作区数据
rm -rf ~/.local/share/eclipse/

# 重新打开 Java 文件会自动创建新的工作区
```

### Q5: 项目切换后 LSP 混乱？

```bash
# 方法1：在 Neovim 中重启 LSP
:LspRestart

# 方法2：重启 Neovim
:qa
nvim Main.java

# 方法3：清理该项目的工作区
rm -rf ~/.local/share/eclipse/项目名称
```

---

## 文件位置参考

| 文件 | 位置 | 说明 |
|------|------|------|
| Java LSP 配置 | `~/.config/nvim/gs-runtime/lua/lsp/java.lua` | jdtls 主配置 |
| Java ftplugin | `~/.config/nvim/gs-runtime/ftplugin/java.lua` | 自动加载配置 |
| 主插件配置 | `~/.config/nvim/gs-runtime/lua/plugins.lua` | jdtls 已移除 |
| .gitignore 模板 | `~/.config/nvim/java-gitignore-template` | 项目忽略文件模板 |
| jdtls 工作区 | `~/.local/share/eclipse/项目名/` | 中间文件存放位置 |
| jdtls 安装目录 | `~/.local/share/nvim/mason/packages/jdtls/` | jdtls 本体 |

---

## 配置原理

### ftplugin 机制

当 Neovim 打开 `.java` 文件时：

```
1. Neovim 检测到文件类型是 java
2. 自动查找 ftplugin/java.lua
3. 执行 ftplugin/java.lua
4. 加载 require("lsp.java")
5. jdtls 启动，连接到项目
6. LSP 功能激活（跳转、补全等）
```

### 工作区隔离

每个项目使用独立的工作区：

```
~/.local/share/eclipse/
├── project-a/          # 项目A的工作区
│   ├── .metadata/
│   └── ...
├── project-b/          # 项目B的工作区
│   ├── .metadata/
│   └── ...
└── my-app/             # 项目my-app的工作区
    ├── .metadata/
    └── ...
```

---

## 总结

### 优点
- ✅ 配置解耦，易于维护
- ✅ 中间文件不污染项目
- ✅ 每个项目独立工作区
- ✅ 自动加载，无需手动配置
- ✅ 支持高级功能（重构、调试等）

### 使用建议
1. 首次使用等待 jdtls 下载依赖（可能需要几分钟）
2. 大型项目建议增加 JVM 内存（修改 `cmd` 中的 `-Xms` 参数）
3. 定期清理不用的工作区（`~/.local/share/eclipse/`）
4. 使用 `.gitignore` 模板保持项目整洁

---

**有问题？** 查看日志：`:LspLog` 或检查 `~/.local/share/nvim/lsp.log`
