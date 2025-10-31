# MultiRepo Plugin

多仓库管理工具，支持 `git clone` 和 `repo` 两种后端模式（**默认使用 git**）。

## 功能特性

- 📦 支持 git clone 和 repo 双后端（**默认 git，无需额外工具**）
- 🔍 智能 manifest 文件检测
- 📁 灵活的文件路径解析
- 🛠️ 完整的项目同步和分支管理
- 🚀 智能 push 支持 Gerrit 和普通 Git

## 命令列表

### 1. 列出内置 manifest

```bash
gs multirepo list
```

### 2. 初始化项目（默认使用 git）

#### 自动检测当前目录的 manifest

```bash
# 默认使用 git clone 模式（推荐）
gs multirepo init

# 显式指定使用 repo 模式
gs multirepo init --backend=repo
```

#### 使用内置 manifest

```bash
# 使用内置的 mini-aosp.xml（默认 git 模式）
gs multirepo init mini-aosp

# 使用 repo 模式
gs multirepo init mini-aosp --backend=repo
```

#### 使用自定义 manifest

```bash
# 使用当前目录的文件（默认 git 模式）
gs multirepo init custom-manifest  # 自动查找 custom-manifest.xml

# 使用绝对路径
gs multirepo init /path/to/manifest.xml

# 使用 repo 模式
gs multirepo init /path/to/manifest.xml --backend=repo
```

### 3. 同步项目

```bash
# 普通同步（自动检测 repo/git 模式）
gs multirepo sync

# 使用指定 manifest 同步
gs multirepo sync mini-aosp

# 清理模式（git clean + reset）
gs multirepo sync clean
```

### 4. 智能推送（自动检测 Gerrit/Git）

```bash
# 推送到当前分支（自动检测 Gerrit 或普通 Git）
gs multirepo push

# 推送到指定分支
gs multirepo push -b develop

# Gerrit 模式：添加评审人
gs multirepo push -r reviewer@example.com,another@example.com

# Gerrit 模式：推送草稿
gs multirepo push -d

# 指定远程仓库
gs multirepo push --remote origin

# 查看帮助
gs multirepo push -h
```

**智能检测说明**：
- ✅ **Gerrit 服务器**（URL 包含 `gerrit`、`/a/`、`review.`）
  - 自动使用 `refs/for/<branch>` 推送
  - 支持添加评审人 `-r`
  - 支持草稿模式 `-d`（推送到 `refs/drafts/<branch>`）

- ✅ **普通 Git 服务器**（GitHub/GitLab/Bitbucket）
  - 使用标准 `git push origin HEAD:<branch>`
  - 不支持 Gerrit 特有选项

### 5. 创建远程分支 (repo 模式)

```bash
gs multirepo checkout
```

### 6. 查看状态

```bash
gs multirepo status
```

## Manifest 解析优先级

1. **绝对路径**：`/path/to/file.xml`
2. **当前目录**：
   - 完整文件名：`default.xml`
   - 添加后缀：`default` → `default.xml`
3. **内置 manifests**：`mini-aosp` → `plugins/multirepo/manifests/mini-aosp.xml`

## 后端模式对比

| 特性 | repo 模式 | git clone 模式 |
|------|-----------|----------------|
| 执行方式 | 使用 `repo` 命令 | 直接 `git clone` |
| 目录结构 | 创建 `.repo/` 元数据 | 每个项目独立 `.git/` |
| 适用场景 | AOSP 等大型项目 | 需要单独复制项目 |
| 依赖 | 需要安装 repo | 只需要 git |

## 使用场景

### Android 源码开发

```bash
# 使用 repo 模式（推荐）
gs multirepo init mini-aosp
gs multirepo sync
```

### 快速克隆单个项目

```bash
# 使用 git 模式，方便后续复制单个项目
gs multirepo init mini-aosp --backend=git
```

### 自定义项目集合

1. 创建自己的 manifest.xml
2. 在项目目录运行：

```bash
gs multirepo init --backend=git
```

## 相关插件

如果需要管理 repo 源（Google/Intel/清华镜像），请使用：

```bash
gs system repo google      # 切换到 Google 官方源
gs system repo tsinghua    # 切换到清华镜像源
gs system repo status      # 查看当前源
```
