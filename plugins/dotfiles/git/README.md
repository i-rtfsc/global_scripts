# Git Configuration

全局 Git 配置管理，包含 Git 别名、基础配置和全局 Commit 规范验证。

## 功能特性

- ✅ 全局 Git 配置（.gitconfig）
- ✅ 丰富的 Git 别名
- ✅ 全局 Commit Message 规范验证（Conventional Commits）
- ✅ 多账户支持（通过 includeIf）
- ✅ 自动备份和恢复

## 快速开始

### 安装配置

```bash
# 安装 Git 配置和 hooks
gs dotfiles git install

# 查看安装状态
gs dotfiles git status

# 强制安装（覆盖现有配置）
gs dotfiles git install --force
```

安装后将自动设置：
1. `.gitconfig` → `~/.gitconfig`
2. Git hooks → `~/.config/global-scripts/git/hooks/`
3. 全局 `core.hooksPath` 配置指向 hooks 目录

## 全局 Commit 规范

### 工作原理

通过 Git 的全局 `core.hooksPath` 配置，所有仓库（新建/现有）都会自动使用全局 hooks，实现完全无感知的 commit 规范验证。

**vs Husky**:
- **Husky**: 基于项目的 npm 包，需要每个仓库单独安装
- **全局方案**: 一次配置，所有仓库自动生效（包括非 Node.js 项目）

### Commit Message 格式

遵循 [Conventional Commits](https://www.conventionalcommits.org/) 规范：

```
<type>(<scope>): <subject>
```

**有效类型**:
- `feat` - 新功能
- `fix` - Bug 修复
- `docs` - 文档变更
- `style` - 代码格式（不影响功能）
- `refactor` - 重构（既不修复 bug 也不添加功能）
- `perf` - 性能优化
- `test` - 添加或修改测试
- `build` - 构建系统或依赖变更
- `ci` - CI 配置变更
- `chore` - 其他变更（维护等）
- `revert` - 回退之前的 commit

**示例**:
```bash
git commit -m "feat(auth): add user login feature"
git commit -m "fix(api): resolve null pointer in user service"
git commit -m "docs: update README installation guide"
git commit -m "refactor(utils): simplify string parsing logic"
```

### 验证效果

**格式正确**:
```bash
$ git commit -m "feat(core): add new feature"
✓ Commit message format is valid
[main 1234567] feat(core): add new feature
```

**格式错误**:
```bash
$ git commit -m "added new feature"
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✗ Commit message format error!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Your commit message:
  added new feature

Expected format (Conventional Commits):
  <type>(<scope>): <subject>

Valid types:
  feat     - A new feature
  fix      - A bug fix
  ...

Examples:
  feat(auth): add user login feature
  fix(api): resolve null pointer in user service
  ...
```

### 特殊情况

以下类型的 commit 会自动跳过验证：
- Merge commits（合并提交）
- Revert commits（回退提交）
- 以 `#` 开头的注释

## Git 配置内容

### 核心配置

```ini
[core]
    editor = nvim
    hooksPath = ~/.config/global-scripts/git/hooks  # 全局 hooks 路径
    autocrlf = input
    filemode = true

[color]
    ui = auto
    ...
```

### Git 别名

```bash
# 常用别名
git st      # git status
git co      # git checkout
git cb      # git checkout -b
git br      # git branch
git ci      # git commit
git cm      # git commit -m
git aa      # git add --all
git p       # git push
git pl      # git pull

# 高级别名
git lg      # git log --oneline --graph --all
git unstage # git reset HEAD --
git last    # git log -1 HEAD
```

### 多账户配置

通过 `includeIf` 实现不同目录使用不同账户：

```ini
# 默认账户
[include]
    path = ~/.config/global-scripts/git/.gitconfig-user

# 工作账户（特定目录）
[includeIf "gitdir:~/work/"]
    path = ~/.config/global-scripts/git/.gitconfig-work
```

**注意**: `.gitconfig-user` 和 `.gitconfig-work` 是私密配置，应在私有插件中管理。

## 配置管理

### 备份配置

```bash
# 备份当前配置
gs dotfiles git backup
```

备份位置：`~/.config/global-scripts/backups/dotfiles/git/`

### 恢复配置

```bash
# 恢复配置（会列出可选备份）
gs dotfiles git restore
```

### 卸载配置

```bash
# 卸载配置（自动备份）
gs dotfiles git uninstall
```

卸载操作：
- 自动备份后删除 `.gitconfig`
- 删除全局 hooks 目录
- 不影响其他配置文件

## 自定义 Hooks

你可以添加更多 Git hooks 到 `plugins/dotfiles/git/hooks/` 目录：

**可用的 hooks**:
- `commit-msg` - ✓ 已包含（Commit 规范验证）
- `pre-commit` - 提交前检查（可自行添加）
- `pre-push` - 推送前检查（可自行添加）
- `prepare-commit-msg` - 准备 commit 消息（可自行添加）
- 更多请参考 [Git Hooks 文档](https://git-scm.com/docs/githooks)

添加后重新安装：
```bash
gs dotfiles git install
```

## 故障排除

### Hooks 不生效

检查全局配置：
```bash
git config --global core.hooksPath
# 应该输出: /Users/xxx/.config/global-scripts/git/hooks
```

检查 hooks 文件权限：
```bash
ls -la ~/.config/global-scripts/git/hooks/
# commit-msg 应该有可执行权限（-rwxr-xr-x）
```

### 临时禁用验证

如果需要临时绕过 commit 规范验证：
```bash
git commit --no-verify -m "your message"
```

### 恢复默认设置

```bash
# 取消全局 hooks 配置
git config --global --unset core.hooksPath

# 或卸载配置
gs dotfiles git uninstall
```

## 更多资源

- [Conventional Commits 规范](https://www.conventionalcommits.org/)
- [Git Hooks 文档](https://git-scm.com/docs/githooks)
- [Git 配置文档](https://git-scm.com/docs/git-config)
- [Global Scripts 文档](https://github.com/i-rtfsc/global_scripts)

---

**最后更新**: 2025-10-17
**适用版本**: Git 2.9+
