# Git 工作流规范

> Global Scripts 项目的 Git 分支管理和版本发布流程

## 分支策略

本项目采用 **GitHub Flow** 简化工作流，适合持续集成和快速迭代。

### 长期分支

- **`main`**: 生产环境分支，永远保持稳定可部署状态
  - 只接受来自 `develop` 或 `hotfix/*` 的合并
  - 每次合并后打 Tag 发布版本
  - 受保护，禁止直接推送

- **`develop`**: 开发主分支，集成所有开发中的功能
  - 日常开发的主要分支
  - 接受来自 `feature/*` 的合并
  - 相对稳定，但允许存在实验性功能

### 短期分支

- **`feature/*`**: 功能开发分支
  - 从 `develop` 分支创建
  - 开发完成后合并回 `develop`
  - 命名规范：`feature/功能名称`
  - 示例：`feature/android-plugin`, `feature/async-executor`

- **`hotfix/*`**: 紧急修复分支
  - 从 `main` 分支创建
  - 修复完成后同时合并到 `main` 和 `develop`
  - 命名规范：`hotfix/问题描述`
  - 示例：`hotfix/fix-plugin-loader-crash`

- **`release/*`**: 发布准备分支（可选）
  - 从 `develop` 分支创建
  - 用于发布前的最终测试和版本号更新
  - 完成后合并到 `main` 并打 Tag

## 工作流程

### 1. 日常功能开发

```bash
# 1. 更新本地 develop 分支
git checkout develop
git pull origin develop

# 2. 创建功能分支
git checkout -b feature/new-feature

# 3. 开发过程中定期提交
git add .
git commit -m "feat(scope): 描述性提交信息"

# 4. 开发完成后，推送到远程
git push origin feature/new-feature

# 5. 在 GitHub 上创建 Pull Request
# 目标分支：develop
# 等待 Code Review 和测试通过

# 6. PR 合并后，删除功能分支
git checkout develop
git pull origin develop
git branch -d feature/new-feature
git push origin --delete feature/new-feature
```

### 2. 发布新版本

```bash
# 方式A：直接从 develop 发布（小版本更新）
git checkout main
git pull origin main
git merge develop
git tag -a v5.1.0 -m "Release v5.1.0: 新功能描述"
git push origin main --tags

# 方式B：通过 release 分支发布（大版本更新）
git checkout develop
git checkout -b release/v6.0.0

# 在 release 分支上：
# - 更新版本号（VERSION 文件）
# - 更新 CHANGELOG.md
# - 最终测试和 bug 修复

git checkout main
git merge release/v6.0.0
git tag -a v6.0.0 -m "Release v6.0.0: 主要变更描述"
git push origin main --tags

# 合并回 develop
git checkout develop
git merge release/v6.0.0
git push origin develop

# 删除 release 分支
git branch -d release/v6.0.0
```

### 3. 紧急修复（Hotfix）

```bash
# 1. 从 main 创建 hotfix 分支
git checkout main
git pull origin main
git checkout -b hotfix/fix-critical-bug

# 2. 修复 bug 并测试
git add .
git commit -m "fix: 修复关键bug描述"

# 3. 合并到 main 并打补丁版本 Tag
git checkout main
git merge hotfix/fix-critical-bug
git tag -a v5.0.1 -m "Hotfix v5.0.1: 修复关键bug"
git push origin main --tags

# 4. 同时合并到 develop
git checkout develop
git merge hotfix/fix-critical-bug
git push origin develop

# 5. 删除 hotfix 分支
git branch -d hotfix/fix-critical-bug
```

## 版本号规范

采用 **语义化版本（Semantic Versioning）** 2.0.0 规范。

### 版本格式

```
v主版本号.次版本号.修订号[-预发布标识]

示例：
v5.0.0        - 正式版本
v5.1.0        - 新增功能
v5.0.1        - Bug 修复
v6.0.0-beta.1 - 测试版本
v6.0.0-rc.1   - 候选版本
```

### 版本号递增规则

- **主版本号（Major）**: 不兼容的 API 修改
  - 架构重大重构
  - 破坏性变更
  - 示例：v4.x.x → v5.0.0

- **次版本号（Minor）**: 向下兼容的功能新增
  - 新增插件
  - 新增命令
  - 功能增强
  - 示例：v5.0.0 → v5.1.0

- **修订号（Patch）**: 向下兼容的问题修复
  - Bug 修复
  - 文档更新
  - 性能优化
  - 示例：v5.0.0 → v5.0.1

### 预发布版本

- **alpha**: 内部测试版本
  - `v5.0.0-alpha.1`
  - 功能不完整，可能有严重 bug

- **beta**: 公开测试版本
  - `v5.0.0-beta.1`
  - 功能基本完整，需要更多测试

- **rc**: 候选发布版本
  - `v5.0.0-rc.1`
  - 准备正式发布，无重大问题

## Commit 规范

采用 [Conventional Commits](https://www.conventionalcommits.org/) 规范。

### Commit 消息格式

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Type 类型

- **feat**: 新功能
- **fix**: Bug 修复
- **docs**: 文档更新
- **style**: 代码格式（不影响功能）
- **refactor**: 重构（不是新功能也不是 bug 修复）
- **perf**: 性能优化
- **test**: 测试相关
- **chore**: 构建过程或辅助工具的变动

### Scope 范围（可选）

- **core**: 核心模块
- **cli**: 命令行界面
- **plugin**: 插件系统
- **android**: Android 插件
- **system**: System 插件
- **docs**: 文档

### 示例

```bash
# 好的提交消息
git commit -m "feat(android): 新增 Frida 注入功能"
git commit -m "fix(core): 修复插件加载时的路径解析错误"
git commit -m "docs: 更新 Git 工作流文档"
git commit -m "refactor(cli): 重构命令解析逻辑，提升性能"

# 多行提交消息
git commit -m "feat(plugin): 支持异步插件执行

- 引入 asyncio 异步执行引擎
- 添加超时控制和进程管理
- 更新插件 API 文档

Closes #123"
```

## Tag 管理

### 创建 Tag

```bash
# 轻量标签（不推荐用于版本发布）
git tag v5.0.0

# 附注标签（推荐，包含完整信息）
git tag -a v5.0.0 -m "Release v5.0.0: Global Scripts V5 架构重构

主要变更：
- 完成 Clean Architecture 重构
- 支持四种插件类型
- 引入 UV 依赖管理
- 完整的异步执行引擎
"

# 推送 Tag 到远程
git push origin v5.0.0

# 推送所有 Tag
git push origin --tags
```

### 查看 Tag

```bash
# 列出所有 Tag
git tag

# 查看 Tag 详细信息
git show v5.0.0

# 列出符合模式的 Tag
git tag -l "v5.*"
```

### 删除 Tag

```bash
# 删除本地 Tag
git tag -d v5.0.0

# 删除远程 Tag
git push origin --delete tag v5.0.0
```

## Pull Request 规范

### PR 标题格式

```
<type>(<scope>): <简短描述>

示例：
feat(android): 新增设备管理功能
fix(core): 修复插件加载器崩溃问题
docs: 更新 Git 工作流文档
```

### PR 描述模板

```markdown
## 变更说明

简要描述本次 PR 的目的和实现方式。

## 变更类型

- [ ] 新功能 (feature)
- [ ] Bug 修复 (bugfix)
- [ ] 重构 (refactor)
- [ ] 文档更新 (docs)
- [ ] 其他

## 相关 Issue

Closes #123
Related #456

## 测试

- [ ] 单元测试通过
- [ ] 集成测试通过
- [ ] 手动测试通过

测试步骤：
1. ...
2. ...

## Checklist

- [ ] 代码符合项目规范（Black、Ruff、MyPy）
- [ ] 添加了必要的测试
- [ ] 更新了相关文档
- [ ] 更新了 CHANGELOG.md
- [ ] 提交信息符合 Conventional Commits 规范
```

### Code Review 检查点

- 代码质量和可读性
- 是否符合项目架构规范
- 是否有充分的测试覆盖
- 是否更新了文档
- 是否有安全隐患
- 性能影响评估

## 分支保护规则

### main 分支保护

- 禁止直接推送
- 必须通过 Pull Request 合并
- 需要至少 1 个 Reviewer 批准（团队开发）
- 必须通过 CI 测试
- 管理员可强制合并（紧急情况）

### develop 分支保护（可选）

- 禁止强制推送
- 建议通过 Pull Request 合并
- 鼓励 Code Review

## 常见场景

### 场景 1：Feature 开发中需要 develop 最新代码

```bash
# 在 feature 分支上
git checkout feature/my-feature
git fetch origin
git rebase origin/develop

# 解决冲突后
git add .
git rebase --continue
git push origin feature/my-feature --force-with-lease
```

### 场景 2：Feature 开发完成，develop 已有新提交

```bash
# 更新 feature 分支
git checkout feature/my-feature
git fetch origin
git rebase origin/develop

# 解决冲突并推送
git push origin feature/my-feature --force-with-lease

# 然后创建或更新 Pull Request
```

### 场景 3：错误提交到了 main 分支

```bash
# 如果还未推送，重置到上一个提交
git reset --hard HEAD~1

# 如果已推送（谨慎操作！）
git revert <commit-hash>
git push origin main
```

### 场景 4：需要撤销已合并的 PR

```bash
# 找到合并提交的 hash
git log --oneline

# 创建 revert 提交
git revert -m 1 <merge-commit-hash>
git push origin main
```

## 最佳实践

### 提交粒度

- ✅ 每个提交应该是一个完整的逻辑单元
- ✅ 提交信息清晰描述变更内容
- ❌ 避免 "WIP" 或 "修复" 等模糊信息
- ❌ 避免一个提交包含多个不相关的变更

### 分支管理

- ✅ 定期同步 develop 到 feature 分支
- ✅ Feature 开发完成后及时删除分支
- ✅ 保持分支命名清晰有意义
- ❌ 避免长期存在的 feature 分支（>2周）
- ❌ 避免在 feature 分支上基于 feature 创建新分支

### 合并策略

- **develop** ← feature: 使用 Squash and Merge（保持历史清晰）
- **main** ← develop: 使用 Merge Commit（保留完整历史）
- **main** ← hotfix: 使用 Merge Commit

### Code Review

- 及时响应 PR Review
- 提供建设性的反馈意见
- 关注代码质量和架构设计
- 鼓励知识分享和讨论

## 参考资料

- [GitHub Flow](https://docs.github.com/en/get-started/quickstart/github-flow)
- [Semantic Versioning](https://semver.org/)
- [Conventional Commits](https://www.conventionalcommits.org/)
- [Git Flow](https://nvie.com/posts/a-successful-git-branching-model/)

## 变更历史

- **2025-10-15**: 初始版本，定义 GitHub Flow 工作流
