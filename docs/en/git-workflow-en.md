# Git Workflow Guidelines

> Git branch management and version release process for Global Scripts project

## Branch Strategy

This project uses **GitHub Flow** simplified workflow, suitable for continuous integration and rapid iteration.

### Long-lived Branches

- **`main`**: Production branch, always stable and deployable
  - Only accepts merges from `develop` or `hotfix/*`
  - Tag a version after each merge
  - Protected, no direct push allowed

- **`develop`**: Main development branch, integrates all features under development
  - Primary branch for daily development
  - Accepts merges from `feature/*`
  - Relatively stable but allows experimental features

### Short-lived Branches

- **`feature/*`**: Feature development branches
  - Created from `develop` branch
  - Merged back to `develop` after completion
  - Naming convention: `feature/feature-name`
  - Examples: `feature/android-plugin`, `feature/async-executor`

- **`hotfix/*`**: Emergency fix branches
  - Created from `main` branch
  - Merged to both `main` and `develop` after completion
  - Naming convention: `hotfix/issue-description`
  - Examples: `hotfix/fix-plugin-loader-crash`

- **`release/*`**: Release preparation branches (optional)
  - Created from `develop` branch
  - Used for final testing and version number updates before release
  - Merged to `main` and tagged after completion

## Workflows

### 1. Daily Feature Development

```bash
# 1. Update local develop branch
git checkout develop
git pull origin develop

# 2. Create feature branch
git checkout -b feature/new-feature

# 3. Commit regularly during development
git add .
git commit -m "feat(scope): descriptive commit message"

# 4. Push to remote after completion
git push origin feature/new-feature

# 5. Create Pull Request on GitHub
# Target branch: develop
# Wait for Code Review and tests to pass

# 6. Delete feature branch after PR merge
git checkout develop
git pull origin develop
git branch -d feature/new-feature
git push origin --delete feature/new-feature
```

### 2. Release New Version

```bash
# Approach A: Direct release from develop (minor updates)
git checkout main
git pull origin main
git merge develop
git tag -a v5.1.0 -m "Release v5.1.0: new feature description"
git push origin main --tags

# Approach B: Release via release branch (major updates)
git checkout develop
git checkout -b release/v6.0.0

# On release branch:
# - Update version number (VERSION file)
# - Update CHANGELOG.md
# - Final testing and bug fixes

git checkout main
git merge release/v6.0.0
git tag -a v6.0.0 -m "Release v6.0.0: major changes description"
git push origin main --tags

# Merge back to develop
git checkout develop
git merge release/v6.0.0
git push origin develop

# Delete release branch
git branch -d release/v6.0.0
```

### 3. Emergency Fix (Hotfix)

```bash
# 1. Create hotfix branch from main
git checkout main
git pull origin main
git checkout -b hotfix/fix-critical-bug

# 2. Fix bug and test
git add .
git commit -m "fix: critical bug description"

# 3. Merge to main and tag patch version
git checkout main
git merge hotfix/fix-critical-bug
git tag -a v5.0.1 -m "Hotfix v5.0.1: fix critical bug"
git push origin main --tags

# 4. Also merge to develop
git checkout develop
git merge hotfix/fix-critical-bug
git push origin develop

# 5. Delete hotfix branch
git branch -d hotfix/fix-critical-bug
```

## Versioning Guidelines

Follows **Semantic Versioning** 2.0.0 specification.

### Version Format

```
vMAJOR.MINOR.PATCH[-PRERELEASE]

Examples:
v5.0.0        - Official release
v5.1.0        - New features
v5.0.1        - Bug fixes
v6.0.0-beta.1 - Beta version
v6.0.0-rc.1   - Release candidate
```

### Version Increment Rules

- **MAJOR**: Incompatible API changes
  - Major architecture refactoring
  - Breaking changes
  - Example: v4.x.x → v5.0.0

- **MINOR**: Backward-compatible new features
  - New plugins
  - New commands
  - Feature enhancements
  - Example: v5.0.0 → v5.1.0

- **PATCH**: Backward-compatible bug fixes
  - Bug fixes
  - Documentation updates
  - Performance optimizations
  - Example: v5.0.0 → v5.0.1

### Pre-release Versions

- **alpha**: Internal testing version
  - `v5.0.0-alpha.1`
  - Incomplete features, may have serious bugs

- **beta**: Public testing version
  - `v5.0.0-beta.1`
  - Features mostly complete, needs more testing

- **rc**: Release candidate version
  - `v5.0.0-rc.1`
  - Ready for release, no major issues

## Commit Conventions

Follows [Conventional Commits](https://www.conventionalcommits.org/) specification.

### Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Type Categories

- **feat**: New feature
- **fix**: Bug fix
- **docs**: Documentation updates
- **style**: Code formatting (no functionality change)
- **refactor**: Refactoring (not a new feature or bug fix)
- **perf**: Performance optimization
- **test**: Test-related changes
- **chore**: Build process or auxiliary tool changes

### Scope (Optional)

- **core**: Core modules
- **cli**: Command-line interface
- **plugin**: Plugin system
- **android**: Android plugin
- **system**: System plugin
- **docs**: Documentation

### Examples

```bash
# Good commit messages
git commit -m "feat(android): add Frida injection support"
git commit -m "fix(core): fix plugin loader path resolution error"
git commit -m "docs: update Git workflow documentation"
git commit -m "refactor(cli): refactor command parsing logic, improve performance"

# Multi-line commit message
git commit -m "feat(plugin): support async plugin execution

- Introduce asyncio async execution engine
- Add timeout control and process management
- Update plugin API documentation

Closes #123"
```

## Tag Management

### Create Tags

```bash
# Lightweight tag (not recommended for releases)
git tag v5.0.0

# Annotated tag (recommended, contains full information)
git tag -a v5.0.0 -m "Release v5.0.0: Global Scripts V5 Architecture Refactoring

Major Changes:
- Complete Clean Architecture refactoring
- Support four plugin types
- Introduce UV dependency management
- Complete async execution engine
"

# Push tag to remote
git push origin v5.0.0

# Push all tags
git push origin --tags
```

### View Tags

```bash
# List all tags
git tag

# View tag details
git show v5.0.0

# List tags matching pattern
git tag -l "v5.*"
```

### Delete Tags

```bash
# Delete local tag
git tag -d v5.0.0

# Delete remote tag
git push origin --delete tag v5.0.0
```

## Pull Request Guidelines

### PR Title Format

```
<type>(<scope>): <brief description>

Examples:
feat(android): add device management feature
fix(core): fix plugin loader crash issue
docs: update Git workflow documentation
```

### PR Description Template

```markdown
## Summary

Brief description of the purpose and implementation of this PR.

## Change Type

- [ ] New feature
- [ ] Bug fix
- [ ] Refactoring
- [ ] Documentation update
- [ ] Other

## Related Issues

Closes #123
Related #456

## Testing

- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual tests pass

Test steps:
1. ...
2. ...

## Checklist

- [ ] Code follows project conventions (Black, Ruff, MyPy)
- [ ] Added necessary tests
- [ ] Updated relevant documentation
- [ ] Updated CHANGELOG.md
- [ ] Commit messages follow Conventional Commits
```

### Code Review Checklist

- Code quality and readability
- Compliance with project architecture standards
- Adequate test coverage
- Documentation updates
- Security concerns
- Performance impact assessment

## Branch Protection Rules

### main Branch Protection

- No direct push allowed
- Must merge via Pull Request
- Requires at least 1 Reviewer approval (team development)
- Must pass CI tests
- Admins can force merge (emergency situations)

### develop Branch Protection (Optional)

- No force push allowed
- Recommended to merge via Pull Request
- Code Review encouraged

## Common Scenarios

### Scenario 1: Feature needs latest develop code

```bash
# On feature branch
git checkout feature/my-feature
git fetch origin
git rebase origin/develop

# After resolving conflicts
git add .
git rebase --continue
git push origin feature/my-feature --force-with-lease
```

### Scenario 2: Feature complete, develop has new commits

```bash
# Update feature branch
git checkout feature/my-feature
git fetch origin
git rebase origin/develop

# Resolve conflicts and push
git push origin feature/my-feature --force-with-lease

# Then create or update Pull Request
```

### Scenario 3: Mistakenly committed to main branch

```bash
# If not pushed yet, reset to previous commit
git reset --hard HEAD~1

# If already pushed (use with caution!)
git revert <commit-hash>
git push origin main
```

### Scenario 4: Need to undo merged PR

```bash
# Find merge commit hash
git log --oneline

# Create revert commit
git revert -m 1 <merge-commit-hash>
git push origin main
```

## Best Practices

### Commit Granularity

- ✅ Each commit should be a complete logical unit
- ✅ Commit message clearly describes changes
- ❌ Avoid vague messages like "WIP" or "fix"
- ❌ Avoid multiple unrelated changes in one commit

### Branch Management

- ✅ Regularly sync develop to feature branches
- ✅ Delete branches promptly after feature completion
- ✅ Keep branch names clear and meaningful
- ❌ Avoid long-lived feature branches (>2 weeks)
- ❌ Avoid creating new branches based on feature branches

### Merge Strategy

- **develop** ← feature: Use Squash and Merge (keep history clean)
- **main** ← develop: Use Merge Commit (preserve full history)
- **main** ← hotfix: Use Merge Commit

### Code Review

- Respond to PR reviews promptly
- Provide constructive feedback
- Focus on code quality and architecture design
- Encourage knowledge sharing and discussion

## References

- [GitHub Flow](https://docs.github.com/en/get-started/quickstart/github-flow)
- [Semantic Versioning](https://semver.org/)
- [Conventional Commits](https://www.conventionalcommits.org/)
- [Git Flow](https://nvie.com/posts/a-successful-git-branching-model/)

## Changelog

- **2025-10-15**: Initial version, defining GitHub Flow workflow
