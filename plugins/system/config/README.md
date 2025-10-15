# System Config Plugin

配置管理插件，支持多种shell和编辑器的配置管理。

## 功能特性

- 🐚 **多Shell支持**: Zsh, Fish
- 📝 **多编辑器支持**: Vim, Neovim
- 🔧 **开发工具**: Tmux, Git, SSH
- 🔒 **隐私保护**: 敏感配置分离存储
- 📦 **备份恢复**: 自动备份和版本管理
- 🚀 **现代化**: 基于最新最佳实践

## 使用方法

### 基本命令

```bash
# 初始化配置系统
gs system config init

# 列出所有可用配置
gs system config list

# 安装特定配置
gs system config install zsh
gs system config install vim
gs system config install fish

# 强制安装（覆盖现有配置）
gs system config install zsh force

# 备份配置
gs system config backup zsh
gs system config backup  # 备份所有

# 查看备份
gs system config list backups

# 恢复配置
gs system config restore zsh_20250918_112934
```

### 配置类型

| 配置 | 类型 | 目标文件 | 描述 |
|------|------|----------|------|
| zsh | 公开 | ~/.zshrc | Zsh shell配置 |
| fish | 公开 | ~/.config/fish/config.fish | Fish shell配置 |
| vim | 公开 | ~/.vimrc | Vim编辑器配置 |
| nvim | 公开 | ~/.config/nvim/init.vim | Neovim配置 |
| tmux | 公开 | ~/.tmux.conf | Tmux终端复用配置 |
| git | 私有 | ~/.gitconfig | Git配置 |
| ssh | 私有 | ~/.ssh/config | SSH配置 |

## 配置亮点

### Zsh配置
- Oh My Zsh集成准备
- 丰富的别名和函数
- 智能插件支持
- 多平台兼容

### Fish配置
- 现代shell特性
- 智能自动补全
- 语法高亮准备
- 函数库

### Vim/Neovim配置
- 现代化设置
- 基础插件管理准备
- 语言特定配置
- 高效键位映射

### Tmux配置
- 直观的键位绑定
- 插件管理准备
- 会话管理优化
- 开发友好布局

### Git配置
- 丰富的别名
- 颜色优化
- 安全设置
- 工作流支持

### SSH配置
- 安全默认设置
- 连接优化
- 模板示例
- 最佳实践指南

## 安全特性

1. **文件权限**: 自动设置适当的文件权限
2. **私有配置**: 敏感信息存储在private目录
3. **版本控制**: 私有配置不会被提交
4. **模板系统**: 避免暴露敏感信息

## 目录结构

```
plugins/system/config/
├── plugin.json              # 插件元信息
├── plugin.py                # 核心实现
├── configs/                 # 配置文件模板
│   ├── zsh/                # Zsh配置
│   ├── fish/               # Fish配置
│   ├── vim/                # Vim配置
│   ├── nvim/               # Neovim配置
│   ├── tmux/               # Tmux配置
│   ├── git/                # Git配置模板
│   └── ssh/                # SSH配置模板
├── backups/                # 配置备份
└── .gitignore              # 忽略私有文件

私有配置目录（全局）:
custom/private/
├── git/                    # 私有Git配置
│   ├── .gitconfig-user     # 用户信息
│   └── .gitconfig-work     # 工作配置
└── ssh/                    # 私有SSH配置
    ├── config-private      # 私有主机配置
    └── keys/               # SSH密钥目录
```

## 配置分离存储策略

### Git配置
- **公开配置**: `configs/git/.gitconfig` - 包含别名、颜色、工具等通用配置
- **私有配置**:
  - `custom/private/git/.gitconfig-user` - 用户信息（姓名、邮箱）
  - `custom/private/git/.gitconfig-work` - 工作配置（公司邮箱、代理等）

### SSH配置
- **公开配置**: `configs/ssh/config` - 包含全局设置、公共服务器配置
- **私有配置**:
  - `custom/private/ssh/config-private` - 私有主机配置
  - `custom/private/ssh/keys/` - SSH密钥存储目录

## 安全特性

1. **权限控制**: SSH配置自动设置正确权限(600/700)
2. **路径隔离**: 敏感配置使用Include引用私有文件
3. **模板系统**: 自动创建私有配置模板，指导用户填写
4. **版本控制**: .gitignore正确排除私有目录

## 使用示例

```bash
# 安装配置（自动处理分离存储）
gs system config install git
gs system config install ssh

# 编辑私有配置
vim ~/.config/global-scripts/custom/private/git/.gitconfig-user
vim ~/.config/global-scripts/custom/private/ssh/config-private

# 添加SSH密钥
cp id_rsa ~/.config/global-scripts/custom/private/ssh/keys/
```
  
## 许可证

Apache License 2.0