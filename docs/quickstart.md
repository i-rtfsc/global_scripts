# 快速入门

5分钟快速掌握 Global Scripts 的基本使用。

## 前置要求

- Python 3.7+
- Bash, Zsh 或 Fish Shell

## 安装

### 1. 克隆项目

```bash
git clone https://github.com/i-rtfsc/global_scripts.git
cd global_scripts
```

### 2. 运行安装脚本

```bash
uv run python scripts/setup.py
```

安装程序会:
- 自动检测并配置环境
- 生成shell配置文件 `env.sh`
- 创建补全脚本
- 配置插件系统

### 3. 加载环境

```bash
# 对于 Bash 用户
source ~/.bashrc

# 对于 Zsh 用户
source ~/.zshrc

# 对于 Fish 用户
source ~/.config/fish/config.fish
```

## 基本使用

### 查看帮助

```bash
gs help
```

### 查看版本

```bash
gs version
```

### 列出所有插件

```bash
gs plugin list
```

输出示例（表格格式）:
```
┌───────────┬────────┬────────────┬──────────┬──────────┬──────────┬───────────────┐
│ 插件名称  │ 状态   │ 类型       │ 优先级   │ 版本     │ 命令数量 │ 描述          │
├───────────┼────────┼────────────┼──────────┼──────────┼──────────┼───────────────┤
│ android   │ 正常   │ 混合插件   │ 20       │ 1.0.0    │ 97       │ Android开发   │
│ system    │ 正常   │ 混合插件   │ 50       │ 1.0.0    │ 23       │ 系统管理工具  │
│ multirepo │ 正常   │ Python插件 │ 50       │ 1.0.0    │ 6        │ 多仓库管理    │
└───────────┴────────┴────────────┴──────────┴──────────┴──────────┴───────────────┘
```

### 查看插件详情

```bash
gs plugin info android
```

### 使用插件命令

```bash
# 格式: gs <插件名> <子插件> <命令> [参数]
gs android logcat clear
gs android device devices
gs system config install vim
```

## 配置

### 配置文件位置

- 用户配置: `~/.config/global-scripts/config/gs.json`
- 项目配置: `./config/gs.json`

### 启用/禁用插件

```bash
# 启用插件
gs plugin enable android

# 禁用插件
gs plugin disable android
```

### 修改语言设置

编辑 `~/.config/global-scripts/config/gs.json`:

```json
{
  "language": "en"  // "zh" 或 "en"
}
```

## 常用命令

### 系统管理

```bash
# 查看系统状态
gs status

# 刷新插件和补全
gs refresh

# 系统健康检查
gs doctor
```

### 插件管理

```bash
# 列出所有插件
gs plugin list

# 查看插件信息
gs plugin info <插件名>

# 启用插件
gs plugin enable <插件名>

# 禁用插件
gs plugin disable <插件名>
```

## 下一步

- 阅读 [CLI命令参考](./cli-reference.md) 了解所有命令
- 查看 [插件使用指南](./plugin-guide.md) 学习如何使用插件
- 参考 [配置说明](./configuration.md) 定制你的环境
- 访问 [插件开发指南](./plugin-development.md) 开发自己的插件

## 常见问题

**Q: 命令不存在？**

A: 确保已经 `source` 了shell配置文件,或运行 `source $GS_ROOT/env.sh`

**Q: 插件命令执行失败？**

A: 检查插件是否已启用: `gs plugin list`

**Q: 如何更新？**

A: 拉取最新代码后运行 `gs refresh`

更多问题请查看 [FAQ](./faq.md)
