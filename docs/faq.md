# 常见问题FAQ

Global Scripts 常见问题与解决方案。

## 安装相关

### Q: 安装后命令不可用?

**A:** 确保已经加载了环境配置:

```bash
# 对于 Bash
source ~/.bashrc

# 对于 Zsh
source ~/.zshrc

# 对于 Fish
source ~/.config/fish/config.fish

# 或直接加载
source $GS_ROOT/env.sh
```

### Q: Python版本不兼容?

**A:** Global Scripts需要Python 3.7+:

```bash
# 检查Python版本
python3 --version

# 如果版本过低,安装新版Python
# macOS:
brew install python@3.11

# Ubuntu:
sudo apt install python3.11
```

### Q: 权限错误?

**A:** 确保有执行权限:

```bash
chmod +x /path/to/global_scripts-v6/env.sh
chmod +x /path/to/global_scripts-v6/scripts/setup.py
```

## 配置相关

### Q: 如何修改语言?

**A:** 编辑配置文件 `~/.config/global-scripts/config/gs.json`:

```json
{
  "language": "en"  // "zh" 或 "en"
}
```

或设置环境变量:

```bash
export GS_LANGUAGE="en"
```

### Q: 配置文件在哪里?

**A:** 配置文件优先级:

1. `~/.config/global-scripts/config/gs.json` (用户配置)
2. `/path/to/global_scripts-v6/config/gs.json` (项目配置)

### Q: 如何重置配置?

**A:** 删除用户配置文件并重新运行安装:

```bash
rm ~/.config/global-scripts/config/gs.json
python3 scripts/setup.py
```

## 插件相关

### Q: 插件不显示?

**A:** 检查以下几点:

1. 插件是否有`plugin.json`文件
2. `plugin.json`中的`name`字段是否正确
3. 插件是否已启用:

```bash
gs plugin list
gs plugin enable <插件名>
```

### Q: 插件命令执行失败?

**A:** 查看详细错误信息:

```bash
# 启用调试模式
export GS_DEBUG=1
gs <插件> <命令>

# 查看日志
tail -f ~/.config/global-scripts/logs/gs.log
```

### Q: 如何开发自己的插件?

**A:** 参考[插件开发指南](./plugin-development.md)

最简单的方式 - 创建JSON插件:

```json
{
  "name": "myplugin",
  "version": "1.0.0",
  "commands": {
    "hello": {
      "command": "echo 'Hello!'",
      "description": "Say hello"
    }
  }
}
```

## 执行相关

### Q: 命令超时?

**A:** 修改超时设置:

1. 在配置文件中:
```json
{
  "default_timeout": 60  // 秒
}
```

2. 或在函数定义中:
```python
@plugin_function(name="long-task", timeout=300)
```

### Q: 命令输出乱码?

**A:** 设置正确的编码:

```bash
export LANG=zh_CN.UTF-8
export LC_ALL=zh_CN.UTF-8
```

### Q: 并发执行限制?

**A:** 修改并发数:

```json
{
  "max_concurrent_commands": 20
}
```

## 性能相关

### Q: 插件加载慢?

**A:**

1. 禁用不需要的插件:
```bash
gs plugin disable <不需要的插件>
```

2. 不显示示例插件:
```json
{
  "show_examples": false
}
```

3. 清理日志文件:
```bash
rm ~/.config/global-scripts/logs/gs.log
```

### Q: 命令响应慢?

**A:**

1. 检查router索引:
```bash
gs refresh  # 重建索引
```

2. 启用缓存(如果可用):
```json
{
  "enable_cache": true
}
```

## 补全相关

### Q: Tab补全不工作?

**A:**

1. 确保补全脚本已生成:
```bash
ls ~/.config/global-scripts/completions/
```

2. 重新生成补全:
```bash
gs refresh
```

3. 重新加载Shell:
```bash
# Bash
source ~/.bashrc

# Zsh
source ~/.zshrc

# Fish
source ~/.config/fish/config.fish
```

### Q: 补全列表不完整?

**A:** 运行`gs refresh`重建补全脚本。

## 日志相关

### Q: 如何查看日志?

**A:**

```bash
# 实时查看
tail -f ~/.config/global-scripts/logs/gs.log

# 查看全部
cat ~/.config/global-scripts/logs/gs.log

# 清空日志
> ~/.config/global-scripts/logs/gs.log
```

### Q: 日志级别如何调整?

**A:**

```json
{
  "logging_level": "DEBUG"  // NANO/ERROR/WARNING/INFO/DEBUG/VERBOSE
}
```

或环境变量:
```bash
export GS_LOG_LEVEL="DEBUG"
```

## 错误处理

### Q: "Plugin not found" 错误?

**A:**

1. 检查插件名是否正确:
```bash
gs plugin list
```

2. 检查插件是否已启用:
```bash
gs plugin enable <插件名>
```

### Q: "Command not found" 错误?

**A:**

1. 确认命令路径:
```bash
gs plugin info <插件名>
```

2. 检查router索引:
```bash
gs refresh
```

### Q: "Permission denied" 错误?

**A:**

```bash
# 给予执行权限
chmod +x /path/to/script.sh

# 或使用sudo (不推荐,除非必要)
sudo gs <command>
```

### Q: "Timeout expired" 错误?

**A:** 增加超时时间或检查命令是否卡住:

```bash
# 调试模式查看详情
GS_DEBUG=1 gs <command>
```

## 开发相关

### Q: 如何调试插件?

**A:**

```bash
# 1. 启用调试模式
export GS_DEBUG=1

# 2. 查看详细日志
tail -f ~/.config/global-scripts/logs/gs.log

# 3. 使用print调试 (在Python插件中)
print(f"Debug: variable = {variable}")

# 4. 检查返回值
gs plugin info myplugin
```

### Q: Python导入错误?

**A:**

确保PYTHONPATH正确:

```bash
export PYTHONPATH="/path/to/global_scripts-v6:$PYTHONPATH"
```

或在插件中使用绝对导入:

```python
from gs_system.models import CommandResult
```

### Q: Shell脚本不执行?

**A:**

1. 检查shebang:
```bash
#!/usr/bin/env bash
```

2. 检查执行权限:
```bash
chmod +x script.sh
```

3. 检查Shell注解格式:
```bash
# @plugin_function
# name: function-name
# description: Description
```

## 系统相关

### Q: 如何卸载?

**A:**

1. 从Shell配置中移除:
```bash
# Bash用户编辑 ~/.bashrc
# Zsh用户编辑 ~/.zshrc
# Fish用户编辑 ~/.config/fish/config.fish
# 删除: source /path/to/global_scripts-v6/env.sh
```

2. 删除配置文件 (可选):
```bash
rm -rf ~/.config/global-scripts
```

3. 删除项目目录:
```bash
rm -rf /path/to/global_scripts-v6
```

### Q: 多个版本共存?

**A:** 使用不同的GS_ROOT:

```bash
# Version 5
export GS_ROOT="/path/to/global_scripts-v5"
source "$GS_ROOT/env.sh"

# Version 6
export GS_ROOT="/path/to/global_scripts-v6"
source "$GS_ROOT/env.sh"
```

### Q: 如何贡献代码?

**A:** 参考[贡献指南](./contributing.md)

## 更多帮助

### 获取社区支持

- GitHub Issues: 提交bug或功能请求
- 讨论区: 参与社区讨论
- 文档: 查看完整文档

### 报告Bug

提交Issue时请包含:

1. 系统信息: `gs doctor`
2. 错误日志: `~/.config/global-scripts/logs/gs.log`
3. 复现步骤
4. 预期行为vs实际行为

### 请求功能

清晰描述:

1. 使用场景
2. 期望功能
3. 可选的实现方案

---

**找不到答案?**

- 查看[完整文档](./README.md)
- 提交[GitHub Issue](https://github.com/i-rtfsc/global_scripts/issues)
- 在讨论区提问
