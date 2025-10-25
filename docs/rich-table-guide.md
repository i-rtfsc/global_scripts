# Rich Table 功能使用指南

本文档介绍 Global Scripts v5.0 中的 Rich Table 功能，提供美观的表格显示。

## 功能概述

Global Scripts 现已集成 [Rich](https://github.com/Textualize/rich) 库，提供：
- ✅ 更美观的表格显示（圆角边框、颜色高亮）
- ✅ 自适应屏幕宽度（表格自动填充终端宽度）
- ✅ 自动处理中文字符宽度
- ✅ 向后兼容（可回退到传统表格）

## 环境变量控制

### 启用/禁用 Rich Table

```bash
# 启用 Rich Table（默认）
export GS_USE_RICH=true

# 禁用 Rich Table（使用传统表格）
export GS_USE_RICH=false
```

## 基本使用

### 1. 插件列表显示

```bash
# Rich 表格显示
gs plugin list

# 使用传统表格
GS_USE_RICH=false gs plugin list
```

### 2. 插件详细信息

```bash
gs plugin info android
```

### 3. 系统状态

```bash
gs status
```

## 程序化使用

### 基本表格

```python
from gscripts.cli.formatters import OutputFormatter

# 创建格式化器（自动使用 Rich）
formatter = OutputFormatter(chinese=True)

# 打印表格
headers = ["插件名称", "状态", "类型"]
rows = [
    ["android", "启用", "系统"],
    ["system", "启用", "系统"],
]
formatter.print_table(headers, rows, title="插件列表")
```

## 高级使用

### 直接使用 RichTableFormatter

```python
from gscripts.utils.rich_table import RichTableFormatter

# 创建格式化器
formatter = RichTableFormatter(style='rounded')  # 可选: rounded, double, simple, minimal

# 创建表格
headers = ["列1", "列2", "列3"]
rows = [["数据1", "数据2", "数据3"]]

# 打印表格
formatter.print_table(headers, rows, title="我的表格")

# 或者获取字符串
table_str = formatter.draw_table(headers, rows, title="我的表格")
print(table_str)
```

### 在 Panel 中显示表格

```python
from gscripts.utils.rich_table import RichTableFormatter

formatter = RichTableFormatter()
headers = ["名称", "值"]
rows = [["配置1", "值1"], ["配置2", "值2"]]

formatter.print_table_with_panel(
    headers=headers,
    rows=rows,
    title="配置信息",
    subtitle="v1.0.0"
)
```

## 表格样式

Rich Table 支持多种边框样式：

```python
from gscripts.utils.rich_table import RichTableFormatter

# 圆角边框（默认，推荐）
formatter = RichTableFormatter(style='rounded')

# 双线边框
formatter = RichTableFormatter(style='double')

# 简单边框
formatter = RichTableFormatter(style='simple')

# 最小边框
formatter = RichTableFormatter(style='minimal')
```

## 兼容性说明

- **自动降级**: 如果 Rich 库不可用，系统会自动回退到传统表格
- **环境变量**: 可通过 `GS_USE_RICH=false` 强制禁用 Rich
- **向后兼容**: 所有现有代码无需修改即可使用新功能

## 性能建议

- **小数据集**: 直接使用 `print_table()`
- **大数据集**: 考虑分页显示

### 自适应宽度

所有表格默认会自动扩展到终端宽度：
- 表格会填充整个终端宽度（`expand=True`）
- 如果内容过长，会自动换行或截断（带省略号）
- 建议保持列数在 3-8 个之间，以获得最佳显示效果
- 中文字符会被正确计算宽度（占 2 个字符位）

## 示例输出

### 基本表格
```
                            插件列表
╭──────────┬──────┬────────┬───────┬────────┬──────────────────╮
│ 插件名称 │ 状态 │ 类型   │ 版本  │ 命令数 │ 描述             │
├──────────┼──────┼────────┼───────┼────────┼──────────────────┤
│ android  │ 启用 │ 系统   │ 1.0.0 │ 15     │ Android 开发工具 │
│ system   │ 启用 │ 系统   │ 1.0.0 │ 8      │ 系统管理工具     │
╰──────────┴──────┴────────┴───────┴────────┴──────────────────╯
```

## 故障排除

### Rich 未安装

```bash
# 重新同步依赖
uv sync
```

### 强制使用传统表格

```bash
export GS_USE_RICH=false
gs plugin list
```

### 颜色显示异常

某些终端可能不支持 ANSI 颜色，可以禁用：

```bash
export NO_COLOR=1
gs plugin list
```

## 相关文件

- `src/gscripts/utils/rich_table.py` - Rich Table 核心实现
- `src/gscripts/cli/formatters.py` - 输出格式化器集成
- `test_rich_tables.py` - 测试脚本
- `pyproject.toml` - 依赖配置

## 参考资料

- [Rich 官方文档](https://rich.readthedocs.io/)
- [Rich GitHub](https://github.com/Textualize/rich)
- [Global Scripts 文档](./docs/)
