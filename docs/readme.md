# Global Scripts - 文档中心

欢迎来到 Global Scripts 的文档中心！这里提供从快速入门到深入开发的完整文档。

[English Documentation](./en/readme-en.md)

## 📚 文档结构

### 快速开始

| 文档 | 描述 |
|------|------|
| [快速开始](./quickstart.md) | 5分钟快速上手指南 |
| [安装指南](./installation.md) | 详细的安装步骤和故障排除 |

### 用户文档

| 文档 | 描述 |
|------|------|
| [CLI命令参考](./cli-reference.md) | 完整的命令行参考 |
| [常见问题](./faq.md) | 问题排查指南 |

### 开发文档

| 文档 | 描述 |
|------|------|
| [插件开发](./plugin-development.md) | 从零开发插件 |
| [架构设计](./architecture.md) | 深入理解系统架构 |

### 项目文档

| 文档 | 描述 |
|------|------|
| [贡献指南](./contributing.md) | 如何贡献代码 |
| [更新日志](./changelog.md) | 版本历史 |
| [GS 6.0 迁移状态](./gs6-migration-status.md) | GS6 迁移、隔离和验收状态 |

### 高级主题

| 文档 | 描述 |
|------|------|
| [系统依赖说明](./advanced/dependencies.md) | 详细的依赖要求和安装 |
| [Shell直接执行](./advanced/shell-direct-execution.md) | 核心特性：Shell命令直接执行 |
| [UV使用指南](./advanced/uv-guide.md) | UV包管理器完整指南 |
| [自定义解析器](./advanced/extensibility/custom-parsers.md) | 开发自定义解析器扩展 |
| [解析器示例](./advanced/examples/custom_parser/) | YAML解析器示例代码 |

## 🎯 按场景查找

### 我想安装和配置
- 首次使用？查看 [快速开始](./quickstart.md)
- 详细安装？查看 [安装指南](./installation.md)
- 遇到问题？查看 [常见问题](./faq.md)
- UV工具？查看 [UV使用指南](./advanced/uv-guide.md)

### 我想使用现有功能
- 基本用法？查看 [快速开始](./quickstart.md)
- 查看命令？查看 [CLI命令参考](./cli-reference.md)
- Android开发？使用 `gs android` 命令系列
- 系统管理？使用 `gs system` 命令系列

### 我想开发插件
- 入门开发？查看 [插件开发](./plugin-development.md)
- 理解架构？查看 [架构设计](./architecture.md)
- 参与贡献？查看 [贡献指南](./contributing.md)
- Shell特性？查看 [Shell直接执行](./advanced/shell-direct-execution.md)

### 我想扩展系统
- 自定义解析器？查看 [自定义解析器开发指南](./advanced/extensibility/custom-parsers.md)
- 查看示例？查看 [YAML解析器示例](./advanced/examples/custom_parser/)
- 了解依赖？查看 [系统依赖说明](./advanced/dependencies.md)

## 📂 文档目录

```
docs/
├── readme.md                            # 文档索引（本文件）
│
├── 快速开始
│   ├── quickstart.md                    # 快速开始
│   └── installation.md                  # 安装指南
│
├── 用户文档
│   ├── cli-reference.md                 # CLI命令参考
│   └── faq.md                           # 常见问题
│
├── 开发文档
│   ├── plugin-development.md            # 插件开发指南
│   └── architecture.md                  # 架构设计
│
├── 项目文档
│   ├── contributing.md                  # 贡献指南
│   └── changelog.md                     # 更新日志
│
├── advanced/                            # 高级主题
│   ├── dependencies.md                  # 系统依赖说明
│   ├── shell-direct-execution.md        # Shell直接执行特性
│   ├── uv-guide.md                      # UV使用指南
│   ├── extensibility/                   # 扩展性
│   │   └── custom-parsers.md            # 自定义解析器开发
│   └── examples/                        # 高级示例
│       └── custom_parser/               # YAML解析器示例
│
└── en/                                  # 英文文档
    ├── readme-en.md                     # 英文文档索引
    ├── quickstart-en.md                 # 英文快速开始
    └── installation-en.md               # 英文安装指南
```

## 📖 推荐阅读路径

### 新用户路径
1. [快速开始](./quickstart.md) - 了解基本概念和使用
2. [安装指南](./installation.md) - 完成系统安装
3. [CLI命令参考](./cli-reference.md) - 查看所有可用命令

### 开发者路径
1. [快速开始](./quickstart.md) - 了解系统概况
2. [架构设计](./architecture.md) - 理解系统架构
3. [插件开发](./plugin-development.md) - 开发自己的插件
4. [贡献指南](./contributing.md) - 参与项目贡献

### 高级用户路径
1. [Shell直接执行](./advanced/shell-direct-execution.md) - 理解核心特性
2. [系统依赖说明](./advanced/dependencies.md) - 深入了解依赖
3. [自定义解析器](./advanced/extensibility/custom-parsers.md) - 扩展系统功能
4. [UV使用指南](./advanced/uv-guide.md) - 精通包管理

## 📌 重要说明

### 安装方式
Global Scripts 使用 **UV** 作为包管理工具，这是唯一支持的安装方式。详见 [安装指南](./installation.md) 和 [UV使用指南](./advanced/uv-guide.md)。

### 命令验证
本文档中的所有命令示例均已通过实际执行验证，确保准确性。

### Shell直接执行
Global Scripts 的 Shell 插件可以直接执行 Shell 命令，不经过 Python 包装。这意味着 `cd`、`export` 等命令可以直接生效。详见 [Shell直接执行特性](./advanced/shell-direct-execution.md)。

## 🔗 外部资源

- [GitHub 仓库](https://github.com/i-rtfsc/global_scripts)
- [问题追踪](https://github.com/i-rtfsc/global_scripts/issues)
- [讨论区](https://github.com/i-rtfsc/global_scripts/discussions)

## 💬 获取帮助

遇到问题？以下资源可以帮助你：

1. 查看 [常见问题](./faq.md) 获取常见问题解答
2. 运行 `gs doctor` 检查系统健康状态
3. 在 GitHub 上提交 [Issue](https://github.com/i-rtfsc/global_scripts/issues)

## 📄 许可证

本项目采用 Apache License 2.0 许可证。详见项目根目录的 [LICENSE](../LICENSE) 文件。

---

**开始使用**: [快速开始](./quickstart.md) | **English**: [Documentation Index](./en/readme-en.md)
