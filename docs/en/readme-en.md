# Global Scripts - Documentation Center

[中文文档](../readme.md) | English

Welcome to the Global Scripts documentation center! This provides complete documentation from quick start to in-depth development.

## 📚 Documentation Structure

### Getting Started

| Document | Description |
|----------|-------------|
| [Quick Start](./quickstart-en.md) | 5-minute quick start guide |
| [Installation](./installation-en.md) | Detailed installation steps and troubleshooting |

### User Documentation

| Document | Description |
|----------|-------------|
| [CLI Reference](./cli-reference-en.md) | Complete command-line reference |
| [FAQ](./faq-en.md) | Troubleshooting guide |

### Developer Documentation

| Document | Description |
|----------|-------------|
| [Plugin Development](./plugin-development-en.md) | Build plugins from scratch |
| [Architecture Design](./architecture-en.md) | Deep dive into system architecture |

### Project Documentation

| Document | Description |
|----------|-------------|
| [Contributing Guide](./contributing-en.md) | How to contribute code |
| [Changelog](../changelog.md) | Version history |

### Advanced Topics

| Document | Description |
|----------|-------------|
| [System Dependencies](./advanced/dependencies-en.md) | Detailed dependency requirements and installation |
| [Shell Direct Execution](./advanced/shell-direct-execution-en.md) | Core feature: Direct shell command execution |
| [UV Guide](./advanced/uv-guide-en.md) | Complete UV package manager guide |
| [Custom Parsers](../advanced/extensibility/custom-parsers.md) | Develop custom parser extensions |
| [Parser Examples](../advanced/examples/custom_parser/) | YAML parser example code |

## 🎯 Find by Scenario

### I want to install and configure
- First time user? See [Quick Start](./quickstart-en.md)
- Detailed installation? See [Installation Guide](./installation-en.md)
- Encountered issues? See [FAQ](./faq-en.md)
- UV tool? See [UV Guide](./advanced/uv-guide-en.md)

### I want to use existing features
- Basic usage? See [Quick Start](./quickstart-en.md)
- View commands? See [CLI Reference](./cli-reference-en.md)
- Android development? Use `gs android` command series
- System management? Use `gs system` command series

### I want to develop plugins
- Getting started? See [Plugin Development](./plugin-development-en.md)
- Understand architecture? See [Architecture Design](./architecture-en.md)
- Contribute to project? See [Contributing Guide](./contributing-en.md)
- Shell features? See [Shell Direct Execution](./advanced/shell-direct-execution-en.md)

### I want to extend the system
- Custom parsers? See [Custom Parser Development Guide](../advanced/extensibility/custom-parsers.md)
- View examples? See [YAML Parser Example](../advanced/examples/custom_parser/)
- Understand dependencies? See [System Dependencies](./advanced/dependencies-en.md)

## 📂 Documentation Directory

```
docs/
├── readme.md                            # Chinese documentation index
│
├── Getting Started
│   ├── quickstart.md                    # Quick start (Chinese)
│   └── installation.md                  # Installation guide (Chinese)
│
├── User Documentation
│   ├── cli-reference.md                 # CLI reference
│   └── faq.md                           # FAQ
│
├── Developer Documentation
│   ├── plugin-development.md            # Plugin development guide
│   └── architecture.md                  # Architecture design
│
├── Project Documentation
│   ├── contributing.md                  # Contributing guide
│   └── changelog.md                     # Changelog
│
├── advanced/                            # Advanced Topics
│   ├── dependencies.md                  # System dependencies
│   ├── shell-direct-execution.md        # Shell direct execution feature
│   ├── uv-guide.md                      # UV guide
│   ├── extensibility/                   # Extensibility
│   │   └── custom-parsers.md            # Custom parser development
│   └── examples/                        # Advanced examples
│       └── custom_parser/               # YAML parser example
│
└── en/                                  # English Documentation
    ├── readme-en.md                     # English documentation index (this file)
    ├── quickstart-en.md                 # Quick start (English)
    └── installation-en.md               # Installation guide (English)
```

## 📖 Recommended Reading Path

### New User Path
1. [Quick Start](./quickstart-en.md) - Understand basic concepts and usage
2. [Installation Guide](./installation-en.md) - Complete system installation
3. [CLI Reference](./cli-reference-en.md) - View all available commands

### Developer Path
1. [Quick Start](./quickstart-en.md) - Understand system overview
2. [Architecture Design](./architecture-en.md) - Understand system architecture
3. [Plugin Development](./plugin-development-en.md) - Develop your own plugins
4. [Contributing Guide](./contributing-en.md) - Contribute to the project

### Advanced User Path
1. [Shell Direct Execution](./advanced/shell-direct-execution-en.md) - Understand core features
2. [System Dependencies](./advanced/dependencies-en.md) - Deep dive into dependencies
3. [Custom Parsers](../advanced/extensibility/custom-parsers.md) - Extend system functionality
4. [UV Guide](./advanced/uv-guide-en.md) - Master package management

## 📌 Important Notes

### Installation Method
Global Scripts uses **UV** as the package manager. This is the only supported installation method. See [Installation Guide](./installation-en.md) and [UV Guide](./advanced/uv-guide-en.md) for details.

### Command Verification
All command examples in this documentation have been verified through actual execution to ensure accuracy.

### Shell Direct Execution
Global Scripts' Shell plugins can execute shell commands directly without Python wrapping. This means `cd`, `export`, and other commands work directly. See [Shell Direct Execution Feature](./advanced/shell-direct-execution-en.md) for details.

## 🔗 External Resources

- [GitHub Repository](https://github.com/i-rtfsc/global_scripts)
- [Issue Tracker](https://github.com/i-rtfsc/global_scripts/issues)
- [Discussions](https://github.com/i-rtfsc/global_scripts/discussions)

## 💬 Get Help

Need help? Here are some resources:

1. Check [FAQ](./faq-en.md) for common questions and solutions
2. Run `gs doctor` to check system health status
3. Submit an [Issue](https://github.com/i-rtfsc/global_scripts/issues) on GitHub

## 📄 License

This project is licensed under Apache License 2.0. See [LICENSE](../../LICENSE) file in the project root directory.

---

**Get Started**: [Quick Start](./quickstart-en.md) | **中文**: [文档索引](../readme.md)
