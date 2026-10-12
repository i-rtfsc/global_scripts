# 更新日志

All notable changes to Global Scripts will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [6.0.0] - 开发中

GS 6.0 是 Rust 前门 + `plugin.toml` 协议的一次重写。5.x 的条目保留在下方作为历史。

### Added

- **Rust 前门**（`rust/crates/gs`）与前门命令：`version` / `help` / `status` /
  `doctor` / `refresh` / `init` / `plugin …` / `completions` / `shell-init`。
- **`plugin.toml` 协议**：单一事实来源的命令树、参数、补全规则与能力声明，
  规范见 [docs/protocol.md](./protocol.md)。
- **分层（tier）**：T1 声明式（零进程）、T2 脚本、T3 常驻 daemon、T4 wasm。
- **能力模型**：`[capabilities]` 默认拒绝，`exec`/`env` 由核心强制。
- **原生补全**：无 jq、无 Python 的全链路 Tab 补全（含描述与 directive）。
- **`gs init`**：读 `config/init.toml` 的装机步骤清单，区分就绪 / 需要 sudo /
  尚未创建；需要 root 的步骤只打印命令。
- **插件迁移工具**：`gs plugin migrate` 把旧 `plugin.json` 转成 `plugin.toml`。
- 表格化 UI（`tabled`）、颜色（`anstyle`）、进度（`indicatif`），无 emoji。

### Changed

- 正式插件统一为 `plugin.toml`；每个插件只有一份实现。
- `gs doctor` 新增插件运行时检查：解释器不在 `PATH` 时不再报“通过”。
- `GS_ALLOW_LEGACY` 更名为 `GS_ALLOW_EXTERNAL_PLUGINS`。

### Removed

- **5.2 Python 实现整体退役**：`src/gscripts/`、`tests/`、`scripts/setup.py`、
  `scripts/audit_command_parity.py`、`pyproject.toml`、`pytest.ini`。
- 各插件的 `plugin.json` / 旧 `plugin.py` / `plugin.sh` / `commands.json`，
  以及 `plugins/menubar/`。
- 前门里的 `router.json` 派发路径与 Python 兜底（`delegate_python`）。
  未知命令现在明确报错，不再静默调用另一个解释器。
- 对 `jq` 与 `uv` 的运行时依赖。决策见
  [ADR 005](./adr/005-retire-gs52-python-runtime.md)。

### Fixed

- fish 集成不再把 `cd` 静默改写成 `zoxide z`，也不再有硬编码的 Homebrew 路径。
- zsh 集成不再用 `alias gs='git status'` 抢占产品名。
- 源码检出不再无条件读取用户已安装的插件（`$GS_ROOT` 默认隔离）。

## [5.0.0]

### Added

#### Core Features
- **Unified Data Models**: Type-safe dataclass-based structures (`CommandResult`, `PluginMetadata`, `FunctionInfo`)
- **Dependency Injection**: Complete DI container implementation for better modularity
- **Smart Caching**: LRU cache for plugin configurations with 72% hit rate
- **Process Executor**: Unified command execution with timeout and security controls
- **Four Plugin Types**: Python, Shell, Config, and Hybrid plugin support
- **Dynamic Completion**: jq-based real-time command completion system
- **Async First**: asyncio-based execution engine for high performance
- **Template Engine**: Jinja2-based template rendering for env scripts and completion files
- **System Config Loader**: YAML-based system configuration with dataclass validation

#### Plugin System
- Python plugin support with `@plugin_function` decorator
- Shell plugin with annotation-based function discovery
- Config plugin for simple command wrapping
- Hybrid plugin for mixed implementation strategies
- Subplugin architecture for better organization
- Plugin enable/disable functionality
- Plugin discovery from `plugins/`, `custom/`, and `examples/` directories

#### CLI Enhancements
- New command structure: `gs <plugin> <subplugin> <command>`
- `gs doctor` - System health check command
- `gs refresh` - Rebuild plugins and completion
- `gs plugin list/info/enable/disable` - Plugin management commands
- `gs system config get/set/list` - Configuration management
- Multi-language support (Chinese/English)
- Improved error messages with suggestions

#### Documentation
- Comprehensive README with badges and examples
- Architecture documentation with detailed diagrams
- Plugin development guide with all plugin types
- Quick start guide (5-minute tutorial)
- Installation guide with multiple methods
- FAQ with troubleshooting steps
- Contributing guide with development setup
- API reference documentation
- Bilingual documentation (Chinese/English)

#### Development Tools
- UV project management support
- Pre-commit hooks configuration
- pytest with async support
- Black code formatting
- Ruff linting
- MyPy type checking
- 80%+ type annotation coverage

### Changed

- **Breaking**: Restructured from `gs_system` to `src/gscripts` package
- **Breaking**: New command format requires `gs <plugin> <subplugin> <command>`
- **Breaking**: Configuration format updated with `system_plugins` and `custom_plugins`
- Improved plugin loader with parser registry system
- Enhanced router indexer with version 2.0 format
- Better error handling with specific exception types
- Optimized plugin loading with async operations

### Improved

- **Performance**: Plugin loading 34% faster (100 plugins < 3 seconds)
- **Code Quality**: Reduced duplicate code by 2,638+ lines (40% reduction) through template engine refactoring
- **Type Safety**: Increased type annotation coverage to 80%+
- **Caching**: Automatic caching reduces I/O overhead by 30%
- **Security**: Enhanced command validation and timeout controls
- **Documentation**: Complete documentation system from basics to advanced
- **PEP 8 Compliance**: Full PEP 8 naming convention compliance (64 @property methods refactored)
- **Template System**: Eliminated hardcoded string generation in setup.py (2317 → ~200 lines, 90% reduction)
- **Configuration**: Simplified system_config.yaml by removing 40% unused configuration items
- **Shell Completion**: Improved Fish shell completion with position-specific helper functions

### Fixed

- Plugin loading race conditions
- Configuration merge issues
- Shell completion edge cases (Fish plugin info completion bug)
- Import path resolution
- Async execution error handling
- Process timeout and cleanup
- Class-level constant access in GlobalConstants
- Missing exit codes (invalid_arguments, plugin_not_found) in system config

### Security

- Command whitelist enforcement
- Dangerous pattern blocking
- Shell argument escaping
- Process group management
- Timeout controls for all commands

## [4.x.x] - Previous Version

(Historical versions not documented here. See git history for details.)

## Upgrade Guide

### From 4.x to 5.0

#### Breaking Changes

1. **Package Name Change**:
   ```python
   # Old
   from gs_system.models import CommandResult

   # New
   from gscripts.models import CommandResult
   ```

2. **Command Format**:
   ```bash
   # Old
   gs android-device-list

   # New
   gs android device list
   ```

3. **Configuration Format**:
   ```json
   {
     "system_plugins": {
       "android": true
     },
     "custom_plugins": {}
   }
   ```

#### Migration Steps

1. Update imports in Python plugins
2. Update command calls in scripts
3. Migrate configuration to new format
4. Run `gs refresh` to rebuild completion
5. Test all custom plugins

See [Migration Guide](./migration-status.md) for detailed steps.

## Future Plans

### v5.1.0 (Planned)
- [ ] Plugin marketplace
- [ ] Web UI for plugin management
- [ ] Docker plugin
- [ ] Kubernetes plugin
- [ ] Enhanced logging with structured output

### v5.2.0 (Planned)
- [ ] Plugin versioning and dependencies
- [ ] Auto-update functionality
- [ ] Remote plugin installation
- [ ] Plugin sandboxing
- [ ] Performance profiling tools

### v6.0.0 (Future)
- [ ] gRPC-based plugin system
- [ ] Distributed execution
- [ ] Cloud integration
- [ ] AI-powered command suggestions

## Versioning Policy

- **Major** (X.0.0): Breaking changes, major features
- **Minor** (x.X.0): New features, backward compatible
- **Patch** (x.x.X): Bug fixes, backward compatible

## Support Policy

- **Current version (5.x)**: Full support, active development
- **Previous version (4.x)**: Bug fixes only for 6 months
- **Older versions**: Community support only

## Contributing

See [Contributing Guide](./contributing.md) for how to contribute to this project.

## Links

- [GitHub Repository](https://github.com/i-rtfsc/global_scripts)
- [Issue Tracker](https://github.com/i-rtfsc/global_scripts/issues)
- [Documentation](./readme.md)
- [Release Notes](https://github.com/i-rtfsc/global_scripts/releases)

---

**[Unreleased]**: https://github.com/i-rtfsc/global_scripts/compare/v5.0.0...HEAD
**[5.0.0]**: https://github.com/i-rtfsc/global_scripts/releases/tag/v5.0.0
