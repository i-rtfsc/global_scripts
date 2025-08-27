## Global Scripts V3 使用与开发指南（Shell 插件工程）

本指南面向使用者与二次开发者，梳理 Global Scripts V3 的工程结构、启动与加载流程、插件与系统命令规范、日志与平台兼容性、环境变量配置，以及快速上手与开发实践。

---

### 1. 简介
- Global Scripts V3 是一个基于 Bash/Zsh 的插件化脚本框架。
- 通过“.meta + 自动函数检测”的架构，自动发现并加载插件/系统命令，并将符合约定的函数注册为命令。
- 强调跨平台与跨 Shell 版本兼容（macOS/Linux、Bash 3+/Zsh）。

---

### 2. 目录结构总览（节选）
- bin/、tools/：脚手架与模板等工具
- core/：核心模块（日志、平台兼容、插件检测、命令注册、缓存、系统命令加载）
- lib/：基础库（常量保护、轻量 KV 存储等）
- plugins/：用户插件（git、system、utils、android、repo、config、spider、weather 等）
- system/：系统命令集合（help、plugins、status、theme、version 等）
- themes/：提示符主题（prompt）
- docs/：文档（需求、架构、部署、测试等）
- gs_env.sh：框架主入口（环境初始化与加载）

---

### 3. 快速开始（使用）
1) 在当前 Shell 会话中加载框架：
- 建议在 ~/.zshrc 或 ~/.bashrc 中添加如下行：
  - source /path/to/global_scripts-augment/gs_env.sh
- 也可在项目根目录临时执行：
  - source ./gs_env.sh

2) 可选：开启调试模式与日志彩色输出：
- export GS_DEBUG_MODE=true
- export GS_LOG_COLOR=auto  # or always/never

3) 运行示例命令（根据已加载的插件/系统命令而定）：
- gs-system-info
- gs-system-status --detailed
- gs-git-status-enhanced --files --remote

提示：命令均以“gs-”为前缀，来源于函数自动注册（详见第 6 章）。

---

### 4. 启动与加载流程（gs_env.sh）
整体流程：
1) 加载 lib/base.sh（常量保护、基础工具）
2) 启动 core/logger.sh 并初始化日志（文件 logs/gs.log，颜色与等级可配）
3) 基础检查：必需文件、环境与常用命令（grep/awk/sed/find/cat/date）
4) 加载核心模块 core/：
   - platform_compat.sh：Shell/OS 检测、工具别名(_GS_GREP_CMD/SED/AWK)
   - plugin_detector.sh：扫描 plugins/ 下主插件（.meta）并加载
   - command_registry.sh：将新函数注册为命令（别名）
   - cache_manager.sh：缓存系统（如存在）
   - system_loader.sh：扫描 system/ 下系统命令并加载
5) 初始化组件：
   - 兼容性检查与数据结构初始化（关联数组或兼容模拟）
   - 按顺序加载系统命令与插件（支持优先级）
   - 初始化缓存（如存在）
6) 加载提示符主题 themes/prompt（可配 gs_themes_prompt）
7) 输出启动摘要（调试模式下显示统计与提示）

---

### 5. 核心模块要点
- lib/base.sh
  - 常量保护：_gs_set_constant/_gs_get_constant/_gs_is_constant
  - 轻量 KV：_gs_base_set/_gs_base_get
  - Shell 基本检测：_gs_detect_shell_basic
- core/platform_compat.sh
  - 检测 Shell 类型与版本，决定是否使用关联数组
  - 选择工具别名（macOS 优先 ggrep/gsed/gawk）并暴露 _GS_GREP_CMD/_GS_SED_CMD/_GS_AWK_CMD
  - 统一时间戳获取 _gs_get_timestamp_ms
  - 统一“映射”操作 _gs_map_set/_gs_map_get/_gs_map_keys/_gs_map_unset/_gs_map_count
- core/logger.sh
  - 等级：TRACE/DEBUG/INFO/WARN/ERROR/FATAL
  - 颜色：auto/always/never，可写入日志文件（默认 logs/gs.log）
  - 便捷函数：_gs_debug/_gs_info/_gs_warn/_gs_error/_gs_fatal
- core/plugin_detector.sh
  - 在 plugins/ 下发现含 .meta 且 PLUGIN_TYPE=main 的目录
  - 加载主文件 <plugin>/<plugin>.sh，然后按 SUBMODULES= 逐个加载子模块
  - 调用 _gs_register_plugin_functions 仅注册新增的公开函数
- core/system_loader.sh
  - 在 system/ 下发现 .meta 且 COMMAND_TYPE=system 的目录
  - 加载 <cmd>/<cmd>.sh 并调用 _gs_register_system_functions 注册新增函数
- core/command_registry.sh
  - 自动将函数注册为命令：
    - 插件函数匹配：gs_<plugin> 或 gs_<plugin>_<name>
    - 系统函数匹配：gs_system_<name> 或 gs_system_<name>_<sub>
    - 命令名转换：前缀 gs_ -> gs-，下划线 _ -> 连字符 -
      例如：gs_git_status_enhanced -> gs-git-status-enhanced
  - 避免重复注册；在 Shell 中创建同名函数作为命令入口

---

### 6. 插件（plugins/）与 .meta 规范
- 主插件目录结构（示例：plugins/git）：
  - git.meta（必需）
  - git.sh（必需）
  - 子模块目录（可选）：branch/、commit/、remote/ ...

- 主插件 .meta 必需字段：
  - PLUGIN_TYPE=main
  - NAME=<插件名>
  - VERSION=<版本>
  - DESCRIPTION=<描述>
  可选字段：
  - PRIORITY=<数字，越小越先加载，默认 99>
  - SUBMODULES=moduleA,moduleB
  - SYSTEM_DEPS=git,curl  # 依赖的系统命令
  - PLUGIN_DEPS=utils     # 依赖其它已加载插件

- 子模块：
  - 若 SUBMODULES=branch,commit，则加载 plugins/git/branch/branch.sh 与 plugins/git/commit/commit.sh
  - 子模块 .meta 非强制；加载成功与否会打印调试信息。

- 公开函数命名（自动注册为命令）：
  - gs_<plugin> 或 gs_<plugin>_<something>
  - 请勿以下划线前缀（_gs_）作为公开函数名

- 插件自检（可选）：
  - 定义 _gs_<plugin>_selfcheck；若返回非 0，日志会给出警告

---

### 7. 系统命令（system/）与 .meta 规范
- 目录结构（示例）：system/version、system/status、system/help、...
  - 每个系统命令目录需包含：<name>.meta 与 <name>.sh

- .meta 必需字段：
  - COMMAND_TYPE=system
  - NAME=<命令名>
  - VERSION=<版本>
  - DESCRIPTION=<描述>
  可选字段：
  - PRIORITY=<数字，越小越先加载，默认 99>
  - SYSTEM_DEPS=curl,jq

- 公开函数命名（自动注册为命令）：
  - gs_system_<name> 或 gs_system_<name>_<sub>
  - 最终命令名将变为 gs-<name> 或 gs-<name>-<sub>

---

### 8. 命令注册与命名转换规则
- 匹配范围仅限于“加载前快照”与“加载后函数列表”的差集，即“新增的公开函数”。
- 函数到命令的转换：
  - 前缀：gs_ -> gs-
  - 前缀：gs_system_ -> gs-
  - 下划线 _ -> 连字符 -
- 命令来源会记录在注册表中，可用于溯源与禁用（内部函数）。

---

### 9. 日志系统
- 默认日志文件：logs/gs.log（自动创建目录与轮转）
- 等级控制：
  - 环境变量：GS_LOG_LEVEL（数字 0~5），GS_LOG_CONSOLE_LEVEL，GS_LOG_FILE_LEVEL
  - 编程接口：_gs_set_log_level TRACE|DEBUG|INFO|WARN|ERROR|FATAL
- 彩色输出：
  - GS_LOG_COLOR=auto|always|never
- 查看状态（开发期）：_gs_log_status（内部函数）

---

### 10. 兼容性与平台适配
- Shell：自动检测 bash/zsh 及版本，决定是否使用关联数组。
- 工具别名：在 macOS 上优先 ggrep/gsed/gawk；在 Linux 上使用 grep/sed/awk。
- 插件/系统命令读取/匹配 .meta 或进行文本处理时，建议优先使用 _GS_GREP_CMD/_GS_SED_CMD/_GS_AWK_CMD。
- 时间戳：统一通过 _gs_get_timestamp_ms 获取（自动择优）。

---

### 11. 配置与环境变量（常用）
- GS_DEBUG_MODE=true|false  # 是否输出调试日志
- GS_FORCE_RELOAD=true|false  # 是否允许重复加载模块（开发调试用）
- GS_LOG_COLOR=auto|always|never  # 日志彩色输出策略
- GS_LOG_FILE=...  # 自定义日志文件路径
- gs_themes_prompt=tech-dev  # 提示符主题名（themes/prompt 下）

框架导出的路径常量（只读语义）：
- GS_ROOT、GS_CORE_DIR、GS_SYSTEM_DIR、GS_PLUGINS_DIR、GS_3RD_PLUGINS_DIR、GS_CONFIG_DIR、GS_TOOLS_DIR、GS_TESTS_DIR

---

### 12. 主题（themes/prompt）
- 在 gs_env.sh 的启动流程中按 gs_themes_prompt 加载主题（默认 tech-dev）。
- 若未找到指定主题，将回退到默认；若默认也不存在则跳过并给出错误日志。

---

### 13. 示例：Git 插件（plugins/git）
- 提供命令：
  - gs-git-status-enhanced [--files] [--remote] [--compact]
  - gs-git-log-pretty [--oneline|--compact|--graph] [--count N] [--since ...] [--author ...] [--grep ...]
  - gs-git-commit-quick -m "msg" [--all] [--amend] [--no-verify]
- 内部辅助检查：
  - _gs_git_check_git（依赖 git），_gs_git_check_repo（必须在 git 仓库内）
- 公开函数以 gs_git_ 前缀定义，自动注册为 gs-git-* 命令。

---

### 14. 开发指南：创建你的第一个插件
1) 创建目录结构（以 mytool 为例）：
- plugins/mytool/
  - mytool.meta
  - mytool.sh
  - utils/（可选子模块）

2) 编写 mytool.meta（示例）：
- PLUGIN_TYPE=main
- NAME=mytool
- VERSION=1.0.0
- DESCRIPTION=示例插件
- PRIORITY=50
- SUBMODULES=utils
- SYSTEM_DEPS=curl

3) 编写 mytool.sh（关键点）：
- 定义公开函数：gs_mytool 或 gs_mytool_<name>
- 避免使用 _gs_ 前缀作为公开函数名（该前缀保留为内部函数）
- 若需要自检：实现 _gs_mytool_selfcheck，返回 0 表示通过

4) 可选子模块 utils/utils.sh：
- 当 SUBMODULES=utils 时，框架会尝试 source plugins/mytool/utils/utils.sh

5) 运行与验证：
- source ./gs_env.sh 使框架生效
- 直接调用命令：gs-mytool-...（根据你的函数名自动生成）
- 如命令不可用，检查：
  - .meta 是否存在且字段完整（PLUGIN_TYPE/NAME/VERSION/DESCRIPTION）
  - 函数命名是否符合规范（gs_mytool*）
  - 日志（logs/gs.log）与调试输出是否提示加载/注册问题

---

### 15. 故障排查 FAQ
- Q: 插件没被加载？
  - A: 确认目录下存在 <plugin>.meta 且包含 PLUGIN_TYPE=main；确认 <plugin>.sh 可被 source；检查 PRIORITY 和 SUBMODULES 的拼写；打开 GS_DEBUG_MODE 查看详细日志。
- Q: 命令没有注册出来？
  - A: 函数名需以 gs_<plugin> 或 gs_system_<name> 前缀；仅“新增函数”会被注册，确保函数在插件文件被 source 后才存在；函数名中下划线会被转换为连字符。
- Q: macOS 与 Linux 行为差异？
  - A: 使用 _GS_GREP_CMD/_GS_SED_CMD/_GS_AWK_CMD 进行文本处理；macOS 上优先 ggrep/gsed/gawk。
- Q: 如何查看所有命令？
  - A: 内部函数 _gs_list_all_commands 可用于开发阶段调试（区分 system/plugin）。

---

### 16. 版本与日志
- 框架版本读取自 ./VERSION
- 启动与运行日志默认位于 logs/gs.log（支持轮转，最大 10MB*10）

---

### 17. 建议的开发与测试实践
- 在新建或修改插件后，重新 source gs_env.sh 并开启 GS_DEBUG_MODE 观察加载与注册日志。
- 使用最小依赖的命令进行实现，并通过 SYSTEM_DEPS 明确声明关键依赖。
- 若编写自动化测试，可在 tests/ 目录中补充你的测试脚本，并在 CI 或本地通过 sh/bash/zsh 执行。

---

如需更多信息，可阅读以下核心文件以加深理解：
- lib/base.sh
- core/logger.sh
- core/platform_compat.sh
- core/plugin_detector.sh
- core/command_registry.sh
- core/system_loader.sh

