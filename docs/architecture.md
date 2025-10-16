# 架构设计

Global Scripts 的系统架构详解。

## 系统概览

```
┌─────────────────────────────────────────────────────────────┐
│                        CLI Layer                            │
│  ┌──────────────┐  ┌───────────────┐  ┌──────────────────┐  │
│  │  main.py     │  │ commands.py   │  │ formatters.py    │  │
│  └──────────────┘  └───────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│                        Core Layer                           │
│  ┌──────────────┐  ┌───────────────┐  ┌──────────────────┐  │
│  │ Plugin       │  │ Config        │  │ Command          │  │
│  │ Manager      │  │ Manager       │  │ Executor         │  │
│  └──────────────┘  └───────────────┘  └──────────────────┘  │
│  ┌──────────────┐  ┌───────────────┐  ┌──────────────────┐  │
│  │ Plugin       │  │ Router        │  │ Logger           │  │
│  │ Loader       │  │ Indexer       │  │                  │  │
│  └──────────────┘  └───────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│                       Models Layer                          │
│  ┌──────────────┐  ┌───────────────┐  ┌──────────────────┐  │
│  │ CommandResult│  │ PluginMetadata│  │ FunctionInfo     │  │
│  └──────────────┘  └───────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│                      Plugin Layer                           │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌──────────────┐    │
│  │ Python  │  │  Shell  │  │ Config  │  │   Hybrid     │    │
│  │ Plugins │  │ Plugins │  │ Plugins │  │   Plugins    │    │
│  └─────────┘  └─────────┘  └─────────┘  └──────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## 核心组件

### 1. CLI 层 (`src/gscripts/cli/`)

#### main.py
- **职责**: CLI入口点,参数解析
- **关键类**: `GlobalScriptsCLI`
- **工作流程**:
  1. 初始化配置和插件管理器
  2. 解析命令行参数
  3. 路由到对应的处理器
  4. 格式化并输出结果

#### commands.py
- **职责**: 命令处理逻辑
- **关键类**: `CommandHandler`
- **支持的命令类型**:
  - 系统命令 (`help`, `version`, `status`)
  - 插件管理命令 (`plugin list/info/enable/disable`)
  - 插件函数命令 (`<plugin> <subplugin> <function>`)

#### formatters.py
- **职责**: 输出格式化
- **关键类**: `OutputFormatter`
- **功能**:
  - 表格格式化(支持中文字符宽度计算)
  - 多语言输出
  - 颜色高亮

### 2. Core 层 (`src/gscripts/core/`)

#### plugin_manager.py
- **职责**: 插件生命周期管理
- **关键功能**:
  - 插件加载与卸载
  - 插件启用/禁用
  - 函数执行调度
  - 健康检查

**主要方法**:
```python
async def initialize()  # 初始化插件系统
async def load_all_plugins()  # 加载所有插件
async def execute_plugin_function()  # 执行插件函数
def enable_plugin()  # 启用插件
def disable_plugin()  # 禁用插件
```

#### plugin_loader.py
- **职责**: 插件发现与解析
- **关键功能**:
  - 扫描插件目录
  - 解析plugin.json
  - 解析Python装饰器
  - 解析Shell注解
  - 构建函数索引

**插件类型识别**:
1. Python插件: 包含`plugin.py`,使用`@plugin_function`装饰器
2. Shell插件: 包含`.sh`文件,使用Shell注解
3. Config插件: 仅`plugin.json`,包含`commands`字段
4. Hybrid插件: 混合使用以上类型

#### config_manager.py
- **职责**: 配置管理
- **配置优先级**:
  1. 用户配置 (`~/.config/global-scripts/config/gs.json`)
  2. 项目配置 (`./config/gs.json`)
  3. 默认配置

**配置结构**:
```json
{
  "system_plugins": {
    "android": true,
    "gerrit": false
  },
  "custom_plugins": {
    "myplugin": true
  },
  "logging_level": "INFO",
  "language": "zh",
  "show_examples": false
}
```

#### command_executor.py
- **职责**: 安全的命令执行
- **安全机制**:
  - 命令白名单检查
  - 危险命令黑名单
  - 超时控制
  - 进程组管理
- **并发控制**: 信号量限制并发数

#### router/indexer.py
- **职责**: 构建命令路由索引
- **索引结构**:
```json
{
  "version": "2.0",
  "plugins": {
    "plugin_name": {
      "commands": {
        "command_key": {
          "kind": "shell|json|python",
          "entry": "/path/to/file",
          "command": "template"
        }
      }
    }
  }
}
```

### 3. Models 层 (`src/gscripts/models/`)

统一的数据结构定义,提升类型安全性。

#### result.py
```python
@dataclass
class CommandResult:
    success: bool
    output: str
    error: str
    exit_code: int
    execution_time: float
    metadata: Dict[str, Any]
```

#### plugin.py
```python
@dataclass
class PluginMetadata:
    name: str
    version: str
    author: str
    description: Union[str, Dict[str, str]]
    enabled: bool
    ...

class PluginType(Enum):
    PYTHON = "python"
    SHELL = "shell"
    CONFIG = "config"
    HYBRID = "hybrid"
```

#### function.py
```python
@dataclass
class FunctionInfo:
    name: str
    description: Union[str, Dict[str, str]]
    type: FunctionType
    command: Optional[str]
    python_file: Optional[Path]
    ...
```

### 4. Plugin 层 (`src/gscripts/plugins/`)

#### base.py
- 插件基类 `BasePlugin`
- 子插件基类 `BaseSubPlugin`

#### decorators.py
- `@plugin_function`: 标记Python函数为插件命令
- `@subplugin`: 标记类为子插件

## 数据流程

### 命令执行流程

```
用户输入: gs android logcat clear
    │
    ├─> CLI解析参数: ['android', 'logcat', 'clear']
    │
    ├─> CommandHandler分发
    │   ├─ 识别为插件命令
    │   └─ 调用 plugin_manager.execute_plugin_function()
    │
    ├─> PluginManager执行
    │   ├─ 查找插件: 'android'
    │   ├─ 查找函数: 'logcat-clear'
    │   ├─ 确定类型: shell|python|config
    │   └─ 调用对应执行器
    │
    ├─> 执行器运行
    │   ├─ 安全检查 (CommandExecutor)
    │   ├─ 执行命令/函数
    │   └─ 返回 CommandResult
    │
    └─> 输出格式化
        ├─ OutputFormatter格式化
        ├─ 应用多语言
        └─ 终端显示
```

### 插件加载流程

```
系统启动
    │
    ├─> PluginManager.initialize()
    │
    ├─> PluginLoader.load_all_plugins()
    │   ├─ 扫描 plugins/ 目录
    │   ├─ 扫描 custom/ 目录
    │   ├─ (可选) 扫描 examples/ 目录
    │   │
    │   └─ 对每个插件目录:
    │       ├─ 读取 plugin.json
    │       ├─ 创建 PluginMetadata
    │       ├─ 扫描函数:
    │       │   ├─ Python函数 (装饰器)
    │       │   ├─ Shell函数 (注解)
    │       │   └─ Config函数 (JSON)
    │       └─ 创建 SimplePlugin 对象
    │
    ├─> 加载插件启用状态 (从config)
    │
    └─> 生成 Router Index (用于shell分发)
```

## 配置系统

### 配置加载优先级

```
1. 用户配置 (~/.config/global-scripts/config/gs.json)
   │
   ├─ 存在 → 作为覆盖层
   │
2. 项目配置 (./config/gs.json)
   │
   ├─ 存在 → 作为基础层
   │
3. 默认配置 (代码生成)
   │
   └─ 作为回退
```

### 配置合并规则

- `system_plugins` / `custom_plugins`: 键级合并
- 其他字段: 用户配置覆盖项目配置
- 自动清理不存在的插件条目

## 安全模型

### 命令执行安全

1. **白名单机制**
   - `GlobalConstants.SAFE_COMMANDS` 定义允许的命令
   - 只有白名单中的命令才能执行

2. **黑名单机制**
   - `GlobalConstants.DANGEROUS_COMMANDS` 危险命令列表
   - `GlobalConstants.FORBIDDEN_PATTERNS` 危险模式
   - 正则匹配拦截危险操作

3. **超时控制**
   - 默认30秒超时
   - 可通过配置调整
   - 超时自动终止进程组

4. **参数转义**
   - 使用`shlex.quote`转义所有参数
   - 防止命令注入攻击

### 进程管理

- 使用`os.setsid`创建新进程组
- 超时时终止整个进程组
- SIGTERM + SIGKILL两级终止

## 扩展点

### 如何添加新的插件类型

1. 在`models/plugin.py`中添加新的`PluginType`
2. 在`plugin_loader.py`中添加扫描逻辑
3. 在`plugin_manager.py`中添加执行逻辑
4. 更新`router/indexer.py`以支持路由

### 如何添加新的系统命令

1. 在`cli/commands.py`的`CommandHandler`中添加处理方法
2. 在`config/i18n.json`中添加多语言描述
3. 更新补全脚本生成逻辑

## 性能优化

### 当前优化
- 异步I/O(asyncio)
- 并发执行(Semaphore)
- 延迟加载(插件按需加载)

### 计划优化
- ✅ 统一数据结构(减少Dict[str, Any])
- ⏳ 插件配置缓存(`@lru_cache`)
- ⏳ 并发插件加载
- ⏳ ProcessExecutor复用

## 设计原则

1. **单一职责**: 每个模块职责明确
2. **依赖注入**: 通过构造函数注入依赖
3. **接口隔离**: 使用抽象基类定义接口
4. **开闭原则**: 对扩展开放,对修改关闭
5. **类型安全**: 使用dataclass和类型注解

## 技术栈

- **语言**: Python 3.7+
- **异步**: asyncio
- **类型**: typing, dataclasses
- **配置**: JSON
- **日志**: logging (自定义格式)
- **Shell**: Bash/Zsh 补全

## 下一步阅读

- [插件开发指南](./plugin-development.md) - 如何开发插件
- [API文档](./api-reference.md) - 详细的API说明
- [数据结构](./data-structures.md) - 数据结构详解
