# Alias Plugin for Global Scripts v6

Shell 别名管理插件，为常用命令提供快捷别名，提高命令行操作效率。

## 功能特性

- **跨平台支持**：自动检测并加载适合当前平台（macOS/Linux）的别名配置
- **智能加载**：仅在交互式 Shell 中加载别名，不影响脚本执行
- **模块化设计**：将别名按用途和平台分离，便于维护
- **优先级控制**：支持多插件别名的优先级管理

## 目录结构

```
alias/
├── plugin.json         # 插件配置文件
├── README.md          # 本文档
├── common/            # 通用别名（所有平台）
│   └── aliases.sh     
├── darwin/            # macOS 特定别名
│   └── aliases.sh
└── linux/             # Linux 特定别名
    └── aliases.sh
```

## 配置说明

### plugin.json 配置

```json
{
  "name": "alias",
  "version": "1.0.0",
  "alias": {
    "interactive_only": true,  // 仅在交互式 shell 中加载
    "priority": 10,            // 加载优先级（数值越小越先加载）
    "shells": ["bash", "zsh"], // 支持的 shell 类型
    "sources": [               // 要加载的脚本文件（相对路径）
      "common/aliases.sh",
      "darwin/aliases.sh",
      "linux/aliases.sh"
    ]
  }
}
```

### 字段说明

- **interactive_only**: 默认为 `true`，表示仅在交互式 Shell 中加载别名
- **priority**: 控制多个插件的加载顺序，数值越小越先加载
- **shells**: 指定支持的 Shell 类型，目前支持 `bash` 和 `zsh`
- **sources**: 列出要加载的别名脚本文件，路径相对于插件根目录

## 已定义的别名

### 通用别名 (common/aliases.sh)

#### 文件操作
- `l`, `sl` - ls 的简写
- `..`, `...`, `....` - 快速返回上级目录
- `~` - 返回用户主目录
- `rm`, `cp`, `mv` - 带确认提示的安全操作

#### 系统管理
- `h` - 显示历史命令
- `hgrep` - 搜索历史命令
- `psa`, `psg` - 进程查看和搜索
- `dfh`, `duh` - 磁盘使用情况

#### Git 别名
- `gs` - git status
- `ga` - git add
- `gc` - git commit
- `gp` - git push
- `gl` - git log (图形化)
- `gd` - git diff
- `gb` - git branch
- `gco` - git checkout

#### Docker 别名
- `dps` - docker ps
- `dpsa` - docker ps -a
- `dim` - docker images
- `dex` - docker exec -it

#### 实用函数
- `mkcd` - 创建目录并进入
- `extract` - 智能解压任意格式的压缩文件

### macOS 特定别名 (darwin/aliases.sh)

#### 文件和目录
- `ls`, `ll`, `lh`, `la` - 带颜色的列表命令（使用 -G 选项）
- `finder` - 在 Finder 中打开当前目录
- `o`, `oo` - 使用默认程序打开文件/目录

#### 系统设置
- `showfiles`, `hidefiles` - 显示/隐藏隐藏文件
- `cleanupds` - 清理 .DS_Store 文件
- `showdesktop`, `hidedesktop` - 显示/隐藏桌面图标

#### Homebrew
- `brewup` - 更新和升级所有包
- `brewinfo`, `brewsearch`, `brewclean` - Homebrew 管理命令

#### 网络和系统
- `flushdns` - 清空 DNS 缓存
- `wifion`, `wifioff`, `wifirestart` - WiFi 控制
- `mute`, `unmute` - 音量控制
- `lock` - 快速锁屏

### Linux 特定别名 (linux/aliases.sh)

#### 文件和目录
- `ls`, `ll`, `lh`, `la` - 带颜色的列表命令（使用 --color=auto）
- `grep`, `fgrep`, `egrep` - 带颜色高亮的搜索

#### 包管理器
- APT (Debian/Ubuntu): `aptup`, `aptsearch`, `aptinstall`, `aptremove`, `aptclean`
- YUM/DNF (RHEL/CentOS/Fedora): `dnfup`, `yumup` 等
- Pacman (Arch Linux): `pacup`, `pacsearch`, `pacinstall` 等

#### Systemd 服务管理
- `sysstart`, `sysstop`, `sysrestart` - 服务控制
- `sysstatus`, `syslist` - 服务状态查看
- `sysenable`, `sysdisable` - 服务启用/禁用

#### 系统监控
- `meminfo` - 内存使用情况
- `psmem`, `pscpu` - 按内存/CPU 排序的进程列表
- `cpuinfo`, `hwinfo` - 硬件信息
- `jctl`, `jctlf` - journalctl 日志查看

## 从 v2 迁移

### 主要变化

1. **文件位置变更**
   - v2: `tmp/global_scripts-v2/plugins/alias/common/gs_alias_common.sh`
   - v6: 拆分为 `common/`, `darwin/`, `linux/` 三个目录

2. **加载机制变更**
   - v2: 单一文件，通过脚本内部判断平台
   - v6: 分离平台特定配置，由 env.sh 自动加载

3. **配置方式变更**
   - v2: 硬编码在脚本中
   - v6: 通过 plugin.json 配置，支持更灵活的控制

### 迁移步骤

1. 备份现有别名配置
2. 安装 Global Scripts v6
3. 别名会自动从新位置加载
4. 如需自定义，编辑对应平台的 aliases.sh 文件

## 自定义别名

### 添加通用别名

编辑 `common/aliases.sh`：
```bash
alias myalias='my command'
```

### 添加平台特定别名

- macOS: 编辑 `darwin/aliases.sh`
- Linux: 编辑 `linux/aliases.sh`

### 创建新的别名插件

1. 复制 alias 插件目录结构
2. 修改 plugin.json 中的名称和配置
3. 设置不同的优先级以控制加载顺序
4. 运行 `python3 setup.py` 重新生成 env.sh

## 故障排除

### 别名未生效

1. 确认在交互式 Shell 中：`echo $-`（应包含 'i'）
2. 确认 Shell 类型：`echo $SHELL`
3. 重新加载环境：`source $GS_ROOT/env.sh`

### 别名冲突

- 后加载的别名会覆盖先前的定义
- 调整 plugin.json 中的 priority 值控制加载顺序
- 使用 `type <alias>` 查看当前别名定义

### 平台检测问题

检查系统识别：
```bash
uname -s  # 应返回 Darwin (macOS) 或 Linux
```

## 许可证

本插件作为 Global Scripts v6 的一部分，遵循项目整体的许可证。