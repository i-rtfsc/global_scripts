# System Plugin - 系统管理工具集

系统管理工具集插件，提供代理管理、Homebrew镜像源管理、Android Repo源管理等实用功能。

## 功能特性

### 🌐 Proxy - HTTP/HTTPS 代理管理
- 快速开启/关闭系统代理
- 支持查看代理状态和配置
- 默认代理地址: `127.0.0.1:7890`

### 🍺 Brew - Homebrew 镜像源管理  
- 支持多个国内镜像源切换
- 自动处理 brew、homebrew-core、homebrew-cask 仓库
- 支持 bottles 域名配置
- 切换后自动执行 `brew update`

### 📦 Repo - Android Repo 源管理
- 支持 Google 官方源和国内镜像源
- 通过 REPO_URL 环境变量控制
- 适用于 Android 源码开发

## 子插件列表

| 子插件 | 描述 | 主要命令 |
|--------|------|----------|
| proxy | HTTP/HTTPS 代理管理 | on, off, status, config |
| brew | Homebrew 镜像源管理 | remote, github, ustc, tsinghua, aliyun |
| repo | Android Repo 源管理 | status, google, intel, tsinghua |

## 使用方法

### 基础语法
```bash
gs system <subplugin> <command> [options]
```

### Proxy 代理管理
```bash
# 开启系统代理
gs system proxy on

# 关闭系统代理  
gs system proxy off

# 查看代理状态
gs system proxy status

# 查看代理配置
gs system proxy config
```

### Brew 镜像源管理
```bash
# 查看当前镜像源
gs system brew remote

# 切换到中科大镜像源
gs system brew ustc

# 切换到清华镜像源
gs system brew tsinghua

# 切换到阿里云镜像源
gs system brew aliyun

# 切换回官方源
gs system brew github
```

### Repo 源管理
```bash
# 查看当前Repo源
gs system repo status

# 切换到清华镜像源
gs system repo tsinghua

# 切换到Intel镜像源
gs system repo intel

# 切换回Google官方源
gs system repo google
```

## 支持的镜像源

### Homebrew 镜像源
- **GitHub官方**: `github.com/Homebrew/*`
- **中科大**: `mirrors.ustc.edu.cn`
- **清华大学**: `mirrors.tuna.tsinghua.edu.cn`  
- **阿里云**: `mirrors.aliyun.com`

### Repo 镜像源
- **Google官方**: `gerrit.googlesource.com/git-repo`
- **Intel**: `gerrit.intel.com/git-repo`
- **清华大学**: `mirrors.tuna.tsinghua.edu.cn/git/git-repo`

## 环境变量

### Proxy 相关
- `http_proxy` / `HTTP_PROXY`: HTTP代理地址
- `https_proxy` / `HTTPS_PROXY`: HTTPS代理地址  
- `no_proxy` / `NO_PROXY`: 不使用代理的主机列表

### Brew 相关
- `HOMEBREW_BOTTLE_DOMAIN`: Homebrew bottles 镜像域名

### Repo 相关
- `REPO_URL`: Android Repo 工具的源地址

## 技术实现

- 基于 Python 3.7+ 和 Global Scripts V6 插件系统
- 使用 asyncio 进行异步命令执行
- 通过环境变量控制系统行为
- 支持跨平台使用

## 注意事项

1. **权限要求**: 部分操作可能需要网络访问权限
2. **环境依赖**: Brew 功能需要系统安装 Homebrew
3. **代理设置**: 代理功能仅在当前 shell 会话中生效
4. **镜像源选择**: 建议根据网络环境选择合适的镜像源

## 版本历史

- **v6.0.0**: 初始版本，从 Global Scripts V2 移植并重构
  - 重构为 Python 插件架构
  - 新增 asyncio 支持
  - 改进错误处理和用户体验
  - 排除了原 clash 子插件