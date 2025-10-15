# Grep 插件

智能代码搜索工具，针对不同文件类型提供专门优化的 grep 功能。基于 AOSP V2 版本的成熟实现，支持跨平台使用。

## 📋 目录

- [功能概览](#功能概览)
- [快速开始](#快速开始)
- [命令详解](#命令详解)
- [使用示例](#使用示例)
- [平台支持](#平台支持)
- [最佳实践](#最佳实践)

## 🚀 功能概览

Grep 插件提供 **20 个专门优化的搜索命令**，涵盖各种开发场景：

| 分类 | 命令 | 搜索范围 | 主要用途 |
|------|------|----------|----------|
| **通用** | `sgrep` | 所有源代码文件 | 全项目代码搜索 |
| **原生代码** | `cgrep` | C/C++ 文件 | 系统级开发 |
| **JVM语言** | `jgrep`, `ktgrep` | Java, Kotlin | Android/后端开发 |
| **现代语言** | `gogrep`, `rsgrep`, `pygrep` | Go, Rust, Python | 云原生/ML开发 |
| **前端** | `jsgrep`, `tsgrep` | JavaScript, TypeScript | Web 开发 |
| **构建系统** | `ggrep`, `mgrep` | Gradle, Makefile | 构建配置 |
| **配置文件** | `xmlgrep`, `jsongrep`, `yamlgrep` | XML, JSON, YAML | 配置管理 |
| **脚本** | `shgrep` | Shell 脚本 | 自动化脚本 |
| **Android** | `resgrep`, `mangrep`, `rcgrep` | 资源文件, Manifest, 配置 | Android 开发 |
| **智能搜索** | `treegrep` | 常见代码文件 | 模糊搜索 |

## 🎯 快速开始

### 基础搜索
```bash
# 查看所有可用命令
gs grep help

# 在所有源代码中搜索
gs grep sgrep "function"

# 在Java文件中搜索
gs grep jgrep "onCreate"

# 在Python文件中搜索
gs grep pygrep "def main"
```

### 高级搜索
```bash
# 显示搜索结果前后3行
gs grep cgrep "malloc" -A 3 -B 3

# 只显示文件名
gs grep jsgrep "TODO" -l

# 不区分大小写搜索
gs grep sgrep "error" -i

# 使用正则表达式
gs grep pygrep "def\s+\w+\(" -E
```

## 🔧 命令详解

### 通用搜索

#### `sgrep` - 全源码搜索
搜索所有源代码文件，包括：C/C++, Java, Kotlin, XML, Shell, Python, JavaScript, TypeScript, Go, Rust, Swift 等。

```bash
gs grep sgrep "TODO"           # 查找所有TODO注释
gs grep sgrep "deprecated" -i  # 不区分大小写查找废弃代码
gs grep sgrep "import.*pandas" # 查找pandas相关导入
```

#### `treegrep` - 智能模糊搜索
在常见代码文件中进行不区分大小写的搜索，适合快速定位。

```bash
gs grep treegrep "fixme"       # 查找修复标记
gs grep treegrep "bug"         # 查找bug相关代码
```

### 语言专用搜索

#### `cgrep` - C/C++ 搜索
```bash
gs grep cgrep "malloc"         # 查找内存分配
gs grep cgrep "struct.*{"      # 查找结构体定义
gs grep cgrep "#include"       # 查找头文件引用
```

#### `jgrep` - Java 搜索
```bash
gs grep jgrep "public class"   # 查找公共类定义
gs grep jgrep "onCreate"       # Android Activity生命周期
gs grep jgrep "@Override"      # 查找重写方法
```

#### `ktgrep` - Kotlin 搜索
```bash
gs grep ktgrep "fun "          # 查找函数定义
gs grep ktgrep "class.*Activity" # 查找Activity类
gs grep ktgrep "data class"    # 查找数据类
```

#### `pygrep` - Python 搜索
```bash
gs grep pygrep "def "          # 查找函数定义
gs grep pygrep "class.*:"      # 查找类定义
gs grep pygrep "import.*numpy" # 查找numpy导入
```

#### `gogrep` - Go 搜索
```bash
gs grep gogrep "func "         # 查找函数定义
gs grep gogrep "package main"  # 查找主包
gs grep gogrep "import.*gin"   # 查找gin框架使用
```

#### `rsgrep` - Rust 搜索
```bash
gs grep rsgrep "fn "           # 查找函数定义
gs grep rsgrep "struct.*{"     # 查找结构体
gs grep rsgrep "use.*std"      # 查找标准库使用
```

### 前端开发

#### `jsgrep` - JavaScript 搜索
```bash
gs grep jsgrep "function"      # 查找函数定义
gs grep jsgrep "const.*="      # 查找常量定义
gs grep jsgrep "async.*=>"     # 查找异步箭头函数
```

#### `tsgrep` - TypeScript 搜索
```bash
gs grep tsgrep "interface"     # 查找接口定义
gs grep tsgrep "type.*="       # 查找类型别名
gs grep tsgrep "export.*class" # 查找导出的类
```

### 构建系统

#### `ggrep` - Gradle 搜索
```bash
gs grep ggrep "implementation" # 查找依赖声明
gs grep ggrep "android.*{"     # 查找Android配置
gs grep ggrep "buildTypes"     # 查找构建类型配置
```

#### `mgrep` - Makefile 搜索
```bash
gs grep mgrep "target:"        # 查找构建目标
gs grep mgrep "LOCAL_MODULE"   # Android.mk模块定义
gs grep mgrep "include.*mk"    # 查找文件包含
```

### 配置文件

#### `xmlgrep` - XML 搜索
```bash
gs grep xmlgrep "android:layout" # Android布局属性
gs grep xmlgrep "<activity"      # Activity声明
gs grep xmlgrep "permission"     # 权限相关
```

#### `jsongrep` - JSON 搜索
```bash
gs grep jsongrep "version"     # 查找版本信息
gs grep jsongrep "dependencies" # 查找依赖配置
gs grep jsongrep "scripts"     # npm脚本配置
```

#### `yamlgrep` - YAML 搜索
```bash
gs grep yamlgrep "name:"       # 查找名称配置
gs grep yamlgrep "version.*:"  # 查找版本配置
gs grep yamlgrep "workflow"    # GitHub Actions工作流
```

### Android 专用

#### `resgrep` - 资源文件搜索
```bash
gs grep resgrep "string name"  # 查找字符串资源
gs grep resgrep "android:text" # 查找文本属性
gs grep resgrep "drawable"     # 查找图片资源引用
```

#### `mangrep` - Manifest 搜索
```bash
gs grep mangrep "activity"     # 查找Activity声明
gs grep mangrep "permission"   # 查找权限申请
gs grep mangrep "intent-filter" # 查找Intent过滤器
```

#### `rcgrep` - 配置文件搜索
```bash
gs grep rcgrep "service"       # 查找服务配置
gs grep rcgrep "on boot"       # 查找启动时配置
gs grep rcgrep "setprop"       # 查找属性设置
```

## 📚 使用示例

### 代码审查场景
```bash
# 查找所有TODO和FIXME
gs grep sgrep "TODO\|FIXME" -E

# 查找可能的内存泄漏
gs grep cgrep "malloc.*free" -A 5

# 查找废弃的API使用
gs grep jgrep "deprecated" -i

# 查找硬编码的字符串
gs grep sgrep "\".*[A-Z].*\"" -E
```

### Android 开发场景
```bash
# 查找特定Activity的使用
gs grep jgrep "MainActivity"
gs grep mangrep "MainActivity"
gs grep resgrep "MainActivity"

# 查找权限相关代码
gs grep mangrep "permission"
gs grep jgrep "checkSelfPermission"

# 查找网络请求相关代码
gs grep jgrep "http.*request" -i
gs grep ktgrep "retrofit\|okhttp" -i
```

### 构建问题排查
```bash
# 查找依赖冲突
gs grep ggrep "implementation.*conflict"
gs grep ggrep "exclude.*group"

# 查找构建配置问题
gs grep mgrep "LOCAL_.*_LIBRARIES"
gs grep ggrep "buildConfigField"

# 查找版本不一致
gs grep jsongrep "version.*[0-9]"
gs grep ggrep "versionCode\|versionName"
```

### 前端项目维护
```bash
# 查找未使用的导入
gs grep jsgrep "import.*unused" -B 2 -A 2
gs grep tsgrep "import.*type.*never"

# 查找控制台日志
gs grep jsgrep "console\.(log\|warn\|error)"

# 查找异步函数
gs grep tsgrep "async.*function\|async.*=>"
```

## 🖥️ 平台支持

### macOS
- 使用 BSD 兼容的 `find -E` 命令
- 支持扩展正则表达式
- 优化的文件类型匹配

### Linux/Unix
- 使用 POSIX 兼容的 `find` 命令
- 支持 `posix-egrep` 正则类型
- 广泛的发行版兼容性

### 通用特性
- 自动排除常见的非源码目录：`.git`, `.repo`, `node_modules`, `out`, `dist`, `build`
- 智能的文件类型识别
- 彩色输出支持（`--color=auto`）
- 行号显示（`-n`）

## 💡 最佳实践

### 性能优化
```bash
# 限制搜索深度（大项目）
find . -maxdepth 3 -name "*.java" -exec grep "pattern" {} +

# 使用并行搜索（GNU grep）
gs grep sgrep "pattern" --include="*.py" | head -20

# 只搜索特定目录
cd src/ && gs grep jgrep "pattern"
```

### 搜索技巧
```bash
# 组合多个模式
gs grep sgrep "TODO\|FIXME\|XXX" -E

# 排除特定内容
gs grep pygrep "import" | grep -v "__pycache__"

# 统计匹配数量
gs grep jgrep "Activity" -c

# 只显示匹配的部分
gs grep cgrep "func.*(" -o
```

### 结果处理
```bash
# 保存搜索结果
gs grep sgrep "error" > search_results.txt

# 分页查看结果
gs grep jgrep "onCreate" | less

# 统计文件数量
gs grep pygrep "import" -l | wc -l

# 按文件分组显示
gs grep jsgrep "function" | sort
```

## 🔍 进阶用法

### 正则表达式示例
```bash
# 查找函数定义（多语言）
gs grep sgrep "(def|function|func)\s+\w+" -E

# 查找IP地址
gs grep sgrep "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" -E

# 查找邮箱地址
gs grep sgrep "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b" -E

# 查找URL
gs grep sgrep "https?://[^\s]+" -E
```

### 组合命令
```bash
# 查找并替换（预览）
gs grep pygrep "old_function" -l | xargs sed -n 's/old_function/new_function/gp'

# 查找大文件中的模式
gs grep sgrep "pattern" | grep "large_file"

# 统计代码行数
gs grep pygrep "^[[:space:]]*def " -c
```

---

**版本**: 1.0.0  
**基于**: AOSP V2 grep 工具  
**平台**: macOS, Linux, Unix  
**作者**: Global Scripts Team