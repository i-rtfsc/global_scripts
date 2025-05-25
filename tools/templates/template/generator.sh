#!/bin/bash
# Global Scripts V3 - 插件生成器
# 版本: 1.0.0
# 描述: 自动生成插件的工具

# ============================================================================
# 插件生成器核心函数
# ============================================================================

# 创建新插件
gs_generator_create_plugin() {
    local plugin_name="$1"
    local plugin_description="${2:-新插件}"
    local plugin_author="${3:-$(whoami)}"
    
    if [[ -z "$plugin_name" ]]; then
        echo "用法: gs-generate-plugin <插件名> [描述] [作者]"
        echo ""
        echo "示例:"
        echo "  gs-generate-plugin my-tool '我的工具插件'"
        echo "  gs-generate-plugin backup-manager '备份管理器' 'John Doe'"
        return 1
    fi
    
    # 验证插件名
    if [[ ! "$plugin_name" =~ ^[a-z][a-z0-9_-]*$ ]]; then
        _gs_error "generator" "插件名只能包含小写字母、数字、下划线和连字符，且必须以字母开头"
        return 1
    fi
    
    local plugin_dir="$GS_PLUGINS_DIR/$plugin_name"
    
    # 检查插件是否已存在
    if [[ -d "$plugin_dir" ]]; then
        _gs_error "generator" "插件 '$plugin_name' 已存在: $plugin_dir"
        return 1
    fi
    
    _gs_info "generator" "创建插件: $plugin_name"
    
    # 创建插件目录
    mkdir -p "$plugin_dir" || {
        _gs_error "generator" "无法创建插件目录: $plugin_dir"
        return 1
    }
    
    # 生成元数据文件
    _gs_generate_plugin_meta "$plugin_dir" "$plugin_name" "$plugin_description" "$plugin_author"
    
    # 生成插件实现文件
    _gs_generate_plugin_impl "$plugin_dir" "$plugin_name" "$plugin_description"
    
    _gs_info "generator" "✅ 插件 '$plugin_name' 创建成功!"
    _gs_info "generator" "📁 位置: $plugin_dir"
    _gs_info "generator" "📝 请编辑以下文件来实现你的插件:"
    _gs_info "generator" "   - $plugin_dir/$plugin_name.meta (元数据)"
    _gs_info "generator" "   - $plugin_dir/$plugin_name.sh (实现)"
    
    return 0
}

# 创建系统命令
gs_generator_create_system() {
    local command_name="$1"
    local command_description="${2:-新系统命令}"
    
    if [[ -z "$command_name" ]]; then
        echo "用法: gs-generate-system <命令名> [描述]"
        echo ""
        echo "示例:"
        echo "  gs-generate-system gs-status '显示系统状态'"
        echo "  gs-generate-system gs-help '显示帮助信息'"
        return 1
    fi
    
    # 验证命令名
    if [[ ! "$command_name" =~ ^gs-[a-z][a-z0-9_-]*$ ]]; then
        _gs_error "generator" "系统命令名必须以 'gs-' 开头，后跟小写字母、数字、下划线或连字符"
        return 1
    fi
    
    local cmd_short_name="${command_name#gs-}"  # 移除gs-前缀
    local system_dir="$GS_SYSTEM_DIR/$cmd_short_name"
    
    # 检查命令是否已存在
    if [[ -d "$system_dir" ]]; then
        _gs_error "generator" "系统命令 '$command_name' 已存在: $system_dir"
        return 1
    fi
    
    _gs_info "generator" "创建系统命令: $command_name"
    
    # 创建系统命令目录
    mkdir -p "$system_dir" || {
        _gs_error "generator" "无法创建系统命令目录: $system_dir"
        return 1
    }
    
    # 生成元数据文件
    _gs_generate_system_meta "$system_dir" "$command_name" "$command_description"
    
    # 生成命令实现文件
    _gs_generate_system_impl "$system_dir" "$command_name" "$command_description"
    
    _gs_info "generator" "✅ 系统命令 '$command_name' 创建成功!"
    _gs_info "generator" "📁 位置: $system_dir"
    _gs_info "generator" "📝 请编辑以下文件来实现你的命令:"
    _gs_info "generator" "   - $system_dir/$command_name.meta (元数据)"
    _gs_info "generator" "   - $system_dir/$command_name.sh (实现)"
    
    return 0
}

# ============================================================================
# 模板生成函数
# ============================================================================

# 生成插件元数据文件
_gs_generate_plugin_meta() {
    local plugin_dir="$1"
    local plugin_name="$2"
    local plugin_description="$3"
    local plugin_author="$4"
    
    cat > "$plugin_dir/$plugin_name.meta" << EOF
# Global Scripts V3 - $plugin_description
# 版本: 1.0.0

name="$plugin_name"
version="1.0.0"
description="$plugin_description"
author="$plugin_author"
category="user"

# 插件命令定义
commands=(
    "gs-$plugin_name:gs_${plugin_name//-/_}_main:$plugin_description"
)

# 依赖项
dependencies=()

# 插件类型
type="plugin"
EOF
}

# 生成插件实现文件
_gs_generate_plugin_impl() {
    local plugin_dir="$1"
    local plugin_name="$2"
    local plugin_description="$3"
    local func_name="gs_${plugin_name//-/_}_main"
    
    cat > "$plugin_dir/$plugin_name.sh" << EOF
#!/bin/bash
# Global Scripts V3 - $plugin_description
# 版本: 1.0.0
# 描述: $plugin_description

# ============================================================================
# $plugin_description - 主要功能
# ============================================================================

# 主函数
$func_name() {
    local action="\${1:-help}"
    
    case "\$action" in
        "help"|"-h"|"--help")
            _gs_${plugin_name//-/_}_show_help
            ;;
        "version"|"-v"|"--version")
            echo "$plugin_name v1.0.0"
            ;;
        *)
            _gs_info "$plugin_name" "执行操作: \$action"
            # TODO: 在这里实现你的插件逻辑
            _gs_info "$plugin_name" "Hello from $plugin_name plugin!"
            ;;
    esac
}

# 显示帮助信息
_gs_${plugin_name//-/_}_show_help() {
    cat << 'HELP'
$plugin_description

用法:
    gs-$plugin_name [选项] [参数]

选项:
    help, -h, --help     显示此帮助信息
    version, -v, --version  显示版本信息

示例:
    gs-$plugin_name help
    gs-$plugin_name version

HELP
}

# 插件自检函数
_gs_${plugin_name//-/_}_self_check() {
    # TODO: 在这里添加插件自检逻辑
    return 0
}

# 执行自检
if ! _gs_${plugin_name//-/_}_self_check; then
    _gs_error "$plugin_name" "插件自检失败"
    return 1
fi

_gs_debug "$plugin_name" "插件加载完成"
EOF
}

# 生成系统命令元数据文件
_gs_generate_system_meta() {
    local system_dir="$1"
    local command_name="$2"
    local command_description="$3"
    local cmd_short_name="${command_name#gs-}"  # 移除gs-前缀

    cat > "$system_dir/$cmd_short_name.meta" << EOF
# Global Scripts V3 - $command_description
# 版本: 1.0.0

COMMAND_TYPE=system
NAME=$cmd_short_name
VERSION=1.0.0
DESCRIPTION=$command_description
AUTHOR=Global Scripts Team
SYSTEM_DEPS=none
PLUGIN_DEPS=none
MIN_GS_VERSION=3.0.0
PRIORITY=10

# 兼容性字段
name="$cmd_short_name"
version="1.0.0"
description="$command_description"
author="Global Scripts Team"
category="system"
type="system"
EOF
}

# 生成系统命令实现文件
_gs_generate_system_impl() {
    local system_dir="$1"
    local command_name="$2"
    local command_description="$3"
    local cmd_short_name="${command_name#gs-}"  # 移除gs-前缀
    local func_name="gs_system_${cmd_short_name//-/_}"

    cat > "$system_dir/$cmd_short_name.sh" << EOF
#!/bin/bash
# Global Scripts V3 - $command_description
# 版本: 1.0.0
# 描述: $command_description

# ============================================================================
# $command_description - 系统命令
# ============================================================================

# 主函数（按照设计文档的命名规范）
$func_name() {
    # 功能描述: $command_description
    # 参数: \$1 - 选项 (字符串) [可选]
    # 返回值: 0 - 成功, 1 - 失败
    # 示例: $command_name, $command_name --help

    local option="\${1:-}"

    # 处理帮助选项
    if [[ "\$option" == "--help" || "\$option" == "-h" ]]; then
        _gs_${cmd_short_name//-/_}_show_help
        return 0
    fi

    # 处理版本选项
    if [[ "\$option" == "--version" || "\$option" == "-v" ]]; then
        echo "$command_name v1.0.0"
        return 0
    fi

    case "\$option" in
        "")
            # 默认显示帮助信息
            _gs_${cmd_short_name//-/_}_show_help
            ;;
        *)
            _gs_error "$cmd_short_name" "未知选项: \$option"
            _gs_info "$cmd_short_name" "使用 '$command_name --help' 查看帮助"
            return 1
            ;;
    esac
}

# 显示帮助信息
_gs_${cmd_short_name//-/_}_show_help() {
    cat << 'HELP'
$command_name - $command_description

功能描述:
  $command_description

用法:
  $command_name [选项]

选项:
  --help, -h      显示此帮助信息
  --version, -v   显示版本信息

示例:
  $command_name
  $command_name --help

HELP
}

# 命令自检函数
_gs_system_${cmd_short_name//-/_}_selfcheck() {
    # TODO: 在这里添加命令自检逻辑
    return 0
}

# 执行自检
if ! _gs_system_${cmd_short_name//-/_}_selfcheck; then
    _gs_error "$cmd_short_name" "系统命令自检失败"
    return 1
fi

_gs_debug "$cmd_short_name" "系统命令加载完成"
EOF
}

# 插件自检
if command -v _gs_info >/dev/null 2>&1; then
    _gs_debug "generator" "插件生成器加载完成"
else
    echo "[WARNING] 插件生成器: 日志系统未就绪" >&2
fi
