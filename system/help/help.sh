#!/bin/bash
# Global Scripts V3 - 显示帮助信息
# 版本: 1.0.0
# 描述: 显示帮助信息

# ============================================================================
# 显示帮助信息 - 系统命令
# ============================================================================

# 主函数（按照设计文档的命名规范）
gs_system_help() {
    # 功能描述: 显示帮助信息
    # 参数: $1 - 选项 (字符串) [可选]
    # 返回值: 0 - 成功, 1 - 失败
    # 示例: gs-help, gs-help --help

    local option="${1:-}"

    # 处理帮助选项
    if [[ "$option" == "--help" || "$option" == "-h" ]]; then
        _gs_help_show_help
        return 0
    fi

    # 处理版本选项
    if [[ "$option" == "--version" || "$option" == "-v" ]]; then
        echo "gs-help v1.0.0"
        return 0
    fi

    case "$option" in
        "")
            # 默认显示帮助信息
            _gs_help_show_help
            ;;
        *)
            _gs_error "help" "未知选项: $option"
            _gs_info "help" "使用 'gs-help --help' 查看帮助"
            return 1
            ;;
    esac
}

# 显示帮助信息
_gs_help_show_help() {
    cat << 'HELP'
gs-help - 显示帮助信息

功能描述:
  显示帮助信息

用法:
  gs-help [选项]

选项:
  --help, -h      显示此帮助信息
  --version, -v   显示版本信息

示例:
  gs-help
  gs-help --help

HELP
}

# 命令自检函数
_gs_system_help_selfcheck() {
    # TODO: 在这里添加命令自检逻辑
    return 0
}

# 执行自检
if ! _gs_system_help_selfcheck; then
    _gs_error "help" "系统命令自检失败"
    return 1
fi

_gs_debug "help" "系统命令加载完成"
