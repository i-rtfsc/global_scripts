#!/bin/bash
# Global Scripts V3 - 显示版本信息
# 版本: 1.0.0
# 描述: 显示版本信息

# ============================================================================
# 显示版本信息 - 系统命令
# ============================================================================

# 主函数（按照设计文档的命名规范）
gs_system_version() {
    # 功能描述: 显示版本信息
    # 参数: $1 - 选项 (字符串) [可选]
    # 返回值: 0 - 成功, 1 - 失败
    # 示例: gs-version, gs-version --help

    local option="${1:-}"

    # 处理帮助选项
    if [[ "$option" == "--help" || "$option" == "-h" ]]; then
        _gs_version_show_help
        return 0
    fi

    # 处理版本选项
    if [[ "$option" == "--version" || "$option" == "-v" ]]; then
        echo "gs-version v1.0.0"
        return 0
    fi

    case "$option" in
        "")
            # 默认显示帮助信息
            _gs_version_show_help
            ;;
        *)
            _gs_error "version" "未知选项: $option"
            _gs_info "version" "使用 'gs-version --help' 查看帮助"
            return 1
            ;;
    esac
}

# 显示帮助信息
_gs_version_show_help() {
    cat << 'HELP'
gs-version - 显示版本信息

功能描述:
  显示版本信息

用法:
  gs-version [选项]

选项:
  --help, -h      显示此帮助信息
  --version, -v   显示版本信息

示例:
  gs-version
  gs-version --help

HELP
}

# 命令自检函数
_gs_system_version_selfcheck() {
    # TODO: 在这里添加命令自检逻辑
    return 0
}

# 执行自检
if ! _gs_system_version_selfcheck; then
    _gs_error "version" "系统命令自检失败"
    return 1
fi

_gs_debug "version" "系统命令加载完成"
