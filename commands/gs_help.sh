#!/bin/bash
# Global Scripts V3 - Help Command System
# 作者: Solo
# 版本: 3.0.0
# 描述: 分层帮助系统，提供总体帮助、命令特定帮助和分层帮助显示

# 防止重复加载
if [[ -n "${_GS_HELP_LOADED:-}" ]]; then
    return 0
fi
readonly _GS_HELP_LOADED=1

# 设置基础路径
if [[ -z "${_GS_ROOT:-}" ]]; then
    readonly _GS_ROOT="$(cd "$(dirname "$(dirname "${BASH_SOURCE[0]}")")" && pwd)"
fi

# 加载依赖模块
source "${_GS_ROOT}/lib/utils.sh"
source "${_GS_ROOT}/lib/logger.sh"
source "${_GS_ROOT}/lib/error.sh"
source "${_GS_ROOT}/core/registry.sh" 2>/dev/null || true
source "${_GS_ROOT}/api/command_api.sh" 2>/dev/null || true

# ===================================
# 帮助内容数据结构
# ===================================

# 总体帮助信息
readonly _GS_HELP_GENERAL="
Global Scripts V3 - 现代化Shell开发工具集

用法: gs-<command> [options] [arguments]

核心命令:
  help             显示帮助信息
  version          显示版本信息  
  status           显示系统状态

配置管理:
  config-get       获取配置值
  config-set       设置配置值
  config-list      列出配置项
  config-validate  验证配置文件
  config-reset     重置配置
  config-backup    备份配置
  config-restore   恢复配置
  config-merge     合并配置

插件管理:
  plugins-list     列出插件
  plugins-enable   启用插件
  plugins-disable  禁用插件
  plugins-info     插件信息

工具命令:
  tools-health     健康检查
  tools-performance 性能分析
  tools-cache      缓存管理

通用选项:
  --help, -h       显示帮助信息
  --verbose, -v    详细输出模式
  --quiet, -q      静默模式
  --format         输出格式 (text|json|yaml)
  --config         指定配置文件

获取命令特定帮助:
  gs-help <command>        显示特定命令的详细帮助
  gs-<command> --help      直接获取命令帮助

示例:
  gs-help                  显示此总体帮助
  gs-help config-get       显示config-get命令的详细帮助
  gs-version --format json 以JSON格式显示版本信息
  gs-config-get system.log_level  获取日志级别配置

更多信息: https://github.com/solox/global_scripts
"

# 命令特定帮助信息 - 使用Python处理复杂数据结构
gs_help_get_command_help() {
    local command="$1"
    
    case "$command" in
        "help")
            echo "gs-help - 分层帮助系统

用法: gs-help [command]

参数:
  command          可选，指定要查看帮助的命令名称

选项:
  --format FORMAT  输出格式 (text|json)
  --list          列出所有可用命令
  --search TEXT   搜索包含指定文本的命令
  --category CAT  按类别筛选命令

示例:
  gs-help config-get         显示config-get命令帮助  
  gs-help --list            列出所有命令
  gs-help --search config   搜索配置相关命令
  gs-help --category core   显示核心命令"
            ;;
        "version")
            echo "gs-version - 版本信息显示

用法: gs-version [options]

选项:
  --format FORMAT  输出格式 (text|json)
  --check-deps     检查依赖版本
  --full          显示完整版本信息

输出信息:
  - Global Scripts版本
  - Shell版本信息
  - Python版本信息
  - 依赖工具版本
  - 系统环境信息

示例:
  gs-version                 显示基本版本信息
  gs-version --format json   JSON格式输出
  gs-version --check-deps    检查所有依赖版本
  gs-version --full          显示完整信息"
            ;;
        "status")
            echo "gs-status - 系统状态检查

用法: gs-status [options]

选项:
  --format FORMAT  输出格式 (text|json)
  --verbose       详细状态信息
  --check-health  执行健康检查
  --performance   显示性能指标

显示内容:
  - 系统环境状态
  - 配置文件状态
  - 插件加载状态
  - 缓存状态
  - 性能指标

示例:
  gs-status                   显示基本状态
  gs-status --verbose         详细状态信息
  gs-status --format json     JSON格式输出
  gs-status --check-health    执行完整健康检查"
            ;;
        *)
            return 1
            ;;
    esac
}

# 获取类别命令列表
gs_help_get_category_commands() {
    local category="$1"
    
    case "$category" in
        "core")
            echo "help version status"
            ;;
        "config") 
            echo "config-get config-set config-list config-validate config-reset config-backup config-restore config-merge"
            ;;
        "plugins")
            echo "plugins-list plugins-enable plugins-disable plugins-info"
            ;;
        "tools")
            echo "tools-health tools-performance tools-cache"
            ;;
        *)
            return 1
            ;;
    esac
}

# ===================================
# 帮助系统核心函数
# ===================================

# 显示总体帮助信息
gs_help_show_general() {
    local format="${1:-text}"
    
    case "$format" in
        "json")
            gs_help_general_json
            ;;
        *)
            echo "$_GS_HELP_GENERAL"
            ;;
    esac
}

# JSON格式的总体帮助
gs_help_general_json() {
    cat << 'EOF'
{
  "name": "Global Scripts V3",
  "description": "现代化Shell开发工具集",
  "usage": "gs-<command> [options] [arguments]",
  "categories": {
    "core": {
      "description": "核心命令",
      "commands": ["help", "version", "status"]
    },
    "config": {
      "description": "配置管理",
      "commands": ["config-get", "config-set", "config-list", "config-validate", "config-reset", "config-backup", "config-restore", "config-merge"]
    },
    "plugins": {
      "description": "插件管理", 
      "commands": ["plugins-list", "plugins-enable", "plugins-disable", "plugins-info"]
    },
    "tools": {
      "description": "工具命令",
      "commands": ["tools-health", "tools-performance", "tools-cache"]
    }
  },
  "common_options": [
    {"option": "--help, -h", "description": "显示帮助信息"},
    {"option": "--verbose, -v", "description": "详细输出模式"},
    {"option": "--quiet, -q", "description": "静默模式"},
    {"option": "--format", "description": "输出格式 (text|json|yaml)"},
    {"option": "--config", "description": "指定配置文件"}
  ]
}
EOF
}

# 显示命令特定帮助
gs_help_show_command() {
    local command="$1"
    local format="${2:-text}"
    
    # 移除可能的gs-前缀
    command="${command#gs-}"
    
    # 获取命令帮助信息
    local help_text
    help_text=$(gs_help_get_command_help "$command")
    
    if [[ -z "$help_text" ]]; then
        gs_log_warn "没有找到命令 '$command' 的帮助信息"
        
        # 尝试从注册表获取命令信息
        if command -v gs_registry_command_exists >/dev/null 2>&1 && gs_registry_command_exists "gs-$command" 2>/dev/null; then
            gs_help_show_from_registry "$command" "$format"
        else
            gs_error 1 "未知命令: $command"
        fi
        return 1
    fi
    
    case "$format" in
        "json")
            gs_help_command_json "$command" "$help_text"
            ;;
        *)
            echo "$help_text"
            ;;
    esac
}

# JSON格式的命令帮助
gs_help_command_json() {
    local command="$1"
    local help_text="$2"
    
    # 简化的JSON输出
    cat << EOF
{
  "command": "$command",
  "help_text": $(echo "$help_text" | jq -Rs .)
}
EOF
}

# 从注册表获取命令帮助
gs_help_show_from_registry() {
    local command="$1" 
    local format="${2:-text}"
    
    if command -v gs_registry_get_command_info >/dev/null 2>&1; then
        local cmd_info
        cmd_info=$(gs_registry_get_command_info "gs-$command" 2>/dev/null)
        
        if [[ -n "$cmd_info" ]]; then
            case "$format" in
                "json")
                    echo "$cmd_info"
                    ;;
                *)
                    echo "gs-$command - $(echo "$cmd_info" | jq -r '.description // "无描述"' 2>/dev/null || echo "无描述")"
                    echo
                    echo "此命令由插件提供，使用 gs-$command --help 获取详细帮助"
                    ;;
            esac
        else
            gs_error 1 "命令 gs-$command 不存在"
        fi
    else
        gs_error 1 "命令 gs-$command 不存在"
    fi
}

# 列出所有可用命令
gs_help_list_commands() {
    local format="${1:-text}"
    local category="${2:-}"
    
    case "$format" in
        "json")
            gs_help_list_commands_json "$category"
            ;;
        *)
            gs_help_list_commands_text "$category"
            ;;
    esac
}

# 文本格式列出命令
gs_help_list_commands_text() {
    local category="$1"
    
    if [[ -n "$category" ]]; then
        local commands
        commands=$(gs_help_get_category_commands "$category")
        if [[ -n "$commands" ]]; then
            echo "类别: $category"
            echo "命令: $commands"
        else
            gs_error 1 "未知类别: $category"
        fi
    else
        echo "所有可用命令:"
        echo
        
        local categories="core config plugins tools"
        for cat in $categories; do
            local commands
            commands=$(gs_help_get_category_commands "$cat")
            echo "[$cat]"
            for cmd in $commands; do
                echo "  gs-$cmd"
            done
            echo
        done
        
        # 从注册表获取额外命令
        if command -v gs_registry_list_commands >/dev/null 2>&1; then
            local registry_commands
            registry_commands=$(gs_registry_list_commands 2>/dev/null || true)
            if [[ -n "$registry_commands" ]]; then
                echo "[插件命令]"
                echo "$registry_commands" | while read -r cmd; do
                    echo "  $cmd"
                done
            fi
        fi
    fi
}

# JSON格式列出命令
gs_help_list_commands_json() {
    local category="$1"
    
    if [[ -n "$category" ]]; then
        local commands
        commands=$(gs_help_get_category_commands "$category")
        if [[ -n "$commands" ]]; then
            local commands_array=""
            for cmd in $commands; do
                commands_array+='"gs-'$cmd'",'
            done
            commands_array="${commands_array%,}"
            
            cat << EOF
{
  "category": "$category",
  "commands": [$commands_array]
}
EOF
        else
            gs_error 1 "未知类别: $category"
        fi
    else
        echo "{"
        echo '  "categories": {'
        local categories="core config plugins tools"
        local first=true
        for cat in $categories; do
            [[ "$first" == true ]] && first=false || echo ","
            echo -n "    \"$cat\": ["
            local commands
            commands=$(gs_help_get_category_commands "$cat")
            local cmd_first=true
            for cmd in $commands; do
                [[ "$cmd_first" == true ]] && cmd_first=false || echo -n ", "
                echo -n "\"gs-$cmd\""
            done
            echo -n "]"
        done
        echo
        echo "  }"
        echo "}"
    fi
}

# 搜索包含指定文本的命令
gs_help_search_commands() {
    local search_text="$1"
    local format="${2:-text}"
    
    local found_commands=""
    
    # 在内建命令中搜索
    local categories="core config plugins tools"
    for cat in $categories; do
        local commands
        commands=$(gs_help_get_category_commands "$cat")
        for cmd in $commands; do
            if [[ "$cmd" == *"$search_text"* ]]; then
                found_commands+="gs-$cmd "
            else
                # 检查帮助文本是否包含搜索内容
                local help_text
                help_text=$(gs_help_get_command_help "$cmd" 2>/dev/null)
                if [[ "$help_text" == *"$search_text"* ]]; then
                    found_commands+="gs-$cmd "
                fi
            fi
        done
    done
    
    case "$format" in
        "json")
            printf '{"search_text": "%s", "found_commands": [' "$search_text"
            local first=true
            for cmd in $found_commands; do
                [[ "$first" == true ]] && first=false || echo -n ", "
                echo -n "\"$cmd\""
            done
            echo "]}"
            ;;
        *)
            if [[ -z "$found_commands" ]]; then
                echo "没有找到包含 '$search_text' 的命令"
            else
                local count=0
                for cmd in $found_commands; do
                    count=$((count + 1))
                done
                echo "找到 $count 个相关命令:"
                for cmd in $found_commands; do
                    echo "  $cmd"
                done
            fi
            ;;
    esac
}

# ===================================
# 简化的参数解析函数
# ===================================
gs_help_parse_args() {
    local format="text"
    local command=""
    local list="false"
    local search=""
    local category=""
    local help="false"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --format)
                format="$2"
                shift 2
                ;;
            --list)
                list="true"
                shift
                ;;
            --search)
                search="$2"
                shift 2
                ;;
            --category)
                category="$2"
                shift 2
                ;;
            --help|-h)
                help="true"
                shift
                ;;
            -*)
                gs_error 1 "未知选项: $1"
                ;;
            *)
                if [[ -z "$command" ]]; then
                    command="$1"
                fi
                shift
                ;;
        esac
    done
    
    # 输出解析结果
    echo "$format|$command|$list|$search|$category|$help"
}

# ===================================
# 主要的帮助命令函数
# ===================================

gs_cmd() {
    gs_help_get_command_help "help"
}

gs_help_cmd() {
    # 简化的参数处理，避免复杂的解析逻辑
    local format="text"
    local command=""
    local show_help="false"
    local show_list="false"
    local search_text=""
    local category=""
    
    # 简单的参数检查
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --help|-h)
                show_help="true"
                shift
                ;;
            --format)
                if [[ "$2" == "json" ]]; then
                    format="json"
                fi
                shift 2
                ;;
            --json)
                format="json"
                shift
                ;;
            --list)
                show_list="true"
                shift
                ;;
            --search)
                search_text="$2"
                shift 2
                ;;
            --category)
                category="$2" 
                shift 2
                ;;
            *)
                if [[ -z "$command" && "$1" != --* ]]; then
                    command="$1"
                fi
                shift
                ;;
        esac
    done
    
    # 处理帮助请求
    if [[ "$show_help" == "true" ]]; then
        gs_help_get_command_help "help"
        return 0
    fi
    
    # 处理列表请求
    if [[ "$show_list" == "true" ]]; then
        gs_help_list_commands "$format" "$category"
        return 0
    fi
    
    # 处理搜索请求
    if [[ -n "$search_text" ]]; then
        gs_help_search_commands "$search_text" "$format"
        return 0
    fi
    
    # 显示帮助信息
    if [[ -n "$command" ]]; then
        gs_help_show_command "$command" "$format"
    else
        gs_help_show_general "$format"
    fi
}

# ===================================
# 命令注册
# ===================================

# 注册help命令到系统
gs_help_register() {
    if command -v gs_registry_register_command >/dev/null 2>&1; then
        # 获取当前文件路径
        local script_path
        if [[ -n "${BASH_SOURCE:-}" ]]; then
            script_path="${BASH_SOURCE[0]}"
        elif [[ -n "${(%):-%x}" ]] 2>/dev/null; then
            script_path="${(%):-%x}"
        else
            script_path="$0"
        fi
        gs_registry_register_command "gs" "$script_path" "显示帮助信息" "3.0.0" "core"
        gs_registry_register_command "gs-help" "$script_path" "显示帮助信息" "3.0.0" "core"
    fi
}

# 如果直接执行此脚本
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    gs_help_cmd "$@"
fi