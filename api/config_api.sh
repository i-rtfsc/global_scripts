#!/bin/bash
# Global Scripts V3 - 配置管理API
# 作者: Solo
# 版本: 1.0.0
# 描述: gs-config-* 系列命令实现，JSON Schema验证集成，配置备份恢复功能

# 获取脚本目录
if [[ -z "${_GS_CONFIG_API_DIR:-}" ]]; then
    if [[ -n "${BASH_SOURCE:-}" ]]; then
        readonly _GS_CONFIG_API_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    elif [[ -n "${(%):-%x}" ]] 2>/dev/null; then
        readonly _GS_CONFIG_API_DIR="$(cd "$(dirname "${(%):-%x}")" && pwd)"
    else
        readonly _GS_CONFIG_API_DIR="$(cd "$(dirname "$0")" && pwd)"
    fi
fi

if [[ -z "${_GS_ROOT:-}" ]]; then
    readonly _GS_ROOT="$(cd "$_GS_CONFIG_API_DIR/.." && pwd)"
fi

# 加载依赖模块
source "$_GS_ROOT/lib/utils.sh"
source "$_GS_ROOT/lib/logger.sh"
source "$_GS_ROOT/lib/error.sh"
source "$_GS_ROOT/core/config.sh"
source "$_GS_ROOT/api/command_api.sh"

# ===================================
# gs-config-get 命令实现
# ===================================

# 获取配置值命令
gs_config_get_cmd() {
    local -A parsed_args
    
    # 解析参数
    if ! gs_parse_arguments parsed_args "$@"; then
        return $?
    fi
    
    # 处理帮助
    if [[ "${parsed_args["help"]}" == "true" ]]; then
        _gs_config_get_help
        return 0
    fi
    
    local positional=(${parsed_args["positional"]})
    local key="${positional[0]:-}"
    local default_value="${positional[1]:-}"
    local config_file="${parsed_args["config"]:-}"
    local format="${parsed_args["format"]}"
    
    # 参数验证
    if [[ -z "$key" ]]; then
        if [[ "$format" == "json" ]]; then
            gs_format_error "需要指定配置键" "$format" $_GS_ERROR_PARAMETER
        else
            echo "用法: gs-config-get <key> [default] [选项]"
            echo "使用 'gs-config-get --help' 查看详细帮助"
        fi
        return $_GS_ERROR_PARAMETER
    fi
    
    # 获取配置值
    local value
    value=$(gs_config_get "$key" "$default_value" "$config_file")
    local exit_code=$?
    
    # 格式化输出
    if [[ $exit_code -eq 0 || -n "$value" ]]; then
        case "$format" in
            json)
                local json_output
                json_output=$(printf '{"key": "%s", "value": "%s", "source": "%s", "timestamp": "%s"}' \
                    "$key" "$value" "${config_file:-default}" "$(date -Iseconds)")
                echo "$json_output" | jq .
                ;;
            *)
                if [[ "${parsed_args["verbose"]}" == "true" ]]; then
                    printf "配置键: %s\n值: %s\n来源: %s\n" \
                        "$key" "$value" "${config_file:-用户配置}"
                else
                    echo "$value"
                fi
                ;;
        esac
    else
        gs_format_error "配置键不存在: $key" "$format" $_GS_ERROR_CONFIG
        return $_GS_ERROR_CONFIG
    fi
    
    return 0
}

# gs-config-get 帮助信息
_gs_config_get_help() {
    cat << 'EOF'
名称:
    gs-config-get - 获取配置值

用法:
    gs-config-get <key> [default] [选项]

描述:
    从配置文件中获取指定键的值。支持嵌套键访问（如 system.log_level）。
    如果键不存在且提供了默认值，则返回默认值。

参数:
    key                          配置键名称，支持点号分隔的嵌套访问
    default                      可选的默认值，键不存在时返回

选项:
    -h, --help                   显示此帮助信息
    -v, --verbose                显示详细信息（键名、值、来源等）
    --json                       JSON格式输出
    --config <file>              指定配置文件路径
    --no-color                   禁用彩色输出

示例:
    gs-config-get system.log_level
    gs-config-get cache.enabled true
    gs-config-get plugins.android.timeout 30 --verbose
    gs-config-get system --json
    gs-config-get ui.colors --config /path/to/config.json

EOF
}

# ===================================
# gs-config-set 命令实现
# ===================================

# 设置配置值命令
gs_config_set_cmd() {
    local -A parsed_args
    
    # 解析参数
    if ! gs_parse_arguments parsed_args "$@"; then
        return $?
    fi
    
    # 处理帮助
    if [[ "${parsed_args["help"]}" == "true" ]]; then
        _gs_config_set_help
        return 0
    fi
    
    local positional=(${parsed_args["positional"]})
    local key="${positional[0]:-}"
    local value="${positional[1]:-}"
    local config_file="${parsed_args["config"]:-}"
    local format="${parsed_args["format"]}"
    
    # 参数验证
    if [[ -z "$key" || -z "$value" ]]; then
        if [[ "$format" == "json" ]]; then
            gs_format_error "需要指定配置键和值" "$format" $_GS_ERROR_PARAMETER
        else
            echo "用法: gs-config-set <key> <value> [选项]"
            echo "使用 'gs-config-set --help' 查看详细帮助"
        fi
        return $_GS_ERROR_PARAMETER
    fi
    
    # 备份原配置（如果启用）
    local backup_file=""
    if [[ "${parsed_args["verbose"]}" == "true" ]]; then
        backup_file=$(gs_config_backup "before_set_$(date +%Y%m%d_%H%M%S).json" 2>/dev/null)
    fi
    
    # 设置配置值
    if gs_config_set "$key" "$value" "$config_file"; then
        local success_msg="配置已更新: $key = $value"
        
        # 格式化成功输出
        case "$format" in
            json)
                local json_output
                json_output=$(printf '{"status": "success", "key": "%s", "value": "%s", "backup": "%s", "timestamp": "%s"}' \
                    "$key" "$value" "${backup_file:-}" "$(date -Iseconds)")
                echo "$json_output" | jq .
                ;;
            *)
                gs_format_success "$success_msg" "$format"
                if [[ -n "$backup_file" ]]; then
                    echo "备份文件: $backup_file"
                fi
                ;;
        esac
        return 0
    else
        gs_format_error "设置配置失败: $key = $value" "$format" $_GS_ERROR_CONFIG
        return $_GS_ERROR_CONFIG
    fi
}

# gs-config-set 帮助信息
_gs_config_set_help() {
    cat << 'EOF'
名称:
    gs-config-set - 设置配置值

用法:
    gs-config-set <key> <value> [选项]

描述:
    设置配置文件中指定键的值。支持嵌套键设置（如 system.log_level）。
    会自动创建不存在的配置文件和目录结构。

参数:
    key                          配置键名称，支持点号分隔的嵌套设置
    value                        要设置的值，支持自动类型转换

选项:
    -h, --help                   显示此帮助信息
    -v, --verbose                详细模式，显示备份信息
    --json                       JSON格式输出
    --config <file>              指定配置文件路径
    --no-color                   禁用彩色输出

值类型转换:
    数字值会自动转换为 number 类型
    true/false 会转换为 boolean 类型
    JSON 格式字符串会解析为对应的数据结构

示例:
    gs-config-set system.log_level DEBUG
    gs-config-set cache.enabled true
    gs-config-set plugins.android.timeout 30
    gs-config-set ui.theme '{"mode": "dark", "colors": true}'
    gs-config-set custom.settings value --config /path/to/config.json

EOF
}

# ===================================
# gs-config-list 命令实现
# ===================================

# 列出配置命令
gs_config_list_cmd() {
    local -A parsed_args
    
    # 解析参数
    if ! gs_parse_arguments parsed_args "$@"; then
        return $?
    fi
    
    # 处理帮助
    if [[ "${parsed_args["help"]}" == "true" ]]; then
        _gs_config_list_help
        return 0
    fi
    
    local positional=(${parsed_args["positional"]})
    local pattern="${positional[0]:-}"
    local config_file="${parsed_args["config"]:-}"
    local format="${parsed_args["format"]}"
    
    # 确定要列出的配置文件
    local target_file="${config_file:-$_GS_CONFIG_USER_FILE}"
    
    if [[ ! -f "$target_file" ]]; then
        target_file="$_GS_CONFIG_DEFAULT_FILE"
    fi
    
    if [[ ! -f "$target_file" ]]; then
        gs_format_error "配置文件不存在" "$format" $_GS_ERROR_FILE_NOT_FOUND
        return $_GS_ERROR_FILE_NOT_FOUND
    fi
    
    # 列出配置
    local config_data
    if gs_python_available; then
        if [[ -n "$pattern" ]]; then
            config_data=$(gs_python_call json_keys "$target_file" "$pattern")
        else
            config_data=$(gs_python_call json_keys "$target_file")
        fi
    else
        # 降级到jq实现
        if command -v jq >/dev/null 2>&1; then
            if [[ -n "$pattern" ]]; then
                config_data=$(jq -r "to_entries[] | select(.key | test(\"$pattern\")) | \"\(.key): \(.value)\"" "$target_file")
            else
                config_data=$(jq -r 'to_entries[] | "\(.key): \(.value)"' "$target_file")
            fi
        else
            gs_format_error "需要Python或jq环境来列出配置" "$format" $_GS_ERROR_DEPENDENCY
            return $_GS_ERROR_DEPENDENCY
        fi
    fi
    
    # 格式化输出
    local title="配置列表"
    if [[ -n "$pattern" ]]; then
        title="配置列表 (模式: $pattern)"
    fi
    
    gs_format_output "$format" "$config_data" "$title"
    return 0
}

# gs-config-list 帮助信息
_gs_config_list_help() {
    cat << 'EOF'
名称:
    gs-config-list - 列出配置项

用法:
    gs-config-list [pattern] [选项]

描述:
    列出配置文件中的所有配置项。可以使用正则表达式模式过滤结果。

参数:
    pattern                      可选的过滤模式（正则表达式）

选项:
    -h, --help                   显示此帮助信息
    --json                       JSON格式输出
    --format <format>            输出格式 (text|json|table|yaml)
    --config <file>              指定配置文件路径
    --no-color                   禁用彩色输出

示例:
    gs-config-list                           # 列出所有配置
    gs-config-list "system.*"                # 列出系统相关配置
    gs-config-list ".*\.enabled"             # 列出所有enabled配置
    gs-config-list --format table            # 表格格式显示
    gs-config-list --config /path/to/config.json  # 指定配置文件

EOF
}

# ===================================
# gs-config-validate 命令实现
# ===================================

# 验证配置命令
gs_config_validate_cmd() {
    local -A parsed_args
    
    # 解析参数
    if ! gs_parse_arguments parsed_args "$@"; then
        return $?
    fi
    
    # 处理帮助
    if [[ "${parsed_args["help"]}" == "true" ]]; then
        _gs_config_validate_help
        return 0
    fi
    
    local positional=(${parsed_args["positional"]})
    local config_file="${positional[0]:-${parsed_args["config"]:-$_GS_CONFIG_USER_FILE}}"
    local schema_file="${positional[1]:-$_GS_ROOT/config/schema/core.schema.json}"
    local format="${parsed_args["format"]}"
    
    # 验证配置文件
    local validation_result
    validation_result=$(gs_config_validate "$config_file" "$schema_file" 2>&1)
    local exit_code=$?
    
    # 格式化输出结果
    if [[ $exit_code -eq 0 ]]; then
        case "$format" in
            json)
                local json_output
                json_output=$(printf '{"status": "valid", "file": "%s", "schema": "%s", "message": "%s", "timestamp": "%s"}' \
                    "$config_file" "$schema_file" "$validation_result" "$(date -Iseconds)")
                echo "$json_output" | jq .
                ;;
            *)
                gs_format_success "配置文件验证通过: $config_file" "$format"
                if [[ "${parsed_args["verbose"]}" == "true" ]]; then
                    echo "Schema文件: $schema_file"
                    echo "验证详情: $validation_result"
                fi
                ;;
        esac
    else
        case "$format" in
            json)
                local json_output
                json_output=$(printf '{"status": "invalid", "file": "%s", "schema": "%s", "errors": "%s", "timestamp": "%s"}' \
                    "$config_file" "$schema_file" "$validation_result" "$(date -Iseconds)")
                echo "$json_output" | jq .
                ;;
            *)
                gs_format_error "配置文件验证失败: $config_file" "$format" $exit_code
                echo "错误详情: $validation_result" >&2
                ;;
        esac
    fi
    
    return $exit_code
}

# gs-config-validate 帮助信息
_gs_config_validate_help() {
    cat << 'EOF'
名称:
    gs-config-validate - 验证配置文件

用法:
    gs-config-validate [config-file] [schema-file] [选项]

描述:
    验证配置文件的JSON格式和Schema规范。如果不指定文件，
    默认验证用户配置文件。

参数:
    config-file                  要验证的配置文件路径
    schema-file                  Schema文件路径（默认使用核心Schema）

选项:
    -h, --help                   显示此帮助信息
    -v, --verbose                显示详细验证信息
    --json                       JSON格式输出
    --config <file>              指定配置文件路径（等同于第一个参数）
    --no-color                   禁用彩色输出

验证内容:
    - JSON格式正确性
    - 必需字段完整性
    - 数据类型匹配
    - 值约束验证
    - Schema规范符合性

示例:
    gs-config-validate                        # 验证默认配置
    gs-config-validate /path/to/config.json   # 验证指定配置
    gs-config-validate config.json schema.json  # 使用自定义Schema
    gs-config-validate --json --verbose       # 详细JSON输出

EOF
}

# ===================================
# gs-config-reset 命令实现
# ===================================

# 重置配置命令
gs_config_reset_cmd() {
    local -A parsed_args
    
    # 解析参数
    if ! gs_parse_arguments parsed_args "$@"; then
        return $?
    fi
    
    # 处理帮助
    if [[ "${parsed_args["help"]}" == "true" ]]; then
        _gs_config_reset_help
        return 0
    fi
    
    local positional=(${parsed_args["positional"]})
    local key="${positional[0]:-}"
    local config_file="${parsed_args["config"]:-$_GS_CONFIG_USER_FILE}"
    local format="${parsed_args["format"]}"
    
    # 确认操作（非静默模式）
    if [[ "${parsed_args["quiet"]}" != "true" ]]; then
        local confirm_msg
        if [[ -n "$key" ]]; then
            confirm_msg="确认重置配置键 '$key' 为默认值？[y/N] "
        else
            confirm_msg="确认重置整个配置文件为默认值？这将删除所有自定义配置！[y/N] "
        fi
        
        if [[ "$format" != "json" ]]; then
            printf "%s" "$confirm_msg"
            read -r confirmation
            if [[ "$confirmation" != "y" && "$confirmation" != "Y" ]]; then
                echo "操作已取消"
                return 0
            fi
        fi
    fi
    
    # 创建备份
    local backup_file
    backup_file=$(gs_config_backup "before_reset_$(date +%Y%m%d_%H%M%S).json" 2>/dev/null)
    
    # 执行重置
    local reset_result
    if [[ -n "$key" ]]; then
        # 重置特定键
        local default_value
        default_value=$(gs_config_get "$key" "" "$_GS_CONFIG_DEFAULT_FILE")
        if gs_config_set "$key" "$default_value" "$config_file"; then
            reset_result="配置键已重置: $key = $default_value"
        else
            gs_format_error "重置配置键失败: $key" "$format" $_GS_ERROR_CONFIG
            return $_GS_ERROR_CONFIG
        fi
    else
        # 重置整个配置文件
        if gs_config_reset; then
            reset_result="配置文件已重置为默认值"
        else
            gs_format_error "重置配置文件失败" "$format" $_GS_ERROR_CONFIG
            return $_GS_ERROR_CONFIG
        fi
    fi
    
    # 格式化输出
    case "$format" in
        json)
            local json_output
            json_output=$(printf '{"status": "success", "action": "reset", "key": "%s", "backup": "%s", "message": "%s", "timestamp": "%s"}' \
                "${key:-all}" "${backup_file:-}" "$reset_result" "$(date -Iseconds)")
            echo "$json_output" | jq .
            ;;
        *)
            gs_format_success "$reset_result" "$format"
            if [[ -n "$backup_file" ]]; then
                echo "备份文件: $backup_file"
            fi
            ;;
    esac
    
    return 0
}

# gs-config-reset 帮助信息
_gs_config_reset_help() {
    cat << 'EOF'
名称:
    gs-config-reset - 重置配置为默认值

用法:
    gs-config-reset [key] [选项]

描述:
    重置配置文件或特定配置键为默认值。如果指定键名，只重置该键；
    否则重置整个配置文件。操作前会自动创建备份。

参数:
    key                          可选的配置键名称，不指定则重置整个配置

选项:
    -h, --help                   显示此帮助信息
    -q, --quiet                  静默模式，不询问确认
    --json                       JSON格式输出
    --config <file>              指定配置文件路径
    --no-color                   禁用彩色输出

安全特性:
    - 操作前自动创建备份文件
    - 非静默模式下需要用户确认
    - 支持恢复到备份状态

示例:
    gs-config-reset                          # 重置整个配置文件
    gs-config-reset system.log_level         # 重置特定配置键
    gs-config-reset --quiet                  # 静默重置，不询问确认
    gs-config-reset custom.key --json        # JSON格式输出

EOF
}

# ===================================
# gs-config-backup 命令实现
# ===================================

# 备份配置命令
gs_config_backup_cmd() {
    local -A parsed_args
    
    # 解析参数
    if ! gs_parse_arguments parsed_args "$@"; then
        return $?
    fi
    
    # 处理帮助
    if [[ "${parsed_args["help"]}" == "true" ]]; then
        _gs_config_backup_help
        return 0
    fi
    
    local positional=(${parsed_args["positional"]})
    local backup_name="${positional[0]:-config_backup_$(date +%Y%m%d_%H%M%S).json}"
    local config_file="${parsed_args["config"]:-$_GS_CONFIG_USER_FILE}"
    local format="${parsed_args["format"]}"
    
    # 执行备份
    local backup_file
    backup_file=$(gs_config_backup "$backup_name")
    local exit_code=$?
    
    if [[ $exit_code -eq 0 && -n "$backup_file" ]]; then
        case "$format" in
            json)
                local json_output
                json_output=$(printf '{"status": "success", "backup_file": "%s", "source_file": "%s", "timestamp": "%s"}' \
                    "$backup_file" "$config_file" "$(date -Iseconds)")
                echo "$json_output" | jq .
                ;;
            *)
                gs_format_success "配置已备份到: $backup_file" "$format"
                if [[ "${parsed_args["verbose"]}" == "true" ]]; then
                    local file_size
                    file_size=$(gs_file_size "$backup_file")
                    echo "备份文件大小: ${file_size}字节"
                    echo "源配置文件: $config_file"
                fi
                ;;
        esac
    else
        gs_format_error "配置备份失败" "$format" $exit_code
        return $exit_code
    fi
    
    return 0
}

# gs-config-backup 帮助信息
_gs_config_backup_help() {
    cat << 'EOF'
名称:
    gs-config-backup - 备份配置文件

用法:
    gs-config-backup [backup-name] [选项]

描述:
    创建当前配置文件的备份副本。备份文件存储在配置目录的backups子目录中。

参数:
    backup-name                  可选的备份文件名称（默认包含时间戳）

选项:
    -h, --help                   显示此帮助信息
    -v, --verbose                显示详细备份信息
    --json                       JSON格式输出
    --config <file>              指定要备份的配置文件路径
    --no-color                   禁用彩色输出

备份特性:
    - 自动创建备份目录
    - 支持自定义备份文件名
    - 默认文件名包含时间戳
    - 验证备份文件完整性

示例:
    gs-config-backup                         # 使用默认文件名备份
    gs-config-backup my_config_backup.json   # 指定备份文件名
    gs-config-backup --verbose               # 显示详细信息
    gs-config-backup --config /path/to/config.json  # 备份指定文件

EOF
}

# ===================================
# gs-config-restore 命令实现
# ===================================

# 恢复配置命令
gs_config_restore_cmd() {
    local -A parsed_args
    
    # 解析参数
    if ! gs_parse_arguments parsed_args "$@"; then
        return $?
    fi
    
    # 处理帮助
    if [[ "${parsed_args["help"]}" == "true" ]]; then
        _gs_config_restore_help
        return 0
    fi
    
    local positional=(${parsed_args["positional"]})
    local backup_file="${positional[0]:-}"
    local format="${parsed_args["format"]}"
    
    # 参数验证
    if [[ -z "$backup_file" ]]; then
        if [[ "$format" == "json" ]]; then
            gs_format_error "需要指定备份文件路径" "$format" $_GS_ERROR_PARAMETER
        else
            echo "用法: gs-config-restore <backup-file> [选项]"
            echo "使用 'gs-config-restore --help' 查看详细帮助"
        fi
        return $_GS_ERROR_PARAMETER
    fi
    
    # 确认操作（非静默模式）
    if [[ "${parsed_args["quiet"]}" != "true" && "$format" != "json" ]]; then
        printf "确认从备份文件恢复配置？这将覆盖当前配置！[y/N] "
        read -r confirmation
        if [[ "$confirmation" != "y" && "$confirmation" != "Y" ]]; then
            echo "操作已取消"
            return 0
        fi
    fi
    
    # 执行恢复
    if gs_config_restore "$backup_file"; then
        case "$format" in
            json)
                local json_output
                json_output=$(printf '{"status": "success", "action": "restore", "backup_file": "%s", "timestamp": "%s"}' \
                    "$backup_file" "$(date -Iseconds)")
                echo "$json_output" | jq .
                ;;
            *)
                gs_format_success "配置已从备份文件恢复: $backup_file" "$format"
                ;;
        esac
    else
        gs_format_error "配置恢复失败: $backup_file" "$format" $_GS_ERROR_CONFIG
        return $_GS_ERROR_CONFIG
    fi
    
    return 0
}

# gs-config-restore 帮助信息
_gs_config_restore_help() {
    cat << 'EOF'
名称:
    gs-config-restore - 从备份恢复配置

用法:
    gs-config-restore <backup-file> [选项]

描述:
    从备份文件恢复配置。会自动验证备份文件的有效性，并在恢复前
    创建当前配置的备份。

参数:
    backup-file                  备份文件的路径

选项:
    -h, --help                   显示此帮助信息
    -q, --quiet                  静默模式，不询问确认
    --json                       JSON格式输出
    --no-color                   禁用彩色输出

安全特性:
    - 恢复前验证备份文件格式
    - 自动创建当前配置的备份
    - 非静默模式下需要用户确认
    - 支持回滚操作

示例:
    gs-config-restore backup.json            # 从备份文件恢复
    gs-config-restore --quiet backup.json    # 静默恢复，不询问确认
    gs-config-restore backup.json --json     # JSON格式输出

EOF
}

# ===================================
# gs-config-merge 命令实现
# ===================================

# 合并配置命令
gs_config_merge_cmd() {
    local -A parsed_args
    
    # 解析参数
    if ! gs_parse_arguments parsed_args "$@"; then
        return $?
    fi
    
    # 处理帮助
    if [[ "${parsed_args["help"]}" == "true" ]]; then
        _gs_config_merge_help
        return 0
    fi
    
    local positional=(${parsed_args["positional"]})
    local source_file="${positional[0]:-}"
    local target_file="${positional[1]:-$_GS_CONFIG_USER_FILE}"
    local format="${parsed_args["format"]}"
    
    # 参数验证
    if [[ -z "$source_file" ]]; then
        if [[ "$format" == "json" ]]; then
            gs_format_error "需要指定源配置文件" "$format" $_GS_ERROR_PARAMETER
        else
            echo "用法: gs-config-merge <source-file> [target-file] [选项]"
            echo "使用 'gs-config-merge --help' 查看详细帮助"
        fi
        return $_GS_ERROR_PARAMETER
    fi
    
    # 创建备份
    local backup_file
    backup_file=$(gs_config_backup "before_merge_$(date +%Y%m%d_%H%M%S).json" 2>/dev/null)
    
    # 执行合并
    if gs_config_merge "$_GS_CONFIG_DEFAULT_FILE" "$source_file" "$target_file"; then
        case "$format" in
            json)
                local json_output
                json_output=$(printf '{"status": "success", "action": "merge", "source": "%s", "target": "%s", "backup": "%s", "timestamp": "%s"}' \
                    "$source_file" "$target_file" "${backup_file:-}" "$(date -Iseconds)")
                echo "$json_output" | jq .
                ;;
            *)
                gs_format_success "配置合并完成: $source_file -> $target_file" "$format"
                if [[ -n "$backup_file" ]]; then
                    echo "备份文件: $backup_file"
                fi
                ;;
        esac
    else
        gs_format_error "配置合并失败" "$format" $_GS_ERROR_CONFIG
        return $_GS_ERROR_CONFIG
    fi
    
    return 0
}

# gs-config-merge 帮助信息
_gs_config_merge_help() {
    cat << 'EOF'
名称:
    gs-config-merge - 合并配置文件

用法:
    gs-config-merge <source-file> [target-file] [选项]

描述:
    将源配置文件的设置合并到目标配置文件中。使用深度合并算法，
    源文件的设置会覆盖目标文件的相同键值。

参数:
    source-file                  源配置文件路径
    target-file                  目标配置文件路径（默认为用户配置）

选项:
    -h, --help                   显示此帮助信息
    --json                       JSON格式输出
    --no-color                   禁用彩色输出

合并规则:
    - 使用深度合并算法
    - 源文件设置优先级更高
    - 保留目标文件的其他设置
    - 自动创建备份文件

示例:
    gs-config-merge additional.json           # 合并到用户配置
    gs-config-merge src.json dst.json         # 合并到指定文件
    gs-config-merge settings.json --json      # JSON格式输出

EOF
}

# ===================================
# 配置命令注册
# ===================================

# 注册所有配置管理命令
gs_register_config_commands() {
    # 使用registry系统注册命令，让registry自动创建alias
    if command -v gs_registry_register_command >/dev/null 2>&1; then
        # 获取当前文件路径作为虚拟命令路径的基础
        local script_path
        if [[ -n "${BASH_SOURCE:-}" ]]; then
            script_path="${BASH_SOURCE[0]}"
        elif [[ -n "${(%):-%x}" ]] 2>/dev/null; then
            script_path="${(%):-%x}"
        else
            script_path="$0"
        fi
        
        # 注册config命令组 - 这些命令的实现都在当前文件中
        gs_registry_register_command "gs-config-get" "$script_path" "获取配置值" "3.0.0" "config"
        gs_registry_register_command "gs-config-set" "$script_path" "设置配置值" "3.0.0" "config"
        gs_registry_register_command "gs-config-list" "$script_path" "列出配置项" "3.0.0" "config"
        gs_registry_register_command "gs-config-validate" "$script_path" "验证配置文件" "3.0.0" "config"
        gs_registry_register_command "gs-config-reset" "$script_path" "重置配置为默认值" "3.0.0" "config"
        gs_registry_register_command "gs-config-backup" "$script_path" "备份配置文件" "3.0.0" "config"
        gs_registry_register_command "gs-config-restore" "$script_path" "从备份恢复配置" "3.0.0" "config"
        gs_registry_register_command "gs-config-merge" "$script_path" "合并配置文件" "3.0.0" "config"
        
        # 注册短别名
        # TODO
    else
        # 如果registry系统不可用，fallback到手动alias
        gs_log_warn "Registry系统不可用，使用手动alias注册config命令"
        alias gs-config-get='gs_config_get_cmd'
        alias gs-config-set='gs_config_set_cmd'
        alias gs-config-list='gs_config_list_cmd'
        alias gs-config-validate='gs_config_validate_cmd'
        alias gs-config-reset='gs_config_reset_cmd'
        alias gs-config-backup='gs_config_backup_cmd'
        alias gs-config-restore='gs_config_restore_cmd'
        alias gs-config-merge='gs_config_merge_cmd'
        
        alias cfg-get='gs_config_get_cmd'
        alias cfg-set='gs_config_set_cmd'
        alias cfg-list='gs_config_list_cmd'
        alias cfg-validate='gs_config_validate_cmd'
    fi
    
    gs_log_debug "配置管理命令注册完成"
}

# ===================================
# 自测代码
# ===================================

# 仅在非测试模式下加载
if [[ "${_GS_TEST_MODE:-}" != 1 ]]; then
    # 自动注册配置命令
    gs_register_config_commands
    gs_log_debug "配置管理API模块加载完成"
fi