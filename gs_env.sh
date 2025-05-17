#!/bin/bash
# Global Scripts V3 - 主入口文件
# 版本: 3.0.0
# 描述: Global Scripts V3 环境初始化和加载入口

# 获取脚本目录（兼容Bash和Zsh）
_gs_get_script_dir() {
    if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
        # Bash环境
        echo "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    elif [[ -n "${(%):-%x}" ]]; then
        # Zsh环境
        echo "$(cd "$(dirname "${(%):-%x}")" && pwd)"
    elif [[ -n "$0" ]]; then
        # 备选方案
        echo "$(cd "$(dirname "$0")" && pwd)"
    else
        # 最后备选
        pwd
    fi
}

# 设置基础路径
GS_ROOT="$(_gs_get_script_dir)"
GS_VERSION="$(cat "$GS_ROOT/VERSION" 2>/dev/null || echo "unknown")"

# 首先加载基础库
source "$GS_ROOT/lib/base.sh" || {
    echo "[ERROR] 无法加载基础库: $GS_ROOT/lib/base.sh" >&2
    return 1
}

# 使用常量保护机制设置核心变量
_gs_set_constant "GS_ROOT" "$GS_ROOT"
_gs_set_constant "GS_VERSION" "$GS_VERSION"
_gs_set_constant "_GS_ENV_LOADED" "true"

# 导出核心环境变量
export GS_ROOT
export GS_VERSION
export GS_DEBUG_MODE="${GS_DEBUG_MODE:-false}"

# 设置路径变量（使用常量保护）
_gs_set_constant "GS_CORE_DIR" "$GS_ROOT/core"
_gs_set_constant "GS_SYSTEM_DIR" "$GS_ROOT/system"
_gs_set_constant "GS_PLUGINS_DIR" "$GS_ROOT/plugins"
_gs_set_constant "GS_CONFIG_DIR" "$GS_ROOT/config"
_gs_set_constant "GS_TOOLS_DIR" "$GS_ROOT/tools"
_gs_set_constant "GS_TESTS_DIR" "$GS_ROOT/tests"

# 导出路径变量
export GS_CORE_DIR GS_SYSTEM_DIR GS_PLUGINS_DIR GS_CONFIG_DIR GS_TOOLS_DIR GS_TESTS_DIR

# 检查并加载日志系统
_gs_bootstrap_logger() {
    local logger_file="$GS_CORE_DIR/logger.sh"
    
    # 检查logger.sh是否存在
    if [[ ! -f "$logger_file" ]]; then
        echo "❌ [ERROR] 日志系统不存在: $logger_file" >&2
        return 1
    fi
    
    # 加载logger.sh
    if ! source "$logger_file"; then
        echo "❌ [ERROR] 日志系统加载失败: $logger_file" >&2
        return 1
    fi
    
    # 初始化日志系统
    if ! _gs_init_logger; then
        echo "❌ [ERROR] 日志系统初始化失败" >&2
        return 1
    fi
    
    # 根据调试模式设置日志等级
    if [[ "${GS_DEBUG_MODE:-false}" == "true" ]]; then
        GS_LOG_LEVEL=$GS_LOG_LEVEL_DEBUG
        GS_LOG_CONSOLE_LEVEL=$GS_LOG_LEVEL_DEBUG
    else
        GS_LOG_LEVEL=$GS_LOG_LEVEL_INFO
        GS_LOG_CONSOLE_LEVEL=$GS_LOG_LEVEL_INFO
    fi

    _gs_log_status
    
    return 0
}

# 环境检查函数
_gs_check_environment() {
    _gs_debug "gs_env" "检查运行环境..."
    
    # 检查Shell版本
    if [[ -z "${BASH_VERSION:-}" && -z "${ZSH_VERSION:-}" ]]; then
        _gs_error "gs_env" "需要Bash或Zsh环境"
        return 1
    fi
    
    local shell_info=""
    if [[ -n "${BASH_VERSION:-}" ]]; then
        shell_info="Bash $BASH_VERSION"
    elif [[ -n "${ZSH_VERSION:-}" ]]; then
        shell_info="Zsh $ZSH_VERSION"
    fi
    _gs_debug "gs_env" "Shell环境: $shell_info"
    
    # 检查基础命令
    local required_commands=("grep" "awk" "sed" "find" "cat" "date")
    local missing_commands=()
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_commands+=("$cmd")
        fi
    done
    
    if [[ ${#missing_commands[@]} -gt 0 ]]; then
        _gs_error "gs_env" "缺少必需命令: ${missing_commands[*]}"
        return 1
    fi
    
    _gs_debug "gs_env" "环境检查通过"
    return 0
}

# 检查必要文件
_gs_check_required_files() {
    _gs_debug "gs_env" "检查必要文件..."
    
    local required_files=(
        "$GS_CORE_DIR/logger.sh"
    )
    
    local missing_files=()
    for file in "${required_files[@]}"; do
        if [[ ! -f "$file" ]]; then
            missing_files+=("$file")
        fi
    done
    
    if [[ ${#missing_files[@]} -gt 0 ]]; then
        _gs_error "gs_env" "缺少必要文件:"
        for file in "${missing_files[@]}"; do
            _gs_error "gs_env" "  - $file"
        done
        return 1
    fi
    
    _gs_debug "gs_env" "必要文件检查通过"
    return 0
}

# 加载核心模块
_gs_load_core_modules() {
    _gs_info "gs_env" "加载核心模块..."
    
    local core_modules=(
        "platform_compat.sh"
        "plugin_detector.sh"
        "command_registry.sh"
        "cache_manager.sh"
        "system_loader.sh"
    )
    
    local loaded_count=0
    local failed_count=0
    local skipped_count=0
    
    for module in "${core_modules[@]}"; do
        local core_module_file="$GS_CORE_DIR/$module"

        if [[ -f "$core_module_file" ]]; then
            if source "$core_module_file"; then
                _gs_debug "gs_env" "  ✓ $module"
                ((loaded_count++))
            else
                _gs_error "gs_env" "  ❌ $module (加载失败)"
                ((failed_count++))
            fi
        else
            _gs_warn "gs_env" "  ⚠️  $module (文件不存在)"
            ((skipped_count++))
        fi
    done
    
    _gs_info "gs_env" "核心模块加载完成: 成功 $loaded_count, 失败 $failed_count, 跳过 $skipped_count"
    
    # 只有在有模块加载失败时才返回错误
    return $failed_count
}

# 初始化组件
_gs_initialize_components() {
    _gs_info "gs_env" "初始化组件..."
    
    local init_count=0
    
    # 初始化平台兼容性
    if declare -F "_gs_check_compatibility" >/dev/null 2>&1; then
        if _gs_check_compatibility; then
            _gs_debug "gs_env" "平台兼容性检查完成"
            ((init_count++))
        else
            _gs_warn "gs_env" "平台兼容性检查失败"
        fi
    fi
    
    if declare -F "_gs_init_data_structures" >/dev/null 2>&1; then
        if _gs_init_data_structures; then
            _gs_debug "gs_env" "数据结构初始化完成"
            ((init_count++))
        else
            _gs_warn "gs_env" "数据结构初始化失败"
        fi
    fi
    
    # 加载系统命令
    if declare -F "load_system_commands_impl" >/dev/null 2>&1; then
        if load_system_commands_impl; then
            _gs_debug "gs_env" "系统命令加载完成"
            ((init_count++))
        else
            _gs_warn "gs_env" "系统命令加载失败"
        fi
    else
        _gs_debug "gs_env" "系统命令加载器不可用"
    fi
    
    # 加载用户插件
    if declare -F "load_user_plugins_impl" >/dev/null 2>&1; then
        if load_user_plugins_impl; then
            _gs_debug "gs_env" "用户插件加载完成"
            ((init_count++))
        else
            _gs_warn "gs_env" "用户插件加载失败"
        fi
    else
        _gs_debug "gs_env" "插件检测器不可用"
    fi
    
    # 初始化缓存
    if declare -F "initialize_cache_impl" >/dev/null 2>&1; then
        if initialize_cache_impl; then
            _gs_debug "gs_env" "缓存初始化完成"
            ((init_count++))
        else
            _gs_warn "gs_env" "缓存初始化失败"
        fi
    else
        _gs_debug "gs_env" "缓存管理器不可用"
    fi
    
    _gs_info "gs_env" "组件初始化完成 (成功初始化 $init_count 个组件)"
}

# 显示启动摘要
_gs_show_startup_summary() {
    if [[ "${GS_DEBUG_MODE:-false}" == "true" ]]; then
        echo
        _gs_info "gs_env" "=== Global Scripts V3 启动摘要 ==="
        _gs_info "gs_env" "版本: $GS_VERSION"
        _gs_info "gs_env" "安装路径: $GS_ROOT"
        _gs_info "gs_env" "调试模式: ${GS_DEBUG_MODE}"
        _gs_info "gs_env" "日志等级: $(_gs_get_log_level)"
        _gs_info "gs_env" "日志颜色: ${GS_LOG_COLOR:-auto}"
        _gs_info "gs_env" "日志文件: ${GS_LOG_FILE:-未设置}"
        
        # 显示统计信息（如果可用）
        if declare -F "_gs_map_count" >/dev/null 2>&1; then
            local sys_count=$(_gs_map_count "_GS_SYSTEM_COMMANDS" 2>/dev/null || echo "0")
            local plugin_count=$(_gs_map_count "_GS_PLUGIN_COMMANDS" 2>/dev/null || echo "0")
            local loaded_count=$(_gs_map_count "_GS_LOADED_PLUGINS" 2>/dev/null || echo "0")
            
            _gs_info "gs_env" "系统命令: $sys_count 个"
            _gs_info "gs_env" "插件命令: $plugin_count 个"
            _gs_info "gs_env" "已加载插件: $loaded_count 个"
        fi
        
        _gs_info "gs_env" "============================"
        echo
    fi
}

# 获取毫秒时间戳（如果可用）
_gs_get_timestamp_ms() {
    if command -v python3 >/dev/null 2>&1; then
        python3 -c "import time; print(int(time.time() * 1000))"
    elif command -v python >/dev/null 2>&1; then
        python -c "import time; print(int(time.time() * 1000))"
    elif command -v node >/dev/null 2>&1; then
        node -e "console.log(Date.now())"
    else
        # 备选方案：使用秒级时间戳 * 1000
        echo $(($(date +%s) * 1000))
    fi
}

# 主初始化流程
_gs_main_init() {
    # 简化版本，专注于基本功能

    # 1. 引导加载日志系统
    _gs_bootstrap_logger || {
        echo "❌ [FATAL] 日志系统引导失败，无法继续" >&2
        return 1
    }

    # 2. 基本启动信息
    _gs_info "gs_env" "🚀 Global Scripts V3 启动中..."

    # 3. 检查必要文件
    _gs_check_required_files || {
        _gs_error "gs_env" "必要文件检查失败，但继续执行"
    }

    # 4. 检查运行环境
    _gs_check_environment || {
        _gs_error "gs_env" "环境检查失败，但继续执行"
    }

    # 5. 加载核心模块
    _gs_load_core_modules || {
        _gs_error "gs_env" "核心模块加载存在错误，但继续执行"
    }

    # 6. 初始化组件
    _gs_initialize_components || {
        _gs_error "gs_env" "组件初始化存在错误，但继续执行"
    }

    _gs_info "gs_env" "✅ Global Scripts V3 启动完成"

    return 0
}

# 错误处理函数
_gs_handle_error() {
    local exit_code=$?
    local line_no=${1:-"未知"}
    
    # 如果日志系统可用，使用它；否则使用基本输出
    if declare -F "_gs_fatal" >/dev/null 2>&1; then
        _gs_fatal "gs_env" "启动过程中发生错误 (行号: $line_no, 退出码: $exit_code)"
    else
        echo "❌ [FATAL] Global Scripts V3 启动失败 (行号: $line_no, 退出码: $exit_code)" >&2
    fi
    
    return $exit_code
}

# 主入口点
main() {
    # 使用更温和的错误处理（不使用set -e，因为在zsh中可能有兼容性问题）

    # 执行主初始化
    _gs_main_init
    local init_result=$?

    if [[ $init_result -ne 0 ]]; then
        # 如果日志系统可用，使用它；否则使用基本输出
        if declare -F "_gs_fatal" >/dev/null 2>&1; then
            _gs_fatal "gs_env" "主初始化失败 (退出码: $init_result)"
        else
            echo "❌ [FATAL] Global Scripts V3 启动失败 (退出码: $init_result)" >&2
        fi
        return $init_result
    fi

    return 0
}

# 简化的主函数调用（避免复杂的错误处理和陷阱）
_gs_simple_init() {
    # 1. 引导日志系统
    _gs_bootstrap_logger || {
        echo "❌ [FATAL] 日志系统引导失败，无法继续" >&2
        return 1
    }

    # 2. 基本启动信息
    _gs_info "gs_env" "🚀 Global Scripts V3 启动中..."

    # 3. 检查必要文件
    _gs_check_required_files || {
        _gs_warn "gs_env" "必要文件检查失败，但继续执行"
    }

    # 4. 检查运行环境
    _gs_check_environment || {
        _gs_warn "gs_env" "环境检查失败，但继续执行"
    }

    # 5. 加载核心模块
    _gs_load_core_modules || {
        _gs_warn "gs_env" "核心模块加载存在错误，但继续执行"
    }

    # 6. 初始化组件
    _gs_initialize_components || {
        _gs_warn "gs_env" "组件初始化存在错误，但继续执行"
    }

    _gs_info "gs_env" "✅ Global Scripts V3 启动完成"

    return 0
}

# 执行简化的初始化
_gs_simple_init
