#!/bin/bash
# Global Scripts V3 - 系统命令加载器
# 版本: 3.0.0
# 描述: 加载系统命令，与插件加载机制一致

# 防止重复加载
if _gs_is_constant "_GS_SYSTEM_LOADER_LOADED" && [[ "${GS_FORCE_RELOAD:-false}" != "true" ]]; then
    return 0
fi
_gs_set_constant "_GS_SYSTEM_LOADER_LOADED" "true"

# 系统命令加载实现
load_system_commands_impl() {
    local system_dir="${GS_SYSTEM_DIR}"
    
    _gs_debug "system_loader" "开始加载系统命令..."
    _gs_debug "system_loader" "系统命令目录: $system_dir"
    
    if [[ ! -d "$system_dir" ]]; then
        _gs_debug "system_loader" "系统命令目录不存在，跳过系统命令加载"
        return 0
    fi
    
    # 1. 发现所有系统命令
    local system_commands
    system_commands=$(discover_system_commands "$system_dir")
    
    if [[ -z "$system_commands" ]]; then
        _gs_debug "system_loader" "未发现任何系统命令"
        return 0
    fi
    
    # 2. 按优先级加载系统命令
    while IFS= read -r cmd_dir; do
        local cmd_name=$(basename "$cmd_dir")
        load_single_system_command "$cmd_name" "$cmd_dir"
    done <<< "$system_commands"
    
    _gs_debug "system_loader" "系统命令加载完成"
    return 0
}

# 发现系统命令
discover_system_commands() {
    local system_dir="$1"
    
    _gs_debug "system_loader" "发现系统命令..."
    
    # 查找所有包含.meta文件的目录
    find "$system_dir" -maxdepth 2 -name "*.meta" -type f | \
    while IFS= read -r meta_file; do
        # 检查是否为系统命令
        if $_GS_GREP_CMD -q "^COMMAND_TYPE=system" "$meta_file" 2>/dev/null; then
            dirname "$meta_file"
        fi
    done | sort_system_commands_by_priority
}

# 按优先级排序系统命令
sort_system_commands_by_priority() {
    while IFS= read -r cmd_dir; do
        local meta_file="$cmd_dir/$(basename "$cmd_dir").meta"
        local priority=99
        
        if [[ -f "$meta_file" ]]; then
            priority=$($_GS_GREP_CMD "^PRIORITY=" "$meta_file" 2>/dev/null | cut -d'=' -f2 || echo "99")
        fi
        
        echo "$priority $cmd_dir"
    done | sort -n | cut -d' ' -f2-
}

# 加载单个系统命令
load_single_system_command() {
    local cmd_name="$1"
    local cmd_dir="$2"
    local meta_file="$cmd_dir/$cmd_name.meta"
    local impl_file="$cmd_dir/$cmd_name.sh"
    
    _gs_debug "system_loader" "加载系统命令: $cmd_name"
    
    # 1. 验证系统命令结构
    if ! validate_system_command_structure "$cmd_dir"; then
        _gs_debug "system_loader" "系统命令结构无效: $cmd_name"
        return 1
    fi
    
    # 2. 检查依赖
    if ! check_system_command_dependencies "$meta_file"; then
        _gs_debug "system_loader" "系统命令依赖不满足: $cmd_name"
        return 1
    fi
    
    # 3. 获取加载前的函数快照
    local before_functions
    before_functions=$(_gs_get_function_snapshot)
    
    # 4. 加载系统命令实现
    if [[ -f "$impl_file" ]]; then
        if source "$impl_file"; then
            _gs_debug "system_loader" "  ✓ 加载系统命令实现: $cmd_name"
            _gs_map_set "_GS_LOADED_SYSTEMS" "$cmd_name" "loaded"
        else
            _gs_debug "system_loader" "  ❌ 系统命令实现加载失败: $cmd_name"
            return 1
        fi
    else
        _gs_debug "system_loader" "  ❌ 系统命令实现文件不存在: $impl_file"
        return 1
    fi
    
    # 5. 注册系统命令函数（只注册新增的）
    _gs_register_system_functions "$cmd_name" "$before_functions"
    
    # 6. 运行系统命令自检
    if declare -F "_gs_system_${cmd_name}_selfcheck" >/dev/null 2>&1; then
        if ! "_gs_system_${cmd_name}_selfcheck"; then
            _gs_debug "system_loader" "  ⚠️  系统命令自检失败: $cmd_name"
        fi
    fi
    
    return 0
}

# 验证系统命令结构
validate_system_command_structure() {
    local cmd_dir="$1"
    local cmd_name=$(basename "$cmd_dir")
    local meta_file="$cmd_dir/$cmd_name.meta"
    local impl_file="$cmd_dir/$cmd_name.sh"
    
    # 检查必需文件
    [[ -f "$meta_file" ]] || {
        _gs_debug "system_loader" "缺少元数据文件: $meta_file"
        return 1
    }
    
    [[ -f "$impl_file" ]] || {
        _gs_debug "system_loader" "缺少实现文件: $impl_file"
        return 1
    }
    
    # 检查元数据格式
    if ! validate_system_meta_format "$meta_file"; then
        _gs_debug "system_loader" "元数据格式无效: $meta_file"
        return 1
    fi
    
    return 0
}

# 验证系统命令.meta文件格式
validate_system_meta_format() {
    local meta_file="$1"
    
    # 检查必需字段
    local required_fields=("COMMAND_TYPE" "NAME" "VERSION" "DESCRIPTION")
    
    for field in "${required_fields[@]}"; do
        if ! $_GS_GREP_CMD -q "^$field=" "$meta_file"; then
            _gs_debug "system_loader" "缺少必需字段: $field"
            return 1
        fi
    done
    
    # 检查命令类型
    if ! $_GS_GREP_CMD -q "^COMMAND_TYPE=system" "$meta_file"; then
        _gs_debug "system_loader" "无效的命令类型，必须是system"
        return 1
    fi
    
    return 0
}

# 检查系统命令依赖
check_system_command_dependencies() {
    local meta_file="$1"
    
    # 检查系统依赖
    local system_deps
    system_deps=$($_GS_GREP_CMD "^SYSTEM_DEPS=" "$meta_file" 2>/dev/null | cut -d'=' -f2)
    
    if [[ -n "$system_deps" && "$system_deps" != "none" ]]; then
        IFS=',' read -ra deps <<< "$system_deps"
        for dep in "${deps[@]}"; do
            dep=$(echo "$dep" | xargs)  # 去除空格
            if ! command -v "$dep" >/dev/null 2>&1; then
                _gs_debug "system_loader" "缺少系统依赖: $dep"
                return 1
            fi
        done
    fi
    
    return 0
}
