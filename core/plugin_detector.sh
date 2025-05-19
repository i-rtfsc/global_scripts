#!/bin/bash
# Global Scripts V3 - 插件自动检测器
# 版本: 3.0.0
# 描述: 自动检测和加载插件，实现.meta+函数检测架构

# 防止重复加载
if _gs_is_constant "_GS_PLUGIN_DETECTOR_LOADED" && [[ "${GS_FORCE_RELOAD:-false}" != "true" ]]; then
    return 0
fi
_gs_set_constant "_GS_PLUGIN_DETECTOR_LOADED" "true"

# 插件检测器调试输出（使用新的日志系统）
_gs_plugin_debug() {
    # 如果新的日志系统可用，使用它
    if declare -F "_gs_debug" >/dev/null 2>&1; then
        _gs_debug "plugin" "$1"
    elif [[ "${GS_DEBUG_MODE:-false}" == "true" ]]; then
        # 备选：使用简单输出
        echo "[DEBUG:plugin_detector] $*" >&2
    fi
}

# 用户插件加载实现
load_user_plugins_impl() {
    local plugins_dir="${GS_PLUGINS_DIR}"
    
    _gs_plugin_debug "开始加载用户插件..."
    _gs_plugin_debug "插件目录: $plugins_dir"
    
    if [[ ! -d "$plugins_dir" ]]; then
        _gs_plugin_debug "插件目录不存在，跳过插件加载"
        return 0
    fi
    
    # 1. 发现所有主插件
    local main_plugins
    main_plugins=$(discover_main_plugins "$plugins_dir")
    
    if [[ -z "$main_plugins" ]]; then
        _gs_plugin_debug "未发现任何主插件"
        return 0
    fi
    
    # 2. 按优先级加载主插件
    while IFS= read -r plugin_dir; do
        local plugin_name=$(basename "$plugin_dir")
        load_single_plugin "$plugin_name" "$plugin_dir"
    done <<< "$main_plugins"
    
    # 3. 注册插件命令别名
    register_plugin_command_aliases
    
    _gs_plugin_debug "用户插件加载完成"
    return 0
}

# 发现主插件
discover_main_plugins() {
    local plugins_dir="$1"
    
    _gs_plugin_debug "发现主插件..."
    
    # 查找所有包含.meta文件的目录
    find "$plugins_dir" -maxdepth 2 -name "*.meta" -type f | \
    while IFS= read -r meta_file; do
        # 检查是否为主插件
        if grep -q "^PLUGIN_TYPE=main" "$meta_file" 2>/dev/null; then
            dirname "$meta_file"
        fi
    done | sort_plugins_by_priority
}

# 按优先级排序插件
sort_plugins_by_priority() {
    while IFS= read -r plugin_dir; do
        local meta_file="$plugin_dir/$(basename "$plugin_dir").meta"
        local priority=99
        
        if [[ -f "$meta_file" ]]; then
            priority=$(grep "^PRIORITY=" "$meta_file" 2>/dev/null | cut -d'=' -f2 || echo "99")
        fi
        
        echo "$priority $plugin_dir"
    done | sort -n | cut -d' ' -f2-
}

# 加载单个插件
load_single_plugin() {
    local plugin_name="$1"
    local plugin_dir="$2"
    local meta_file="$plugin_dir/$plugin_name.meta"
    local impl_file="$plugin_dir/$plugin_name.sh"

    _gs_plugin_debug "加载插件: $plugin_name"

    # 1. 验证插件结构
    if ! validate_plugin_structure "$plugin_dir"; then
        _gs_plugin_debug "插件结构无效: $plugin_name"
        return 1
    fi

    # 2. 检查依赖
    if ! check_plugin_dependencies "$meta_file"; then
        _gs_plugin_debug "插件依赖不满足: $plugin_name"
        return 1
    fi

    # 3. 获取加载前的函数快照
    local before_functions
    before_functions=$(_gs_get_function_snapshot)

    # 4. 加载插件实现
    if [[ -f "$impl_file" ]]; then
        if source "$impl_file"; then
            _gs_plugin_debug "  ✓ 加载插件实现: $plugin_name"
            _gs_map_set "_GS_LOADED_PLUGINS" "$plugin_name" "loaded"
        else
            _gs_plugin_debug "  ❌ 插件实现加载失败: $plugin_name"
            return 1
        fi
    else
        _gs_plugin_debug "  ❌ 插件实现文件不存在: $impl_file"
        return 1
    fi

    # 5. 加载子模块
    load_plugin_submodules "$plugin_dir" "$meta_file" "$before_functions"

    # 6. 注册插件函数（只注册新增的）
    _gs_register_plugin_functions "$plugin_name" "$before_functions"

    # 7. 运行插件自检
    if declare -F "_gs_${plugin_name}_selfcheck" >/dev/null 2>&1; then
        if ! "_gs_${plugin_name}_selfcheck"; then
            _gs_plugin_debug "  ⚠️  插件自检失败: $plugin_name"
        fi
    fi

    return 0
}

# 验证插件结构
validate_plugin_structure() {
    local plugin_dir="$1"
    local plugin_name=$(basename "$plugin_dir")
    local meta_file="$plugin_dir/$plugin_name.meta"
    local impl_file="$plugin_dir/$plugin_name.sh"
    
    # 检查必需文件
    [[ -f "$meta_file" ]] || {
        _gs_plugin_debug "缺少元数据文件: $meta_file"
        return 1
    }
    
    [[ -f "$impl_file" ]] || {
        _gs_plugin_debug "缺少实现文件: $impl_file"
        return 1
    }
    
    # 检查元数据格式
    if ! validate_meta_format "$meta_file"; then
        _gs_plugin_debug "元数据格式无效: $meta_file"
        return 1
    fi
    
    return 0
}

# 验证.meta文件格式
validate_meta_format() {
    local meta_file="$1"
    
    # 检查必需字段
    local required_fields=("PLUGIN_TYPE" "NAME" "VERSION" "DESCRIPTION")
    
    for field in "${required_fields[@]}"; do
        if ! grep -q "^$field=" "$meta_file"; then
            _gs_plugin_debug "缺少必需字段: $field"
            return 1
        fi
    done
    
    return 0
}

# 检查插件依赖
check_plugin_dependencies() {
    local meta_file="$1"
    
    # 检查系统依赖
    local system_deps
    system_deps=$(grep "^SYSTEM_DEPS=" "$meta_file" 2>/dev/null | cut -d'=' -f2)
    
    if [[ -n "$system_deps" && "$system_deps" != "none" ]]; then
        IFS=',' read -ra deps <<< "$system_deps"
        for dep in "${deps[@]}"; do
            dep=$(echo "$dep" | xargs)  # 去除空格
            if ! command -v "$dep" >/dev/null 2>&1; then
                _gs_plugin_debug "缺少系统依赖: $dep"
                return 1
            fi
        done
    fi
    
    # 检查插件依赖
    local plugin_deps
    plugin_deps=$(grep "^PLUGIN_DEPS=" "$meta_file" 2>/dev/null | cut -d'=' -f2)
    
    if [[ -n "$plugin_deps" && "$plugin_deps" != "none" ]]; then
        IFS=',' read -ra deps <<< "$plugin_deps"
        for dep in "${deps[@]}"; do
            dep=$(echo "$dep" | xargs)  # 去除空格
            if [[ -z "${_GS_LOADED_PLUGINS[$dep]:-}" ]]; then
                _gs_plugin_debug "缺少插件依赖: $dep"
                return 1
            fi
        done
    fi
    
    return 0
}

# 加载插件子模块
load_plugin_submodules() {
    local plugin_dir="$1"
    local meta_file="$2"
    local before_functions="$3"  # 传递函数快照

    local submodules
    submodules=$($_GS_GREP_CMD "^SUBMODULES=" "$meta_file" 2>/dev/null | cut -d'=' -f2)

    if [[ -n "$submodules" && "$submodules" != "none" ]]; then
        _gs_plugin_debug "加载子模块: $submodules"

        IFS=',' read -ra modules <<< "$submodules"
        for module in "${modules[@]}"; do
            module=$(echo "$module" | xargs)  # 去除空格
            load_single_submodule "$plugin_dir" "$module"
        done
    fi
}

# 加载单个子模块
load_single_submodule() {
    local plugin_dir="$1"
    local module_name="$2"
    local module_dir="$plugin_dir/$module_name"
    local module_meta="$module_dir/$module_name.meta"
    local module_impl="$module_dir/$module_name.sh"
    
    _gs_plugin_debug "  加载子模块: $module_name"
    
    if [[ -f "$module_impl" ]]; then
        if source "$module_impl"; then
            _gs_plugin_debug "    ✓ 子模块加载成功: $module_name"
        else
            _gs_plugin_debug "    ❌ 子模块加载失败: $module_name"
        fi
    else
        _gs_plugin_debug "    ⚠️  子模块实现文件不存在: $module_impl"
    fi
}

# 注册插件命令别名（现在由command_registry.sh处理）
register_plugin_command_aliases() {
    _gs_plugin_debug "插件命令注册已移至command_registry.sh"
    # 这个函数保留为兼容性，实际注册在load_single_plugin中调用
}
