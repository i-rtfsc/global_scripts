#!/bin/bash
# Global Scripts V3 - 缓存管理器
# 版本: 3.0.0
# 描述: 管理插件和命令的缓存，提高启动性能

# 防止重复加载
if _gs_is_constant "_GS_CACHE_MANAGER_LOADED" && [[ "${GS_FORCE_RELOAD:-false}" != "true" ]]; then
    return 0
fi
_gs_set_constant "_GS_CACHE_MANAGER_LOADED" "true"

# 缓存文件路径（使用常量保护机制）
_gs_set_constant "GS_CACHE_DIR" "${GS_CONFIG_DIR}/cache"
_gs_set_constant "GS_PLUGIN_CACHE" "$(_gs_get_constant "GS_CACHE_DIR")/plugins.cache"
_gs_set_constant "GS_COMMAND_CACHE" "$(_gs_get_constant "GS_CACHE_DIR")/commands.cache"
_gs_set_constant "GS_METADATA_CACHE" "$(_gs_get_constant "GS_CACHE_DIR")/metadata.cache"

# 缓存管理器初始化实现
initialize_cache_impl() {
    _gs_debug "cache_manager" "初始化缓存管理器..."
    
    # 创建缓存目录
    [[ -d "$GS_CACHE_DIR" ]] || mkdir -p "$GS_CACHE_DIR" 2>/dev/null
    
    # 检查缓存有效性
    if ! is_cache_valid; then
        _gs_debug "cache_manager" "缓存无效，正在重建..."
        # 同步重建缓存（避免后台进程输出问题）
        rebuild_cache_sync >/dev/null 2>&1
        _gs_debug "cache_manager" "缓存重建完成"
    else
        _gs_debug "cache_manager" "缓存有效"
    fi
    
    _gs_debug "cache_manager" "缓存管理器初始化完成"
    return 0
}

# 检查缓存是否有效
is_cache_valid() {
    # 检查缓存文件是否存在
    [[ -f "$GS_PLUGIN_CACHE" ]] || return 1
    [[ -f "$GS_COMMAND_CACHE" ]] || return 1
    [[ -f "$GS_METADATA_CACHE" ]] || return 1
    
    # 检查缓存是否过期（24小时）
    local cache_age
    if command -v stat >/dev/null 2>&1; then
        # 获取缓存文件的修改时间
        local cache_mtime
        cache_mtime=$(stat -f%m "$GS_PLUGIN_CACHE" 2>/dev/null || stat -c%Y "$GS_PLUGIN_CACHE" 2>/dev/null || echo 0)
        local current_time
        current_time=$(date +%s)
        cache_age=$((current_time - cache_mtime))
        
        # 24小时 = 86400秒
        if [[ $cache_age -gt 86400 ]]; then
            _gs_debug "cache_manager" "缓存已过期 (${cache_age}秒)"
            return 1
        fi
    fi
    
    # 检查插件目录是否有变化
    if [[ -d "${GS_PLUGINS_DIR}" ]]; then
        local plugins_hash
        plugins_hash=$(find "${GS_PLUGINS_DIR}" -name "*.meta" -o -name "*.sh" | \
                      xargs ls -la 2>/dev/null | \
                      $_GS_SED_CMD 's/^[^ ]* *[^ ]* *[^ ]* *[^ ]* *[^ ]* *//' | \
                      sort | md5sum 2>/dev/null | cut -d' ' -f1 || echo "unknown")
        
        local cached_hash
        cached_hash=$(head -n1 "$GS_METADATA_CACHE" 2>/dev/null || echo "")
        
        if [[ "$plugins_hash" != "$cached_hash" ]]; then
            _gs_debug "cache_manager" "插件目录有变化"
            return 1
        fi
    fi
    
    return 0
}

# 同步重建缓存
rebuild_cache_sync() {
    # 重建插件缓存
    rebuild_plugin_cache

    # 重建命令缓存
    rebuild_command_cache

    # 重建元数据缓存
    rebuild_metadata_cache
}

# 异步重建缓存（保留兼容性）
rebuild_cache_async() {
    rebuild_cache_sync
}

# 重建插件缓存
rebuild_plugin_cache() {
    local temp_cache="${GS_PLUGIN_CACHE}.tmp"
    
    {
        echo "# Global Scripts V3 插件缓存"
        echo "# 生成时间: $(date)"
        echo ""
        
        if [[ -d "${GS_PLUGINS_DIR}" ]]; then
            find "${GS_PLUGINS_DIR}" -name "*.meta" -type f | \
            while IFS= read -r meta_file; do
                local plugin_dir
                plugin_dir=$(dirname "$meta_file")
                local plugin_name
                plugin_name=$(basename "$plugin_dir")
                
                echo "PLUGIN:$plugin_name:$plugin_dir"
                
                # 读取元数据
                while IFS='=' read -r key value; do
                    [[ "$key" =~ ^[A-Z_]+$ ]] && echo "META:$plugin_name:$key:$value"
                done < "$meta_file"
            done
        fi
    } > "$temp_cache"
    
    mv "$temp_cache" "$GS_PLUGIN_CACHE" 2>/dev/null
}

# 重建命令缓存
rebuild_command_cache() {
    local temp_cache="${GS_COMMAND_CACHE}.tmp"
    
    {
        echo "# Global Scripts V3 命令缓存"
        echo "# 生成时间: $(date)"
        echo ""
        
        # 缓存系统命令
        if [[ -d "${GS_SYSTEM_DIR}" ]]; then
            find "${GS_SYSTEM_DIR}" -name "*.sh" -type f | \
            while IFS= read -r impl_file; do
                local cmd_name
                cmd_name=$(basename "$impl_file" .sh)
                
                # 扫描函数
                $_GS_GREP_CMD "^gs_system_" "$impl_file" 2>/dev/null | \
                while IFS= read -r line; do
                    local func_name
                    func_name=$(echo "$line" | $_GS_SED_CMD 's/().*//' | $_GS_AWK_CMD '{print $1}')
                    [[ -n "$func_name" ]] && echo "SYSTEM:$func_name:$impl_file"
                done
            done
        fi
        
        # 缓存插件命令
        if [[ -d "${GS_PLUGINS_DIR}" ]]; then
            find "${GS_PLUGINS_DIR}" -name "*.sh" -type f | \
            while IFS= read -r impl_file; do
                local plugin_name
                plugin_name=$(basename "$(dirname "$impl_file")")
                
                # 扫描函数
                $_GS_GREP_CMD "^gs_${plugin_name}_" "$impl_file" 2>/dev/null | \
                while IFS= read -r line; do
                    local func_name
                    func_name=$(echo "$line" | $_GS_SED_CMD 's/().*//' | $_GS_AWK_CMD '{print $1}')
                    [[ -n "$func_name" ]] && echo "PLUGIN:$func_name:$impl_file"
                done
            done
        fi
    } > "$temp_cache"
    
    mv "$temp_cache" "$GS_COMMAND_CACHE" 2>/dev/null
}

# 重建元数据缓存
rebuild_metadata_cache() {
    local temp_cache="${GS_METADATA_CACHE}.tmp"
    
    {
        # 第一行存储插件目录的哈希值
        if [[ -d "${GS_PLUGINS_DIR}" ]]; then
            find "${GS_PLUGINS_DIR}" -name "*.meta" -o -name "*.sh" | \
            xargs ls -la 2>/dev/null | \
            $_GS_SED_CMD 's/^[^ ]* *[^ ]* *[^ ]* *[^ ]* *[^ ]* *//' | \
            sort | md5sum 2>/dev/null | cut -d' ' -f1 || echo "unknown"
        else
            echo "no_plugins"
        fi
        
        echo "# 元数据缓存"
        echo "# 生成时间: $(date)"
        echo "# GS版本: $GS_VERSION"
        echo "# Shell: $_GS_SHELL_TYPE $_GS_SHELL_VERSION"
    } > "$temp_cache"
    
    mv "$temp_cache" "$GS_METADATA_CACHE" 2>/dev/null
}

# 清理缓存
clear_cache() {
    _gs_debug "cache_manager" "清理缓存..."
    
    rm -f "$GS_PLUGIN_CACHE" "$GS_COMMAND_CACHE" "$GS_METADATA_CACHE" 2>/dev/null
    
    _gs_debug "cache_manager" "缓存已清理"
}

# 获取缓存状态
get_cache_status() {
    echo "=== Global Scripts 缓存状态 ==="
    echo "缓存目录: $GS_CACHE_DIR"
    
    if [[ -f "$GS_PLUGIN_CACHE" ]]; then
        local size
        size=$(wc -l < "$GS_PLUGIN_CACHE" 2>/dev/null || echo "0")
        echo "插件缓存: 存在 ($size 行)"
    else
        echo "插件缓存: 不存在"
    fi
    
    if [[ -f "$GS_COMMAND_CACHE" ]]; then
        local size
        size=$(wc -l < "$GS_COMMAND_CACHE" 2>/dev/null || echo "0")
        echo "命令缓存: 存在 ($size 行)"
    else
        echo "命令缓存: 不存在"
    fi
    
    if [[ -f "$GS_METADATA_CACHE" ]]; then
        local mtime
        if command -v stat >/dev/null 2>&1; then
            mtime=$(stat -f%Sm "$GS_METADATA_CACHE" 2>/dev/null || stat -c%y "$GS_METADATA_CACHE" 2>/dev/null || echo "未知")
        else
            mtime="未知"
        fi
        echo "元数据缓存: 存在 (修改时间: $mtime)"
    else
        echo "元数据缓存: 不存在"
    fi
    
    if is_cache_valid; then
        echo "缓存状态: 有效"
    else
        echo "缓存状态: 无效或过期"
    fi
}
