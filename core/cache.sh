#!/bin/bash
# Global Scripts V3 - 缓存系统
# 作者: Solo
# 版本: 1.0.0
# 描述: 任务3.1 - 二级缓存系统实现，支持内存和磁盘缓存

# 加载依赖模块
if ! command -v gs_log_info >/dev/null 2>&1 && ! type gs_log_info >/dev/null 2>&1; then
    source "$(dirname "${BASH_SOURCE[0]:-$0}")/../lib/logger.sh"
fi

if ! command -v gs_time_ms >/dev/null 2>&1 && ! type gs_time_ms >/dev/null 2>&1; then
    source "$(dirname "${BASH_SOURCE[0]:-$0}")/../lib/time_compat.sh"
fi

if ! command -v gs_error >/dev/null 2>&1 && ! type gs_error >/dev/null 2>&1; then
    source "$(dirname "${BASH_SOURCE[0]:-$0}")/../lib/error.sh"
fi

# 缓存系统配置 - 避免使用declare语法，改用Shell+Python混合架构
_GS_CACHE_L1_MAX_SIZE="${_GS_CACHE_L1_MAX_SIZE:-100}"           # L1缓存最大条目数
_GS_CACHE_L1_DEFAULT_TTL="${_GS_CACHE_L1_DEFAULT_TTL:-300}"     # 默认TTL（秒）
_GS_CACHE_L2_DIR="${_GS_CACHE_L2_DIR:-$HOME/.gs/cache}"        # L2缓存目录
_GS_CACHE_L2_MAX_SIZE="${_GS_CACHE_L2_MAX_SIZE:-10485760}"     # L2缓存最大大小（10MB）
_GS_CACHE_CLEANUP_INTERVAL="${_GS_CACHE_CLEANUP_INTERVAL:-3600}" # 清理间隔（秒）

# 缓存状态变量 - 使用简单变量避免关联数组兼容性问题
_GS_CACHE_L1_DATA=""           # L1缓存数据，格式：key1:value1:timestamp1:access_count1|key2:value2:timestamp2:access_count2
_GS_CACHE_L1_ACCESS_ORDER=""   # L1访问顺序，用于LRU
_GS_CACHE_L1_COUNT=0           # L1缓存当前条目数
_GS_CACHE_STATS_HITS=0         # 缓存命中数
_GS_CACHE_STATS_MISSES=0       # 缓存未命中数
_GS_CACHE_STATS_EVICTIONS=0    # 缓存淘汰数

# 导出配置变量
export _GS_CACHE_L1_MAX_SIZE _GS_CACHE_L1_DEFAULT_TTL _GS_CACHE_L2_DIR
export _GS_CACHE_L2_MAX_SIZE _GS_CACHE_CLEANUP_INTERVAL

# =================================================================
# L1 内存缓存实现 (Shell实现，适合简单数据)
# =================================================================

# 初始化缓存系统
gs_cache_init() {
    gs_log_debug "初始化缓存系统"
    
    # 创建L2缓存目录
    if [[ ! -d "$_GS_CACHE_L2_DIR" ]]; then
        mkdir -p "$_GS_CACHE_L2_DIR" || {
            gs_error_config "无法创建缓存目录: $_GS_CACHE_L2_DIR"
            return 1
        }
    fi
    
    # 创建缓存索引文件
    local index_file="$_GS_CACHE_L2_DIR/.index"
    if [[ ! -f "$index_file" ]]; then
        echo "# Global Scripts V3 Cache Index" > "$index_file"
        echo "# Format: key:filename:timestamp:size" >> "$index_file"
    fi
    
    gs_log_info "缓存系统初始化完成"
    return 0
}

# L1缓存: 设置缓存项
gs_cache_l1_set() {
    local key="$1"
    local value="$2"
    local ttl="${3:-$_GS_CACHE_L1_DEFAULT_TTL}"
    
    [[ -n "$key" ]] || {
        gs_error_invalid_arg "缓存键不能为空"
        return 1
    }
    
    local current_time
    current_time=$(gs_time_ms)
    local expire_time=$((current_time / 1000 + ttl))
    
    # 检查缓存是否已满，需要淘汰
    if [[ $_GS_CACHE_L1_COUNT -ge $_GS_CACHE_L1_MAX_SIZE ]]; then
        _gs_cache_l1_evict_lru
    fi
    
    # 移除现有项（如果存在）
    _gs_cache_l1_remove "$key"
    
    # 添加新项
    local cache_entry="$key:$value:$expire_time:1"
    if [[ -n "$_GS_CACHE_L1_DATA" ]]; then
        _GS_CACHE_L1_DATA="$_GS_CACHE_L1_DATA|$cache_entry"
    else
        _GS_CACHE_L1_DATA="$cache_entry"
    fi
    
    # 更新访问顺序
    _gs_cache_l1_update_access_order "$key"
    
    _GS_CACHE_L1_COUNT=$((_GS_CACHE_L1_COUNT + 1))
    
    gs_log_debug "L1缓存设置: $key (TTL: ${ttl}秒)"
    return 0
}

# L1缓存: 获取缓存项
gs_cache_l1_get() {
    local key="$1"
    
    [[ -n "$key" ]] || {
        gs_error_invalid_arg "缓存键不能为空"
        return 1
    }
    
    local current_time
    current_time=$(($(gs_time_ms) / 1000))
    
    # 查找缓存项
    local entry
    entry=$(_gs_cache_l1_find_entry "$key")
    
    if [[ -z "$entry" ]]; then
        _GS_CACHE_STATS_MISSES=$((_GS_CACHE_STATS_MISSES + 1))
        gs_log_debug "L1缓存未命中: $key"
        return 1
    fi
    
    # 解析缓存项
    local cached_key cached_value expire_time access_count
    IFS=':' read -r cached_key cached_value expire_time access_count <<< "$entry"
    
    # 检查是否过期
    if [[ $current_time -gt $expire_time ]]; then
        _gs_cache_l1_remove "$key"
        _GS_CACHE_STATS_MISSES=$((_GS_CACHE_STATS_MISSES + 1))
        gs_log_debug "L1缓存过期: $key"
        return 1
    fi
    
    # 更新访问次数和访问顺序
    access_count=$((access_count + 1))
    _gs_cache_l1_update_entry "$key" "$cached_value" "$expire_time" "$access_count"
    _gs_cache_l1_update_access_order "$key"
    
    _GS_CACHE_STATS_HITS=$((_GS_CACHE_STATS_HITS + 1))
    gs_log_debug "L1缓存命中: $key"
    echo "$cached_value"
    return 0
}

# L1缓存: 检查缓存项是否存在
gs_cache_l1_exists() {
    local key="$1"
    
    [[ -n "$key" ]] || return 1
    
    local entry
    entry=$(_gs_cache_l1_find_entry "$key")
    
    if [[ -z "$entry" ]]; then
        return 1
    fi
    
    # 检查是否过期
    local current_time
    current_time=$(($(gs_time_ms) / 1000))
    local expire_time
    expire_time=$(echo "$entry" | cut -d':' -f3)
    
    if [[ $current_time -gt $expire_time ]]; then
        _gs_cache_l1_remove "$key"
        return 1
    fi
    
    return 0
}

# L1缓存: 删除缓存项
gs_cache_l1_delete() {
    local key="$1"
    
    [[ -n "$key" ]] || {
        gs_error_invalid_arg "缓存键不能为空"
        return 1
    }
    
    if _gs_cache_l1_remove "$key"; then
        gs_log_debug "L1缓存删除: $key"
        return 0
    else
        gs_log_debug "L1缓存删除失败，键不存在: $key"
        return 1
    fi
}

# L1缓存: 清空所有缓存
gs_cache_l1_clear() {
    _GS_CACHE_L1_DATA=""
    _GS_CACHE_L1_ACCESS_ORDER=""
    _GS_CACHE_L1_COUNT=0
    
    gs_log_info "L1缓存已清空"
    return 0
}

# =================================================================
# L1 缓存内部辅助函数
# =================================================================

# 查找缓存项
_gs_cache_l1_find_entry() {
    local key="$1"
    
    if [[ -z "$_GS_CACHE_L1_DATA" ]]; then
        return 1
    fi
    
    # 使用while循环遍历缓存项
    local entry
    local IFS_backup="$IFS"
    IFS='|'
    for entry in $_GS_CACHE_L1_DATA; do
        local cached_key
        cached_key=$(echo "$entry" | cut -d':' -f1)
        if [[ "$cached_key" == "$key" ]]; then
            echo "$entry"
            IFS="$IFS_backup"
            return 0
        fi
    done
    IFS="$IFS_backup"
    
    return 1
}

# 移除缓存项
_gs_cache_l1_remove() {
    local key="$1"
    
    if [[ -z "$_GS_CACHE_L1_DATA" ]]; then
        return 1
    fi
    
    local new_data=""
    local found=false
    local entry
    local IFS_backup="$IFS"
    IFS='|'
    for entry in $_GS_CACHE_L1_DATA; do
        local cached_key
        cached_key=$(echo "$entry" | cut -d':' -f1)
        if [[ "$cached_key" != "$key" ]]; then
            if [[ -n "$new_data" ]]; then
                new_data="$new_data|$entry"
            else
                new_data="$entry"
            fi
        else
            found=true
        fi
    done
    IFS="$IFS_backup"
    
    if [[ "$found" == "true" ]]; then
        _GS_CACHE_L1_DATA="$new_data"
        _GS_CACHE_L1_COUNT=$((_GS_CACHE_L1_COUNT - 1))
        
        # 从访问顺序中移除
        _gs_cache_l1_remove_from_access_order "$key"
        return 0
    fi
    
    return 1
}

# 更新缓存项
_gs_cache_l1_update_entry() {
    local key="$1"
    local value="$2"
    local expire_time="$3"
    local access_count="$4"
    
    local new_data=""
    local entry
    local IFS_backup="$IFS"
    IFS='|'
    for entry in $_GS_CACHE_L1_DATA; do
        local cached_key
        cached_key=$(echo "$entry" | cut -d':' -f1)
        if [[ "$cached_key" == "$key" ]]; then
            entry="$key:$value:$expire_time:$access_count"
        fi
        
        if [[ -n "$new_data" ]]; then
            new_data="$new_data|$entry"
        else
            new_data="$entry"
        fi
    done
    IFS="$IFS_backup"
    
    _GS_CACHE_L1_DATA="$new_data"
}

# LRU淘汰策略：淘汰最近最少使用的项
_gs_cache_l1_evict_lru() {
    if [[ -z "$_GS_CACHE_L1_ACCESS_ORDER" ]]; then
        return 0
    fi
    
    # 获取最老的访问项（第一个）
    local oldest_key
    oldest_key=$(echo "$_GS_CACHE_L1_ACCESS_ORDER" | cut -d'|' -f1)
    
    if [[ -n "$oldest_key" ]]; then
        _gs_cache_l1_remove "$oldest_key"
        _GS_CACHE_STATS_EVICTIONS=$((_GS_CACHE_STATS_EVICTIONS + 1))
        gs_log_debug "LRU淘汰缓存项: $oldest_key"
    fi
}

# 更新访问顺序
_gs_cache_l1_update_access_order() {
    local key="$1"
    
    # 先从访问顺序中移除（如果存在）
    _gs_cache_l1_remove_from_access_order "$key"
    
    # 添加到访问顺序末尾
    if [[ -n "$_GS_CACHE_L1_ACCESS_ORDER" ]]; then
        _GS_CACHE_L1_ACCESS_ORDER="$_GS_CACHE_L1_ACCESS_ORDER|$key"
    else
        _GS_CACHE_L1_ACCESS_ORDER="$key"
    fi
}

# 从访问顺序中移除
_gs_cache_l1_remove_from_access_order() {
    local key="$1"
    
    if [[ -z "$_GS_CACHE_L1_ACCESS_ORDER" ]]; then
        return 0
    fi
    
    local new_order=""
    local access_key
    local IFS_backup="$IFS"
    IFS='|'
    for access_key in $_GS_CACHE_L1_ACCESS_ORDER; do
        if [[ "$access_key" != "$key" ]]; then
            if [[ -n "$new_order" ]]; then
                new_order="$new_order|$access_key"
            else
                new_order="$access_key"
            fi
        fi
    done
    IFS="$IFS_backup"
    
    _GS_CACHE_L1_ACCESS_ORDER="$new_order"
}

# =================================================================
# L2 磁盘缓存实现 (使用文件系统)
# =================================================================

# L2缓存: 设置缓存项
gs_cache_l2_set() {
    local key="$1"
    local value="$2"
    local ttl="${3:-$_GS_CACHE_L1_DEFAULT_TTL}"
    
    [[ -n "$key" ]] || {
        gs_error_invalid_arg "缓存键不能为空"
        return 1
    }
    
    # 确保缓存目录存在
    [[ -d "$_GS_CACHE_L2_DIR" ]] || gs_cache_init
    
    local current_time
    current_time=$(gs_time_ms)
    local expire_time=$((current_time / 1000 + ttl))
    
    # 生成安全的文件名
    local filename
    filename=$(_gs_cache_generate_filename "$key")
    local cache_file="$_GS_CACHE_L2_DIR/$filename"
    
    # 写入缓存文件
    {
        echo "# Global Scripts V3 Cache Entry"
        echo "# Key: $key"
        echo "# Created: $(date -d "@$((current_time / 1000))" 2>/dev/null || date -r $((current_time / 1000)) 2>/dev/null || date)"
        echo "# Expires: $(date -d "@$expire_time" 2>/dev/null || date -r $expire_time 2>/dev/null || date)"
        echo "CACHE_KEY=$key"
        echo "CACHE_EXPIRE_TIME=$expire_time"
        echo "CACHE_CREATED_TIME=$((current_time / 1000))"
        echo "---CACHE_DATA_START---"
        echo "$value"
        echo "---CACHE_DATA_END---"
    } > "$cache_file" || {
        gs_error_disk_space "无法写入缓存文件: $cache_file"
        return 1
    }
    
    # 更新索引
    _gs_cache_l2_update_index "$key" "$filename" "$expire_time" "$(wc -c < "$cache_file")"
    
    # 检查磁盘缓存大小限制
    _gs_cache_l2_check_size_limit
    
    gs_log_debug "L2缓存设置: $key -> $filename"
    return 0
}

# L2缓存: 获取缓存项
gs_cache_l2_get() {
    local key="$1"
    
    [[ -n "$key" ]] || {
        gs_error_invalid_arg "缓存键不能为空"
        return 1
    }
    
    local filename
    filename=$(_gs_cache_generate_filename "$key")
    local cache_file="$_GS_CACHE_L2_DIR/$filename"
    
    if [[ ! -f "$cache_file" ]]; then
        gs_log_debug "L2缓存文件不存在: $cache_file"
        return 1
    fi
    
    # 读取缓存元数据
    local cache_key cache_expire_time
    cache_key=$(command grep '^CACHE_KEY=' "$cache_file" 2>/dev/null | cut -d'=' -f2)
    cache_expire_time=$(command grep '^CACHE_EXPIRE_TIME=' "$cache_file" 2>/dev/null | cut -d'=' -f2)
    
    # 验证缓存键
    if [[ "$cache_key" != "$key" ]]; then
        gs_log_warn "L2缓存键不匹配: 期望$key, 实际$cache_key"
        return 1
    fi
    
    # 检查是否过期
    local current_time
    current_time=$(($(gs_time_ms) / 1000))
    if [[ $current_time -gt $cache_expire_time ]]; then
        gs_log_debug "L2缓存过期: $key"
        rm -f "$cache_file" 2>/dev/null
        _gs_cache_l2_remove_from_index "$key"
        return 1
    fi
    
    # 提取缓存数据
    sed -n '/---CACHE_DATA_START---/,/---CACHE_DATA_END---/p' "$cache_file" | \
        sed '1d;$d'
    
    gs_log_debug "L2缓存命中: $key"
    return 0
}

# L2缓存: 检查缓存项是否存在
gs_cache_l2_exists() {
    local key="$1"
    
    [[ -n "$key" ]] || return 1
    
    local filename
    filename=$(_gs_cache_generate_filename "$key")
    local cache_file="$_GS_CACHE_L2_DIR/$filename"
    
    if [[ ! -f "$cache_file" ]]; then
        return 1
    fi
    
    # 检查是否过期
    local cache_expire_time
    cache_expire_time=$(command grep '^CACHE_EXPIRE_TIME=' "$cache_file" 2>/dev/null | cut -d'=' -f2)
    
    local current_time
    current_time=$(($(gs_time_ms) / 1000))
    
    if [[ $current_time -gt $cache_expire_time ]]; then
        rm -f "$cache_file" 2>/dev/null
        _gs_cache_l2_remove_from_index "$key"
        return 1
    fi
    
    return 0
}

# L2缓存: 删除缓存项
gs_cache_l2_delete() {
    local key="$1"
    
    [[ -n "$key" ]] || {
        gs_error_invalid_arg "缓存键不能为空"
        return 1
    }
    
    local filename
    filename=$(_gs_cache_generate_filename "$key")
    local cache_file="$_GS_CACHE_L2_DIR/$filename"
    
    if [[ -f "$cache_file" ]]; then
        rm -f "$cache_file" || {
            gs_error_permission "无法删除缓存文件: $cache_file"
            return 1
        }
        _gs_cache_l2_remove_from_index "$key"
        gs_log_debug "L2缓存删除: $key"
        return 0
    else
        gs_log_debug "L2缓存删除失败，文件不存在: $cache_file"
        return 1
    fi
}

# L2缓存: 清空所有缓存
gs_cache_l2_clear() {
    if [[ -d "$_GS_CACHE_L2_DIR" ]]; then
        rm -rf "$_GS_CACHE_L2_DIR"/* 2>/dev/null || {
            gs_error_permission "无法清空缓存目录: $_GS_CACHE_L2_DIR"
            return 1
        }
        
        # 重新创建索引文件
        local index_file="$_GS_CACHE_L2_DIR/.index"
        echo "# Global Scripts V3 Cache Index" > "$index_file"
        echo "# Format: key:filename:timestamp:size" >> "$index_file"
    fi
    
    gs_log_info "L2缓存已清空"
    return 0
}

# =================================================================
# L2 缓存内部辅助函数
# =================================================================

# 生成安全的文件名
_gs_cache_generate_filename() {
    local key="$1"
    
    # 使用SHA1哈希生成安全文件名，如果没有可用的工具则使用简单替换
    if command -v sha1sum >/dev/null 2>&1; then
        echo -n "$key" | sha1sum | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        echo -n "$key" | shasum -a 1 | cut -d' ' -f1
    else
        # 简单的字符替换作为备选方案
        echo "$key" | tr '/' '_' | tr ' ' '_' | tr ':' '_'
    fi
}

# 更新L2缓存索引
_gs_cache_l2_update_index() {
    local key="$1"
    local filename="$2"
    local expire_time="$3"
    local size="$4"
    
    local index_file="$_GS_CACHE_L2_DIR/.index"
    
    # 移除旧的索引项
    _gs_cache_l2_remove_from_index "$key"
    
    # 添加新的索引项
    echo "$key:$filename:$expire_time:$size" >> "$index_file"
}

# 从L2缓存索引中移除项
_gs_cache_l2_remove_from_index() {
    local key="$1"
    local index_file="$_GS_CACHE_L2_DIR/.index"
    
    if [[ -f "$index_file" ]]; then
        local temp_file
        temp_file=$(mktemp)
        command grep -v "^$key:" "$index_file" > "$temp_file" 2>/dev/null
        mv "$temp_file" "$index_file"
    fi
}

# 检查L2缓存大小限制
_gs_cache_l2_check_size_limit() {
    local current_size
    current_size=$(du -sb "$_GS_CACHE_L2_DIR" 2>/dev/null | cut -f1)
    
    # 如果当前大小超过限制，清理最老的缓存
    while [[ $current_size -gt $_GS_CACHE_L2_MAX_SIZE ]]; do
        local oldest_file
        oldest_file=$(_gs_cache_l2_find_oldest_file)
        
        if [[ -n "$oldest_file" && -f "$oldest_file" ]]; then
            local key
            key=$(command grep '^CACHE_KEY=' "$oldest_file" 2>/dev/null | cut -d'=' -f2)
            rm -f "$oldest_file"
            [[ -n "$key" ]] && _gs_cache_l2_remove_from_index "$key"
            
            current_size=$(du -sb "$_GS_CACHE_L2_DIR" 2>/dev/null | cut -f1)
            gs_log_debug "L2缓存大小限制清理: $oldest_file"
        else
            break
        fi
    done
}

# 查找最老的L2缓存文件
_gs_cache_l2_find_oldest_file() {
    find "$_GS_CACHE_L2_DIR" -type f -name "*.cache" -o -name "[a-f0-9]*" 2>/dev/null | \
        head -1
}

# =================================================================
# 统一缓存接口 (L1 -> L2 -> 原始数据)
# =================================================================

# 统一缓存设置
gs_cache_set() {
    local key="$1"
    local value="$2"
    local ttl="${3:-$_GS_CACHE_L1_DEFAULT_TTL}"
    
    # 同时设置L1和L2缓存
    gs_cache_l1_set "$key" "$value" "$ttl"
    gs_cache_l2_set "$key" "$value" "$ttl"
}

# 统一缓存获取
gs_cache_get() {
    local key="$1"
    
    # 先尝试L1缓存
    local value
    if value=$(gs_cache_l1_get "$key"); then
        echo "$value"
        return 0
    fi
    
    # 再尝试L2缓存
    if value=$(gs_cache_l2_get "$key"); then
        # 将L2缓存的值回填到L1缓存
        gs_cache_l1_set "$key" "$value" "$_GS_CACHE_L1_DEFAULT_TTL"
        echo "$value"
        return 0
    fi
    
    return 1
}

# 统一缓存存在检查
gs_cache_exists() {
    local key="$1"
    
    gs_cache_l1_exists "$key" || gs_cache_l2_exists "$key"
}

# 统一缓存删除
gs_cache_delete() {
    local key="$1"
    
    local l1_result l2_result
    gs_cache_l1_delete "$key"
    l1_result=$?
    gs_cache_l2_delete "$key"
    l2_result=$?
    
    # 如果任一层删除成功，视为成功
    [[ $l1_result -eq 0 || $l2_result -eq 0 ]]
}

# 统一缓存清空
gs_cache_clear() {
    gs_cache_l1_clear
    gs_cache_l2_clear
}

# =================================================================
# 缓存统计和管理
# =================================================================

# 获取缓存统计信息
gs_cache_stats() {
    local format="${1:-text}"
    
    case "$format" in
        json)
            local json_output
            json_output=$(cat << EOF
{
    "l1_cache": {
        "count": $_GS_CACHE_L1_COUNT,
        "max_size": $_GS_CACHE_L1_MAX_SIZE,
        "hit_rate": $(awk "BEGIN {printf \"%.2f\", $_GS_CACHE_STATS_HITS / ($_GS_CACHE_STATS_HITS + $_GS_CACHE_STATS_MISSES + 0.01) * 100}")
    },
    "l2_cache": {
        "directory": "$_GS_CACHE_L2_DIR",
        "size_bytes": $(du -sb "$_GS_CACHE_L2_DIR" 2>/dev/null | cut -f1 || echo 0),
        "max_size_bytes": $_GS_CACHE_L2_MAX_SIZE
    },
    "statistics": {
        "hits": $_GS_CACHE_STATS_HITS,
        "misses": $_GS_CACHE_STATS_MISSES,
        "evictions": $_GS_CACHE_STATS_EVICTIONS
    }
}
EOF
)
            echo "$json_output" | jq . 2>/dev/null || echo "$json_output"
            ;;
        *)
            echo "📊 缓存系统统计"
            echo "================="
            echo "L1 内存缓存:"
            echo "  当前条目数: $_GS_CACHE_L1_COUNT / $_GS_CACHE_L1_MAX_SIZE"
            echo "  命中率: $(awk "BEGIN {printf \"%.2f%%\", $_GS_CACHE_STATS_HITS / ($_GS_CACHE_STATS_HITS + $_GS_CACHE_STATS_MISSES + 0.01) * 100}")"
            echo ""
            echo "L2 磁盘缓存:"
            echo "  缓存目录: $_GS_CACHE_L2_DIR"
            echo "  当前大小: $(du -sh "$_GS_CACHE_L2_DIR" 2>/dev/null | cut -f1 || echo "0B")"
            echo "  最大大小: $(((_GS_CACHE_L2_MAX_SIZE + 1048575) / 1048576))MB"
            echo ""
            echo "统计信息:"
            echo "  缓存命中: $_GS_CACHE_STATS_HITS"
            echo "  缓存未命中: $_GS_CACHE_STATS_MISSES"
            echo "  缓存淘汰: $_GS_CACHE_STATS_EVICTIONS"
            ;;
    esac
}

# 缓存清理任务
gs_cache_cleanup() {
    local force="${1:-false}"
    
    gs_log_info "开始缓存清理任务"
    
    local current_time
    current_time=$(($(gs_time_ms) / 1000))
    local cleaned_count=0
    
    # 清理过期的L1缓存项
    if [[ -n "$_GS_CACHE_L1_DATA" ]]; then
        local new_data=""
        local new_order=""
        local entry
        local IFS_backup="$IFS"
        IFS='|'
        for entry in $_GS_CACHE_L1_DATA; do
            local key expire_time
            key=$(echo "$entry" | cut -d':' -f1)
            expire_time=$(echo "$entry" | cut -d':' -f3)
            
            if [[ "$force" == "true" || $current_time -gt $expire_time ]]; then
                cleaned_count=$((cleaned_count + 1))
                # 从访问顺序中移除
                _gs_cache_l1_remove_from_access_order "$key"
            else
                if [[ -n "$new_data" ]]; then
                    new_data="$new_data|$entry"
                else
                    new_data="$entry"
                fi
            fi
        done
        IFS="$IFS_backup"
        
        _GS_CACHE_L1_DATA="$new_data"
        _GS_CACHE_L1_COUNT=$(echo "$_GS_CACHE_L1_DATA" | tr '|' '\n' | wc -l)
        [[ -z "$_GS_CACHE_L1_DATA" ]] && _GS_CACHE_L1_COUNT=0
    fi
    
    # 清理过期的L2缓存文件
    if [[ -d "$_GS_CACHE_L2_DIR" ]]; then
        local cache_file
        while IFS= read -r -d '' cache_file; do
            if [[ -f "$cache_file" ]]; then
                local cache_expire_time
                cache_expire_time=$(command grep '^CACHE_EXPIRE_TIME=' "$cache_file" 2>/dev/null | cut -d'=' -f2)
                
                if [[ "$force" == "true" || ( -n "$cache_expire_time" && $current_time -gt $cache_expire_time ) ]]; then
                    local cache_key
                    cache_key=$(command grep '^CACHE_KEY=' "$cache_file" 2>/dev/null | cut -d'=' -f2)
                    rm -f "$cache_file" 2>/dev/null
                    [[ -n "$cache_key" ]] && _gs_cache_l2_remove_from_index "$cache_key"
                    cleaned_count=$((cleaned_count + 1))
                fi
            fi
        done < <(find "$_GS_CACHE_L2_DIR" -type f \( -name "*.cache" -o -name "[a-f0-9]*" \) -print0 2>/dev/null)
    fi
    
    gs_log_info "缓存清理完成，清理了 $cleaned_count 个过期项"
    return 0
}

# 缓存健康检查
gs_cache_health_check() {
    local issues=0
    
    echo "🏥 缓存系统健康检查"
    echo "==================="
    
    # 检查L2缓存目录
    if [[ ! -d "$_GS_CACHE_L2_DIR" ]]; then
        echo "❌ L2缓存目录不存在: $_GS_CACHE_L2_DIR"
        issues=$((issues + 1))
    elif [[ ! -w "$_GS_CACHE_L2_DIR" ]]; then
        echo "❌ L2缓存目录不可写: $_GS_CACHE_L2_DIR"
        issues=$((issues + 1))
    else
        echo "✅ L2缓存目录正常: $_GS_CACHE_L2_DIR"
    fi
    
    # 检查缓存大小
    if [[ -d "$_GS_CACHE_L2_DIR" ]]; then
        local current_size
        current_size=$(du -sb "$_GS_CACHE_L2_DIR" 2>/dev/null | cut -f1 || echo 0)
        local size_percentage
        size_percentage=$((current_size * 100 / _GS_CACHE_L2_MAX_SIZE))
        
        if [[ $size_percentage -gt 90 ]]; then
            echo "⚠️  L2缓存使用率过高: ${size_percentage}%"
            issues=$((issues + 1))
        else
            echo "✅ L2缓存使用率正常: ${size_percentage}%"
        fi
    fi
    
    # 检查L1缓存
    local l1_percentage
    l1_percentage=$((_GS_CACHE_L1_COUNT * 100 / _GS_CACHE_L1_MAX_SIZE))
    if [[ $l1_percentage -gt 90 ]]; then
        echo "⚠️  L1缓存使用率过高: ${l1_percentage}%"
        issues=$((issues + 1))
    else
        echo "✅ L1缓存使用率正常: ${l1_percentage}%"
    fi
    
    # 检查命中率
    local hit_rate
    hit_rate=$(awk "BEGIN {printf \"%.2f\", $_GS_CACHE_STATS_HITS / ($_GS_CACHE_STATS_HITS + $_GS_CACHE_STATS_MISSES + 0.01) * 100}")
    if awk "BEGIN {exit ($hit_rate < 50)}"; then
        echo "⚠️  缓存命中率较低: ${hit_rate}%"
        issues=$((issues + 1))
    else
        echo "✅ 缓存命中率正常: ${hit_rate}%"
    fi
    
    echo ""
    if [[ $issues -eq 0 ]]; then
        echo "🎉 缓存系统健康状况良好"
        return 0
    else
        echo "⚠️  发现 $issues 个问题需要关注"
        return 1
    fi
}