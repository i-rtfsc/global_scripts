#!/bin/bash
# Global Scripts V3 - 基础工具库
# 版本: 3.0.0
# 描述: 提供最基础的工具函数，包括常量保护机制

# ============================================================================
# 基础变量存储机制（兼容Bash 3.x和Zsh）
# ============================================================================

# 简单的键值存储（不依赖关联数组）
_gs_base_set() {
    local namespace="$1"
    local key="$2"
    local value="$3"
    
    # 使用变量名编码：namespace_key
    local var_name="_GS_${namespace}_${key//[^a-zA-Z0-9]/_}"
    eval "$var_name=\"$value\""
}

_gs_base_get() {
    local namespace="$1"
    local key="$2"
    
    local var_name="_GS_${namespace}_${key//[^a-zA-Z0-9]/_}"
    eval "echo \"\${$var_name:-}\""
}

_gs_base_exists() {
    local namespace="$1"
    local key="$2"
    
    local var_name="_GS_${namespace}_${key//[^a-zA-Z0-9]/_}"
    eval "[[ -n \"\${$var_name:-}\" ]]"
}

# ============================================================================
# 常量保护机制（替代readonly）
# ============================================================================

# 设置常量（只能设置一次，除非强制）
_gs_set_constant() {
    local name="$1"
    local value="$2"
    local force="${3:-false}"
    
    # 检查是否已经设置
    if _gs_base_exists "CONSTANTS" "$name" && [[ "$force" != "true" ]]; then
        # 常量已存在，不允许修改
        [[ "${GS_DEBUG_MODE:-false}" == "true" ]] && \
        echo "[DEBUG:base] 常量 $name 已存在，跳过设置" >&2
        return 0
    fi
    
    # 设置常量值到存储
    _gs_base_set "CONSTANTS" "$name" "$value"
    
    # 同时设置为普通变量（供使用），避免只读变量错误
    eval "$name=\"$value\"" 2>/dev/null || true
    
    [[ "${GS_DEBUG_MODE:-false}" == "true" ]] && \
    echo "[DEBUG:base] 设置常量: $name=$value" >&2
}

# 获取常量值
_gs_get_constant() {
    local name="$1"
    _gs_base_get "CONSTANTS" "$name"
}

# 检查是否为常量
_gs_is_constant() {
    local name="$1"
    _gs_base_exists "CONSTANTS" "$name"
}

# 强制重新设置常量（用于重新加载）
_gs_reset_constant() {
    local name="$1"
    local value="$2"
    _gs_set_constant "$name" "$value" "true"
}

# 列出所有常量
_gs_list_constants() {
    echo "=== Global Scripts 常量列表 ==="
    
    # 列出所有_GS_CONSTANTS_*变量
    set | grep "^_GS_CONSTANTS_" | while IFS='=' read -r var_name var_value; do
        # 提取常量名
        local const_name="${var_name#_GS_CONSTANTS_}"
        const_name="${const_name//_/-}"  # 恢复原始名称
        echo "$const_name = $var_value"
    done
    
    echo "=========================="
}

# ============================================================================
# 基础工具函数
# ============================================================================

# 安全的变量设置（避免覆盖已存在的变量）
_gs_safe_set() {
    local name="$1"
    local value="$2"
    local force="${3:-false}"
    
    if [[ -n "${!name:-}" && "$force" != "true" ]]; then
        [[ "${GS_DEBUG_MODE:-false}" == "true" ]] && \
        echo "[DEBUG:base] 变量 $name 已存在，跳过设置" >&2
        return 0
    fi
    
    eval "$name=\"$value\""
}

# 检查变量是否已设置
_gs_is_set() {
    local name="$1"
    [[ -n "${!name:-}" ]]
}

# 获取变量值（带默认值）
_gs_get_var() {
    local name="$1"
    local default="$2"
    
    local value="${!name:-$default}"
    echo "$value"
}

# ============================================================================
# Shell检测（基础版本）
# ============================================================================

_gs_detect_shell_basic() {
    if [[ -n "${BASH_VERSION:-}" ]]; then
        echo "bash"
    elif [[ -n "${ZSH_VERSION:-}" ]]; then
        echo "zsh"
    else
        echo "unknown"
    fi
}

# ============================================================================
# 初始化基础库
# ============================================================================

# 设置基础常量
_gs_set_constant "_GS_BASE_LOADED" "true"
_gs_set_constant "_GS_BASE_VERSION" "3.0.0"
_gs_set_constant "_GS_SHELL_TYPE_BASIC" "$(_gs_detect_shell_basic)"

# 调试信息
if [[ "${GS_DEBUG_MODE:-false}" == "true" ]]; then
    echo "[DEBUG:base] 基础库已加载，Shell类型: $(_gs_detect_shell_basic)" >&2
fi
