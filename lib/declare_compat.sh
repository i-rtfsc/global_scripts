#!/bin/bash
# declare兼容性脚本 - lib/declare_compat.sh
# 智能检测并使用原生或兼容实现

# 检测bash版本
BASH_MAJOR_VERSION="${BASH_VERSION:-3.0.0}"
BASH_MAJOR_VERSION="${BASH_MAJOR_VERSION%%.*}"
[[ -z "${BASH_MAJOR_VERSION:-}" ]] && BASH_MAJOR_VERSION="3"

# 动态检测declare -A支持
_gs_test_declare_A() {
    declare -A __test_array 2>/dev/null
    local result=$?
    unset __test_array 2>/dev/null
    return $result
}

# 动态检测declare -F支持
_gs_test_declare_F() {
    declare -F >/dev/null 2>&1
}

# 智能关联数组声明 - 自动选择原生或兼容模式
gs_declare_A() {
    local array_name="$1"
    
    if _gs_test_declare_A; then
        # 使用原生declare -A
        eval "declare -A ${array_name}"
    else
        # 使用兼容模式初始化
        eval "${array_name}__INIT=1"
    fi
}

# 智能数组设置
gs_array_set() {
    local array_name="$1"
    local key="$2" 
    local value="$3"
    
    if _gs_test_declare_A; then
        # 使用原生关联数组
        eval "${array_name}[\"\$key\"]=\"\$value\""
    else
        # 使用兼容模式
        local safe_key
        safe_key=$(printf '%s' "$key" | sed 's/[^a-zA-Z0-9]/_/g')
        [[ "$safe_key" =~ ^[0-9] ]] && safe_key="_${safe_key}"
        
        local var_name="${array_name}__${safe_key}" 
        eval "${var_name}=\"\$value\""
        
        # 维护key映射表
        local keymap_var="${array_name}__KEYMAP"
        eval "local current_map=\"\${${keymap_var}}\""
        if [[ "$current_map" != *"${safe_key}:${key};"* ]]; then
            eval "${keymap_var}=\"\${current_map}${safe_key}:\${key};\""
        fi
    fi
}

# 智能数组获取
gs_array_get() {
    local array_name="$1"
    local key="$2"
    
    if _gs_test_declare_A; then
        # 使用原生关联数组
        eval "printf '%s' \"\${${array_name}[\"\$key\"]}\""
    else
        # 使用兼容模式
        local safe_key
        safe_key=$(printf '%s' "$key" | sed 's/[^a-zA-Z0-9]/_/g')
        [[ "$safe_key" =~ ^[0-9] ]] && safe_key="_${safe_key}"
        
        local var_name="${array_name}__${safe_key}"
        eval "printf '%s' \"\${${var_name}}\""
    fi
}

# 智能键存在检查
gs_array_exists() {
    local array_name="$1"
    local key="$2"
    
    if _gs_test_declare_A; then
        # 使用原生关联数组
        eval "[[ -n \"\${${array_name}[\"\$key\"]}\" ]]"
    else
        # 使用兼容模式
        local safe_key
        safe_key=$(printf '%s' "$key" | sed 's/[^a-zA-Z0-9]/_/g')
        [[ "$safe_key" =~ ^[0-9] ]] && safe_key="_${safe_key}"
        
        local var_name="${array_name}__${safe_key}"
        eval "[[ -n \"\${${var_name}}\" ]]"
    fi
}

# 智能键列表获取
gs_array_keys() {
    local array_name="$1"
    
    if _gs_test_declare_A; then
        # 使用原生关联数组
        eval "printf '%s\\n' \"\${!${array_name}[@]}\""
    else
        # 使用兼容模式
        local keymap_var="${array_name}__KEYMAP"
        eval "local keymap=\"\${${keymap_var}}\""
        
        if [[ -n "$keymap" ]]; then
            printf '%s' "$keymap" | tr ';' '\n' | while IFS=':' read -r safe_key orig_key; do
                [[ -n "$orig_key" ]] && printf '%s\n' "$orig_key"
            done
        fi
    fi
}

# 智能数组清空
gs_array_clear() {
    local array_name="$1"
    
    if _gs_test_declare_A; then
        # 使用原生关联数组
        eval "unset ${array_name}; declare -A ${array_name}"
    else
        # 使用兼容模式
        set | grep "^${array_name}__" | cut -d'=' -f1 | while read -r var_name; do
            unset "$var_name" 2>/dev/null
        done
    fi
}

# 智能函数检测
gs_declare_F() {
    local func_name="$1"
    
    if _gs_test_declare_F; then
        # 使用原生declare -F
        if [[ -n "$func_name" ]]; then
            declare -F "$func_name" >/dev/null 2>&1
        else
            declare -F
        fi
    else
        # 使用兼容实现
        if [[ -n "$func_name" ]]; then
            type "$func_name" 2>/dev/null | grep -q "function\|is a function"
        else
            compgen -A function 2>/dev/null || set | awk '/^[a-zA-Z_][a-zA-Z0-9_]* *\(\)/ {gsub(/\(\).*/, "", $1); print $1}'
        fi
    fi
}

# 变量检查 (declare -p通常都支持，但提供兼容实现)
gs_declare_p() {
    local var_name="$1"
    if [[ -n "$var_name" ]]; then
        if declare -p "$var_name" >/dev/null 2>&1; then
            declare -p "$var_name"
        else
            eval "printf '%s=\"%s\"\\n' '$var_name' \"\${${var_name}}\""
        fi
    else
        declare -p 2>/dev/null || set | grep '^[a-zA-Z_][a-zA-Z0-9_]*='
    fi
}

# 导出兼容性信息
export BASH_MAJOR_VERSION

# 调试信息
gs_declare_info() {
    printf "Bash版本: %s\n" "${BASH_VERSION:-未知}"
    printf "主版本号: %s\n" "$BASH_MAJOR_VERSION"
    printf "declare -A支持: %s\n" "$(_gs_test_declare_A && echo "原生" || echo "兼容")"
    printf "declare -F支持: %s\n" "$(_gs_test_declare_F && echo "原生" || echo "兼容")"
}