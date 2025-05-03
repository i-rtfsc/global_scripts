#!/bin/bash
# declare兼容性测试 - tests/unit/test_declare_compat.sh

# 加载兼容性脚本
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/declare_compat.sh"
source "${SCRIPT_DIR}/../lib/time_compat.sh"

# 测试函数
test_declare_compat() {
    printf "=== declare兼容性测试 ===\n"
    gs_declare_info
    printf "\n"
    
    printf "测试关联数组功能:\n"
    gs_declare_A test_array
    
    gs_array_set test_array "key1" "value1"
    gs_array_set test_array "key with spaces" "value with spaces"
    gs_array_set test_array "key-with-dashes" "value-with-dashes"
    gs_array_set test_array "复杂key!@#$" "特殊值"
    
    printf "test_array[key1] = %s\n" "$(gs_array_get test_array "key1")"
    printf "test_array[key with spaces] = %s\n" "$(gs_array_get test_array "key with spaces")"
    printf "test_array[key-with-dashes] = %s\n" "$(gs_array_get test_array "key-with-dashes")" 
    printf "test_array[复杂key!@#$] = %s\n" "$(gs_array_get test_array "复杂key!@#$")"
    
    printf "\n所有键:\n"
    gs_array_keys test_array
    
    printf "\n测试函数检测:\n"
    test_function() { echo "test"; }
    if gs_declare_F test_function; then
        printf "✓ 函数test_function存在\n"
    else
        printf "✗ 函数test_function不存在\n"
    fi
    
    # 测试键存在性检查
    printf "\n测试键存在性:\n"
    if gs_array_exists test_array "key1"; then
        printf "✓ key1存在\n"
    else
        printf "✗ key1不存在\n"
    fi
    
    if gs_array_exists test_array "nonexistent"; then
        printf "✗ nonexistent不应该存在\n"
    else
        printf "✓ nonexistent正确不存在\n"
    fi
    
    # 测试原生vs兼容模式识别
    printf "\n模式识别测试:\n"
    if _gs_test_declare_A; then
        printf "✓ 检测到原生declare -A支持\n"
    else
        printf "✓ 检测到需要兼容模式\n"
    fi
    
    if _gs_test_declare_F; then
        printf "✓ 检测到原生declare -F支持\n"
    else
        printf "✓ 检测到需要declare -F兼容模式\n"
    fi
    
    gs_array_clear test_array
    printf "\n✓ 所有测试完成\n"
}

# 性能测试
test_performance() {
    printf "\n=== 性能测试 ===\n"
    
    local start_time end_time duration
    start_time=$(gs_time_ms)
    
    gs_declare_A perf_test
    for i in {1..100}; do
        gs_array_set perf_test "key_$i" "value_$i"
    done
    
    for i in {1..100}; do
        gs_array_get perf_test "key_$i" >/dev/null
    done
    
    end_time=$(gs_time_ms)
    duration=$(gs_time_diff_ms "$start_time" "$end_time")
    
    printf "100次设置+100次获取耗时: %s\n" "$(gs_time_format "$duration")"
    gs_array_clear perf_test
}

# 边界测试
test_edge_cases() {
    printf "\n=== 边界测试 ===\n"
    
    gs_declare_A edge_test
    
    # 测试空值
    gs_array_set edge_test "empty" ""
    if [[ "$(gs_array_get edge_test "empty")" == "" ]]; then
        printf "✓ 空值处理正确\n"
    else
        printf "✗ 空值处理错误\n"
    fi
    
    # 测试特殊字符key
    local special_keys=(
        "key with spaces"
        "key-with-dashes"
        "key_with_underscores"
        "key.with.dots"
        "key/with/slashes"
        "key@with#symbols"
        "中文键"
        "123numeric_start"
    )
    
    for key in "${special_keys[@]}"; do
        gs_array_set edge_test "$key" "test_value_$key"
        if [[ "$(gs_array_get edge_test "$key")" == "test_value_$key" ]]; then
            printf "✓ 特殊键处理正确: %s\n" "$key"
        else
            printf "✗ 特殊键处理错误: %s\n" "$key"
        fi
    done
    
    gs_array_clear edge_test
}

# 如果直接执行此脚本，运行所有测试
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    test_declare_compat
    test_performance  
    test_edge_cases
fi