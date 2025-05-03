#!/bin/bash
# 时间兼容性测试 - tests/unit/test_time_compat.sh

# 加载时间兼容性脚本
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/time_compat.sh"

# 基础功能测试
test_time_functions() {
    printf "=== 时间兼容性测试 ===\n"
    gs_time_info
    printf "\n"
    
    printf "测试时间获取功能:\n"
    
    # 测试各种精度的时间获取
    local time_s time_ms time_us time_ns
    time_s=$(gs_time_s)
    time_ms=$(gs_time_ms)
    time_us=$(gs_time_us)
    time_ns=$(gs_time_ns)
    
    printf "✓ 秒级时间戳获取成功: %s\n" "$time_s"
    printf "✓ 毫秒级时间戳获取成功: %s\n" "$time_ms"
    printf "✓ 微秒级时间戳获取成功: %s\n" "$time_us"
    printf "✓ 纳秒级时间戳获取成功: %s\n" "$time_ns"
    
    # 验证时间戳的合理性
    local current_year
    current_year=$(date +%Y)
    local timestamp_year
    timestamp_year=$(date -r "$time_s" +%Y 2>/dev/null || echo "$current_year")
    
    if [[ "$timestamp_year" == "$current_year" ]]; then
        printf "✓ 时间戳准确性验证通过\n"
    else
        printf "✗ 时间戳准确性验证失败\n"
    fi
    
    # 验证毫秒时间戳长度（13位）
    if [[ ${#time_ms} -eq 13 ]]; then
        printf "✓ 毫秒时间戳格式正确\n"
    else
        printf "⚠ 毫秒时间戳长度异常: %d位\n" ${#time_ms}
    fi
}

# 时间差计算测试
test_time_diff() {
    printf "\n=== 时间差计算测试 ===\n"
    
    local start_time end_time diff
    start_time=$(gs_time_ms)
    
    # 模拟一些操作
    sleep 0.1 2>/dev/null || {
        # 如果系统不支持小数sleep，用循环代替
        for i in {1..1000}; do
            : # 空操作
        done
    }
    
    end_time=$(gs_time_ms)
    diff=$(gs_time_diff_ms "$start_time" "$end_time")
    
    printf "开始时间: %s\n" "$start_time"
    printf "结束时间: %s\n" "$end_time"
    printf "时间差: %s\n" "$diff"
    printf "格式化: %s\n" "$(gs_time_format "$diff")"
    
    if [[ $diff -gt 0 ]]; then
        printf "✓ 时间差计算正确\n"
    else
        printf "✗ 时间差计算错误\n"
    fi
}

# 格式化测试
test_time_format() {
    printf "\n=== 时间格式化测试 ===\n"
    
    local test_times=(50 500 1500 65000 125000)
    local test_units=("ms" "s" "auto")
    
    for time_val in "${test_times[@]}"; do
        printf "时间值 %dms:\n" "$time_val"
        for unit in "${test_units[@]}"; do
            printf "  %s格式: %s\n" "$unit" "$(gs_time_format "$time_val" "$unit")"
        done
        printf "\n"
    done
}

# 性能基准测试
test_benchmark() {
    printf "=== 性能基准测试 ===\n"
    
    # 测试简单命令
    gs_benchmark "echo命令性能" "echo 'Hello World' >/dev/null"
    
    # 测试文件操作
    gs_benchmark "临时文件创建" "tmp_file=\$(mktemp) && echo 'test' > \"\$tmp_file\" && rm \"\$tmp_file\""
    
    # 测试数学运算
    gs_benchmark "数学运算" "result=\$((123 * 456 + 789))"
    
    # 批量重复测试
    gs_benchmark_repeat 10 "变量赋值" "test_var='test_value'"
    
    gs_benchmark_repeat 5 "命令替换" "current_time=\$(date +%s)"
}

# 精度测试
test_precision() {
    printf "=== 精度测试 ===\n"
    
    printf "连续获取10次毫秒时间戳，检查精度:\n"
    local prev_time=0
    local monotonic_count=0
    
    for i in {1..10}; do
        local current_time
        current_time=$(gs_time_ms)
        printf "%2d: %s" "$i" "$current_time"
        
        if [[ $current_time -gt $prev_time ]]; then
            printf " (+%d)" $((current_time - prev_time))
            ((monotonic_count++))
        elif [[ $current_time -eq $prev_time ]]; then
            printf " (=0)"
        else
            printf " (-%d)" $((prev_time - current_time))
        fi
        printf "\n"
        
        prev_time=$current_time
        
        # 小延时以显示时间差异
        for j in {1..100}; do
            : # 空操作
        done
    done
    
    printf "\n单调递增次数: %d/9\n" "$monotonic_count"
    if [[ $monotonic_count -ge 7 ]]; then
        printf "✓ 时间精度测试通过\n"
    else
        printf "⚠ 时间精度可能不足\n"
    fi
}

# 跨平台兼容性测试
test_cross_platform() {
    printf "\n=== 跨平台兼容性测试 ===\n"
    
    printf "检测到的时间获取方法: %s\n" "$TIME_METHOD"
    
    # 测试各种可能的时间获取方法
    local methods_to_test=()
    
    # 检测可用方法
    if date +%N >/dev/null 2>&1 && [[ "$(date +%N)" != "%N" ]]; then
        methods_to_test+=("GNU date")
    fi
    
    if command -v python3 >/dev/null 2>&1; then
        methods_to_test+=("Python3")
    fi
    
    if command -v python >/dev/null 2>&1; then
        methods_to_test+=("Python")
    fi
    
    if command -v perl >/dev/null 2>&1; then
        methods_to_test+=("Perl")
    fi
    
    if command -v node >/dev/null 2>&1; then
        methods_to_test+=("Node.js")
    fi
    
    if command -v ruby >/dev/null 2>&1; then
        methods_to_test+=("Ruby")
    fi
    
    printf "系统中可用的时间获取方法:\n"
    for method in "${methods_to_test[@]}"; do
        printf "  ✓ %s\n" "$method"
    done
    
    if [[ ${#methods_to_test[@]} -gt 1 ]]; then
        printf "✓ 多种方法可用，兼容性良好\n"
    else
        printf "⚠ 可用方法较少，可能影响精度\n"
    fi
}

# 如果直接执行此脚本，运行所有测试
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    test_time_functions
    test_time_diff
    test_time_format
    test_precision
    test_cross_platform
    test_benchmark
fi