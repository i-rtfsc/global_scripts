#!/bin/bash
# Global Scripts V3 - Utils测试用例
# 作者: Solo
# 版本: 1.0.0
# 描述: 测试utils.sh的各项功能

# 获取脚本目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# 加载测试模块
source "$PROJECT_ROOT/lib/utils.sh"

# 测试配置
readonly TEST_RESULTS_FILE="$(gs_file_mktemp utils_test_results)"

# 测试计数器
declare -i TESTS_TOTAL=0
declare -i TESTS_PASSED=0
declare -i TESTS_FAILED=0

# 测试结果记录
test_start() {
    local test_name="$1"
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    printf "🧪 测试 %d: %s ... " "$TESTS_TOTAL" "$test_name"
}

test_pass() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    printf "✅ 通过\n"
}

test_fail() {
    local reason="$1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    printf "❌ 失败: %s\n" "$reason"
}

# 清理函数
cleanup() {
    [[ -f "$TEST_RESULTS_FILE" ]] && rm -f "$TEST_RESULTS_FILE"
}

# 测试1: 字符串处理函数
test_string_functions() {
    test_start "字符串处理函数"
    
    # 测试trim函数
    local trimmed
    trimmed="$(gs_str_trim "  hello world  ")"
    if [[ "$trimmed" != "hello world" ]]; then
        test_fail "字符串trim失败: '$trimmed'"
        return
    fi
    
    # 测试大小写转换
    local upper lower
    upper="$(gs_str_upper "hello")"
    lower="$(gs_str_lower "WORLD")"
    if [[ "$upper" != "HELLO" ]] || [[ "$lower" != "world" ]]; then
        test_fail "大小写转换失败: '$upper', '$lower'"
        return
    fi
    
    # 测试字符串长度
    local length
    length="$(gs_str_length "test")"
    if [[ "$length" != "4" ]]; then
        test_fail "字符串长度计算失败: $length"
        return
    fi
    
    # 测试字符串包含检查
    if ! gs_str_contains "hello world" "world"; then
        test_fail "字符串包含检查失败"
        return
    fi
    
    test_pass
}

# 测试2: 字符串前缀后缀检查
test_string_prefix_suffix() {
    test_start "字符串前缀后缀检查"
    
    # 测试前缀检查
    if ! gs_str_starts_with "hello world" "hello"; then
        test_fail "前缀检查失败"
        return
    fi
    
    # 测试后缀检查
    if ! gs_str_ends_with "hello world" "world"; then
        test_fail "后缀检查失败"
        return
    fi
    
    test_pass
}

# 测试3: 字符串替换和分割
test_string_replace_split() {
    test_start "字符串替换和分割"
    
    # 测试替换
    local replaced
    replaced="$(gs_str_replace_first "hello world world" "world" "universe")"
    if [[ "$replaced" != "hello universe world" ]]; then
        test_fail "字符串替换失败: '$replaced'"
        return
    fi
    
    # 测试全部替换
    local all_replaced
    all_replaced="$(gs_str_replace_all "hello world world" "world" "universe")"
    if [[ "$all_replaced" != "hello universe universe" ]]; then
        test_fail "字符串全部替换失败: '$all_replaced'"
        return
    fi
    
    # 测试分割
    local split_result
    split_result="$(gs_str_split "a,b,c" ",")"
    local expected=$'a\nb\nc'
    if [[ "$split_result" != "$expected" ]]; then
        test_fail "字符串分割失败"
        return
    fi
    
    test_pass
}

# 测试4: 字符串格式验证
test_string_validation() {
    test_start "字符串格式验证"
    
    # 测试数字验证
    if ! gs_str_is_number "123.45"; then
        test_fail "数字验证失败"
        return
    fi
    
    if gs_str_is_number "abc"; then
        test_fail "非数字验证失败"
        return
    fi
    
    # 测试整数验证
    if ! gs_str_is_integer "123"; then
        test_fail "整数验证失败"
        return
    fi
    
    if gs_str_is_integer "123.45"; then
        test_fail "非整数验证失败"
        return
    fi
    
    # 测试邮箱验证
    if ! gs_str_is_email "test@example.com"; then
        test_fail "邮箱验证失败"
        return
    fi
    
    if gs_str_is_email "invalid-email"; then
        test_fail "无效邮箱验证失败"
        return
    fi
    
    # 测试URL验证
    if ! gs_str_is_url "https://example.com"; then
        test_fail "URL验证失败"
        return
    fi
    
    # 测试IP验证
    if ! gs_str_is_ip "192.168.1.1"; then
        test_fail "IP验证失败"
        return
    fi
    
    if gs_str_is_ip "999.999.999.999"; then
        test_fail "无效IP验证失败"
        return
    fi
    
    test_pass
}

# 测试5: 文件操作函数
test_file_functions() {
    test_start "文件操作函数"
    
    # 创建测试文件
    local test_file
    test_file="$(gs_file_mktemp)"
    echo -e "line1\nline2\nline3" > "$test_file"
    
    # 测试文件大小
    local size
    size="$(gs_file_size "$test_file")"
    if [[ -z "$size" ]] || [[ "$size" -eq 0 ]]; then
        test_fail "文件大小获取失败: $size"
        rm -f "$test_file"
        return
    fi
    
    # 测试文件行数
    local lines
    lines="$(gs_file_lines "$test_file")"
    if [[ "$lines" != "3" ]]; then
        test_fail "文件行数获取失败: $lines"
        rm -f "$test_file"
        return
    fi
    
    # 测试文件状态检查
    if ! gs_file_is_readable "$test_file"; then
        test_fail "文件可读检查失败"
        rm -f "$test_file"
        return
    fi
    
    if ! gs_file_is_writable "$test_file"; then
        test_fail "文件可写检查失败"
        rm -f "$test_file"
        return
    fi
    
    # 清理测试文件
    rm -f "$test_file"
    
    test_pass
}

# 测试6: 文件路径处理
test_file_path_functions() {
    test_start "文件路径处理"
    
    # 测试扩展名获取
    local ext
    ext="$(gs_file_extension "test.txt")"
    if [[ "$ext" != "txt" ]]; then
        test_fail "扩展名获取失败: $ext"
        return
    fi
    
    # 测试基名获取
    local basename
    basename="$(gs_file_basename "path/to/file.txt")"
    if [[ "$basename" != "file" ]]; then
        test_fail "基名获取失败: $basename"
        return
    fi
    
    # 测试目录获取
    local dirname
    dirname="$(gs_file_dirname "path/to/file.txt")"
    if [[ "$dirname" != "path/to" ]]; then
        test_fail "目录获取失败: $dirname"
        return
    fi
    
    test_pass
}

# 测试7: 系统检测函数
test_system_functions() {
    test_start "系统检测函数"
    
    # 测试操作系统检测
    local os
    os="$(gs_sys_os)"
    if [[ -z "$os" ]]; then
        test_fail "操作系统检测失败"
        return
    fi
    
    # 测试架构检测
    local arch
    arch="$(gs_sys_arch)"
    if [[ -z "$arch" ]]; then
        test_fail "系统架构检测失败"
        return
    fi
    
    # 测试Shell检测
    local shell
    shell="$(gs_sys_shell)"
    if [[ -z "$shell" ]]; then
        test_fail "Shell类型检测失败"
        return
    fi
    
    # 测试用户名获取
    local username
    username="$(gs_sys_username)"
    if [[ -z "$username" ]]; then
        test_fail "用户名获取失败"
        return
    fi
    
    test_pass
}

# 测试8: 命令存在检查
test_command_existence() {
    test_start "命令存在检查"
    
    # 测试存在的命令
    if ! gs_sys_command_exists "bash"; then
        test_fail "bash命令存在检查失败"
        return
    fi
    
    # 测试不存在的命令
    if gs_sys_command_exists "nonexistent_command_xyz123"; then
        test_fail "不存在命令检查失败"
        return
    fi
    
    test_pass
}

# 测试9: 环境变量操作
test_environment_variables() {
    test_start "环境变量操作"
    
    # 设置测试环境变量
    gs_sys_env_set "TEST_VAR" "test_value"
    
    # 获取环境变量
    local value
    value="$(gs_sys_env_get "TEST_VAR")"
    if [[ "$value" != "test_value" ]]; then
        test_fail "环境变量获取失败: $value"
        return
    fi
    
    # 测试变量存在检查
    if ! gs_sys_env_exists "TEST_VAR"; then
        test_fail "环境变量存在检查失败"
        return
    fi
    
    # 测试默认值
    local default_value
    default_value="$(gs_sys_env_get "NONEXISTENT_VAR" "default")"
    if [[ "$default_value" != "default" ]]; then
        test_fail "环境变量默认值失败: $default_value"
        return
    fi
    
    # 清理测试变量
    unset TEST_VAR
    
    test_pass
}

# 测试10: 数组操作函数
test_array_functions() {
    test_start "数组操作函数"
    
    # 测试数组包含检查
    if ! gs_array_contains "b" "a" "b" "c"; then
        test_fail "数组包含检查失败"
        return
    fi
    
    if gs_array_contains "d" "a" "b" "c"; then
        test_fail "数组不包含检查失败"
        return
    fi
    
    # 测试数组去重
    local unique_result
    unique_result="$(gs_array_unique "a" "b" "a" "c" "b")"
    local unique_lines
    unique_lines="$(echo "$unique_result" | wc -l | tr -d ' ')"
    if [[ "$unique_lines" != "3" ]]; then
        test_fail "数组去重失败: 期望3行，实际${unique_lines}行"
        return
    fi
    
    test_pass
}

# 测试11: 颜色输出函数
test_color_functions() {
    test_start "颜色输出函数"
    
    # 测试颜色支持检测
    local color_output
    color_output="$(gs_color_red "test" 2>/dev/null)"
    
    # 在非TTY环境下，应该输出纯文本
    if [[ "$color_output" == "test" ]]; then
        test_pass
    else
        # 在TTY环境下，应该包含颜色代码
        if [[ "$color_output" == *"test"* ]]; then
            test_pass
        else
            test_fail "颜色输出失败: '$color_output'"
        fi
    fi
}

# 测试12: 字符串填充和重复
test_string_padding_repeat() {
    test_start "字符串填充和重复"
    
    # 测试字符串重复
    local repeated
    repeated="$(gs_str_repeat "ab" 3)"
    if [[ "$repeated" != "ababab" ]]; then
        test_fail "字符串重复失败: '$repeated'"
        return
    fi
    
    # 测试左填充
    local padded_left
    padded_left="$(gs_str_pad_left "test" 8 "0")"
    if [[ "$padded_left" != "0000test" ]]; then
        test_fail "左填充失败: '$padded_left'"
        return
    fi
    
    # 测试右填充
    local padded_right
    padded_right="$(gs_str_pad_right "test" 8 "0")"
    if [[ "$padded_right" != "test0000" ]]; then
        test_fail "右填充失败: '$padded_right'"
        return
    fi
    
    # 测试字符串截取
    local substring
    substring="$(gs_str_substring "hello world" 6 5)"
    if [[ "$substring" != "world" ]]; then
        test_fail "字符串截取失败: '$substring'"
        return
    fi
    
    test_pass
}

# 测试13: 目录操作
test_directory_functions() {
    test_start "目录操作"
    
    # 创建临时目录
    local temp_dir
    temp_dir="$(gs_dir_mktemp)"
    
    if [[ ! -d "$temp_dir" ]]; then
        test_fail "临时目录创建失败"
        return
    fi
    
    # 测试目录存在检查
    if ! gs_dir_exists "$temp_dir"; then
        test_fail "目录存在检查失败"
        rm -rf "$temp_dir"
        return
    fi
    
    # 清理临时目录
    rm -rf "$temp_dir"
    
    test_pass
}

# 性能测试
test_performance() {
    test_start "Utils性能测试"
    
    local start_time end_time duration
    start_time=$(gs_time_ms)
    
    # 执行100次字符串操作（减少数量）
    for i in {1..100}; do
        gs_str_trim "  test string $i  " >/dev/null
        gs_str_upper "test" >/dev/null
        gs_str_contains "hello world" "world" >/dev/null
    done
    
    end_time=$(gs_time_ms)
    duration=$((end_time - start_time))
    
    # 如果100次操作在1秒内完成，认为性能合格
    if [[ $duration -lt 1000 ]]; then
        test_pass
        printf "    📊 性能: %d毫秒完成100次字符串操作\n" "$duration"
    else
        test_fail "性能不达标: ${duration}毫秒"
    fi
}

# 主测试函数
main() {
    printf "=== Global Scripts Utils 测试套件 ===\n\n"
    
    # 执行测试
    test_string_functions
    test_string_prefix_suffix
    test_string_replace_split
    test_string_validation
    test_file_functions
    test_file_path_functions
    test_system_functions
    test_command_existence
    test_environment_variables
    test_array_functions
    test_color_functions
    test_string_padding_repeat
    test_directory_functions
    test_performance
    
    # 输出测试结果
    printf "\n=== 测试结果统计 ===\n"
    printf "总测试数: %d\n" "$TESTS_TOTAL"
    printf "通过: %d\n" "$TESTS_PASSED"
    printf "失败: %d\n" "$TESTS_FAILED"
    printf "成功率: %.1f%%\n" "$(echo "scale=1; $TESTS_PASSED * 100 / $TESTS_TOTAL" | bc 2>/dev/null || echo "N/A")"
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        printf "\n🎉 所有测试通过！\n"
        cleanup
        exit 0
    else
        printf "\n⚠️  有 %d 个测试失败\n" "$TESTS_FAILED"
        cleanup
        exit 1
    fi
}

# 如果直接执行此脚本，运行测试
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
    # 注册清理函数
    trap cleanup EXIT
    
    main "$@"
fi