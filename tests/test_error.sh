#!/bin/bash
# Global Scripts V3 - Error Handler测试用例
# 作者: Solo
# 版本: 1.0.0
# 描述: 测试error.sh的各项功能

# 设置测试模式，禁用自测代码
export _GS_TEST_MODE=1
# 获取脚本目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# 加载测试模块
source "$PROJECT_ROOT/lib/utils.sh"  # 先加载utils.sh
source "$PROJECT_ROOT/lib/error.sh"

# 测试配置
readonly TEST_RESULTS_FILE="$(gs_file_mktemp error_test_results)"

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

# 测试1: 错误码定义验证
test_error_codes() {
    test_start "错误码定义验证"
    
    # 检查关键错误码是否定义
    if [[ -n "$_GS_ERROR_SUCCESS" ]] && \
       [[ -n "$_GS_ERROR_GENERIC" ]] && \
       [[ -n "$_GS_ERROR_INVALID_ARG" ]] && \
       [[ -n "$_GS_ERROR_FILE_NOT_FOUND" ]]; then
        test_pass
    else
        test_fail "错误码定义不完整"
    fi
}

# 测试2: 错误消息获取
test_error_messages() {
    test_start "错误消息获取"
    
    local message
    message="$(gs_error_get_message "$_GS_ERROR_INVALID_ARG")"
    
    if [[ "$message" == "无效参数" ]]; then
        test_pass
    else
        test_fail "错误消息获取失败: $message"
    fi
}

# 测试3: 错误建议获取
test_error_suggestions() {
    test_start "错误建议获取"
    
    local suggestion
    suggestion="$(gs_error_get_suggestion "$_GS_ERROR_FILE_NOT_FOUND")"
    
    if [[ "$suggestion" == "请确认文件路径是否正确，文件是否存在" ]]; then
        test_pass
    else
        test_fail "错误建议获取失败: $suggestion"
    fi
}

# 测试4: 错误处理配置
test_error_configuration() {
    test_start "错误处理配置"
    
    # 设置不退出模式
    gs_error_set_exit_on_error false
    if [[ "$_GS_ERROR_EXIT_ON_ERROR" == "false" ]]; then
        
        # 设置显示调用栈
        gs_error_set_show_stack true
        if [[ "$_GS_ERROR_SHOW_STACK" == "true" ]]; then
            
            # 设置记录错误
            gs_error_set_log_errors false
            if [[ "$_GS_ERROR_LOG_ERRORS" == "false" ]]; then
                test_pass
            else
                test_fail "错误记录配置失败"
            fi
        else
            test_fail "调用栈配置失败"
        fi
    else
        test_fail "退出模式配置失败"
    fi
    
    # 恢复默认配置
    gs_error_set_exit_on_error false
    gs_error_set_show_stack false
    gs_error_set_log_errors true
}

# 测试5: 便捷错误函数
test_convenience_functions() {
    test_start "便捷错误函数"
    
    # 设置为不退出模式以便测试
    gs_error_set_exit_on_error false
    
    local exit_code
    
    # 测试无效参数错误
    gs_error_invalid_arg "测试参数" >/dev/null 2>&1
    exit_code=$?
    if [[ $exit_code -eq $_GS_ERROR_INVALID_ARG ]]; then
        test_pass
    else
        test_fail "便捷错误函数返回码不正确: $exit_code"
    fi
}

# 测试6: 文件检查函数
test_file_checks() {
    test_start "文件检查函数"
    
    gs_error_set_exit_on_error false
    
    # 创建测试文件
    local test_file
    test_file="$(gs_file_mktemp)"
    echo "test content" > "$test_file"
    
    # 测试文件存在检查
    if gs_check_file_exists "$test_file" >/dev/null 2>&1; then
        
        # 测试不存在文件检查
        if ! gs_check_file_exists "/nonexistent/file" >/dev/null 2>&1; then
            test_pass
        else
            test_fail "不存在文件检查失败"
        fi
    else
        test_fail "存在文件检查失败"
    fi
    
    # 清理测试文件
    rm -f "$test_file"
}

# 测试7: 命令检查函数
test_command_checks() {
    test_start "命令检查函数"
    
    gs_error_set_exit_on_error false
    
    # 测试存在的命令
    if gs_check_command_exists "bash" >/dev/null 2>&1; then
        
        # 测试不存在的命令
        if ! gs_check_command_exists "nonexistent_command_xyz123" >/dev/null 2>&1; then
            test_pass
        else
            test_fail "不存在命令检查失败"
        fi
    else
        test_fail "存在命令检查失败"
    fi
}

# 测试8: 参数验证函数
test_parameter_validation() {
    test_start "参数验证函数"
    
    gs_error_set_exit_on_error false
    
    # 测试非空检查
    if gs_check_not_empty "非空字符串" >/dev/null 2>&1; then
        
        # 测试空字符串检查
        if ! gs_check_not_empty "" >/dev/null 2>&1; then
            
            # 测试数字验证
            if gs_check_numeric "123" >/dev/null 2>&1; then
                
                # 测试非数字验证
                if ! gs_check_numeric "abc" >/dev/null 2>&1; then
                    test_pass
                else
                    test_fail "非数字验证失败"
                fi
            else
                test_fail "数字验证失败"
            fi
        else
            test_fail "空字符串检查失败"
        fi
    else
        test_fail "非空检查失败"
    fi
}

# 测试9: Try-catch模拟
test_try_catch() {
    test_start "Try-catch模拟"
    
    # 保存原始配置
    local original_exit_setting="$_GS_ERROR_EXIT_ON_ERROR"
    
    # 测试try函数
    if gs_try gs_error_invalid_arg "try测试" >/dev/null 2>&1; then
        test_fail "try应该返回错误码"
    else
        local exit_code=$?
        if [[ $exit_code -eq $_GS_ERROR_INVALID_ARG ]]; then
            # 检查原始设置是否恢复
            if [[ "$_GS_ERROR_EXIT_ON_ERROR" == "$original_exit_setting" ]]; then
                test_pass
            else
                test_fail "try-catch配置恢复失败"
            fi
        else
            test_fail "try返回错误码不正确: $exit_code"
        fi
    fi
}

# 测试10: 安全执行函数
test_safe_exec() {
    test_start "安全执行函数"
    
    gs_error_set_exit_on_error false
    
    # 测试成功执行
    if gs_safe_exec "echo 'test success'" >/dev/null 2>&1; then
        
        # 测试失败执行
        if ! gs_safe_exec "exit 1" >/dev/null 2>&1; then
            test_pass
        else
            test_fail "失败命令应该返回错误"
        fi
    else
        test_fail "成功命令执行失败"
    fi
}

# 测试11: 权限检查函数
test_permission_checks() {
    test_start "权限检查函数"
    
    gs_error_set_exit_on_error false
    
    # 创建测试文件
    local test_file
    test_file="$(gs_file_mktemp)"
    echo "test" > "$test_file"
    chmod 644 "$test_file"
    
    # 测试读权限检查
    if gs_check_permission "$test_file" r >/dev/null 2>&1; then
        
        # 测试写权限检查
        if gs_check_permission "$test_file" w >/dev/null 2>&1; then
            test_pass
        else
            test_fail "写权限检查失败"
        fi
    else
        test_fail "读权限检查失败"
    fi
    
    # 清理测试文件
    rm -f "$test_file"
}

# 测试12: 错误码列表功能
test_error_list() {
    test_start "错误码列表功能"
    
    local output
    output="$(gs_error_list_codes 2>/dev/null)"
    
    # 检查是否包含关键错误码
    if echo "$output" | grep -q "SUCCESS" && \
       echo "$output" | grep -q "INVALID_ARG" && \
       echo "$output" | grep -q "FILE_NOT_FOUND"; then
        test_pass
    else
        test_fail "错误码列表内容不完整"
    fi
}

# 性能测试
test_performance() {
    test_start "错误处理性能测试"
    
    gs_error_set_exit_on_error false
    gs_error_set_log_errors false
    
    local start_time end_time duration
    start_time=$(gs_time_ms)
    
    # 执行100次错误处理（减少数量）
    for i in {1..100}; do
        gs_error_invalid_arg "性能测试 $i" >/dev/null 2>&1
    done
    
    end_time=$(gs_time_ms)
    duration=$((end_time - start_time))
    
    # 如果100次错误处理在2秒内完成，认为性能合格
    if [[ $duration -lt 2000 ]]; then
        test_pass
        printf "    📊 性能: %d毫秒完成100次错误处理\n" "$duration"
    else
        test_fail "性能不达标: ${duration}毫秒"
    fi
    
    # 恢复日志设置
    gs_error_set_log_errors true
}

# 主测试函数
main() {
    printf "=== Global Scripts Error Handler 测试套件 ===\n\n"
    
    # 设置测试环境
    gs_error_set_exit_on_error false
    gs_error_set_show_stack false
    gs_error_set_log_errors false  # 禁用日志以便测试
    
    # 执行测试
    test_error_codes
    test_error_messages
    test_error_suggestions
    test_error_configuration
    test_convenience_functions
    test_file_checks
    test_command_checks
    test_parameter_validation
    test_try_catch
    test_safe_exec
    test_permission_checks
    test_error_list
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