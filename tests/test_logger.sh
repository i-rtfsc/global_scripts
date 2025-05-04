#!/bin/bash
# Global Scripts V3 - 简化Logger测试用例
# 作者: Solo
# 版本: 1.0.0
# 描述: 测试logger.sh的核心功能

# 设置测试模式，禁用自测代码
export _GS_TEST_MODE=1
# 获取脚本目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# 加载测试模块
source "$PROJECT_ROOT/lib/utils.sh"  # 先加载utils.sh
source "$PROJECT_ROOT/lib/logger.sh"

# 测试配置
readonly TEST_LOG_FILE="$(gs_file_mktemp logger_test)"

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
    [[ -f "$TEST_LOG_FILE" ]] && rm -f "$TEST_LOG_FILE"
    [[ -f "${TEST_LOG_FILE}.1" ]] && rm -f "${TEST_LOG_FILE}.1"
}

# 测试1: 基础日志功能
test_basic_logging() {
    test_start "基础日志功能"
    
    # 设置测试日志文件
    gs_log_set_file "$TEST_LOG_FILE"
    gs_log_enable_file true
    gs_log_set_level DEBUG
    
    # 输出各级别日志
    gs_log_debug "测试debug消息" 2>/dev/null
    gs_log_info "测试info消息" 2>/dev/null
    gs_log_warn "测试warn消息" 2>/dev/null
    gs_log_error "测试error消息" 2>/dev/null
    
    # 检查文件是否存在且有内容
    if [[ -f "$TEST_LOG_FILE" ]] && [[ -s "$TEST_LOG_FILE" ]]; then
        # 检查是否包含预期内容
        if grep -q "测试debug消息" "$TEST_LOG_FILE" && \
           grep -q "测试info消息" "$TEST_LOG_FILE" && \
           grep -q "测试warn消息" "$TEST_LOG_FILE" && \
           grep -q "测试error消息" "$TEST_LOG_FILE"; then
            test_pass
        else
            test_fail "日志内容不完整"
        fi
    else
        test_fail "日志文件未创建或为空"
    fi
}

# 测试2: 日志级别过滤
test_log_filtering() {
    test_start "日志级别过滤"
    
    # 清空日志文件
    > "$TEST_LOG_FILE"
    
    # 设置ERROR级别
    gs_log_set_level ERROR
    
    # 输出各级别日志
    gs_log_debug "应该被过滤的debug" 2>/dev/null
    gs_log_info "应该被过滤的info" 2>/dev/null
    gs_log_warn "应该被过滤的warn" 2>/dev/null
    gs_log_error "应该显示的error" 2>/dev/null
    
    # 检查过滤效果
    if ! grep -q "应该被过滤" "$TEST_LOG_FILE" && \
       grep -q "应该显示的error" "$TEST_LOG_FILE"; then
        test_pass
    else
        test_fail "日志级别过滤失败"
    fi
}

# 测试3: 日志级别设置
test_log_levels() {
    test_start "日志级别设置"
    
    # 设置DEBUG级别
    gs_log_set_level DEBUG
    if [[ "$(gs_log_get_level)" == "DEBUG" ]]; then
        # 设置INFO级别
        gs_log_set_level INFO
        if [[ "$(gs_log_get_level)" == "INFO" ]]; then
            test_pass
        else
            test_fail "INFO级别设置失败"
        fi
    else
        test_fail "DEBUG级别设置失败"
    fi
}

# 测试4: 配置管理
test_configuration() {
    test_start "配置管理"
    
    # 测试颜色开关
    gs_log_enable_color false
    if [[ "$_GS_LOG_ENABLE_COLOR" == "false" ]]; then
        gs_log_enable_color true
        if [[ "$_GS_LOG_ENABLE_COLOR" == "true" ]]; then
            test_pass
        else
            test_fail "颜色配置切换失败"
        fi
    else
        test_fail "颜色配置设置失败"
    fi
}

# 测试5: 日志清理
test_log_cleanup() {
    test_start "日志清理功能"
    
    # 确保日志文件有内容
    gs_log_info "清理前的内容" 2>/dev/null
    
    # 执行清理
    gs_log_clear 2>/dev/null
    
    # 检查文件是否为空
    if [[ ! -s "$TEST_LOG_FILE" ]]; then
        test_pass
    else
        test_fail "日志清理失败"
    fi
}

# 主测试函数
main() {
    printf "=== Global Scripts Logger 测试套件 (简化版) ===\n\n"
    
    # 设置测试环境
    gs_log_set_file "$TEST_LOG_FILE"
    gs_log_enable_file true
    gs_log_enable_color false
    
    # 执行测试
    test_basic_logging
    test_log_filtering  
    test_log_levels
    test_configuration
    test_log_cleanup
    
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