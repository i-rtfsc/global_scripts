#!/bin/bash
# Global Scripts V3 - 缓存系统简化测试
# 作者: Solo
# 版本: 1.0.0
# 描述: 任务3.1 - 缓存系统核心功能验证

# 设置错误模式
set -e

# 获取脚本根目录
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
readonly PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# 加载被测试模块
source "$PROJECT_ROOT/core/cache.sh"

# 测试计数器 - 避免使用declare语法
TESTS_TOTAL=0
TESTS_PASSED=0
TESTS_FAILED=0

# 简单测试框架
test_simple() {
    local test_name="$1"
    local test_command="$2"
    
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    printf "🧪 测试 %d: %s ... " "$TESTS_TOTAL" "$test_name"
    
    if eval "$test_command" >/dev/null 2>&1; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        printf "✅ 通过\n"
        return 0
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        printf "❌ 失败\n"
        return 1
    fi
}

# 测试设置
setup_test() {
    # 设置测试环境
    export _GS_LOG_LEVEL=2  # 设置为WARN级别，减少日志输出
    export _GS_CACHE_L2_DIR="/tmp/gs_test_cache_simple_$$"
    export _GS_CACHE_L1_MAX_SIZE=10
    
    # 清理并初始化
    rm -rf "$_GS_CACHE_L2_DIR" 2>/dev/null || true
    mkdir -p "$_GS_CACHE_L2_DIR"
    gs_cache_init >/dev/null 2>&1
    gs_cache_clear >/dev/null 2>&1
}

# 清理测试
cleanup_test() {
    rm -rf "$_GS_CACHE_L2_DIR" 2>/dev/null || true
}

# 主测试函数
run_simple_cache_tests() {
    echo "🎯 缓存系统简化功能验证"
    echo "========================"
    
    setup_test
    
    # L1缓存基本测试
    test_simple "L1缓存初始化" "gs_cache_l1_clear"
    test_simple "L1缓存设置" "gs_cache_l1_set 'key1' 'value1' 300"
    test_simple "L1缓存存在检查" "gs_cache_l1_exists 'key1'"
    test_simple "L1缓存删除" "gs_cache_l1_delete 'key1'"
    test_simple "L1缓存删除后不存在" "! gs_cache_l1_exists 'key1'"
    
    # L2缓存基本测试
    test_simple "L2缓存设置" "gs_cache_l2_set 'key2' 'value2' 300"
    test_simple "L2缓存存在检查" "gs_cache_l2_exists 'key2'"
    test_simple "L2缓存删除" "gs_cache_l2_delete 'key2'"
    test_simple "L2缓存删除后不存在" "! gs_cache_l2_exists 'key2'"
    
    # 统一缓存接口测试
    test_simple "统一缓存设置" "gs_cache_set 'key3' 'value3' 300"
    test_simple "统一缓存存在检查" "gs_cache_exists 'key3'"
    test_simple "统一缓存删除" "gs_cache_delete 'key3'"
    test_simple "统一缓存删除后不存在" "! gs_cache_exists 'key3'"
    
    # 缓存管理功能测试
    test_simple "缓存统计功能" "gs_cache_stats text | grep -q '缓存系统统计'"
    test_simple "缓存清理功能" "gs_cache_cleanup"
    test_simple "缓存健康检查" "gs_cache_health_check | grep -q '缓存系统健康检查'"
    
    cleanup_test
    
    echo "========================"
    echo "📊 测试结果:"
    echo "  总计: $TESTS_TOTAL"
    echo "  通过: $TESTS_PASSED"
    echo "  失败: $TESTS_FAILED"
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo "🎉 所有测试通过！缓存系统核心功能正常"
        return 0
    else
        echo "❌ 有 $TESTS_FAILED 个测试失败"
        return 1
    fi
}

# 如果直接执行脚本，运行测试
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
    run_simple_cache_tests
fi