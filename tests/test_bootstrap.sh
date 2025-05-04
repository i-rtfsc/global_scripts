#!/bin/bash
# Global Scripts V3 - Bootstrap测试用例
# 作者: Solo
# 版本: 1.0.0
# 描述: 测试bootstrap.sh的各项功能

# 设置测试模式，禁用自测代码
export _GS_TEST_MODE=1
# 设置测试模式，禁用自测代码
export _GS_TEST_MODE=1

# 获取脚本目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# 加载测试模块
source "$PROJECT_ROOT/lib/utils.sh"
source "$PROJECT_ROOT/core/bootstrap.sh"

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

# 测试1: Bash版本检查
test_bash_version_check() {
    test_start "Bash版本检查"
    
    # 测试当前Bash版本检查
    if _gs_bootstrap_check_bash_version >/dev/null 2>&1; then
        test_pass
    else
        test_fail "Bash版本检查失败"
    fi
}

# 测试2: 系统环境检测
test_system_detection() {
    test_start "系统环境检测"
    
    if _gs_bootstrap_check_system >/dev/null 2>&1; then
        # 检查系统信息是否正确设置
        local os arch
        os=$(gs_bootstrap_get_system_info "os")
        arch=$(gs_bootstrap_get_system_info "arch")
        
        if [[ -n "$os" ]] && [[ -n "$arch" ]]; then
            test_pass
        else
            test_fail "系统信息未正确设置"
        fi
    else
        test_fail "系统环境检测失败"
    fi
}

# 测试3: 必需命令检查
test_required_commands() {
    test_start "必需命令检查"
    
    if _gs_bootstrap_check_required_commands >/dev/null 2>&1; then
        test_pass
    else
        test_fail "必需命令检查失败"
    fi
}

# 测试4: 可选命令检查
test_optional_commands() {
    test_start "可选命令检查"
    
    # 可选命令检查不应该失败
    if _gs_bootstrap_check_optional_commands >/dev/null 2>&1; then
        test_pass
    else
        test_fail "可选命令检查意外失败"
    fi
}

# 测试5: 目录结构检查
test_directory_structure() {
    test_start "目录结构检查"
    
    if _gs_bootstrap_check_directories >/dev/null 2>&1; then
        test_pass
    else
        test_fail "目录结构检查失败"
    fi
}

# 测试6: 运行时目录初始化
test_runtime_dirs() {
    test_start "运行时目录初始化"
    
    if _gs_bootstrap_init_runtime_dirs >/dev/null 2>&1; then
        # 检查关键目录是否创建
        local runtime_dir="$HOME/.local/share/global_scripts"
        if [[ -d "$runtime_dir/logs" ]] && [[ -d "$runtime_dir/cache" ]]; then
            test_pass
        else
            test_fail "运行时目录未正确创建"
        fi
    else
        test_fail "运行时目录初始化失败"
    fi
}

# 测试7: 完整引导流程
test_full_bootstrap() {
    test_start "完整引导流程"
    
    # 设置静默模式
    local original_level
    original_level=$(gs_log_get_level)
    gs_log_set_level ERROR
    
    if gs_bootstrap_system >/dev/null 2>&1; then
        local status
        status=$(gs_bootstrap_get_status)
        if [[ "$status" == "completed" ]]; then
            test_pass
        else
            test_fail "引导状态不正确: $status"
        fi
    else
        test_fail "完整引导流程失败"
    fi
    
    # 恢复日志级别
    gs_log_set_level "$original_level"
}

# 测试8: 快速引导
test_quick_bootstrap() {
    test_start "快速引导"
    
    # 重置状态
    _GS_BOOTSTRAP_STATUS="not_started"
    
    local original_level
    original_level=$(gs_log_get_level)
    gs_log_set_level ERROR
    
    if gs_bootstrap_quick >/dev/null 2>&1; then
        local status
        status=$(gs_bootstrap_get_status)
        if [[ "$status" == "completed" ]]; then
            test_pass
        else
            test_fail "快速引导状态不正确: $status"
        fi
    else
        test_fail "快速引导失败"
    fi
    
    gs_log_set_level "$original_level"
}

# 测试9: 系统信息获取
test_system_info_retrieval() {
    test_start "系统信息获取"
    
    # 确保引导已完成
    gs_bootstrap_quick >/dev/null 2>&1
    
    local os bash_version
    os=$(gs_bootstrap_get_system_info "os")
    bash_version=$(gs_bootstrap_get_system_info "bash_version")
    
    if [[ -n "$os" ]] && [[ -n "$bash_version" ]]; then
        test_pass
    else
        test_fail "系统信息获取失败"
    fi
}

# 测试10: 性能指标获取
test_performance_metrics() {
    test_start "性能指标获取"
    
    # 确保引导已完成
    gs_bootstrap_quick >/dev/null 2>&1
    
    local duration
    duration=$(gs_bootstrap_get_metrics "duration_ms")
    
    if [[ -n "$duration" ]] && [[ "$duration" =~ ^[0-9]+$ ]]; then
        test_pass
    else
        test_fail "性能指标获取失败"
    fi
}

# 测试11: 网络连接检查
test_network_check() {
    test_start "网络连接检查"
    
    # 网络检查不应该导致失败（即使网络不可用）
    if _gs_bootstrap_check_network >/dev/null 2>&1; then
        test_pass
    else
        test_fail "网络检查函数执行失败"
    fi
}

# 测试12: 诊断功能
test_diagnostics() {
    test_start "诊断功能"
    
    # 诊断功能应该能正常运行
    if gs_bootstrap_diagnose >/dev/null 2>&1; then
        test_pass
    else
        test_fail "诊断功能执行失败"
    fi
}

# 主测试函数
main() {
    printf "=== Global Scripts Bootstrap 测试套件 ===\n\n"
    
    # 设置测试环境
    gs_log_set_level WARN  # 减少测试期间的日志输出
    
    # 执行测试
    test_bash_version_check
    test_system_detection
    test_required_commands
    test_optional_commands
    test_directory_structure
    test_runtime_dirs
    test_full_bootstrap
    test_quick_bootstrap
    test_system_info_retrieval
    test_performance_metrics
    test_network_check
    test_diagnostics
    
    # 输出测试结果
    printf "\n=== 测试结果统计 ===\n"
    printf "总测试数: %d\n" "$TESTS_TOTAL"
    printf "通过: %d\n" "$TESTS_PASSED"
    printf "失败: %d\n" "$TESTS_FAILED"
    printf "成功率: %.1f%%\n" "$(echo "scale=1; $TESTS_PASSED * 100 / $TESTS_TOTAL" | bc 2>/dev/null || echo "N/A")"
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        printf "\n🎉 所有测试通过！\n"
        exit 0
    else
        printf "\n⚠️  有 %d 个测试失败\n" "$TESTS_FAILED"
        exit 1
    fi
}

# 如果直接执行此脚本，运行测试
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
    main "$@"
fi