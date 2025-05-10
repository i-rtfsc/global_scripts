#!/bin/bash
# Global Scripts V3 - API接口层简化测试
# 作者: Solo  
# 版本: 1.0.0
# 描述: API接口层功能验证测试，避免复杂的shell特性

# 设置测试环境
readonly _GS_TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly _GS_ROOT="$(cd "$_GS_TEST_DIR/.." && pwd)"

# 设置测试模式
export _GS_TEST_MODE=1

# 测试计数器
_TEST_COUNT=0
_TEST_PASSED=0
_TEST_FAILED=0

# 测试函数
test_assert() {
    local test_name="$1"
    local expected="$2" 
    local actual="$3"
    
    _TEST_COUNT=$((_TEST_COUNT + 1))
    
    if [[ "$expected" == "$actual" ]]; then
        echo "✓ [$(printf "%02d" $_TEST_COUNT)] $test_name"
        _TEST_PASSED=$((_TEST_PASSED + 1))
        return 0
    else
        echo "✗ [$(printf "%02d" $_TEST_COUNT)] $test_name"
        echo "    期望: $expected"
        echo "    实际: $actual"
        _TEST_FAILED=$((_TEST_FAILED + 1))
        return 1
    fi
}

test_function_exists() {
    local test_name="$1"
    local function_name="$2"
    
    _TEST_COUNT=$((_TEST_COUNT + 1))
    
    if declare -F "$function_name" >/dev/null 2>&1; then
        echo "✓ [$(printf "%02d" $_TEST_COUNT)] $test_name"
        _TEST_PASSED=$((_TEST_PASSED + 1))
        return 0
    else
        echo "✗ [$(printf "%02d" $_TEST_COUNT)] $test_name"
        echo "    函数不存在: $function_name"
        _TEST_FAILED=$((_TEST_FAILED + 1))
        return 1
    fi
}

test_file_exists() {
    local test_name="$1"
    local file_path="$2"
    
    _TEST_COUNT=$((_TEST_COUNT + 1))
    
    if [[ -f "$file_path" ]]; then
        echo "✓ [$(printf "%02d" $_TEST_COUNT)] $test_name"
        _TEST_PASSED=$((_TEST_PASSED + 1))
        return 0
    else
        echo "✗ [$(printf "%02d" $_TEST_COUNT)] $test_name"
        echo "    文件不存在: $file_path"
        _TEST_FAILED=$((_TEST_FAILED + 1))
        return 1
    fi
}

# ===================================
# 测试套件1: API文件存在性检查
# ===================================
test_suite_file_structure() {
    echo
    echo "=== 测试套件1: API文件结构检查 ==="
    
    # 测试1: command_api.sh文件存在
    test_file_exists "command_api.sh文件存在" "$_GS_ROOT/api/command_api.sh"
    
    # 测试2: config_api.sh文件存在
    test_file_exists "config_api.sh文件存在" "$_GS_ROOT/api/config_api.sh"
    
    # 测试3: 文件可执行权限
    _TEST_COUNT=$((_TEST_COUNT + 1))
    if [[ -x "$_GS_ROOT/api/command_api.sh" && -x "$_GS_ROOT/api/config_api.sh" ]]; then
        echo "✓ [$(printf "%02d" $_TEST_COUNT)] API文件可执行权限"
        _TEST_PASSED=$((_TEST_PASSED + 1))
    else
        echo "✗ [$(printf "%02d" $_TEST_COUNT)] API文件可执行权限"
        echo "    部分API文件不可执行"
        _TEST_FAILED=$((_TEST_FAILED + 1))
    fi
}

# ===================================
# 测试套件2: 加载依赖模块
# ===================================
test_suite_module_loading() {
    echo
    echo "=== 测试套件2: 模块加载测试 ==="
    
    # 测试4: 加载基础模块
    _TEST_COUNT=$((_TEST_COUNT + 1))
    if source "$_GS_ROOT/lib/utils.sh" 2>/dev/null && \
       source "$_GS_ROOT/lib/logger.sh" 2>/dev/null && \
       source "$_GS_ROOT/lib/error.sh" 2>/dev/null; then
        echo "✓ [$(printf "%02d" $_TEST_COUNT)] 基础模块加载"
        _TEST_PASSED=$((_TEST_PASSED + 1))
    else
        echo "✗ [$(printf "%02d" $_TEST_COUNT)] 基础模块加载"
        echo "    基础模块加载失败"
        _TEST_FAILED=$((_TEST_FAILED + 1))
        return 1
    fi
    
    # 测试5: 加载核心模块
    _TEST_COUNT=$((_TEST_COUNT + 1))
    if source "$_GS_ROOT/core/config.sh" 2>/dev/null; then
        echo "✓ [$(printf "%02d" $_TEST_COUNT)] 核心模块加载"
        _TEST_PASSED=$((_TEST_PASSED + 1))
    else
        echo "✗ [$(printf "%02d" $_TEST_COUNT)] 核心模块加载"
        echo "    核心模块加载失败"
        _TEST_FAILED=$((_TEST_FAILED + 1))
        return 1
    fi
    
    # 测试6: 加载API模块
    _TEST_COUNT=$((_TEST_COUNT + 1))
    if source "$_GS_ROOT/api/command_api.sh" 2>/dev/null && \
       source "$_GS_ROOT/api/config_api.sh" 2>/dev/null; then
        echo "✓ [$(printf "%02d" $_TEST_COUNT)] API模块加载"
        _TEST_PASSED=$((_TEST_PASSED + 1))
    else
        echo "✗ [$(printf "%02d" $_TEST_COUNT)] API模块加载"
        echo "    API模块加载失败"
        _TEST_FAILED=$((_TEST_FAILED + 1))
        return 1
    fi
}

# ===================================
# 测试套件3: API函数存在性检查
# ===================================
test_suite_function_existence() {
    echo
    echo "=== 测试套件3: API函数存在性检查 ==="
    
    # 测试7: 命令分发函数
    test_function_exists "命令分发函数" "gs_command_dispatch"
    
    # 测试8: 参数解析函数
    test_function_exists "参数解析函数" "gs_parse_arguments"
    
    # 测试9: 输出格式化函数
    test_function_exists "输出格式化函数" "gs_format_output"
    
    # 测试10: 配置获取命令
    test_function_exists "配置获取命令" "gs_config_get_cmd"
    
    # 测试11: 配置设置命令
    test_function_exists "配置设置命令" "gs_config_set_cmd"
    
    # 测试12: 配置列表命令
    test_function_exists "配置列表命令" "gs_config_list_cmd"
    
    # 测试13: 配置验证命令
    test_function_exists "配置验证命令" "gs_config_validate_cmd"
    
    # 测试14: 配置重置命令
    test_function_exists "配置重置命令" "gs_config_reset_cmd"
    
    # 测试15: 配置备份命令
    test_function_exists "配置备份命令" "gs_config_backup_cmd"
    
    # 测试16: 配置恢复命令
    test_function_exists "配置恢复命令" "gs_config_restore_cmd"
    
    # 测试17: 配置合并命令
    test_function_exists "配置合并命令" "gs_config_merge_cmd"
}

# ===================================
# 测试套件4: 输出格式化功能
# ===================================
test_suite_output_functions() {
    echo
    echo "=== 测试套件4: 输出格式化功能 ==="
    
    # 测试18: 成功消息格式化
    _TEST_COUNT=$((_TEST_COUNT + 1))
    local success_output
    success_output=$(gs_format_success "测试成功" "text" 2>/dev/null)
    if [[ "$success_output" == *"✓"* ]] && [[ "$success_output" == *"测试成功"* ]]; then
        echo "✓ [$(printf "%02d" $_TEST_COUNT)] 成功消息格式化"
        _TEST_PASSED=$((_TEST_PASSED + 1))
    else
        echo "✗ [$(printf "%02d" $_TEST_COUNT)] 成功消息格式化"
        echo "    输出格式不正确: $success_output"
        _TEST_FAILED=$((_TEST_FAILED + 1))
    fi
    
    # 测试19: 错误消息格式化
    _TEST_COUNT=$((_TEST_COUNT + 1))
    local error_output
    error_output=$(gs_format_error "测试错误" "text" 1 2>&1)
    if [[ "$error_output" == *"✗"* ]] && [[ "$error_output" == *"测试错误"* ]]; then
        echo "✓ [$(printf "%02d" $_TEST_COUNT)] 错误消息格式化"
        _TEST_PASSED=$((_TEST_PASSED + 1))
    else
        echo "✗ [$(printf "%02d" $_TEST_COUNT)] 错误消息格式化"
        echo "    输出格式不正确: $error_output"
        _TEST_FAILED=$((_TEST_FAILED + 1))
    fi
    
    # 测试20: JSON格式输出测试
    _TEST_COUNT=$((_TEST_COUNT + 1))
    local json_output
    json_output=$(gs_format_output "json" '{"test": "value"}' "Test" 2>/dev/null)
    if echo "$json_output" | jq . >/dev/null 2>&1; then
        echo "✓ [$(printf "%02d" $_TEST_COUNT)] JSON格式输出"
        _TEST_PASSED=$((_TEST_PASSED + 1))
    else
        echo "✗ [$(printf "%02d" $_TEST_COUNT)] JSON格式输出"
        echo "    JSON格式无效"
        _TEST_FAILED=$((_TEST_FAILED + 1))
    fi
}

# ===================================
# 运行所有测试
# ===================================
run_all_tests() {
    echo "Global Scripts V3 - API接口层简化测试套件"
    echo "========================================"
    
    # 运行测试套件
    test_suite_file_structure
    test_suite_module_loading
    test_suite_function_existence  
    test_suite_output_functions
    
    # 输出测试结果
    echo
    echo "========================================"
    echo "测试结果汇总:"
    echo "  总测试数: $_TEST_COUNT"
    echo "  通过数量: $_TEST_PASSED"
    echo "  失败数量: $_TEST_FAILED"
    
    if [[ $_TEST_FAILED -eq 0 ]]; then
        echo "  结果: ✓ 所有测试通过"
        echo "  任务2.1 API接口层开发验证成功"
        return 0
    else
        echo "  结果: ✗ 部分测试失败"
        echo "  任务2.1需要进一步修复"
        return 1
    fi
}

# 主函数
main() {
    run_all_tests
}

# 如果直接执行脚本，运行主函数
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi