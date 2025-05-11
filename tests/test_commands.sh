#!/bin/bash
# Global Scripts V3 - Core Commands Test Suite
# 作者: Solo
# 版本: 3.0.0
# 描述: 核心命令测试套件，测试gs-help、gs-version、gs-status命令

# 设置测试环境
if [[ -z "${_GS_TEST_DIR:-}" ]]; then
    readonly _GS_TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

if [[ -z "${_GS_ROOT:-}" ]]; then  
    readonly _GS_ROOT="$(cd "$_GS_TEST_DIR/.." && pwd)"
fi

# 设置测试模式
export _GS_TEST_MODE=1

# 加载依赖模块
source "$_GS_ROOT/lib/utils.sh"
source "$_GS_ROOT/lib/logger.sh" 
source "$_GS_ROOT/lib/error.sh"
source "$_GS_ROOT/commands/gs_help.sh"
source "$_GS_ROOT/commands/gs_version.sh"
source "$_GS_ROOT/commands/gs_status.sh"

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

test_assert_success() {
    local test_name="$1"
    local command="$2"
    
    _TEST_COUNT=$((_TEST_COUNT + 1))
    
    if eval "$command" >/dev/null 2>&1; then
        echo "✓ [$(printf "%02d" $_TEST_COUNT)] $test_name"
        _TEST_PASSED=$((_TEST_PASSED + 1))
        return 0
    else
        echo "✗ [$(printf "%02d" $_TEST_COUNT)] $test_name"
        echo "    命令失败: $command"
        _TEST_FAILED=$((_TEST_FAILED + 1))
        return 1
    fi
}

test_contains() {
    local test_name="$1"
    local expected_substring="$2"
    local actual_output="$3"
    
    _TEST_COUNT=$((_TEST_COUNT + 1))
    
    if [[ "$actual_output" == *"$expected_substring"* ]]; then
        echo "✓ [$(printf "%02d" $_TEST_COUNT)] $test_name"
        _TEST_PASSED=$((_TEST_PASSED + 1))
        return 0
    else
        echo "✗ [$(printf "%02d" $_TEST_COUNT)] $test_name"
        echo "    期望包含: $expected_substring"
        echo "    实际输出: $actual_output"
        _TEST_FAILED=$((_TEST_FAILED + 1))
        return 1
    fi
}

test_json_valid() {
    local test_name="$1"
    local json_output="$2"
    
    _TEST_COUNT=$((_TEST_COUNT + 1))
    
    if echo "$json_output" | jq . >/dev/null 2>&1; then
        echo "✓ [$(printf "%02d" $_TEST_COUNT)] $test_name"
        _TEST_PASSED=$((_TEST_PASSED + 1))
        return 0
    else
        echo "✗ [$(printf "%02d" $_TEST_COUNT)] $test_name"
        echo "    无效的JSON输出: $json_output"
        _TEST_FAILED=$((_TEST_FAILED + 1))
        return 1
    fi
}

# 临时文件管理
_TEST_TEMP_FILES=()

create_temp_file() {
    local prefix="${1:-test}"
    local temp_file="/tmp/${prefix}_$$_$(date +%s).tmp"
    _TEST_TEMP_FILES+=("$temp_file")
    echo "$temp_file"
}

cleanup_temp_files() {
    for file in "${_TEST_TEMP_FILES[@]}"; do
        [[ -f "$file" ]] && rm -f "$file"
    done
    _TEST_TEMP_FILES=()
}

# ===================================
# 测试套件1: gs-help命令测试
# ===================================
test_suite_help_command() {
    echo
    echo "=== 测试套件1: gs-help命令测试 ==="
    
    # 测试1: 基本帮助显示
    {
        local output
        output=$(gs_help_cmd 2>/dev/null)
        test_contains "基本帮助显示" "Global Scripts V3" "$output"
    }
    
    # 测试2: JSON格式帮助
    {
        local output
        output=$(gs_help_cmd --format json 2>/dev/null)
        test_json_valid "JSON格式帮助输出" "$output"
    }
    
    # 测试3: 帮助命令自身的帮助
    {
        local output
        output=$(gs_help_cmd --help 2>/dev/null)
        test_contains "帮助命令自身帮助" "gs-help - 分层帮助系统" "$output"
    }
    
    # 测试4: 特定命令帮助
    {
        local output
        output=$(gs_help_cmd version 2>/dev/null)
        test_contains "特定命令帮助" "gs-version - 版本信息显示" "$output"
    }
    
    # 测试5: 命令列表显示
    {
        local output
        output=$(gs_help_cmd --list 2>/dev/null)
        test_contains "命令列表显示" "所有可用命令" "$output"
    }
    
    # 测试6: 命令搜索功能
    {
        local output
        output=$(gs_help_cmd --search config 2>/dev/null)
        test_contains "命令搜索功能" "相关命令" "$output"
    }
    
    # 测试7: 按类别筛选命令
    {
        local output
        output=$(gs_help_cmd --list --category core 2>/dev/null)
        test_contains "按类别筛选命令" "help" "$output"
    }
}

# ===================================
# 测试套件2: gs-version命令测试
# ===================================
test_suite_version_command() {
    echo
    echo "=== 测试套件2: gs-version命令测试 ==="
    
    # 测试8: 基本版本显示
    {
        local output
        output=$(gs_version_cmd 2>/dev/null)
        test_contains "基本版本显示" "Global Scripts V3" "$output"
    }
    
    # 测试9: JSON格式版本输出
    {
        local output
        output=$(gs_version_cmd --format json 2>/dev/null)
        test_json_valid "JSON格式版本输出" "$output"
    }
    
    # 测试10: 完整版本信息
    {
        local output
        output=$(gs_version_cmd --full 2>/dev/null)
        test_contains "完整版本信息" "详细信息" "$output"
    }
    
    # 测试11: 依赖检查功能
    {
        local output
        output=$(gs_version_cmd --check-deps 2>/dev/null)
        test_contains "依赖检查功能" "依赖工具版本" "$output"
    }
    
    # 测试12: 版本命令帮助
    {
        local output
        output=$(gs_version_cmd --help 2>/dev/null)
        test_contains "版本命令帮助" "gs-version - 版本信息显示" "$output"
    }
    
    # 测试13: 版本获取函数
    {
        local version
        version=$(gs_version_get_gs_version)
        test_assert "版本获取函数" "false" "$(test -z "$version" && echo true || echo false)"
    }
    
    # 测试14: Shell信息获取
    {
        local shell_info
        shell_info=$(gs_version_get_shell_info)
        test_contains "Shell信息获取" ":" "$shell_info"
    }
    
    # 测试15: 系统信息获取
    {
        local system_info
        system_info=$(gs_version_get_system_info)
        test_contains "系统信息获取" ":" "$system_info"
    }
}

# ===================================
# 测试套件3: gs-status命令测试
# ===================================
test_suite_status_command() {
    echo
    echo "=== 测试套件3: gs-status命令测试 ==="
    
    # 测试16: 基本状态显示
    {
        local output
        output=$(gs_status_cmd 2>/dev/null)
        test_contains "基本状态显示" "系统状态" "$output"
    }
    
    # 测试17: JSON格式状态输出
    {
        local output
        output=$(gs_status_cmd --format json 2>/dev/null)
        test_json_valid "JSON格式状态输出" "$output"
    }
    
    # 测试18: 详细状态信息
    {
        local output
        output=$(gs_status_cmd --verbose 2>/dev/null)
        test_contains "详细状态信息" "性能指标" "$output"
    }
    
    # 测试19: 性能指标显示
    {
        local output
        output=$(gs_status_cmd --performance 2>/dev/null)
        test_contains "性能指标显示" "启动时间" "$output"
    }
    
    # 测试20: 健康检查功能
    {
        local output
        output=$(gs_status_cmd --check-health 2>/dev/null)
        test_contains "健康检查功能" "健康检查完成" "$output"
    }
    
    # 测试21: 系统检查函数
    {
        local result
        result=$(gs_status_check_system)
        test_contains "系统检查函数" "status:" "$result"
    }
    
    # 测试22: 配置检查函数
    {
        local result
        result=$(gs_status_check_config)
        test_contains "配置检查函数" "checked:" "$result"
    }
    
    # 测试23: 插件检查函数
    {
        local result
        result=$(gs_status_check_plugins)
        test_contains "插件检查函数" "total:" "$result"
    }
    
    # 测试24: 缓存检查函数
    {
        local result
        result=$(gs_status_check_cache)
        test_contains "缓存检查函数" "files:" "$result"
    }
    
    # 测试25: 性能检查函数
    {
        local result
        result=$(gs_status_check_performance)
        test_contains "性能检查函数" "startup:" "$result"
    }
}

# ===================================
# 测试套件4: 命令集成测试
# ===================================
test_suite_command_integration() {
    echo
    echo "=== 测试套件4: 命令集成测试 ==="
    
    # 测试26: 所有命令脚本可执行
    {
        test_assert_success "gs-help脚本可执行" "test -x '$_GS_ROOT/commands/gs_help.sh'"
    }
    
    {
        test_assert_success "gs-version脚本可执行" "test -x '$_GS_ROOT/commands/gs_version.sh'"
    }
    
    {
        test_assert_success "gs-status脚本可执行" "test -x '$_GS_ROOT/commands/gs_status.sh'"
    }
    
    # 测试27: 命令脚本直接执行
    {
        test_assert_success "gs-help脚本直接执行" "$_GS_ROOT/commands/gs_help.sh --help"
    }
    
    {
        test_assert_success "gs-version脚本直接执行" "$_GS_ROOT/commands/gs_version.sh --help"
    }
    
    {
        test_assert_success "gs-status脚本直接执行" "$_GS_ROOT/commands/gs_status.sh --help"
    }
    
    # 测试28: 错误参数处理
    {
        local output
        output=$($_GS_ROOT/commands/gs_version.sh --format invalid 2>&1)
        test_contains "版本命令错误参数处理" "不支持的输出格式" "$output"
    }
    
    {
        local output
        output=$($_GS_ROOT/commands/gs_status.sh --format invalid 2>&1)
        test_contains "状态命令错误参数处理" "不支持的输出格式" "$output"
    }
    
    # 测试29: 命令功能完整性
    {
        local help_output version_output status_output
        help_output=$(gs_help_cmd 2>/dev/null)
        version_output=$(gs_version_cmd 2>/dev/null)
        status_output=$(gs_status_cmd 2>/dev/null)
        
        test_assert "所有核心命令输出非空" "false" "$(test -z "$help_output" || test -z "$version_output" || test -z "$status_output" && echo true || echo false)"
    }
    
    # 测试30: JSON输出一致性
    {
        local help_json version_json status_json
        help_json=$(gs_help_cmd --format json 2>/dev/null)
        version_json=$(gs_version_cmd --format json 2>/dev/null)
        status_json=$(gs_status_cmd --format json 2>/dev/null)
        
        local all_valid=true
        echo "$help_json" | jq . >/dev/null 2>&1 || all_valid=false
        echo "$version_json" | jq . >/dev/null 2>&1 || all_valid=false
        echo "$status_json" | jq . >/dev/null 2>&1 || all_valid=false
        
        test_assert "所有命令JSON输出有效" "true" "$all_valid"
    }
}

# ===================================
# 运行所有测试
# ===================================
run_all_tests() {
    echo "Global Scripts V3 - 核心命令测试套件"
    echo "===================================="
    
    # 运行测试套件
    test_suite_help_command
    test_suite_version_command  
    test_suite_status_command
    test_suite_command_integration
    
    # 清理临时文件
    cleanup_temp_files
    
    # 输出测试结果
    echo
    echo "===================================="
    echo "测试结果汇总:"
    echo "  总测试数: $_TEST_COUNT"
    echo "  通过数量: $_TEST_PASSED"
    echo "  失败数量: $_TEST_FAILED"
    
    if [[ $_TEST_FAILED -eq 0 ]]; then
        echo "  结果: ✓ 所有测试通过"
        echo "  任务2.2 核心命令实现验证成功"
        return 0
    else
        echo "  结果: ✗ 部分测试失败"
        echo "  任务2.2需要进一步修复"
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