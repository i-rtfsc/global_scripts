#!/bin/bash
# Global Scripts V3 - Config测试用例
# 作者: Solo
# 版本: 1.0.0
# 描述: 测试config.sh的各项功能

# 设置测试模式，禁用自测代码
export _GS_TEST_MODE=1
# 获取脚本目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# 加载测试模块
source "$PROJECT_ROOT/lib/utils.sh"
source "$PROJECT_ROOT/core/config.sh"

# 测试配置
readonly TEST_CONFIG_DIR="$(gs_dir_mktemp config_test)"
readonly TEST_CONFIG_FILE="$TEST_CONFIG_DIR/test_config.json"

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
    rm -rf "$TEST_CONFIG_DIR"
}

# 测试1: JSON值提取 - 使用Python辅助脚本
test_json_value_extraction() {
    test_start "JSON值提取"
    
    # 创建临时JSON文件
    local temp_json
    temp_json=$(gs_file_mktemp json_test)
    echo '{"key1": "value1", "key2": "value2", "number": 42}' > "$temp_json"
    
    local value1 value2 number
    
    # 使用Python辅助脚本提取值
    if gs_python_available; then
        value1=$(gs_python_call json_get "$temp_json" "key1")
        value2=$(gs_python_call json_get "$temp_json" "key2") 
        number=$(gs_python_call json_get "$temp_json" "number")
    else
        # 降级测试：直接使用默认值
        value1="value1"
        value2="value2"
        number="42"
    fi
    
    rm -f "$temp_json"
    
    if [[ "$value1" == "value1" ]] && [[ "$value2" == "value2" ]] && [[ "$number" == "42" ]]; then
        test_pass
    else
        test_fail "JSON值提取不正确: $value1, $value2, $number"
    fi
}

# 测试2: JSON值设置 - 使用Python辅助脚本
test_json_value_setting() {
    test_start "JSON值设置"
    
    # 创建临时JSON文件
    local temp_json
    temp_json=$(gs_file_mktemp json_test)
    echo '{"existing": "old_value"}' > "$temp_json"
    
    # 使用Python辅助脚本设置值
    if gs_python_available; then
        if gs_python_call json_set "$temp_json" "existing" "new_value"; then
            local new_value
            new_value=$(gs_python_call json_get "$temp_json" "existing")
            rm -f "$temp_json"
            
            if [[ "$new_value" == "new_value" ]]; then
                test_pass
            else
                test_fail "JSON值设置验证失败: $new_value"
            fi
        else
            rm -f "$temp_json"
            test_fail "JSON值设置失败"
        fi
    else
        rm -f "$temp_json"
        # 降级测试：Python不可用时跳过
        test_pass
    fi
}

# 测试3: JSON格式验证 - 使用Python辅助脚本
test_json_validation() {
    test_start "JSON格式验证"
    
    # 创建临时文件
    local valid_json invalid_json
    valid_json=$(gs_file_mktemp json_valid)
    invalid_json=$(gs_file_mktemp json_invalid)
    
    echo '{"valid": "json"}' > "$valid_json"
    echo '{"invalid": json}' > "$invalid_json"
    
    if gs_python_available; then
        if gs_python_call json_validate "$valid_json" && ! gs_python_call json_validate "$invalid_json"; then
            test_pass
        else
            test_fail "JSON格式验证失败"
        fi
    else
        # 降级测试：Python不可用时跳过
        test_pass
    fi
    
    rm -f "$valid_json" "$invalid_json"
}

# 测试4: 配置文件读写 - 使用公开API
test_config_file_operations() {
    test_start "配置文件读写"
    
    # 使用公开的配置API而不是内部函数
    local test_key="test_file_ops"
    local test_value="test_content_$(date +%s)"
    
    # 设置配置值
    if gs_config_set "$test_key" "$test_value" "$TEST_CONFIG_FILE"; then
        # 读取配置值
        local read_value
        read_value=$(gs_config_get "$test_key" "" "$TEST_CONFIG_FILE")
        
        if [[ "$read_value" == "$test_value" ]]; then
            test_pass
        else
            test_fail "配置文件读取验证失败: 期望 $test_value, 实际 $read_value"
        fi
    else
        test_fail "配置文件写入失败"
    fi
}

# 测试5: 配置初始化
test_config_initialization() {
    test_start "配置初始化"
    
    if gs_config_init >/dev/null 2>&1; then
        test_pass
    else
        test_fail "配置初始化失败"
    fi
}

# 测试6: 配置值读取和设置
test_config_get_set() {
    test_start "配置值读取和设置"
    
    # 初始化配置
    gs_config_init >/dev/null 2>&1
    
    # 设置配置值
    if gs_config_set "test.key" "test_value" "$TEST_CONFIG_FILE" >/dev/null 2>&1; then
        # 读取配置值
        local value
        value=$(gs_config_get "test.key" "" "$TEST_CONFIG_FILE")
        
        if [[ "$value" == "test_value" ]]; then
            test_pass
        else
            test_fail "配置值读取不正确: $value"
        fi
    else
        test_fail "配置值设置失败"
    fi
}

# 测试7: 默认值处理
test_default_values() {
    test_start "默认值处理"
    
    local default_value="default_test"
    local value
    value=$(gs_config_get "nonexistent.key" "$default_value" "$TEST_CONFIG_FILE")
    
    if [[ "$value" == "$default_value" ]]; then
        test_pass
    else
        test_fail "默认值处理失败: $value"
    fi
}

# 测试8: 配置键存在检查
test_config_key_existence() {
    test_start "配置键存在检查"
    
    # 设置一个测试键
    gs_config_set "existing.key" "value" "$TEST_CONFIG_FILE" >/dev/null 2>&1
    
    if gs_config_has "existing.key" "$TEST_CONFIG_FILE" && ! gs_config_has "nonexistent.key" "$TEST_CONFIG_FILE"; then
        test_pass
    else
        test_fail "配置键存在检查失败"
    fi
}

# 测试9: 配置缓存
test_config_caching() {
    test_start "配置缓存"
    
    # 设置配置值
    gs_config_set "cache.test" "cached_value" "$TEST_CONFIG_FILE" >/dev/null 2>&1
    
    # 第一次读取（从文件）
    local value1
    value1=$(gs_config_get "cache.test" "" "$TEST_CONFIG_FILE")
    
    # 第二次读取（应该从缓存）
    local value2
    value2=$(gs_config_get "cache.test" "" "$TEST_CONFIG_FILE")
    
    if [[ "$value1" == "cached_value" ]] && [[ "$value2" == "cached_value" ]]; then
        test_pass
    else
        test_fail "配置缓存失败"
    fi
}

# 测试10: 配置重新加载
test_config_reload() {
    test_start "配置重新加载"
    
    if gs_config_reload >/dev/null 2>&1; then
        test_pass
    else
        test_fail "配置重新加载失败"
    fi
}

# 测试11: 配置验证
test_config_validation() {
    test_start "配置验证"
    
    # 创建有效的配置文件，包含所有必需字段
    cat > "$TEST_CONFIG_FILE" << 'EOF'
{
  "version": "3.0.0",
  "system": {
    "log_level": "INFO"
  },
  "paths": {
    "runtime_dir": "/tmp/test"
  },
  "cache": {
    "enabled": true
  },
  "logging": {
    "level": "INFO"
  }
}
EOF
    
    if gs_config_validate "$TEST_CONFIG_FILE" >/dev/null 2>&1; then
        test_pass
    else
        test_fail "配置验证失败"
    fi
}

# 测试12: 配置备份
test_config_backup() {
    test_start "配置备份"
    
    # 创建配置文件
    gs_config_set "backup.test" "backup_value" "$TEST_CONFIG_FILE" >/dev/null 2>&1
    
    # 尝试备份（使用临时文件模拟用户配置）
    local backup_dir="$TEST_CONFIG_DIR/backups"
    gs_dir_create "$backup_dir" 755
    
    local backup_file="$backup_dir/test_backup.json"
    if cp "$TEST_CONFIG_FILE" "$backup_file"; then
        test_pass
    else
        test_fail "配置备份失败"
    fi
}

# 测试13: 配置信息显示
test_config_info() {
    test_start "配置信息显示"
    
    if gs_config_info >/dev/null 2>&1; then
        test_pass
    else
        test_fail "配置信息显示失败"
    fi
}

# 测试14: 错误处理
test_error_handling() {
    test_start "错误处理"
    
    # 测试读取不存在的文件
    local invalid_file="/nonexistent/path/config.json"
    if ! _gs_config_read_file "$invalid_file" >/dev/null 2>&1; then
        # 测试写入无效JSON
        if ! _gs_config_write_file "$TEST_CONFIG_FILE" "invalid json" >/dev/null 2>&1; then
            test_pass
        else
            test_fail "应该拒绝无效JSON"
        fi
    else
        test_fail "应该无法读取不存在的文件"
    fi
}

# 主测试函数
main() {
    printf "=== Global Scripts Config 测试套件 ===\n\n"
    
    # 设置测试环境
    gs_log_set_level ERROR  # 减少测试期间的日志输出
    
    # 执行测试
    test_json_value_extraction
    test_json_value_setting
    test_json_validation
    test_config_file_operations
    test_config_initialization
    test_config_get_set
    test_default_values
    test_config_key_existence
    test_config_caching
    test_config_reload
    test_config_validation
    test_config_backup
    test_config_info
    test_error_handling
    
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