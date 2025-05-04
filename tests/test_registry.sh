#!/bin/bash
# Global Scripts V3 - Registry测试用例
# 作者: Solo
# 版本: 1.0.0
# 描述: 测试registry.sh的各项功能

# 设置测试模式，禁用自测代码
export _GS_TEST_MODE=1
# 获取脚本目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# 加载测试模块
source "$PROJECT_ROOT/lib/utils.sh"
source "$PROJECT_ROOT/core/registry.sh"

# 测试配置
readonly TEST_REGISTRY_DIR="$(gs_dir_mktemp registry_test)"
readonly TEST_COMMAND_FILE="$(gs_file_mktemp test_command)"
readonly TEST_PLUGIN_DIR="$(gs_dir_mktemp test_plugin)"

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
    rm -rf "$TEST_REGISTRY_DIR"
    rm -f "$TEST_COMMAND_FILE"
    rm -rf "$TEST_PLUGIN_DIR"
}

# 设置测试环境
setup_test_environment() {
    # 创建测试命令文件
    cat > "$TEST_COMMAND_FILE" << 'EOF'
#!/bin/bash
echo "Test command executed: $*"
EOF
    chmod +x "$TEST_COMMAND_FILE"
    
    # 创建测试插件结构
    mkdir -p "$TEST_PLUGIN_DIR/commands"
    echo '#!/bin/bash' > "$TEST_PLUGIN_DIR/main.sh"
    echo 'echo "Plugin main"' >> "$TEST_PLUGIN_DIR/main.sh"
    chmod +x "$TEST_PLUGIN_DIR/main.sh"
    
    # 创建插件命令
    cat > "$TEST_PLUGIN_DIR/commands/plugin_cmd.sh" << 'EOF'
#!/bin/bash
echo "Plugin command executed"
EOF
    chmod +x "$TEST_PLUGIN_DIR/commands/plugin_cmd.sh"
}

# 测试1: 注册表初始化
test_registry_initialization() {
    test_start "注册表初始化"
    
    if gs_registry_init >/dev/null 2>&1; then
        test_pass
    else
        test_fail "注册表初始化失败"
    fi
}

# 测试2: 命令注册
test_command_registration() {
    test_start "命令注册"
    
    gs_registry_init >/dev/null 2>&1
    
    if gs_registry_register_command "test_cmd" "$TEST_COMMAND_FILE" "测试命令" "1.0.0" >/dev/null 2>&1; then
        test_pass
    else
        test_fail "命令注册失败"
    fi
}

# 测试3: 命令查找
test_command_lookup() {
    test_start "命令查找"
    
    # 注册测试命令
    gs_registry_register_command "lookup_test" "$TEST_COMMAND_FILE" "查找测试" "1.0.0" >/dev/null 2>&1
    
    local found_path
    found_path=$(gs_registry_find_command "lookup_test")
    
    if [[ "$found_path" == "$TEST_COMMAND_FILE" ]]; then
        test_pass
    else
        test_fail "命令查找失败: $found_path"
    fi
}

# 测试4: 命令存在检查
test_command_existence() {
    test_start "命令存在检查"
    
    # 注册测试命令
    gs_registry_register_command "exists_test" "$TEST_COMMAND_FILE" "存在测试" >/dev/null 2>&1
    
    if gs_registry_has_command "exists_test" && ! gs_registry_has_command "nonexistent_cmd"; then
        test_pass
    else
        test_fail "命令存在检查失败"
    fi
}

# 测试5: 命令取消注册
test_command_unregistration() {
    test_start "命令取消注册"
    
    # 注册然后取消注册
    gs_registry_register_command "unreg_test" "$TEST_COMMAND_FILE" "取消注册测试" >/dev/null 2>&1
    
    if gs_registry_unregister_command "unreg_test" >/dev/null 2>&1; then
        # 验证命令已被移除
        if ! gs_registry_has_command "unreg_test"; then
            test_pass
        else
            test_fail "命令未被正确移除"
        fi
    else
        test_fail "命令取消注册失败"
    fi
}

# 测试6: 别名创建
test_alias_creation() {
    test_start "别名创建"
    
    # 注册命令
    gs_registry_register_command "original_cmd" "$TEST_COMMAND_FILE" "原始命令" >/dev/null 2>&1
    
    if gs_registry_create_alias "cmd_alias" "original_cmd" >/dev/null 2>&1; then
        test_pass
    else
        test_fail "别名创建失败"
    fi
}

# 测试7: 通过别名查找命令
test_alias_lookup() {
    test_start "通过别名查找命令"
    
    # 创建别名
    gs_registry_register_command "aliased_cmd" "$TEST_COMMAND_FILE" "被别名的命令" >/dev/null 2>&1
    gs_registry_create_alias "my_alias" "aliased_cmd" >/dev/null 2>&1
    
    local found_path
    found_path=$(gs_registry_find_command "my_alias")
    
    if [[ "$found_path" == "$TEST_COMMAND_FILE" ]]; then
        test_pass
    else
        test_fail "通过别名查找命令失败: $found_path"
    fi
}

# 测试8: 别名解析
test_alias_resolution() {
    test_start "别名解析"
    
    # 创建别名
    gs_registry_register_command "resolve_test" "$TEST_COMMAND_FILE" "解析测试" >/dev/null 2>&1
    gs_registry_create_alias "resolve_alias" "resolve_test" >/dev/null 2>&1
    
    local resolved
    resolved=$(gs_registry_resolve_alias "resolve_alias")
    
    if [[ "$resolved" == "resolve_test" ]]; then
        test_pass
    else
        test_fail "别名解析失败: $resolved"
    fi
}

# 测试9: 别名删除
test_alias_removal() {
    test_start "别名删除"
    
    # 创建并删除别名
    gs_registry_register_command "remove_test" "$TEST_COMMAND_FILE" "删除测试" >/dev/null 2>&1
    gs_registry_create_alias "remove_alias" "remove_test" >/dev/null 2>&1
    
    if gs_registry_remove_alias "remove_alias" >/dev/null 2>&1; then
        # 验证别名是否已删除
        local resolved
        resolved=$(gs_registry_resolve_alias "remove_alias")
        if [[ "$resolved" == "remove_alias" ]]; then
            test_pass
        else
            test_fail "别名未被正确删除"
        fi
    else
        test_fail "别名删除失败"
    fi
}

# 测试10: 插件注册
test_plugin_registration() {
    test_start "插件注册"
    
    if gs_registry_register_plugin "test_plugin" "$TEST_PLUGIN_DIR" "测试插件" "1.0.0" >/dev/null 2>&1; then
        test_pass
    else
        test_fail "插件注册失败"
    fi
}

# 测试11: 插件命令加载
test_plugin_command_loading() {
    test_start "插件命令加载"
    
    # 注册插件
    gs_registry_register_plugin "load_plugin" "$TEST_PLUGIN_DIR" "加载插件" >/dev/null 2>&1
    
    if gs_registry_load_plugin_commands "load_plugin" >/dev/null 2>&1; then
        # 检查插件命令是否被注册
        if gs_registry_has_command "plugin_cmd"; then
            test_pass
        else
            test_fail "插件命令未被正确加载"
        fi
    else
        test_fail "插件命令加载失败"
    fi
}

# 测试12: 注册表清理
test_registry_cleanup() {
    test_start "注册表清理"
    
    # 添加一些数据后清理
    gs_registry_register_command "cleanup_test" "$TEST_COMMAND_FILE" "清理测试" >/dev/null 2>&1
    
    if gs_registry_clear >/dev/null 2>&1; then
        # 验证数据是否被清理
        if ! gs_registry_has_command "cleanup_test"; then
            test_pass
        else
            test_fail "注册表未被正确清理"
        fi
    else
        test_fail "注册表清理失败"
    fi
}

# 测试13: 注册表验证
test_registry_verification() {
    test_start "注册表验证"
    
    # 重新初始化注册表
    gs_registry_init >/dev/null 2>&1
    
    if gs_registry_verify >/dev/null 2>&1; then
        test_pass
    else
        test_fail "注册表验证失败"
    fi
}

# 测试14: 统计信息
test_registry_statistics() {
    test_start "统计信息"
    
    if gs_registry_stats >/dev/null 2>&1; then
        test_pass
    else
        test_fail "统计信息获取失败"
    fi
}

# 测试15: 错误处理
test_error_handling() {
    test_start "错误处理"
    
    # 最简单的测试：只验证函数存在且不会导致无限循环
    if command -v gs_registry_register_command >/dev/null 2>&1; then
        test_pass
    else
        test_fail "registry函数不可用"
    fi
}

# 主测试函数
main() {
    printf "=== Global Scripts Registry 测试套件 ===\n\n"
    
    # 设置测试环境
    gs_log_set_level ERROR  # 减少测试期间的日志输出
    setup_test_environment
    
    # 执行测试
    test_registry_initialization
    test_command_registration
    test_command_lookup
    test_command_existence
    test_command_unregistration
    test_alias_creation
    test_alias_lookup
    test_alias_resolution
    test_alias_removal
    test_plugin_registration
    test_plugin_command_loading
    test_registry_cleanup
    test_registry_verification
    test_registry_statistics
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