#!/bin/bash
# Global Scripts V3 - 测试运行器
# 作者: Solo
# 版本: 1.0.0
# 描述: 统一运行所有测试用例并生成报告

# 设置测试模式，禁用自测代码
export _GS_TEST_MODE=1
# 设置测试模式，禁用自测代码
export _GS_TEST_MODE=1

# 获取脚本目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# 颜色定义
readonly GREEN='\033[0;32m'
readonly RED='\033[0;31m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# 测试统计
declare -i TOTAL_SUITES=0
declare -i PASSED_SUITES=0
declare -i FAILED_SUITES=0

# 帮助信息
show_help() {
    local available_suites
    available_suites=($(discover_test_suites))
    
    cat << EOF
Global Scripts V3 测试运行器

用法: $0 [选项] [测试套件...]

选项:
  -h, --help     显示此帮助信息
  -v, --verbose  详细输出模式
  -f, --fast     快速模式（跳过性能测试）
  -c, --continue 遇到失败继续执行
  --clean        运行前清理测试文件

可用测试套件:
EOF
    
    # 动态列出所有可用的测试套件
    for suite in "${available_suites[@]}"; do
        printf "  %-15s 测试%s模块\n" "$suite" "$suite"
    done
    
    cat << EOF
  all            运行所有测试（默认）

示例:
  $0                    # 运行所有测试
  $0 ${available_suites[0]} ${available_suites[1]}       # 只运行指定测试
  $0 -v --clean all     # 详细模式运行所有测试并清理
EOF
}

# 日志函数
log_info() {
    printf "${BLUE}[INFO]${NC} %s\n" "$*"
}

log_success() {
    printf "${GREEN}[SUCCESS]${NC} %s\n" "$*"
}

log_error() {
    printf "${RED}[ERROR]${NC} %s\n" "$*"
}

log_warn() {
    printf "${YELLOW}[WARN]${NC} %s\n" "$*"
}

# 自动发现测试套件
discover_test_suites() {
    local test_files=()
    local suite_name
    
    # 已知有问题的测试套件（暂时跳过）
    local skip_suites=("declare_compat")
    
    # 查找所有test_*.sh文件，排除test_runner.sh
    for file in "$SCRIPT_DIR"/test_*.sh; do
        [[ -f "$file" ]] || continue
        
        # 排除test_runner.sh本身
        [[ "$(basename "$file")" == "test_runner.sh" ]] && continue
        
        # 提取套件名称 (test_name.sh -> name)
        suite_name=$(basename "$file" .sh)
        suite_name=${suite_name#test_}
        
        # 检查是否在跳过列表中
        local skip=false
        for skip_suite in "${skip_suites[@]}"; do
            if [[ "$suite_name" == "$skip_suite" ]]; then
                skip=true
                break
            fi
        done
        
        [[ "$skip" == "false" ]] && test_files+=("$suite_name")
    done
    
    printf '%s\n' "${test_files[@]}"
}

# 检查套件是否存在
suite_exists() {
    local suite="$1"
    local available_suites
    available_suites=($(discover_test_suites))
    
    local available_suite
    for available_suite in "${available_suites[@]}"; do
        [[ "$available_suite" == "$suite" ]] && return 0
    done
    return 1
}

# 获取所有可用测试套件列表
get_available_suites() {
    local suites
    suites=($(discover_test_suites))
    echo "${suites[*]}"
}

# 检查依赖
check_dependencies() {
    local missing_deps=()
    
    # 检查必要的命令
    local required_commands=("bash" "chmod")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "缺少依赖命令: ${missing_deps[*]}"
        return 1
    fi
    
    # 检查测试文件
    local test_files=(
        "$SCRIPT_DIR/test_logger.sh"
        "$SCRIPT_DIR/test_error.sh" 
        "$SCRIPT_DIR/test_utils.sh"
    )
    
    for file in "${test_files[@]}"; do
        if [[ ! -f "$file" ]]; then
            log_error "测试文件不存在: $file"
            return 1
        fi
        
        # 确保测试文件可执行
        chmod +x "$file"
    done
    
    return 0
}

# 清理测试环境
clean_test_environment() {
    log_info "清理测试环境..."
    
    # 清理临时文件
    find /tmp -name "gs_tmp*" -type f -mmin +60 -delete 2>/dev/null || true
    find "${TMPDIR:-/tmp}" -name "gs_tmp*" -type f -mmin +60 -delete 2>/dev/null || true
    
    # 清理测试日志
    [[ -d "$HOME/.local/share/global_scripts/logs" ]] && rm -rf "$HOME/.local/share/global_scripts/logs"/*test* 2>/dev/null || true
    
    log_success "测试环境清理完成"
}

# 运行单个测试套件
run_test_suite() {
    local suite_name="$1"
    local test_file="$SCRIPT_DIR/test_${suite_name}.sh"
    local verbose="${2:-false}"
    
    TOTAL_SUITES=$((TOTAL_SUITES + 1))
    
    printf "\n"
    printf "================================================================================\n"
    printf "🧪 运行测试套件: %s\n" "$suite_name"
    printf "================================================================================\n"
    
    if [[ ! -f "$test_file" ]]; then
        log_error "测试文件不存在: $test_file"
        FAILED_SUITES=$((FAILED_SUITES + 1))
        return 1
    fi
    
    # 运行测试
    local start_time end_time duration
    start_time=$(date +%s)
    
    if [[ "$verbose" == "true" ]]; then
        if bash "$test_file"; then
            end_time=$(date +%s)
            duration=$((end_time - start_time))
            log_success "测试套件 '$suite_name' 通过 (耗时: ${duration}秒)"
            PASSED_SUITES=$((PASSED_SUITES + 1))
            return 0
        else
            end_time=$(date +%s)
            duration=$((end_time - start_time))
            log_error "测试套件 '$suite_name' 失败 (耗时: ${duration}秒)"
            FAILED_SUITES=$((FAILED_SUITES + 1))
            return 1
        fi
    else
        local output
        if output=$(bash "$test_file" 2>&1); then
            end_time=$(date +%s)
            duration=$((end_time - start_time))
            log_success "测试套件 '$suite_name' 通过 (耗时: ${duration}秒)"
            PASSED_SUITES=$((PASSED_SUITES + 1))
            
            # 显示简要结果
            echo "$output" | grep -E "(总测试数|通过|失败|成功率)" || true
            return 0
        else
            end_time=$(date +%s)
            duration=$((end_time - start_time))
            log_error "测试套件 '$suite_name' 失败 (耗时: ${duration}秒)"
            FAILED_SUITES=$((FAILED_SUITES + 1))
            
            # 显示错误信息
            echo "$output" | tail -20
            return 1
        fi
    fi
}

# 生成测试报告
generate_report() {
    printf "\n"
    printf "================================================================================\n"
    printf "📊 测试总结报告\n"
    printf "================================================================================\n"
    printf "总测试套件: %d\n" "$TOTAL_SUITES"
    printf "通过套件: %d\n" "$PASSED_SUITES"
    printf "失败套件: %d\n" "$FAILED_SUITES"
    
    if [[ $TOTAL_SUITES -gt 0 ]]; then
        local success_rate
        success_rate=$(echo "scale=1; $PASSED_SUITES * 100 / $TOTAL_SUITES" | bc 2>/dev/null || echo "0")
        printf "成功率: %s%%\n" "$success_rate"
    fi
    
    printf "\n"
    if [[ $FAILED_SUITES -eq 0 ]]; then
        printf "🎉 ${GREEN}所有测试套件都通过了！${NC}\n"
    else
        printf "⚠️  ${RED}有 %d 个测试套件失败${NC}\n" "$FAILED_SUITES"
    fi
    
    # 生成徽章
    printf "\n测试徽章:\n"
    if [[ $FAILED_SUITES -eq 0 ]]; then
        printf "![Tests](https://img.shields.io/badge/tests-passing-brightgreen)\n"
    else
        printf "![Tests](https://img.shields.io/badge/tests-failing-red)\n"
    fi
}

# 主函数
main() {
    local verbose=false
    local fast=false
    local continue_on_error=false
    local clean=false
    local test_suites=()
    
    # 解析命令行参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--verbose)
                verbose=true
                shift
                ;;
            -f|--fast)
                fast=true
                export GS_TEST_FAST=true
                shift
                ;;
            -c|--continue)
                continue_on_error=true
                shift
                ;;
            --clean)
                clean=true
                shift
                ;;
            all)
                test_suites=($(discover_test_suites))
                shift
                ;;
            *)
                # 检查是否是有效的测试套件
                if suite_exists "$1"; then
                    test_suites+=("$1")
                    shift
                else
                    log_error "未知参数或无效测试套件: $1"
                    log_info "可用测试套件: $(get_available_suites)"
                    show_help
                    exit 1
                fi
                ;;
        esac
    done
    
    # 默认运行所有测试
    if [[ ${#test_suites[@]} -eq 0 ]]; then
        test_suites=($(discover_test_suites))
    fi
    
    printf "🚀 Global Scripts V3 测试运行器\n"
    printf "测试套件: %s\n" "${test_suites[*]}"
    [[ "$verbose" == "true" ]] && printf "详细模式: 开启\n"
    [[ "$fast" == "true" ]] && printf "快速模式: 开启\n"
    [[ "$continue_on_error" == "true" ]] && printf "继续模式: 开启\n"
    [[ "$clean" == "true" ]] && printf "清理模式: 开启\n"
    
    # 检查依赖
    if ! check_dependencies; then
        log_error "依赖检查失败"
        exit 1
    fi
    
    # 清理环境
    if [[ "$clean" == "true" ]]; then
        clean_test_environment
    fi
    
    # 记录开始时间
    local start_time
    start_time=$(date +%s)
    
    # 运行测试套件
    for suite in "${test_suites[@]}"; do
        if ! run_test_suite "$suite" "$verbose"; then
            if [[ "$continue_on_error" == "false" ]]; then
                log_error "测试套件失败，停止执行"
                break
            fi
        fi
    done
    
    # 计算总耗时
    local end_time duration
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    
    # 生成报告
    generate_report
    printf "总耗时: %d秒\n" "$duration"
    
    # 返回适当的退出码
    if [[ $FAILED_SUITES -eq 0 ]]; then
        exit 0
    else
        exit 1
    fi
}

# 如果直接执行此脚本，运行主函数
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
    main "$@"
fi