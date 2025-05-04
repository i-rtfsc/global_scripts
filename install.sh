#!/bin/bash
# Global Scripts V3 安装脚本
# 作者: Solo
# 版本: 动态从VERSION文件读取
# 描述: 自动化安装和配置 Global Scripts V3

set -euo pipefail

# 获取脚本目录和版本
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly _GS_VERSION="$(cat "${SCRIPT_DIR}/VERSION" 2>/dev/null || echo "unknown")"

# 颜色定义
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# 全局变量
readonly _GS_INSTALL_DIR="${HOME}/.local/share/global_scripts"
readonly _GS_BIN_DIR="${HOME}/.local/bin"
readonly _GS_CONFIG_DIR="${HOME}/.config/global_scripts"

# 日志函数
log_info() {
    printf "${BLUE}[INFO]${NC} %s\n" "$1"
}

log_success() {
    printf "${GREEN}[SUCCESS]${NC} %s\n" "$1"
}

log_warning() {
    printf "${YELLOW}[WARNING]${NC} %s\n" "$1"
}

log_error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1" >&2
}

# 检查系统要求
check_requirements() {
    log_info "检查系统要求..."
    
    local errors=0
    
    # 检查bash版本
    if [[ ${BASH_VERSION%%.*} -lt 3 ]]; then
        log_error "需要 Bash 3.0 或更高版本，当前版本: ${BASH_VERSION}"
        ((errors++))
    fi
    
    # 检查必需命令
    local required_commands=("jq" "sed" "awk" "grep")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log_error "缺少必需命令: $cmd"
            ((errors++))
        fi
    done
    
    if [[ $errors -gt 0 ]]; then
        log_error "系统要求检查失败，请安装缺少的依赖"
        return 1
    fi
    
    log_success "系统要求检查通过"
    return 0
}

# 创建目录结构
create_directories() {
    log_info "创建目录结构..."
    
    local dirs=(
        "$_GS_INSTALL_DIR"
        "$_GS_BIN_DIR" 
        "$_GS_CONFIG_DIR"
        "${HOME}/.cache/global_scripts"
        "${HOME}/.local/share/global_scripts/logs"
    )
    
    for dir in "${dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            log_info "创建目录: $dir"
        fi
    done
    
    log_success "目录结构创建完成"
}

# 复制文件
copy_files() {
    log_info "复制程序文件..."
    
    # 复制所有文件到安装目录
    cp -r "${SCRIPT_DIR}"/* "$_GS_INSTALL_DIR/"
    
    # 创建可执行文件链接
    ln -sf "${_GS_INSTALL_DIR}/gs_env.sh" "${_GS_BIN_DIR}/gs"
    chmod +x "${_GS_BIN_DIR}/gs"
    
    log_success "文件复制完成"
}

# 配置shell集成
configure_shell() {
    log_info "配置shell集成..."
    
    local shell_config=""
    case "${SHELL##*/}" in
        bash)
            shell_config="${HOME}/.bashrc"
            ;;
        zsh)
            shell_config="${HOME}/.zshrc"
            ;;
        *)
            log_warning "未识别的shell: ${SHELL}，请手动配置"
            return 0
            ;;
    esac
    
    # 检查是否已经配置
    if grep -q "Global Scripts V3" "$shell_config" 2>/dev/null; then
        log_info "shell配置已存在，跳过"
        return 0
    fi
    
    # 添加配置
    cat >> "$shell_config" << 'EOF'

# Global Scripts V3 Configuration
if [[ -f "$HOME/.local/share/global_scripts/gs_env.sh" ]]; then
    source "$HOME/.local/share/global_scripts/gs_env.sh"
fi

# Add Global Scripts bin to PATH
if [[ -d "$HOME/.local/bin" ]] && [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    export PATH="$HOME/.local/bin:$PATH"
fi
EOF
    
    log_success "shell配置完成"
}

# 初始化配置
initialize_config() {
    log_info "初始化配置文件..."
    
    # 如果配置文件不存在，复制默认配置
    if [[ ! -f "${_GS_CONFIG_DIR}/config.json" ]]; then
        if [[ -f "${_GS_INSTALL_DIR}/config/default.json" ]]; then
            cp "${_GS_INSTALL_DIR}/config/default.json" "${_GS_CONFIG_DIR}/config.json"
            log_info "创建默认配置文件"
        fi
    fi
    
    log_success "配置初始化完成"
}

# 运行测试
run_tests() {
    log_info "运行安装测试..."
    
    # 测试基本功能
    if source "${_GS_INSTALL_DIR}/gs_env.sh" >/dev/null 2>&1; then
        log_success "基本功能测试通过"
    else
        log_error "基本功能测试失败"
        return 1
    fi
    
    # 测试兼容性
        log_success "兼容性测试通过"
    else
        log_error "兼容性测试失败"
        return 1
    fi
    
    log_success "所有测试通过"
}

# 显示安装结果
show_installation_result() {
    log_success "Global Scripts V${_GS_VERSION} 安装完成！"
    echo
    log_info "安装位置: $_GS_INSTALL_DIR"
    log_info "配置目录: $_GS_CONFIG_DIR"
    log_info "可执行文件: $_GS_BIN_DIR/gs"
    echo
    log_info "使用以下命令开始："
    echo "  source ~/.bashrc  # 或 source ~/.zshrc"
    echo "  gs-version        # 查看版本信息"
    echo "  gs-help          # 查看帮助信息"
    echo
    log_success "安装成功！享受 Global Scripts V${_GS_VERSION} 🚀"
}

# 主安装函数
main() {
    echo "=================================="
    echo "  Global Scripts V${_GS_VERSION} 安装程序"
    echo "=================================="
    echo
    
    # 执行安装步骤
    check_requirements || exit 1
    create_directories
    copy_files
    configure_shell
    initialize_config  
    run_tests || {
        log_error "安装测试失败，请检查错误信息"
        exit 1
    }
    
    show_installation_result
}

# 如果直接执行脚本，运行主函数
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi