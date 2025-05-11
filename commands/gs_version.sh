#!/bin/bash
# Global Scripts V3 - Version Command
# 作者: Solo
# 版本: 3.0.0
# 描述: 版本信息显示命令，支持多种格式输出和依赖检查

# 防止重复加载
if [[ -n "${_GS_VERSION_LOADED:-}" ]]; then
    return 0
fi
readonly _GS_VERSION_LOADED=1

# 设置基础路径
if [[ -z "${_GS_ROOT:-}" ]]; then
    readonly _GS_ROOT="$(cd "$(dirname "$(dirname "${BASH_SOURCE[0]}")")" && pwd)"
fi

# 加载依赖模块
source "${_GS_ROOT}/lib/utils.sh"
source "${_GS_ROOT}/lib/logger.sh"
source "${_GS_ROOT}/lib/error.sh"
source "${_GS_ROOT}/api/command_api.sh"

# ===================================
# 版本信息获取函数
# ===================================

# 获取Global Scripts版本
gs_version_get_gs_version() {
    if [[ -f "${_GS_ROOT}/VERSION" ]]; then
        cat "${_GS_ROOT}/VERSION" 2>/dev/null || echo "unknown"
    else
        echo "unknown"
    fi
}

# 获取Git版本信息
gs_version_get_git_info() {
    if [[ -d "${_GS_ROOT}/.git" ]] && command -v git >/dev/null 2>&1; then
        local commit_hash commit_date branch
        commit_hash=$(git -C "${_GS_ROOT}" rev-parse --short HEAD 2>/dev/null || echo "unknown")
        commit_date=$(git -C "${_GS_ROOT}" log -1 --format="%ci" 2>/dev/null || echo "unknown")
        branch=$(git -C "${_GS_ROOT}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
        
        echo "commit:$commit_hash,date:$commit_date,branch:$branch"
    else
        echo "not-git-repo"
    fi
}

# 获取Shell版本信息
gs_version_get_shell_info() {
    local shell_name shell_version
    
    if [[ -n "${BASH_VERSION:-}" ]]; then
        shell_name="bash"
        shell_version="$BASH_VERSION"
    elif [[ -n "${ZSH_VERSION:-}" ]]; then
        shell_name="zsh"  
        shell_version="$ZSH_VERSION"
    else
        shell_name="unknown"
        shell_version="unknown"
    fi
    
    echo "$shell_name:$shell_version"
}

# 获取Python版本信息
gs_version_get_python_info() {
    local python_cmd python_version
    
    # 检测可用的Python命令
    for cmd in python3 python python2; do
        if command -v "$cmd" >/dev/null 2>&1; then
            python_cmd="$cmd"
            python_version=$($cmd --version 2>&1 | head -1 | cut -d' ' -f2 2>/dev/null || echo "unknown")
            break
        fi
    done
    
    if [[ -n "$python_cmd" ]]; then
        echo "$python_cmd:$python_version"
    else
        echo "not-found:not-found"
    fi
}

# 获取系统信息
gs_version_get_system_info() {
    local os_name os_version arch
    
    if command -v uname >/dev/null 2>&1; then
        os_name=$(uname -s 2>/dev/null || echo "unknown")
        os_version=$(uname -r 2>/dev/null || echo "unknown")
        arch=$(uname -m 2>/dev/null || echo "unknown")
    else
        os_name="unknown"
        os_version="unknown" 
        arch="unknown"
    fi
    
    echo "$os_name:$os_version:$arch"
}

# 检查工具依赖版本
gs_version_check_dependencies() {
    local deps_info=""
    
    # 必需工具
    local required_tools=("jq" "git" "curl")
    for tool in "${required_tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            local version=$($tool --version 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 2>/dev/null || echo "unknown")
            deps_info+="$tool:$version,"
        else
            deps_info+="$tool:not-found,"
        fi
    done
    
    # 可选工具
    local optional_tools=("fzf" "bat" "fd" "rg")
    for tool in "${optional_tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            local version
            case "$tool" in
                "fzf")
                    version=$(fzf --version 2>&1 | head -1 | cut -d' ' -f1 2>/dev/null || echo "unknown")
                    ;;
                "bat")
                    version=$(bat --version 2>&1 | head -1 | cut -d' ' -f2 2>/dev/null || echo "unknown")
                    ;;
                "fd")
                    version=$(fd --version 2>&1 | head -1 | cut -d' ' -f2 2>/dev/null || echo "unknown")
                    ;;
                "rg")
                    version=$(rg --version 2>&1 | head -1 | cut -d' ' -f2 2>/dev/null || echo "unknown")
                    ;;
                *)
                    version="unknown"
                    ;;
            esac
            deps_info+="$tool:$version,"
        else
            deps_info+="$tool:not-found,"
        fi
    done
    
    echo "${deps_info%,}"
}

# ===================================
# 版本信息格式化输出
# ===================================

# 文本格式输出基本版本信息
gs_version_show_basic_text() {
    local gs_version
    gs_version=$(gs_version_get_gs_version)
    
    echo "Global Scripts V3"
    echo "版本: $gs_version"
    echo
    
    local shell_info system_info
    shell_info=$(gs_version_get_shell_info)
    system_info=$(gs_version_get_system_info)
    
    echo "运行环境:"
    echo "  Shell: ${shell_info//:/ }"
    echo "  系统: ${system_info//:/ }"
}

# JSON格式输出基本版本信息
gs_version_show_basic_json() {
    local gs_version shell_info python_info system_info
    gs_version=$(gs_version_get_gs_version)
    shell_info=$(gs_version_get_shell_info)
    python_info=$(gs_version_get_python_info)
    system_info=$(gs_version_get_system_info)
    
    local shell_name shell_version
    IFS=':' read -r shell_name shell_version <<< "$shell_info"
    
    local python_cmd python_version
    IFS=':' read -r python_cmd python_version <<< "$python_info"
    
    local os_name os_version arch
    IFS=':' read -r os_name os_version arch <<< "$system_info"
    
    cat << EOF
{
  "name": "Global Scripts V3",
  "version": "$gs_version",
  "environment": {
    "shell": {
      "name": "$shell_name",
      "version": "$shell_version"
    },
    "python": {
      "command": "$python_cmd",
      "version": "$python_version"
    },
    "system": {
      "os": "$os_name",
      "version": "$os_version",
      "architecture": "$arch"
    }
  }
}
EOF
}

# 文本格式输出完整版本信息
gs_version_show_full_text() {
    gs_version_show_basic_text
    
    local git_info python_info
    git_info=$(gs_version_get_git_info)
    python_info=$(gs_version_get_python_info)
    
    echo
    echo "详细信息:"
    
    if [[ "$git_info" != "not-git-repo" ]]; then
        local commit_hash commit_date branch
        IFS=',' read -r commit_hash commit_date branch <<< "$git_info"
        echo "  Git信息:"
        echo "    ${commit_hash//commit:/提交: }"
        echo "    ${commit_date//date:/日期: }"
        echo "    ${branch//branch:/分支: }"
    fi
    
    local python_cmd python_version
    IFS=':' read -r python_cmd python_version <<< "$python_info"
    echo "  Python: $python_cmd $python_version"
    
    echo
    echo "安装路径: $_GS_ROOT"
}

# JSON格式输出完整版本信息  
gs_version_show_full_json() {
    local gs_version shell_info python_info system_info git_info
    gs_version=$(gs_version_get_gs_version)
    shell_info=$(gs_version_get_shell_info)
    python_info=$(gs_version_get_python_info)
    system_info=$(gs_version_get_system_info)
    git_info=$(gs_version_get_git_info)
    
    local shell_name shell_version
    IFS=':' read -r shell_name shell_version <<< "$shell_info"
    
    local python_cmd python_version
    IFS=':' read -r python_cmd python_version <<< "$python_info"
    
    local os_name os_version arch
    IFS=':' read -r os_name os_version arch <<< "$system_info"
    
    cat << EOF
{
  "name": "Global Scripts V3",
  "version": "$gs_version",
  "install_path": "$_GS_ROOT",
  "environment": {
    "shell": {
      "name": "$shell_name",
      "version": "$shell_version"
    },
    "python": {
      "command": "$python_cmd",
      "version": "$python_version"
    },
    "system": {
      "os": "$os_name",
      "version": "$os_version",
      "architecture": "$arch"
    }
EOF

    if [[ "$git_info" != "not-git-repo" ]]; then
        local commit_hash commit_date branch
        IFS=',' read -r commit_hash commit_date branch <<< "$git_info"
        commit_hash="${commit_hash//commit:/}"
        commit_date="${commit_date//date:/}"
        branch="${branch//branch:/}"
        
        cat << EOF
  },
  "git": {
    "commit": "$commit_hash",
    "date": "$commit_date", 
    "branch": "$branch"
EOF
    fi
    
    echo "  }"
    echo "}"
}

# 检查和显示依赖版本
gs_version_show_dependencies() {
    local format="${1:-text}"
    local deps_info
    deps_info=$(gs_version_check_dependencies)
    
    case "$format" in
        "json")
            echo "{"
            echo '  "dependencies": {'
            local first=true
            IFS=',' read -ra DEPS <<< "$deps_info"
            for dep in "${DEPS[@]}"; do
                local tool version
                IFS=':' read -r tool version <<< "$dep"
                [[ "$first" == true ]] && first=false || echo ","
                echo -n "    \"$tool\": \"$version\""
            done
            echo
            echo "  }"
            echo "}"
            ;;
        *)
            echo "依赖工具版本:"
            echo
            echo "必需工具:"
            local required_tools=("jq" "git" "curl")
            IFS=',' read -ra DEPS <<< "$deps_info"
            for dep in "${DEPS[@]}"; do
                local tool version
                IFS=':' read -r tool version <<< "$dep"
                for req in "${required_tools[@]}"; do
                    if [[ "$tool" == "$req" ]]; then
                        if [[ "$version" == "not-found" ]]; then
                            echo "  $tool: ❌ 未找到"
                        else
                            echo "  $tool: ✅ $version"
                        fi
                        break
                    fi
                done
            done
            
            echo
            echo "可选工具:"
            local optional_tools=("fzf" "bat" "fd" "rg")
            for dep in "${DEPS[@]}"; do
                local tool version
                IFS=':' read -r tool version <<< "$dep"
                for opt in "${optional_tools[@]}"; do
                    if [[ "$tool" == "$opt" ]]; then
                        if [[ "$version" == "not-found" ]]; then
                            echo "  $tool: ⚠️  未安装"
                        else
                            echo "  $tool: ✅ $version"
                        fi
                        break
                    fi
                done
            done
            ;;
    esac
}

# ===================================
# 主要的版本命令函数
# ===================================

# ===================================
# 简化的参数解析函数
# ===================================
gs_version_parse_args() {
    local format="text"
    local check_deps="false"
    local full="false"
    local help="false"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --format)
                format="$2"
                shift 2
                ;;
            --check-deps)
                check_deps="true"
                shift
                ;;
            --full)
                full="true"
                shift
                ;;
            --help|-h)
                help="true"
                shift
                ;;
            -*)
                gs_error 1 "未知选项: $1"
                ;;
            *)
                shift
                ;;
        esac
    done
    
    # 输出解析结果
    echo "$format|$check_deps|$full|$help"
}

# ===================================
# 主要的版本命令函数
# ===================================

gs_version_cmd() {
    local parsed_result
    parsed_result=$(gs_version_parse_args "$@")
    
    local format check_deps full help
    IFS='|' read -r format check_deps full help <<< "$parsed_result"
    
    # 处理帮助请求
    if [[ "$help" == "true" ]]; then
        echo "gs-version - 版本信息显示

用法: gs-version [options]

选项:
  --format FORMAT  输出格式 (text|json)
  --check-deps     检查依赖版本
  --full          显示完整版本信息
  --help, -h      显示此帮助信息

示例:
  gs-version                 显示基本版本信息
  gs-version --format json   JSON格式输出
  gs-version --check-deps    检查所有依赖版本
  gs-version --full          显示完整信息"
        return 0
    fi
    
    # 验证格式参数
    if [[ "$format" != "text" && "$format" != "json" ]]; then
        gs_error 1 "不支持的输出格式: $format (支持: text, json)"
    fi
    
    # 检查依赖版本
    if [[ "$check_deps" == "true" ]]; then
        gs_version_show_dependencies "$format"
        return 0
    fi
    
    # 显示版本信息
    if [[ "$full" == "true" ]]; then
        case "$format" in
            "json")
                gs_version_show_full_json
                ;;
            *)
                gs_version_show_full_text
                ;;
        esac
    else
        case "$format" in
            "json")
                gs_version_show_basic_json
                ;;
            *)
                gs_version_show_basic_text
                ;;
        esac
    fi
}

# ===================================
# 命令注册
# ===================================

# 注册version命令到系统
gs_version_register() {
    if command -v gs_registry_register_command >/dev/null 2>&1; then
        # 获取当前文件路径
        local script_path
        if [[ -n "${BASH_SOURCE:-}" ]]; then
            script_path="${BASH_SOURCE[0]}"
        elif [[ -n "${(%):-%x}" ]] 2>/dev/null; then
            script_path="${(%):-%x}"
        else
            script_path="$0"
        fi
        gs_registry_register_command "gs-version" "$script_path" "显示版本信息" "3.0.0" "core"
    fi
}

# 如果直接执行此脚本
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    gs_version_cmd "$@"
fi