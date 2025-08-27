#!/bin/bash
# Homebrew包管理器配置子模块
# Homebrew Package Manager Configuration Submodule
# 提供Homebrew镜像源管理和配置功能

# 检查Homebrew是否可用
_gs_system_brew_check() {
    if ! command -v brew &> /dev/null; then
        echo "错误: Homebrew未安装"
        echo "请访问 https://brew.sh 安装Homebrew"
        return 1
    fi
    
    if [[ "$(uname -s)" != "Darwin" ]]; then
        echo "错误: 此功能仅支持macOS系统"
        return 1
    fi
    
    return 0
}

# 获取当前Homebrew仓库信息
_gs_system_brew_get_repo_info() {
    local repo_type="$1"
    local repo_path
    
    case $repo_type in
        "brew")
            repo_path="$(brew --repo)"
            ;;
        "core")
            repo_path="$(brew --repo homebrew/core)"
            ;;
        "cask")
            repo_path="$(brew --repo homebrew/cask)"
            ;;
        *)
            echo "错误: 未知仓库类型 $repo_type"
            return 1
            ;;
    esac
    
    if [[ -d "$repo_path" ]]; then
        git -C "$repo_path" remote get-url origin 2>/dev/null || echo "未知"
    else
        echo "不存在"
    fi
}

# 显示当前镜像源信息
gs_system_brew_remote() {
    local output_format="table"
    local show_all=false
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            --json)
                output_format="json"
                shift
                ;;
            -a|--all)
                show_all=true
                shift
                ;;
            -h|--help)
                echo "用法: gs-system-brew-remote [选项]"
                echo "显示Homebrew镜像源信息"
                echo ""
                echo "选项:"
                echo "  --json                  JSON格式输出"
                echo "  -a, --all               显示所有仓库详细信息"
                echo "  -h, --help              显示此帮助信息"
                return 0
                ;;
            *)
                echo "错误: 未知参数 $1"
                return 1
                ;;
        esac
    done
    
    if ! _gs_system_brew_check; then
        return 1
    fi
    
    # 获取仓库信息
    local brew_url
    local core_url
    local cask_url
    
    brew_url=$(_gs_system_brew_get_repo_info "brew")
    core_url=$(_gs_system_brew_get_repo_info "core")
    cask_url=$(_gs_system_brew_get_repo_info "cask")
    
    if [[ "$output_format" == "json" ]]; then
        # JSON格式输出
        cat <<EOF
{
  "homebrew_remotes": {
    "brew": "$brew_url",
    "core": "$core_url",
    "cask": "$cask_url",
    "bottle_domain": "${HOMEBREW_BOTTLE_DOMAIN:-默认}"
  }
}
EOF
    else
        # 表格格式输出
        echo "Homebrew 镜像源状态"
        echo "==================="
        printf "%-15s %s\n" "Brew 仓库:" "$brew_url"
        printf "%-15s %s\n" "Core 仓库:" "$core_url"
        printf "%-15s %s\n" "Cask 仓库:" "$cask_url"
        printf "%-15s %s\n" "Bottle 域名:" "${HOMEBREW_BOTTLE_DOMAIN:-默认}"
        
        # 镜像源识别
        echo ""
        echo "当前镜像源:"
        if [[ "$brew_url" == *"github.com"* ]]; then
            echo "  官方源 (GitHub)"
        elif [[ "$brew_url" == *"ustc.edu.cn"* ]]; then
            echo "  中科大镜像源 (USTC)"
        elif [[ "$brew_url" == *"tsinghua.edu.cn"* ]] || [[ "$brew_url" == *"tuna.tsinghua.edu.cn"* ]]; then
            echo "  清华大学镜像源 (TUNA)"
        elif [[ "$brew_url" == *"aliyun.com"* ]]; then
            echo "  阿里云镜像源"
        else
            echo "  自定义或其他镜像源"
        fi
        
        if [[ "$show_all" == true ]]; then
            echo ""
            echo "详细仓库信息:"
            echo "=============="
            
            for repo in brew core cask; do
                echo ""
                echo "${repo^} 仓库详情:"
                local repo_path
                case $repo in
                    "brew") repo_path="$(brew --repo)" ;;
                    "core") repo_path="$(brew --repo homebrew/core)" ;;
                    "cask") repo_path="$(brew --repo homebrew/cask)" ;;
                esac
                
                if [[ -d "$repo_path" ]]; then
                    echo "  路径: $repo_path"
                    echo "  远程仓库:"
                    git -C "$repo_path" remote -v 2>/dev/null | sed 's/^/    /'
                else
                    echo "  状态: 仓库不存在"
                fi
            done
        fi
    fi
    
    return 0
}

# 设置中科大镜像源
gs_system_brew_ustc() {
    local dry_run=false
    local verbose=false
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                dry_run=true
                shift
                ;;
            -v|--verbose)
                verbose=true
                shift
                ;;
            -h|--help)
                echo "用法: gs-system-brew-ustc [选项]"
                echo "设置Homebrew为中科大(USTC)镜像源"
                echo ""
                echo "选项:"
                echo "  --dry-run               仅显示操作，不实际执行"
                echo "  -v, --verbose           显示详细执行过程"
                echo "  -h, --help              显示此帮助信息"
                echo ""
                echo "镜像源信息:"
                echo "  名称: 中国科学技术大学开源软件镜像站"
                echo "  网址: https://mirrors.ustc.edu.cn/"
                echo "  特点: 国内访问速度快，更新及时"
                return 0
                ;;
            *)
                echo "错误: 未知参数 $1"
                return 1
                ;;
        esac
    done
    
    if ! _gs_system_brew_check; then
        return 1
    fi
    
    echo "设置Homebrew为中科大(USTC)镜像源..."
    
    if [[ "$dry_run" == true ]]; then
        echo "[DRY RUN] 将执行以下操作:"
        echo "  1. 设置brew仓库: https://mirrors.ustc.edu.cn/brew.git"
        echo "  2. 设置core仓库: https://mirrors.ustc.edu.cn/homebrew-core.git"
        echo "  3. 设置cask仓库: https://mirrors.ustc.edu.cn/homebrew-cask.git"
        echo "  4. 设置bottle域名: https://mirrors.ustc.edu.cn/homebrew-bottles"
        echo "  5. 更新仓库索引"
        return 0
    fi
    
    # 设置镜像源
    local success=true
    
    [[ "$verbose" == true ]] && echo "正在设置brew仓库..."
    if ! git -C "$(brew --repo)" remote set-url origin https://mirrors.ustc.edu.cn/brew.git; then
        echo "错误: 设置brew仓库失败"
        success=false
    fi
    
    [[ "$verbose" == true ]] && echo "正在设置homebrew-core仓库..."
    if ! git -C "$(brew --repo homebrew/core)" remote set-url origin https://mirrors.ustc.edu.cn/homebrew-core.git; then
        echo "错误: 设置homebrew-core仓库失败"
        success=false
    fi
    
    [[ "$verbose" == true ]] && echo "正在设置homebrew-cask仓库..."
    if ! git -C "$(brew --repo homebrew/cask)" remote set-url origin https://mirrors.ustc.edu.cn/homebrew-cask.git; then
        echo "错误: 设置homebrew-cask仓库失败"
        success=false
    fi
    
    # 设置bottle域名
    [[ "$verbose" == true ]] && echo "正在设置bottle域名..."
    export HOMEBREW_BOTTLE_DOMAIN=https://mirrors.ustc.edu.cn/homebrew-bottles
    
    if [[ "$success" == true ]]; then
        echo "✅ 中科大镜像源设置成功"
        echo ""
        echo "建议将以下环境变量添加到 ~/.bashrc 或 ~/.zshrc:"
        echo "export HOMEBREW_BOTTLE_DOMAIN=https://mirrors.ustc.edu.cn/homebrew-bottles"
        echo ""
        
        # 更新仓库
        [[ "$verbose" == true ]] && echo "正在更新仓库索引..."
        if brew update; then
            echo "✅ 仓库索引更新成功"
        else
            echo "⚠️ 仓库索引更新失败，请稍后手动执行 'brew update'"
        fi
    else
        echo "❌ 镜像源设置过程中出现错误"
        return 1
    fi
    
    return 0
}

# 设置清华大学镜像源
gs_system_brew_tsinghua() {
    local dry_run=false
    local verbose=false
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                dry_run=true
                shift
                ;;
            -v|--verbose)
                verbose=true
                shift
                ;;
            -h|--help)
                echo "用法: gs-system-brew-tsinghua [选项]"
                echo "设置Homebrew为清华大学(TUNA)镜像源"
                echo ""
                echo "选项:"
                echo "  --dry-run               仅显示操作，不实际执行"
                echo "  -v, --verbose           显示详细执行过程"
                echo "  -h, --help              显示此帮助信息"
                echo ""
                echo "镜像源信息:"
                echo "  名称: 清华大学开源软件镜像站"
                echo "  网址: https://mirrors.tuna.tsinghua.edu.cn/"
                echo "  特点: 国内知名镜像站，稳定可靠"
                return 0
                ;;
            *)
                echo "错误: 未知参数 $1"
                return 1
                ;;
        esac
    done
    
    if ! _gs_system_brew_check; then
        return 1
    fi
    
    echo "设置Homebrew为清华大学(TUNA)镜像源..."
    
    if [[ "$dry_run" == true ]]; then
        echo "[DRY RUN] 将执行以下操作:"
        echo "  1. 设置brew仓库: https://mirrors.tuna.tsinghua.edu.cn/git/homebrew/brew.git"
        echo "  2. 设置core仓库: https://mirrors.tuna.tsinghua.edu.cn/git/homebrew/homebrew-core.git"
        echo "  3. 设置cask仓库: https://mirrors.tuna.tsinghua.edu.cn/git/homebrew/homebrew-cask.git"
        echo "  4. 设置bottle域名: https://mirrors.tuna.tsinghua.edu.cn/homebrew-bottles"
        echo "  5. 更新仓库索引"
        return 0
    fi
    
    # 设置镜像源
    local success=true
    
    [[ "$verbose" == true ]] && echo "正在设置brew仓库..."
    if ! git -C "$(brew --repo)" remote set-url origin https://mirrors.tuna.tsinghua.edu.cn/git/homebrew/brew.git; then
        echo "错误: 设置brew仓库失败"
        success=false
    fi
    
    [[ "$verbose" == true ]] && echo "正在设置homebrew-core仓库..."
    if ! git -C "$(brew --repo homebrew/core)" remote set-url origin https://mirrors.tuna.tsinghua.edu.cn/git/homebrew/homebrew-core.git; then
        echo "错误: 设置homebrew-core仓库失败"
        success=false
    fi
    
    [[ "$verbose" == true ]] && echo "正在设置homebrew-cask仓库..."
    if ! git -C "$(brew --repo homebrew/cask)" remote set-url origin https://mirrors.tuna.tsinghua.edu.cn/git/homebrew/homebrew-cask.git; then
        echo "错误: 设置homebrew-cask仓库失败"
        success=false
    fi
    
    # 设置bottle域名
    [[ "$verbose" == true ]] && echo "正在设置bottle域名..."
    export HOMEBREW_BOTTLE_DOMAIN=https://mirrors.tuna.tsinghua.edu.cn/homebrew-bottles
    
    if [[ "$success" == true ]]; then
        echo "✅ 清华大学镜像源设置成功"
        echo ""
        echo "建议将以下环境变量添加到 ~/.bashrc 或 ~/.zshrc:"
        echo "export HOMEBREW_BOTTLE_DOMAIN=https://mirrors.tuna.tsinghua.edu.cn/homebrew-bottles"
        echo ""
        
        # 更新仓库
        [[ "$verbose" == true ]] && echo "正在更新仓库索引..."
        if brew update; then
            echo "✅ 仓库索引更新成功"
        else
            echo "⚠️ 仓库索引更新失败，请稍后手动执行 'brew update'"
        fi
    else
        echo "❌ 镜像源设置过程中出现错误"
        return 1
    fi
    
    return 0
}

# 设置阿里云镜像源
gs_system_brew_aliyun() {
    local dry_run=false
    local verbose=false
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                dry_run=true
                shift
                ;;
            -v|--verbose)
                verbose=true
                shift
                ;;
            -h|--help)
                echo "用法: gs-system-brew-aliyun [选项]"
                echo "设置Homebrew为阿里云镜像源"
                echo ""
                echo "选项:"
                echo "  --dry-run               仅显示操作，不实际执行"
                echo "  -v, --verbose           显示详细执行过程"
                echo "  -h, --help              显示此帮助信息"
                echo ""
                echo "镜像源信息:"
                echo "  名称: 阿里云开源镜像站"
                echo "  网址: https://mirrors.aliyun.com/"
                echo "  特点: 企业级镜像服务，稳定高速"
                return 0
                ;;
            *)
                echo "错误: 未知参数 $1"
                return 1
                ;;
        esac
    done
    
    if ! _gs_system_brew_check; then
        return 1
    fi
    
    echo "设置Homebrew为阿里云镜像源..."
    
    if [[ "$dry_run" == true ]]; then
        echo "[DRY RUN] 将执行以下操作:"
        echo "  1. 设置brew仓库: https://mirrors.aliyun.com/homebrew/brew.git"
        echo "  2. 设置core仓库: https://mirrors.aliyun.com/homebrew/homebrew-core.git"
        echo "  3. 设置cask仓库: https://mirrors.aliyun.com/homebrew/homebrew-cask.git"
        echo "  4. 设置bottle域名: https://mirrors.aliyun.com/homebrew/homebrew-bottles"
        echo "  5. 更新仓库索引"
        return 0
    fi
    
    # 设置镜像源
    local success=true
    
    [[ "$verbose" == true ]] && echo "正在设置brew仓库..."
    if ! git -C "$(brew --repo)" remote set-url origin https://mirrors.aliyun.com/homebrew/brew.git; then
        echo "错误: 设置brew仓库失败"
        success=false
    fi
    
    [[ "$verbose" == true ]] && echo "正在设置homebrew-core仓库..."
    if ! git -C "$(brew --repo homebrew/core)" remote set-url origin https://mirrors.aliyun.com/homebrew/homebrew-core.git; then
        echo "错误: 设置homebrew-core仓库失败"
        success=false
    fi
    
    [[ "$verbose" == true ]] && echo "正在设置homebrew-cask仓库..."
    if ! git -C "$(brew --repo homebrew/cask)" remote set-url origin https://mirrors.aliyun.com/homebrew/homebrew-cask.git; then
        echo "错误: 设置homebrew-cask仓库失败"
        success=false
    fi
    
    # 设置bottle域名
    [[ "$verbose" == true ]] && echo "正在设置bottle域名..."
    export HOMEBREW_BOTTLE_DOMAIN=https://mirrors.aliyun.com/homebrew/homebrew-bottles
    
    if [[ "$success" == true ]]; then
        echo "✅ 阿里云镜像源设置成功"
        echo ""
        echo "建议将以下环境变量添加到 ~/.bashrc 或 ~/.zshrc:"
        echo "export HOMEBREW_BOTTLE_DOMAIN=https://mirrors.aliyun.com/homebrew/homebrew-bottles"
        echo ""
        
        # 更新仓库
        [[ "$verbose" == true ]] && echo "正在更新仓库索引..."
        if brew update; then
            echo "✅ 仓库索引更新成功"
        else
            echo "⚠️ 仓库索引更新失败，请稍后手动执行 'brew update'"
        fi
    else
        echo "❌ 镜像源设置过程中出现错误"
        return 1
    fi
    
    return 0
}

# 恢复官方GitHub源
gs_system_brew_github() {
    local dry_run=false
    local verbose=false
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                dry_run=true
                shift
                ;;
            -v|--verbose)
                verbose=true
                shift
                ;;
            -h|--help)
                echo "用法: gs-system-brew-github [选项]"
                echo "恢复Homebrew为官方GitHub源"
                echo ""
                echo "选项:"
                echo "  --dry-run               仅显示操作，不实际执行"
                echo "  -v, --verbose           显示详细执行过程"
                echo "  -h, --help              显示此帮助信息"
                echo ""
                echo "官方源信息:"
                echo "  名称: GitHub官方仓库"
                echo "  网址: https://github.com/Homebrew/"
                echo "  特点: 官方维护，功能最新最全"
                return 0
                ;;
            *)
                echo "错误: 未知参数 $1"
                return 1
                ;;
        esac
    done
    
    if ! _gs_system_brew_check; then
        return 1
    fi
    
    echo "恢复Homebrew为官方GitHub源..."
    
    if [[ "$dry_run" == true ]]; then
        echo "[DRY RUN] 将执行以下操作:"
        echo "  1. 设置brew仓库: https://github.com/Homebrew/brew.git"
        echo "  2. 设置core仓库: https://github.com/Homebrew/homebrew-core.git"
        echo "  3. 设置cask仓库: https://github.com/Homebrew/homebrew-cask.git"
        echo "  4. 清除bottle域名环境变量"
        echo "  5. 更新仓库索引"
        return 0
    fi
    
    # 设置官方源
    local success=true
    
    [[ "$verbose" == true ]] && echo "正在设置brew仓库..."
    if ! git -C "$(brew --repo)" remote set-url origin https://github.com/Homebrew/brew.git; then
        echo "错误: 设置brew仓库失败"
        success=false
    fi
    
    [[ "$verbose" == true ]] && echo "正在设置homebrew-core仓库..."
    if ! git -C "$(brew --repo homebrew/core)" remote set-url origin https://github.com/Homebrew/homebrew-core.git; then
        echo "错误: 设置homebrew-core仓库失败"
        success=false
    fi
    
    [[ "$verbose" == true ]] && echo "正在设置homebrew-cask仓库..."
    if ! git -C "$(brew --repo homebrew/cask)" remote set-url origin https://github.com/Homebrew/homebrew-cask.git; then
        echo "错误: 设置homebrew-cask仓库失败"
        success=false
    fi
    
    # 清除bottle域名
    [[ "$verbose" == true ]] && echo "正在清除bottle域名..."
    unset HOMEBREW_BOTTLE_DOMAIN
    
    if [[ "$success" == true ]]; then
        echo "✅ 官方GitHub源恢复成功"
        echo ""
        echo "请从 ~/.bashrc 或 ~/.zshrc 中移除以下环境变量:"
        echo "export HOMEBREW_BOTTLE_DOMAIN=..."
        echo ""
        
        # 更新仓库
        [[ "$verbose" == true ]] && echo "正在更新仓库索引..."
        if brew update; then
            echo "✅ 仓库索引更新成功"
        else
            echo "⚠️ 仓库索引更新失败，请稍后手动执行 'brew update'"
        fi
    else
        echo "❌ 官方源恢复过程中出现错误"
        return 1
    fi
    
    return 0
}

# 帮助信息
gs_system_brew_help() {
    echo "System Brew 子模块 - Homebrew配置管理"
    echo "=================================="
    echo ""
    echo "可用命令:"
    echo "  gs-system-brew-remote     显示当前镜像源信息"
    echo "  gs-system-brew-ustc       设置中科大镜像源"
    echo "  gs-system-brew-tsinghua   设置清华大学镜像源"
    echo "  gs-system-brew-aliyun     设置阿里云镜像源"
    echo "  gs-system-brew-github     恢复官方GitHub源"
    echo "  gs-system-brew-help       显示此帮助信息"
    echo ""
    echo "常用操作:"
    echo "  1. 查看当前镜像源:"
    echo "     gs-system-brew-remote"
    echo ""
    echo "  2. 设置国内镜像源（推荐）:"
    echo "     gs-system-brew-ustc      # 中科大镜像"
    echo "     gs-system-brew-tsinghua  # 清华镜像"
    echo ""
    echo "  3. 恢复官方源:"
    echo "     gs-system-brew-github"
    echo ""
    echo "  4. 查看详细仓库信息:"
    echo "     gs-system-brew-remote --all"
    echo ""
    echo "注意事项:"
    echo "  - 设置镜像源后，建议将HOMEBREW_BOTTLE_DOMAIN环境变量添加到shell配置文件"
    echo "  - 镜像源切换后会自动执行 brew update 更新索引"
    echo "  - 使用 --dry-run 选项可以预览操作而不实际执行"
    
    return 0
}