#!/bin/bash
# Git插件主文件 - Git版本控制增强工具集
# 作者: Global Scripts Team
# 版本: 1.0.0
# 描述: 提供Git工作流增强功能，包含分支管理、提交优化、远程仓库管理等

# ============================================================================
# 插件基础信息和依赖检查
# ============================================================================

# 检查Git是否可用
_gs_git_check_git() {
    if ! command -v git >/dev/null 2>&1; then
        echo "错误: 缺少必需命令: git" >&2
        echo "建议: 请安装Git版本控制系统" >&2
        return 2
    fi
    return 0
}

# 检查是否在Git仓库中
_gs_git_check_repo() {
    if ! git rev-parse --git-dir >/dev/null 2>&1; then
        echo "错误: 当前目录不是Git仓库" >&2
        echo "建议: 请在Git仓库目录中运行此命令，或使用 'git init' 初始化仓库" >&2
        return 1
    fi
    return 0
}

# 获取当前分支名
_gs_git_get_current_branch() {
    git branch --show-current 2>/dev/null || echo "HEAD"
}

# 获取默认分支名（main或master）
_gs_git_get_default_branch() {
    # 尝试从远程获取默认分支
    local default_branch
    default_branch=$(git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's@^refs/remotes/origin/@@')
    
    if [[ -n "$default_branch" ]]; then
        echo "$default_branch"
        return 0
    fi
    
    # 检查常见的默认分支名
    if git show-ref --verify --quiet refs/heads/main; then
        echo "main"
    elif git show-ref --verify --quiet refs/heads/master; then
        echo "master"
    else
        # 如果都没有，返回第一个分支
        git branch --format='%(refname:short)' | head -n1
    fi
}

# 检查工作区是否干净
_gs_git_check_clean() {
    if ! git diff --quiet || ! git diff --staged --quiet; then
        echo "警告: 工作区有未提交的更改" >&2
        return 1
    fi
    return 0
}

# 获取远程仓库URL
_gs_git_get_remote_url() {
    local remote="${1:-origin}"
    git remote get-url "$remote" 2>/dev/null
}

# ============================================================================
# Git状态增强显示
# ============================================================================

gs_git_status_enhanced() {
    local show_files=false
    local show_remote=false
    local compact=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_git_status_enhanced_help
                return 0
                ;;
            --files|-f)
                show_files=true
                shift
                ;;
            --remote|-r)
                show_remote=true
                shift
                ;;
            --compact|-c)
                compact=true
                shift
                ;;
            *)
                echo "错误: 未知选项 $1" >&2
                echo "使用 'gs-git-status-enhanced --help' 查看帮助" >&2
                return 1
                ;;
        esac
    done
    
    _gs_git_check_git || return 2
    _gs_git_check_repo || return 1
    
    echo "=== Git仓库状态 ==="
    echo
    
    # 基本信息
    local current_branch
    current_branch=$(_gs_git_get_current_branch)
    echo "📍 当前分支: $current_branch"
    
    # 远程信息
    if $show_remote; then
        local remote_url
        remote_url=$(_gs_git_get_remote_url)
        if [[ -n "$remote_url" ]]; then
            echo "🌐 远程仓库: $remote_url"
        fi
        
        # 检查远程分支状态
        if git rev-parse --verify --quiet "origin/$current_branch" >/dev/null; then
            local ahead behind
            ahead=$(git rev-list --count "origin/$current_branch..$current_branch" 2>/dev/null || echo "0")
            behind=$(git rev-list --count "$current_branch..origin/$current_branch" 2>/dev/null || echo "0")
            
            if [[ "$ahead" -gt 0 && "$behind" -gt 0 ]]; then
                echo "🔄 分支状态: 领先$ahead个提交，落后$behind个提交"
            elif [[ "$ahead" -gt 0 ]]; then
                echo "⬆️  分支状态: 领先$ahead个提交"
            elif [[ "$behind" -gt 0 ]]; then
                echo "⬇️  分支状态: 落后$behind个提交"
            else
                echo "✅ 分支状态: 与远程同步"
            fi
        fi
    fi
    
    echo
    
    # 工作区状态
    local staged_count unstaged_count untracked_count
    staged_count=$(git diff --cached --numstat | wc -l | tr -d ' ')
    unstaged_count=$(git diff --numstat | wc -l | tr -d ' ')
    untracked_count=$(git ls-files --others --exclude-standard | wc -l | tr -d ' ')
    
    echo "📊 文件状态:"
    echo "   暂存区: $staged_count 个文件"
    echo "   工作区: $unstaged_count 个未暂存更改"
    echo "   未跟踪: $untracked_count 个文件"
    
    # 详细文件列表
    if $show_files && ! $compact; then
        echo
        if [[ "$staged_count" -gt 0 ]]; then
            echo "🟢 暂存区文件:"
            git diff --cached --name-status | sed 's/^/   /'
        fi
        
        if [[ "$unstaged_count" -gt 0 ]]; then
            echo "🟡 未暂存更改:"
            git diff --name-status | sed 's/^/   /'
        fi
        
        if [[ "$untracked_count" -gt 0 ]]; then
            echo "🔴 未跟踪文件:"
            git ls-files --others --exclude-standard | sed 's/^/   /'
        fi
    fi
    
    # 最近提交信息
    echo
    echo "📝 最近提交:"
    if $compact; then
        git log --oneline -3 | sed 's/^/   /'
    else
        git log --pretty=format:"   %C(yellow)%h%C(reset) %C(blue)%an%C(reset) %C(green)%ar%C(reset) %s" -3
    fi
    
    return 0
}

# ============================================================================
# Git提交历史美化
# ============================================================================

gs_git_log_pretty() {
    local format="full"
    local max_count=""
    local since=""
    local author=""
    local grep_pattern=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_git_log_pretty_help
                return 0
                ;;
            --oneline|-o)
                format="oneline"
                shift
                ;;
            --compact|-c)
                format="compact"
                shift
                ;;
            --graph|-g)
                format="graph"
                shift
                ;;
            --count|-n)
                max_count="$2"
                shift 2
                ;;
            --since|-s)
                since="$2"
                shift 2
                ;;
            --author|-a)
                author="$2"
                shift 2
                ;;
            --grep)
                grep_pattern="$2"
                shift 2
                ;;
            *)
                echo "错误: 未知选项 $1" >&2
                return 1
                ;;
        esac
    done
    
    _gs_git_check_git || return 2
    _gs_git_check_repo || return 1
    
    local git_cmd="git log"
    
    # 设置格式
    case "$format" in
        "oneline")
            git_cmd="$git_cmd --oneline"
            ;;
        "compact")
            git_cmd="$git_cmd --pretty=format:'%C(yellow)%h%C(reset) %C(blue)%an%C(reset) %C(green)%ar%C(reset) %s'"
            ;;
        "graph")
            git_cmd="$git_cmd --graph --pretty=format:'%C(yellow)%h%C(reset) -%C(red)%d%C(reset) %s %C(green)(%cr)%C(reset) %C(blue)<%an>%C(reset)' --abbrev-commit"
            ;;
        "full")
            git_cmd="$git_cmd --pretty=format:'%C(yellow)commit %H%C(reset)%C(red)%d%C(reset)%nAuthor: %C(blue)%an <%ae>%C(reset)%nDate:   %C(green)%ad%C(reset)%n%n    %s%n' --date=format:'%Y-%m-%d %H:%M:%S'"
            ;;
    esac
    
    # 添加过滤选项
    if [[ -n "$max_count" ]]; then
        git_cmd="$git_cmd -n $max_count"
    fi
    
    if [[ -n "$since" ]]; then
        git_cmd="$git_cmd --since='$since'"
    fi
    
    if [[ -n "$author" ]]; then
        git_cmd="$git_cmd --author='$author'"
    fi
    
    if [[ -n "$grep_pattern" ]]; then
        git_cmd="$git_cmd --grep='$grep_pattern'"
    fi
    
    eval "$git_cmd"
    return 0
}

# ============================================================================
# 快速提交功能
# ============================================================================

gs_git_commit_quick() {
    local message=""
    local add_all=false
    local amend=false
    local no_verify=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_git_commit_quick_help
                return 0
                ;;
            -m|--message)
                message="$2"
                shift 2
                ;;
            -a|--all)
                add_all=true
                shift
                ;;
            --amend)
                amend=true
                shift
                ;;
            --no-verify)
                no_verify=true
                shift
                ;;
            *)
                if [[ -z "$message" ]]; then
                    message="$1"
                fi
                shift
                ;;
        esac
    done
    
    if [[ -z "$message" ]]; then
        echo "错误: 缺少提交信息" >&2
        echo "用法: gs-git-commit-quick -m '提交信息'" >&2
        return 1
    fi
    
    _gs_git_check_git || return 2
    _gs_git_check_repo || return 1
    
    local git_cmd="git commit"
    
    # 添加所有文件（如果指定）
    if $add_all; then
        echo "添加所有更改到暂存区..."
        git add -A
    fi
    
    # 构建提交命令
    git_cmd="$git_cmd -m '$message'"
    
    if $amend; then
        git_cmd="$git_cmd --amend"
    fi
    
    if $no_verify; then
        git_cmd="$git_cmd --no-verify"
    fi
    
    echo "执行提交: $message"
    eval "$git_cmd"
    
    if [[ $? -eq 0 ]]; then
        echo "✅ 提交成功"
        echo
        echo "最新提交:"
        git log --oneline -1
        return 0
    else
        echo "❌ 提交失败" >&2
        return 2
    fi
}

# ============================================================================
# 帮助函数
# ============================================================================

_show_git_status_enhanced_help() {
    cat << 'EOF'
gs_git_status_enhanced - Git仓库增强状态显示

功能描述:
  显示详细的Git仓库状态，包含分支信息、文件状态和提交历史

使用方式:
  gs-git-status-enhanced [选项]

选项:
  --files, -f    显示详细文件列表
  --remote, -r   显示远程仓库信息和同步状态
  --compact, -c  紧凑格式显示
  --help, -h     显示此帮助信息

示例:
  gs-git-status-enhanced
  gs-git-status-enhanced --files --remote
  gs-git-status-enhanced -c
  gs-git-status-enhanced --help

依赖:
  系统命令: git
  插件依赖: git

注意事项:
  - 必须在Git仓库目录中运行
  - 显示信息包含工作区、暂存区和提交历史
  - 支持彩色输出和状态图标
EOF
}

_show_git_log_pretty_help() {
    cat << 'EOF'
gs_git_log_pretty - Git提交历史美化显示

功能描述:
  以美观的格式显示Git提交历史，支持多种显示样式和过滤选项

使用方式:
  gs-git-log-pretty [选项]

选项:
  --oneline, -o  单行格式显示
  --compact, -c  紧凑格式显示
  --graph, -g    图形化分支显示
  --count, -n    限制显示的提交数量
  --since, -s    显示指定时间之后的提交
  --author, -a   按作者过滤提交
  --grep         按提交信息内容过滤
  --help, -h     显示此帮助信息

示例:
  gs-git-log-pretty
  gs-git-log-pretty --oneline --count 10
  gs-git-log-pretty --graph
  gs-git-log-pretty --since="2 weeks ago"
  gs-git-log-pretty --author="张三"
  gs-git-log-pretty --grep="fix"

依赖:
  系统命令: git
  插件依赖: git

注意事项:
  - 支持彩色输出
  - 默认显示完整格式
  - 可以组合多个过滤选项
EOF
}

_show_git_commit_quick_help() {
    cat << 'EOF'
gs_git_commit_quick - 快速Git提交

功能描述:
  快速创建Git提交，支持自动添加文件和常用提交选项

使用方式:
  gs-git-commit-quick -m "提交信息" [选项]

选项:
  -m, --message  提交信息（必需）
  -a, --all      自动添加所有更改到暂存区
  --amend        修改最后一次提交
  --no-verify    跳过提交钩子验证
  --help, -h     显示此帮助信息

示例:
  gs-git-commit-quick -m "修复登录问题"
  gs-git-commit-quick -m "添加新功能" --all
  gs-git-commit-quick -m "更新文档" --amend
  gs-git-commit-quick --help

依赖:
  系统命令: git
  插件依赖: git

注意事项:
  - 必须在Git仓库目录中运行
  - 使用 --all 选项会添加所有更改（包括删除）
  - --amend 会修改最后一次提交，慎用
EOF
}

# ============================================================================
# 插件初始化
# ============================================================================

# 如果直接运行此脚本，显示插件信息
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
    echo "Git插件 - Git版本控制增强工具集"
    echo "版本: 1.0.0"
    echo "作者: Global Scripts Team"
    echo
    echo "可用命令:"
    echo "  gs-git-status-enhanced  - 增强的Git状态显示"
    echo "  gs-git-log-pretty      - 美化的提交历史显示"  
    echo "  gs-git-commit-quick    - 快速提交功能"
    echo
    echo "使用 '<命令> --help' 查看详细帮助"
fi