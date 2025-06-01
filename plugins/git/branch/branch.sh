#!/bin/bash
# Git分支管理子模块
# 作者: Global Scripts Team  
# 版本: 1.0.0
# 描述: 提供Git分支创建、切换、合并、删除等管理功能

# ============================================================================
# 分支管理核心函数
# ============================================================================

gs_git_branch_create() {
    local branch_name=""
    local from_branch=""
    local track_remote=false
    local force=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_git_branch_create_help
                return 0
                ;;
            --from|-f)
                from_branch="$2"
                shift 2
                ;;
            --track|-t)
                track_remote=true
                shift
                ;;
            --force)
                force=true
                shift
                ;;
            *)
                if [[ -z "$branch_name" ]]; then
                    branch_name="$1"
                fi
                shift
                ;;
        esac
    done
    
    if [[ -z "$branch_name" ]]; then
        echo "错误: 缺少分支名称" >&2
        echo "用法: gs-git-branch-create <分支名> [选项]" >&2
        return 1
    fi
    
    _gs_git_check_git || return 2
    _gs_git_check_repo || return 1
    
    # 检查分支是否已存在
    if git show-ref --verify --quiet "refs/heads/$branch_name" && ! $force; then
        echo "错误: 分支 '$branch_name' 已存在" >&2
        echo "使用 --force 选项强制覆盖" >&2
        return 1
    fi
    
    local git_cmd="git checkout"
    
    if $force; then
        git_cmd="$git_cmd -B"
    else
        git_cmd="$git_cmd -b"
    fi
    
    git_cmd="$git_cmd $branch_name"
    
    if [[ -n "$from_branch" ]]; then
        # 检查源分支是否存在
        if ! git show-ref --verify --quiet "refs/heads/$from_branch" && ! git show-ref --verify --quiet "refs/remotes/origin/$from_branch"; then
            echo "错误: 源分支 '$from_branch' 不存在" >&2
            return 1
        fi
        git_cmd="$git_cmd $from_branch"
    fi
    
    echo "创建并切换到分支: $branch_name"
    if [[ -n "$from_branch" ]]; then
        echo "基于分支: $from_branch"
    fi
    
    if eval "$git_cmd"; then
        echo "✅ 分支创建成功"
        
        # 设置远程跟踪
        if $track_remote && git ls-remote --heads origin "$branch_name" | grep -q "$branch_name"; then
            echo "设置远程跟踪分支..."
            git branch --set-upstream-to="origin/$branch_name" "$branch_name"
        fi
        
        return 0
    else
        echo "❌ 分支创建失败" >&2
        return 2
    fi
}

gs_git_branch_list() {
    local show_remote=false
    local show_merged=false
    local show_no_merged=false
    local verbose=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_git_branch_list_help
                return 0
                ;;
            --remote|-r)
                show_remote=true
                shift
                ;;
            --all|-a)
                show_remote=true
                shift
                ;;
            --merged|-m)
                show_merged=true
                shift
                ;;
            --no-merged|-n)
                show_no_merged=true
                shift
                ;;
            --verbose|-v)
                verbose=true
                shift
                ;;
            *)
                echo "错误: 未知选项 $1" >&2
                return 1
                ;;
        esac
    done
    
    _gs_git_check_git || return 2
    _gs_git_check_repo || return 1
    
    echo "=== Git分支列表 ==="
    echo
    
    local git_cmd="git branch"
    
    if $verbose; then
        git_cmd="$git_cmd -v"
    fi
    
    if $show_merged; then
        git_cmd="$git_cmd --merged"
    elif $show_no_merged; then
        git_cmd="$git_cmd --no-merged"
    fi
    
    # 显示本地分支
    echo "📍 本地分支:"
    eval "$git_cmd" | sed 's/^/  /'
    
    # 显示远程分支
    if $show_remote; then
        echo
        echo "🌐 远程分支:"
        git branch -r | sed 's/^/  /'
    fi
    
    # 显示当前分支详细信息
    echo
    local current_branch
    current_branch=$(_gs_git_get_current_branch)
    echo "当前分支: $current_branch"
    
    # 显示分支状态统计
    local local_count remote_count
    local_count=$(git branch | wc -l | tr -d ' ')
    remote_count=$(git branch -r 2>/dev/null | wc -l | tr -d ' ')
    
    echo "分支统计: $local_count 个本地分支, $remote_count 个远程分支"
    
    return 0
}

gs_git_branch_switch() {
    local branch_name=""
    local create_if_missing=false
    local force=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_git_branch_switch_help
                return 0
                ;;
            --create|-c)
                create_if_missing=true
                shift
                ;;
            --force|-f)
                force=true
                shift
                ;;
            *)
                if [[ -z "$branch_name" ]]; then
                    branch_name="$1"
                fi
                shift
                ;;
        esac
    done
    
    if [[ -z "$branch_name" ]]; then
        echo "错误: 缺少分支名称" >&2
        echo "用法: gs-git-branch-switch <分支名> [选项]" >&2
        return 1
    fi
    
    _gs_git_check_git || return 2
    _gs_git_check_repo || return 1
    
    # 检查工作区状态
    if ! _gs_git_check_clean && ! $force; then
        echo "错误: 工作区有未提交的更改" >&2
        echo "请先提交更改或使用 --force 选项强制切换" >&2
        return 1
    fi
    
    # 检查分支是否存在
    if ! git show-ref --verify --quiet "refs/heads/$branch_name"; then
        # 检查远程分支是否存在
        if git show-ref --verify --quiet "refs/remotes/origin/$branch_name"; then
            echo "本地分支不存在，但找到远程分支，正在创建本地跟踪分支..."
            git checkout -b "$branch_name" "origin/$branch_name"
            return $?
        elif $create_if_missing; then
            echo "分支不存在，正在创建新分支..."
            git checkout -b "$branch_name"
            return $?
        else
            echo "错误: 分支 '$branch_name' 不存在" >&2
            echo "使用 --create 选项创建新分支" >&2
            return 1
        fi
    fi
    
    local git_cmd="git checkout"
    if $force; then
        git_cmd="$git_cmd --force"
    fi
    git_cmd="$git_cmd $branch_name"
    
    echo "切换到分支: $branch_name"
    
    if eval "$git_cmd"; then
        echo "✅ 分支切换成功"
        
        # 显示当前状态
        echo
        echo "当前分支: $(_gs_git_get_current_branch)"
        
        # 检查是否需要拉取更新
        if git rev-parse --verify --quiet "origin/$branch_name" >/dev/null; then
            local behind
            behind=$(git rev-list --count "$branch_name..origin/$branch_name" 2>/dev/null || echo "0")
            if [[ "$behind" -gt 0 ]]; then
                echo "💡 提示: 分支落后远程 $behind 个提交，建议执行 'git pull' 更新"
            fi
        fi
        
        return 0
    else
        echo "❌ 分支切换失败" >&2
        return 2
    fi
}

gs_git_branch_delete() {
    local branch_name=""
    local force=false
    local delete_remote=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_git_branch_delete_help
                return 0
                ;;
            --force|-f)
                force=true
                shift
                ;;
            --remote|-r)
                delete_remote=true
                shift
                ;;
            *)
                if [[ -z "$branch_name" ]]; then
                    branch_name="$1"
                fi
                shift
                ;;
        esac
    done
    
    if [[ -z "$branch_name" ]]; then
        echo "错误: 缺少分支名称" >&2
        echo "用法: gs-git-branch-delete <分支名> [选项]" >&2
        return 1
    fi
    
    _gs_git_check_git || return 2
    _gs_git_check_repo || return 1
    
    local current_branch
    current_branch=$(_gs_git_get_current_branch)
    
    # 检查是否试图删除当前分支
    if [[ "$branch_name" == "$current_branch" ]]; then
        echo "错误: 无法删除当前分支 '$branch_name'" >&2
        echo "请先切换到其他分支" >&2
        return 1
    fi
    
    # 检查分支是否存在
    if ! git show-ref --verify --quiet "refs/heads/$branch_name"; then
        echo "错误: 分支 '$branch_name' 不存在" >&2
        return 1
    fi
    
    # 安全确认
    echo "⚠️  警告: 即将删除分支 '$branch_name'"
    if ! $force; then
        # 检查分支是否已合并
        if ! git branch --merged | grep -q "\\s$branch_name$"; then
            echo "警告: 分支包含未合并的更改！"
        fi
    fi
    
    echo "确认删除分支？(y/N):"
    read -r confirm
    
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "操作已取消"
        return 0
    fi
    
    local git_cmd="git branch"
    if $force; then
        git_cmd="$git_cmd -D"
    else
        git_cmd="$git_cmd -d"
    fi
    git_cmd="$git_cmd $branch_name"
    
    echo "删除本地分支: $branch_name"
    
    if eval "$git_cmd"; then
        echo "✅ 本地分支删除成功"
        
        # 删除远程分支
        if $delete_remote && git ls-remote --heads origin "$branch_name" | grep -q "$branch_name"; then
            echo "删除远程分支: origin/$branch_name"
            if git push origin --delete "$branch_name"; then
                echo "✅ 远程分支删除成功"
            else
                echo "⚠️  远程分支删除失败" >&2
            fi
        fi
        
        return 0
    else
        echo "❌ 分支删除失败" >&2
        return 2
    fi
}

gs_git_branch_merge() {
    local source_branch=""
    local target_branch=""
    local no_ff=false
    local squash=false
    local strategy=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_git_branch_merge_help
                return 0
                ;;
            --into|-i)
                target_branch="$2"
                shift 2
                ;;
            --no-ff)
                no_ff=true
                shift
                ;;
            --squash)
                squash=true
                shift
                ;;
            --strategy|-s)
                strategy="$2"
                shift 2
                ;;
            *)
                if [[ -z "$source_branch" ]]; then
                    source_branch="$1"
                fi
                shift
                ;;
        esac
    done
    
    if [[ -z "$source_branch" ]]; then
        echo "错误: 缺少源分支名称" >&2
        echo "用法: gs-git-branch-merge <源分支> [选项]" >&2
        return 1
    fi
    
    _gs_git_check_git || return 2
    _gs_git_check_repo || return 1
    
    # 确定目标分支
    if [[ -z "$target_branch" ]]; then
        target_branch=$(_gs_git_get_current_branch)
    fi
    
    echo "合并分支: $source_branch -> $target_branch"
    
    # 检查分支是否存在
    if ! git show-ref --verify --quiet "refs/heads/$source_branch"; then
        echo "错误: 源分支 '$source_branch' 不存在" >&2
        return 1
    fi
    
    # 切换到目标分支
    if [[ "$target_branch" != "$(_gs_git_get_current_branch)" ]]; then
        echo "切换到目标分支: $target_branch"
        git checkout "$target_branch" || return 2
    fi
    
    # 检查工作区状态
    if ! _gs_git_check_clean; then
        echo "错误: 工作区有未提交的更改" >&2
        return 1
    fi
    
    local git_cmd="git merge"
    
    if $no_ff; then
        git_cmd="$git_cmd --no-ff"
    fi
    
    if $squash; then
        git_cmd="$git_cmd --squash"
    fi
    
    if [[ -n "$strategy" ]]; then
        git_cmd="$git_cmd --strategy=$strategy"
    fi
    
    git_cmd="$git_cmd $source_branch"
    
    echo "执行合并..."
    
    if eval "$git_cmd"; then
        echo "✅ 分支合并成功"
        
        if $squash; then
            echo "💡 提示: 使用了 --squash 选项，请手动提交合并结果"
        fi
        
        # 显示合并后状态
        echo
        echo "合并后状态:"
        git log --oneline -3 | sed 's/^/  /'
        
        return 0
    else
        echo "❌ 分支合并失败" >&2
        echo "可能存在冲突，请解决冲突后手动完成合并" >&2
        return 2
    fi
}

# ============================================================================
# 帮助函数
# ============================================================================

_show_git_branch_create_help() {
    cat << 'EOF'
gs_git_branch_create - 创建新的Git分支

功能描述:
  创建新的Git分支并切换到该分支，支持指定基础分支和远程跟踪

使用方式:
  gs-git-branch-create <分支名> [选项]

选项:
  --from, -f     指定基础分支（默认当前分支）
  --track, -t    设置远程跟踪分支
  --force        强制覆盖已存在的分支
  --help, -h     显示此帮助信息

示例:
  gs-git-branch-create feature/new-login
  gs-git-branch-create hotfix/bug-123 --from main
  gs-git-branch-create feature/api --track
  gs-git-branch-create --help

依赖:
  系统命令: git
  插件依赖: git

注意事项:
  - 会自动切换到新创建的分支
  - 基础分支可以是本地分支或远程分支
  - --force 选项会覆盖已存在的同名分支
EOF
}

_show_git_branch_list_help() {
    cat << 'EOF'
gs_git_branch_list - 显示Git分支列表

功能描述:
  显示本地和远程Git分支列表，支持过滤和详细信息显示

使用方式:
  gs-git-branch-list [选项]

选项:
  --remote, -r   显示远程分支
  --all, -a      显示所有分支（本地+远程）
  --merged, -m   仅显示已合并的分支
  --no-merged, -n 仅显示未合并的分支
  --verbose, -v  显示详细信息（最后提交）
  --help, -h     显示此帮助信息

示例:
  gs-git-branch-list
  gs-git-branch-list --remote
  gs-git-branch-list --merged
  gs-git-branch-list --verbose
  gs-git-branch-list --help

依赖:
  系统命令: git
  插件依赖: git

注意事项:
  - 当前分支会用星号标记
  - 支持彩色输出
  - 显示分支统计信息
EOF
}

_show_git_branch_switch_help() {
    cat << 'EOF'
gs_git_branch_switch - 切换Git分支

功能描述:
  切换到指定的Git分支，支持自动创建和远程分支跟踪

使用方式:
  gs-git-branch-switch <分支名> [选项]

选项:
  --create, -c   如果分支不存在则创建
  --force, -f    强制切换（忽略未提交更改）
  --help, -h     显示此帮助信息

示例:
  gs-git-branch-switch main
  gs-git-branch-switch feature/new-api --create
  gs-git-branch-switch develop --force
  gs-git-branch-switch --help

依赖:
  系统命令: git
  插件依赖: git

注意事项:
  - 如果存在同名远程分支会自动设置跟踪
  - 默认不允许在有未提交更改时切换
  - 会提示是否需要拉取远程更新
EOF
}

_show_git_branch_delete_help() {
    cat << 'EOF'
gs_git_branch_delete - 删除Git分支

功能描述:
  删除指定的Git分支，支持同时删除远程分支

使用方式:
  gs-git-branch-delete <分支名> [选项]

选项:
  --force, -f    强制删除（即使未合并）
  --remote, -r   同时删除远程分支
  --help, -h     显示此帮助信息

示例:
  gs-git-branch-delete feature/old-feature
  gs-git-branch-delete hotfix/temp --force
  gs-git-branch-delete feature/done --remote
  gs-git-branch-delete --help

依赖:
  系统命令: git
  插件依赖: git

注意事项:
  - 不能删除当前分支
  - 默认只删除已合并的分支
  - 删除前会要求确认
  - 无法恢复已删除的分支
EOF
}

_show_git_branch_merge_help() {
    cat << 'EOF'
gs_git_branch_merge - 合并Git分支

功能描述:
  将指定分支合并到目标分支，支持多种合并策略

使用方式:
  gs-git-branch-merge <源分支> [选项]

选项:
  --into, -i     指定目标分支（默认当前分支）
  --no-ff        禁用快进合并，始终创建合并提交
  --squash       压缩合并，将所有提交合并为一个
  --strategy, -s 指定合并策略
  --help, -h     显示此帮助信息

合并策略:
  resolve        使用三路合并算法
  recursive      递归三路合并（默认）
  ours           总是使用我们的版本
  theirs         总是使用他们的版本

示例:
  gs-git-branch-merge feature/login
  gs-git-branch-merge hotfix/bug --into main
  gs-git-branch-merge feature/api --no-ff
  gs-git-branch-merge temp-branch --squash
  gs-git-branch-merge --help

依赖:
  系统命令: git
  插件依赖: git

注意事项:
  - 合并前会检查工作区状态
  - 如果发生冲突需要手动解决
  - --squash 选项需要手动提交
EOF
}

# 如果直接运行此脚本，显示模块信息
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
    echo "Git分支管理子模块"
    echo "版本: 1.0.0"
    echo
    echo "可用命令:"
    echo "  gs-git-branch-create  - 创建新分支"
    echo "  gs-git-branch-list    - 显示分支列表"
    echo "  gs-git-branch-switch  - 切换分支"
    echo "  gs-git-branch-delete  - 删除分支"
    echo "  gs-git-branch-merge   - 合并分支"
    echo
    echo "使用 '<命令> --help' 查看详细帮助"
fi