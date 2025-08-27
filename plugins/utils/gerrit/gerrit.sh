#!/bin/bash

# Gerrit代码审查工具
# 基于V2版本的gs_gerrit功能实现

# 检查是否在git仓库中
_gs_gerrit_check_git_repo() {
    if ! git rev-parse --git-dir >/dev/null 2>&1; then
        echo "错误: 当前目录不是git仓库" >&2
        return 1
    fi
}

# 检查gerrit remote配置
_gs_gerrit_check_remote() {
    local remote_url
    remote_url=$(git remote get-url origin 2>/dev/null)
    
    if [[ -z "$remote_url" ]]; then
        echo "错误: 未找到origin远程仓库" >&2
        return 1
    fi
    
    if [[ "$remote_url" != *"gerrit"* ]] && [[ "$remote_url" != *":29418"* ]]; then
        echo "警告: remote URL可能不是gerrit仓库: $remote_url" >&2
    fi
    
    echo "Gerrit remote: $remote_url"
}

# 推送到gerrit进行代码审查
gs_utils_gerrit_push() {
    local branch="${1:-HEAD}"
    local target_branch="${2:-master}"
    local topic=""
    local reviewers=""
    local draft=false
    
    _gs_gerrit_check_git_repo || return 1
    
    # 检查是否有未提交的修改
    if ! git diff --quiet || ! git diff --cached --quiet; then
        echo "错误: 存在未提交的修改，请先提交" >&2
        return 1
    fi
    
    # 构建gerrit推送命令
    local push_ref="refs/for/${target_branch}"
    
    if [[ -n "$topic" ]]; then
        push_ref="${push_ref}%topic=${topic}"
    fi
    
    if [[ -n "$reviewers" ]]; then
        push_ref="${push_ref}%r=${reviewers}"
    fi
    
    if [[ "$draft" == "true" ]]; then
        push_ref="refs/drafts/${target_branch}"
    fi
    
    echo "正在推送到Gerrit进行代码审查..."
    echo "分支: $branch -> $target_branch"
    
    if git push origin "$branch:$push_ref"; then
        echo "✅ 成功推送到Gerrit"
        
        # 尝试获取Change-Id
        local change_id
        change_id=$(git log -1 --pretty=format:"%B" | grep -o "Change-Id: I[a-f0-9]*" | head -1)
        if [[ -n "$change_id" ]]; then
            echo "📋 $change_id"
        fi
        
        return 0
    else
        echo "❌ 推送失败" >&2
        return 1
    fi
}

# 推送草稿到gerrit
gs_utils_gerrit_draft() {
    local branch="${1:-HEAD}"
    local target_branch="${2:-master}"
    
    _gs_gerrit_check_git_repo || return 1
    
    local push_ref="refs/drafts/${target_branch}"
    
    echo "正在推送草稿到Gerrit..."
    echo "分支: $branch -> $target_branch (draft)"
    
    if git push origin "$branch:$push_ref"; then
        echo "✅ 成功推送草稿到Gerrit"
        return 0
    else
        echo "❌ 推送草稿失败" >&2
        return 1
    fi
}

# 设置commit-msg hook
gs_utils_gerrit_setup_hook() {
    _gs_gerrit_check_git_repo || return 1
    
    local git_dir
    git_dir=$(git rev-parse --git-dir)
    local hook_path="${git_dir}/hooks/commit-msg"
    
    if [[ -f "$hook_path" ]]; then
        echo "commit-msg hook已存在"
        return 0
    fi
    
    # 创建hooks目录
    mkdir -p "${git_dir}/hooks"
    
    # 尝试从gerrit服务器下载hook
    local remote_url
    remote_url=$(git remote get-url origin 2>/dev/null)
    
    if [[ -n "$remote_url" ]]; then
        # 提取gerrit服务器地址
        local gerrit_host
        if [[ "$remote_url" == *"@"* ]]; then
            gerrit_host=$(echo "$remote_url" | sed 's/.*@//;s/:.*//;s/\/.*//') 
        else
            gerrit_host=$(echo "$remote_url" | sed 's|.*://||;s|/.*||;s|:.*||')
        fi
        
        local hook_url="http://${gerrit_host}/tools/hooks/commit-msg"
        
        echo "正在下载commit-msg hook..."
        if curl -Lo "$hook_path" "$hook_url" 2>/dev/null; then
            chmod +x "$hook_path"
            echo "✅ commit-msg hook安装成功"
            return 0
        fi
    fi
    
    # 如果下载失败，创建基本的hook
    cat > "$hook_path" << 'EOF'
#!/bin/bash
# Basic commit-msg hook for Gerrit

# Add Change-Id if not present
if ! grep -q "^Change-Id:" "$1"; then
    echo "" >> "$1"
    echo "Change-Id: I$(git hash-object -t commit --stdin < "$1" | sha1sum | cut -c1-40)" >> "$1"
fi
EOF
    
    chmod +x "$hook_path"
    echo "✅ 基本commit-msg hook创建成功"
}

# 查看gerrit状态
gs_utils_gerrit_status() {
    _gs_gerrit_check_git_repo || return 1
    
    echo "=== Gerrit状态检查 ==="
    
    # 检查remote配置
    _gs_gerrit_check_remote
    
    # 检查commit-msg hook
    local git_dir
    git_dir=$(git rev-parse --git-dir)
    local hook_path="${git_dir}/hooks/commit-msg"
    
    if [[ -f "$hook_path" ]]; then
        echo "✅ commit-msg hook: 已安装"
    else
        echo "❌ commit-msg hook: 未安装"
        echo "   使用 'gs-utils-gerrit --setup' 安装"
    fi
    
    # 检查最近的提交是否有Change-Id
    local change_id
    change_id=$(git log -1 --pretty=format:"%B" | grep -o "Change-Id: I[a-f0-9]*" | head -1)
    
    if [[ -n "$change_id" ]]; then
        echo "✅ 最新提交Change-Id: $change_id"
    else
        echo "⚠️  最新提交缺少Change-Id"
    fi
    
    # 检查当前分支状态
    local current_branch
    current_branch=$(git branch --show-current)
    echo "📍 当前分支: $current_branch"
    
    # 检查未推送的提交
    local unpushed_commits
    unpushed_commits=$(git log --oneline origin/"$current_branch"..HEAD 2>/dev/null | wc -l | tr -d ' ')
    
    if [[ "$unpushed_commits" -gt 0 ]]; then
        echo "📤 待推送提交: $unpushed_commits 个"
    else
        echo "✅ 无待推送提交"
    fi
}

# 主入口函数
gs_utils_gerrit_main() {
    local action=""
    local branch=""
    local target_branch="master"
    local topic=""
    local reviewers=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --push|-p)
                action="push"
                shift
                ;;
            --draft|-d)
                action="draft"
                shift
                ;;
            --setup|-s)
                action="setup"
                shift
                ;;
            --status)
                action="status"
                shift
                ;;
            --branch|-b)
                branch="$2"
                shift 2
                ;;
            --target|-t)
                target_branch="$2"
                shift 2
                ;;
            --topic)
                topic="$2"
                shift 2
                ;;
            --reviewers|-r)
                reviewers="$2"
                shift 2
                ;;
            --json)
                export GS_OUTPUT_JSON=true
                shift
                ;;
            --help|-h)
                gs_utils_gerrit_help
                return 0
                ;;
            *)
                echo "错误: 未知参数 '$1'" >&2
                gs_utils_gerrit_help
                return 1
                ;;
        esac
    done
    
    case "$action" in
        "push")
            gs_utils_gerrit_push "${branch:-HEAD}" "$target_branch"
            ;;
        "draft")
            gs_utils_gerrit_draft "${branch:-HEAD}" "$target_branch"
            ;;
        "setup")
            gs_utils_gerrit_setup_hook
            ;;
        "status")
            gs_utils_gerrit_status
            ;;
        *)
            gs_utils_gerrit_status
            ;;
    esac
}

# 帮助函数
gs_utils_gerrit_help() {
    cat << 'EOF'
Gerrit代码审查工具

用法:
    gs-utils-gerrit [选项]

选项:
    --push, -p          推送到gerrit进行代码审查
    --draft, -d         推送草稿到gerrit
    --setup, -s         安装commit-msg hook
    --status            查看gerrit状态(默认)
    --branch, -b <分支>  指定推送分支(默认HEAD)
    --target, -t <分支>  指定目标分支(默认master)
    --topic <主题>      设置gerrit主题
    --reviewers, -r <用户> 指定审查者
    --json              JSON格式输出
    --help, -h          显示此帮助信息

示例:
    gs-utils-gerrit --status         检查gerrit状态
    gs-utils-gerrit --setup          安装commit-msg hook
    gs-utils-gerrit --push           推送当前分支进行审查
    gs-utils-gerrit --draft          推送为草稿
    gs-utils-gerrit --push --target develop  推送到develop分支
    gs-utils-gerrit --push --reviewers user1,user2  指定审查者

注意:
    - 确保在git仓库中使用
    - 推送前确保所有修改已提交
    - 建议先安装commit-msg hook
EOF
}

# 如果直接执行此脚本
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    gs_utils_gerrit_main "$@"
fi