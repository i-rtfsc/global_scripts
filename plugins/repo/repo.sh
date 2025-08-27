#!/bin/bash
# Repo仓库管理插件
# Repository Management Plugin
# 提供Git仓库管理和批量操作功能

# 检查依赖
_gs_repo_check_deps() {
    local missing_deps=()
    
    if ! command -v git &> /dev/null; then
        missing_deps+=("git")
    fi
    
    if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
        missing_deps+=("python")
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        echo "错误: 缺少依赖工具: ${missing_deps[*]}"
        return 1
    fi
    
    return 0
}

# 检查是否在Git仓库中
_gs_repo_check_git_repo() {
    if ! git rev-parse --git-dir &> /dev/null; then
        echo "错误: 当前目录不是Git仓库"
        return 1
    fi
    return 0
}

# 扫描Git仓库项目
gs_repo_scan() {
    local scan_path="${1:-.}"
    local max_depth=3
    local output_format="table"
    local show_status=false
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--depth)
                max_depth="$2"
                shift 2
                ;;
            -p|--path)
                scan_path="$2"
                shift 2
                ;;
            --json)
                output_format="json"
                shift
                ;;
            -s|--status)
                show_status=true
                shift
                ;;
            -h|--help)
                echo "用法: gs-repo-scan [选项] [路径]"
                echo "扫描指定路径下的Git仓库"
                echo ""
                echo "选项:"
                echo "  -d, --depth DEPTH       扫描深度 (默认: 3)"
                echo "  -p, --path PATH         扫描路径 (默认: 当前目录)"
                echo "  --json                  JSON格式输出"
                echo "  -s, --status            显示仓库状态"
                echo "  -h, --help              显示此帮助信息"
                return 0
                ;;
            *)
                if [[ -d "$1" ]]; then
                    scan_path="$1"
                else
                    echo "错误: 未知参数 $1"
                    return 1
                fi
                shift
                ;;
        esac
    done
    
    if ! _gs_repo_check_deps; then
        return 1
    fi
    
    if [[ ! -d "$scan_path" ]]; then
        echo "错误: 路径不存在: $scan_path"
        return 1
    fi
    
    echo "扫描Git仓库: $scan_path (深度: $max_depth)"
    echo "================================="
    
    # 查找Git仓库
    local repos=()
    while IFS= read -r -d '' repo_path; do
        local repo_dir=$(dirname "$repo_path")
        repos+=("$repo_dir")
    done < <(find "$scan_path" -maxdepth "$max_depth" -name ".git" -type d -print0 2>/dev/null)
    
    if [[ ${#repos[@]} -eq 0 ]]; then
        echo "没有找到Git仓库"
        return 0
    fi
    
    if [[ "$output_format" == "json" ]]; then
        # JSON格式输出
        echo "{"
        echo "  \"repositories\": ["
        local first=true
        for repo in "${repos[@]}"; do
            if [[ "$first" == true ]]; then
                first=false
            else
                echo ","
            fi
            
            local repo_name=$(basename "$repo")
            local branch=""
            local status=""
            local remote_url=""
            
            if [[ -d "$repo/.git" ]]; then
                branch=$(cd "$repo" && git branch --show-current 2>/dev/null || echo "unknown")
                remote_url=$(cd "$repo" && git remote get-url origin 2>/dev/null || echo "none")
                
                if [[ "$show_status" == true ]]; then
                    if cd "$repo" && git diff --quiet && git diff --staged --quiet; then
                        status="clean"
                    else
                        status="dirty"
                    fi
                fi
            fi
            
            echo -n "    {"
            echo -n "\"name\": \"$repo_name\", "
            echo -n "\"path\": \"$repo\", "
            echo -n "\"branch\": \"$branch\", "
            echo -n "\"remote\": \"$remote_url\""
            if [[ "$show_status" == true ]]; then
                echo -n ", \"status\": \"$status\""
            fi
            echo -n "}"
        done
        echo ""
        echo "  ]"
        echo "}"
    else
        # 表格格式输出
        printf "%-30s %-15s %-50s\n" "仓库名称" "当前分支" "路径"
        echo "$(printf '%.0s-' {1..100})"
        
        for repo in "${repos[@]}"; do
            local repo_name=$(basename "$repo")
            local branch="unknown"
            local status_indicator=""
            
            if [[ -d "$repo/.git" ]]; then
                branch=$(cd "$repo" && git branch --show-current 2>/dev/null || echo "unknown")
                
                if [[ "$show_status" == true ]]; then
                    if cd "$repo" && git diff --quiet && git diff --staged --quiet 2>/dev/null; then
                        status_indicator="✓"
                    else
                        status_indicator="●"
                    fi
                fi
            fi
            
            printf "%-30s %-15s %s %s\n" "$repo_name" "$branch" "$repo" "$status_indicator"
        done
        
        echo ""
        echo "总计: ${#repos[@]} 个Git仓库"
        if [[ "$show_status" == true ]]; then
            echo "状态: ✓=干净 ●=有未提交更改"
        fi
    fi
    
    return 0
}

# 批量Git操作
gs_repo_batch() {
    local operation="$1"
    local scan_path="${2:-.}"
    local max_depth=3
    local filter=""
    local dry_run=false
    
    shift 2
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--depth)
                max_depth="$2"
                shift 2
                ;;
            -f|--filter)
                filter="$2"
                shift 2
                ;;
            --dry-run)
                dry_run=true
                shift
                ;;
            -h|--help)
                echo "用法: gs-repo-batch <操作> [路径] [选项]"
                echo "批量执行Git操作"
                echo ""
                echo "操作:"
                echo "  status                  显示状态"
                echo "  pull                    拉取更新"
                echo "  push                    推送更改"
                echo "  fetch                   获取远程更新"
                echo "  clean                   清理工作区"
                echo ""
                echo "选项:"
                echo "  -d, --depth DEPTH       扫描深度"
                echo "  -f, --filter PATTERN    仓库名过滤"
                echo "  --dry-run               预览模式"
                echo "  -h, --help              显示此帮助信息"
                return 0
                ;;
            *)
                echo "错误: 未知参数 $1"
                return 1
                ;;
        esac
    done
    
    if ! _gs_repo_check_deps; then
        return 1
    fi
    
    # 查找Git仓库
    local repos=()
    while IFS= read -r -d '' repo_path; do
        local repo_dir=$(dirname "$repo_path")
        local repo_name=$(basename "$repo_dir")
        
        # 应用过滤器
        if [[ -n "$filter" ]] && [[ ! "$repo_name" =~ $filter ]]; then
            continue
        fi
        
        repos+=("$repo_dir")
    done < <(find "$scan_path" -maxdepth "$max_depth" -name ".git" -type d -print0 2>/dev/null)
    
    if [[ ${#repos[@]} -eq 0 ]]; then
        echo "没有找到匹配的Git仓库"
        return 0
    fi
    
    echo "批量Git操作: $operation"
    echo "仓库数量: ${#repos[@]}"
    echo "========================="
    
    local success_count=0
    local current_count=0
    
    for repo in "${repos[@]}"; do
        current_count=$((current_count + 1))
        local repo_name=$(basename "$repo")
        
        echo "[$current_count/${#repos[@]}] 处理: $repo_name"
        
        if [[ "$dry_run" == true ]]; then
            echo "  [DRY RUN] 将在 $repo 执行: git $operation"
            continue
        fi
        
        cd "$repo" || continue
        
        case $operation in
            status)
                echo "  分支: $(git branch --show-current 2>/dev/null || echo 'unknown')"
                if git diff --quiet && git diff --staged --quiet 2>/dev/null; then
                    echo "  状态: ✓ 工作区干净"
                else
                    echo "  状态: ● 有未提交更改"
                fi
                success_count=$((success_count + 1))
                ;;
                
            pull)
                if git pull; then
                    echo "  ✓ 拉取成功"
                    success_count=$((success_count + 1))
                else
                    echo "  ✗ 拉取失败"
                fi
                ;;
                
            push)
                if git push; then
                    echo "  ✓ 推送成功"
                    success_count=$((success_count + 1))
                else
                    echo "  ✗ 推送失败"
                fi
                ;;
                
            fetch)
                if git fetch --all; then
                    echo "  ✓ 获取成功"
                    success_count=$((success_count + 1))
                else
                    echo "  ✗ 获取失败"
                fi
                ;;
                
            clean)
                if git clean -fd; then
                    echo "  ✓ 清理完成"
                    success_count=$((success_count + 1))
                else
                    echo "  ✗ 清理失败"
                fi
                ;;
                
            *)
                echo "  ✗ 未知操作: $operation"
                ;;
        esac
        
        echo ""
    done
    
    echo "批量操作完成！"
    echo "成功: $success_count/${#repos[@]}"
    
    return 0
}

# 仓库分支管理
gs_repo_branch() {
    local action="$1"
    local branch_name="$2"
    local scan_path="${3:-.}"
    
    case $action in
        list)
            # 解析参数
            while [[ $# -gt 0 ]]; do
                case $1 in
                    -p|--path)
                        scan_path="$2"
                        shift 2
                        ;;
                    -h|--help)
                        echo "用法: gs-repo-branch list [选项]"
                        echo "列出所有仓库的分支信息"
                        echo ""
                        echo "选项:"
                        echo "  -p, --path PATH         扫描路径"
                        echo "  -h, --help              显示此帮助信息"
                        return 0
                        ;;
                    *)
                        if [[ -d "$1" ]]; then
                            scan_path="$1"
                        fi
                        shift
                        ;;
                esac
            done
            
            echo "仓库分支信息"
            echo "============"
            
            # 查找Git仓库
            while IFS= read -r -d '' repo_path; do
                local repo_dir=$(dirname "$repo_path")
                local repo_name=$(basename "$repo_dir")
                
                echo ""
                echo "仓库: $repo_name"
                echo "路径: $repo_dir"
                
                cd "$repo_dir" || continue
                
                local current_branch=$(git branch --show-current 2>/dev/null)
                echo "当前分支: ${current_branch:-unknown}"
                
                echo "所有分支:"
                git branch -a 2>/dev/null | sed 's/^/  /' || echo "  无法获取分支信息"
                
            done < <(find "$scan_path" -maxdepth 3 -name ".git" -type d -print0 2>/dev/null)
            ;;
            
        switch)
            if [[ -z "$branch_name" ]]; then
                echo "错误: 请指定分支名"
                echo "用法: gs-repo-branch switch <分支名> [路径]"
                return 1
            fi
            
            echo "批量切换分支: $branch_name"
            echo "========================"
            
            local success_count=0
            local total_count=0
            
            while IFS= read -r -d '' repo_path; do
                local repo_dir=$(dirname "$repo_path")
                local repo_name=$(basename "$repo_dir")
                
                total_count=$((total_count + 1))
                echo "[$total_count] 处理: $repo_name"
                
                cd "$repo_dir" || continue
                
                if git checkout "$branch_name" 2>/dev/null; then
                    echo "  ✓ 切换成功"
                    success_count=$((success_count + 1))
                else
                    echo "  ✗ 切换失败"
                fi
                
            done < <(find "$scan_path" -maxdepth 3 -name ".git" -type d -print0 2>/dev/null)
            
            echo ""
            echo "切换完成: $success_count/$total_count"
            ;;
            
        *)
            echo "用法: gs-repo-branch <command> [options]"
            echo ""
            echo "命令:"
            echo "  list                    列出分支信息"
            echo "  switch <branch>         切换分支"
            echo ""
            echo "使用 'gs-repo-branch <command> --help' 查看详细帮助"
            return 1
            ;;
    esac
    
    return 0
}

# 仓库统计信息
gs_repo_stats() {
    local scan_path="${1:-.}"
    local output_format="table"
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -p|--path)
                scan_path="$2"
                shift 2
                ;;
            --json)
                output_format="json"
                shift
                ;;
            -h|--help)
                echo "用法: gs-repo-stats [选项] [路径]"
                echo "显示仓库统计信息"
                echo ""
                echo "选项:"
                echo "  -p, --path PATH         扫描路径"
                echo "  --json                  JSON格式输出"
                echo "  -h, --help              显示此帮助信息"
                return 0
                ;;
            *)
                if [[ -d "$1" ]]; then
                    scan_path="$1"
                fi
                shift
                ;;
        esac
    done
    
    if ! _gs_repo_check_deps; then
        return 1
    fi
    
    # 收集统计信息
    local total_repos=0
    local clean_repos=0
    local dirty_repos=0
    local branch_stats=""
    
    declare -A branch_count
    
    while IFS= read -r -d '' repo_path; do
        local repo_dir=$(dirname "$repo_path")
        total_repos=$((total_repos + 1))
        
        cd "$repo_dir" || continue
        
        # 检查状态
        if git diff --quiet && git diff --staged --quiet 2>/dev/null; then
            clean_repos=$((clean_repos + 1))
        else
            dirty_repos=$((dirty_repos + 1))
        fi
        
        # 统计分支
        local current_branch=$(git branch --show-current 2>/dev/null || echo "unknown")
        branch_count["$current_branch"]=$((${branch_count["$current_branch"]} + 1))
        
    done < <(find "$scan_path" -maxdepth 3 -name ".git" -type d -print0 2>/dev/null)
    
    if [[ "$output_format" == "json" ]]; then
        # JSON格式输出
        echo "{"
        echo "  \"statistics\": {"
        echo "    \"total_repositories\": $total_repos,"
        echo "    \"clean_repositories\": $clean_repos,"
        echo "    \"dirty_repositories\": $dirty_repos,"
        echo "    \"branch_distribution\": {"
        local first=true
        for branch in "${!branch_count[@]}"; do
            if [[ "$first" == true ]]; then
                first=false
            else
                echo ","
            fi
            echo -n "      \"$branch\": ${branch_count[$branch]}"
        done
        echo ""
        echo "    }"
        echo "  }"
        echo "}"
    else
        # 表格格式输出
        echo "仓库统计信息"
        echo "============"
        echo "扫描路径: $scan_path"
        echo ""
        echo "基础统计:"
        echo "  总仓库数:     $total_repos"
        echo "  干净仓库:     $clean_repos"
        echo "  有更改仓库:   $dirty_repos"
        echo ""
        echo "分支分布:"
        for branch in "${!branch_count[@]}"; do
            printf "  %-15s %d\n" "$branch:" "${branch_count[$branch]}"
        done
    fi
    
    return 0
}

# 帮助信息
gs_repo_help() {
    echo "Repo 仓库管理插件"
    echo "================"
    echo ""
    echo "可用命令:"
    echo "  gs-repo-scan          扫描Git仓库"
    echo "  gs-repo-batch         批量Git操作"
    echo "  gs-repo-branch        分支管理"
    echo "  gs-repo-stats         仓库统计"
    echo "  gs-repo-help          显示此帮助信息"
    echo ""
    echo "常用操作:"
    echo "  1. 扫描仓库:"
    echo "     gs-repo-scan ~/projects              # 扫描指定目录"
    echo "     gs-repo-scan --status                # 显示仓库状态"
    echo ""
    echo "  2. 批量操作:"
    echo "     gs-repo-batch status ~/projects     # 批量查看状态"
    echo "     gs-repo-batch pull ~/projects       # 批量拉取更新"
    echo "     gs-repo-batch --dry-run pull        # 预览操作"
    echo ""
    echo "  3. 分支管理:"
    echo "     gs-repo-branch list                  # 列出所有分支"
    echo "     gs-repo-branch switch main          # 批量切换分支"
    echo ""
    echo "  4. 统计信息:"
    echo "     gs-repo-stats ~/projects             # 显示统计信息"
    echo "     gs-repo-stats --json                 # JSON格式输出"
    echo ""
    echo "功能特点:"
    echo "  - 支持递归扫描多级目录"
    echo "  - 批量Git操作（pull, push, fetch等）"
    echo "  - 仓库状态监控和统计"
    echo "  - 分支管理和批量切换"
    echo "  - JSON格式输出支持"
    echo ""
    echo "使用 'gs-repo-<command> --help' 查看特定命令的详细帮助"
    
    return 0
}