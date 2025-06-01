#!/bin/bash
# Git Remote管理子模块
# Git Remote Management Submodule
# 提供Git远程仓库管理功能

# 检查git是否可用
_gs_git_remote_check() {
    if ! command -v git &> /dev/null; then
        echo "错误: Git未安装"
        return 1
    fi
    
    if ! git rev-parse --is-inside-work-tree &> /dev/null; then
        echo "错误: 当前目录不是Git仓库"  
        return 1
    fi
    
    return 0
}

# 增强的远程仓库添加
gs_git_remote_add() {
    local name=""
    local url=""
    local fetch_ref=""
    local push_ref=""
    local set_upstream=false
    local verify_ssl=true
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -n|--name)
                name="$2"
                shift 2
                ;;
            -u|--url)
                url="$2"
                shift 2
                ;;
            --fetch)
                fetch_ref="$2"
                shift 2
                ;;
            --push)
                push_ref="$2"
                shift 2
                ;;
            --set-upstream)
                set_upstream=true
                shift
                ;;
            --no-verify-ssl)
                verify_ssl=false
                shift
                ;;
            -h|--help)
                echo "用法: gs-git-remote-add [选项] <name> <url>"
                echo "增强的Git远程仓库添加"
                echo ""
                echo "参数:"
                echo "  name                        远程仓库名称"
                echo "  url                         远程仓库URL"
                echo ""
                echo "选项:"
                echo "  -n, --name NAME             远程仓库名称"
                echo "  -u, --url URL               远程仓库URL"
                echo "  --fetch REF                 自定义fetch引用"
                echo "  --push REF                  自定义push引用"
                echo "  --set-upstream              设置为上游分支"
                echo "  --no-verify-ssl             跳过SSL验证"
                echo "  -h, --help                  显示此帮助信息"
                echo ""
                echo "示例:"
                echo "  gs-git-remote-add origin https://github.com/user/repo.git"
                echo "  gs-git-remote-add --set-upstream upstream https://github.com/upstream/repo.git"
                echo "  gs-git-remote-add --fetch '+refs/*:refs/remotes/mirror/*' mirror https://example.com/repo.git"
                return 0
                ;;
            *)
                if [[ -z "$name" ]]; then
                    name="$1"
                elif [[ -z "$url" ]]; then
                    url="$1"
                else
                    echo "错误: 未知参数 $1"
                    return 1
                fi
                shift
                ;;
        esac
    done
    
    if [[ -z "$name" ]] || [[ -z "$url" ]]; then
        echo "错误: 请指定远程仓库名称和URL"
        echo "用法: gs-git-remote-add <name> <url>"
        return 1
    fi
    
    if ! _gs_git_remote_check; then
        return 1
    fi
    
    # 检查远程仓库是否已存在
    if git remote | grep -q "^${name}$"; then
        echo "警告: 远程仓库 '$name' 已存在"
        read -p "是否覆盖? (y/N): " confirm
        if [[ ! $confirm =~ ^[Yy]$ ]]; then
            echo "已取消"
            return 0
        fi
        git remote remove "$name"
    fi
    
    echo "添加远程仓库: $name -> $url"
    git remote add "$name" "$url"
    
    # 设置自定义fetch引用
    if [[ -n "$fetch_ref" ]]; then
        echo "设置fetch引用: $fetch_ref"
        git config remote.${name}.fetch "$fetch_ref"
    fi
    
    # 设置自定义push引用
    if [[ -n "$push_ref" ]]; then
        echo "设置push引用: $push_ref"
        git config remote.${name}.push "$push_ref"
    fi
    
    # 跳过SSL验证
    if [[ "$verify_ssl" == false ]]; then
        echo "跳过SSL验证"
        git config http.sslVerify false
    fi
    
    # 获取远程信息
    echo "获取远程仓库信息..."
    if git fetch "$name"; then
        echo "远程仓库 '$name' 添加成功！"
        
        # 设置上游分支
        if [[ "$set_upstream" == true ]]; then
            local current_branch=$(git branch --show-current)
            if [[ -n "$current_branch" ]]; then
                echo "设置上游分支: $name/$current_branch"
                git branch --set-upstream-to="$name/$current_branch" "$current_branch"
            fi
        fi
        
        # 显示远程分支
        echo "远程分支:"
        git branch -r | grep "^[[:space:]]*${name}/"
    else
        echo "警告: 无法获取远程仓库信息，但已添加到配置中"
    fi
    
    return 0
}

# 远程仓库同步
gs_git_remote_sync() {
    local remote_name=""
    local all_remotes=false
    local prune=true
    local dry_run=false
    local force=false
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -r|--remote)
                remote_name="$2"
                shift 2
                ;;
            -a|--all)
                all_remotes=true
                shift
                ;;
            --no-prune)
                prune=false
                shift
                ;;
            --dry-run)
                dry_run=true
                shift
                ;;
            -f|--force)
                force=true
                shift
                ;;
            -h|--help)
                echo "用法: gs-git-remote-sync [选项] [remote]"
                echo "同步远程仓库"
                echo ""
                echo "选项:"
                echo "  -r, --remote REMOTE         指定远程仓库名"
                echo "  -a, --all                   同步所有远程仓库"
                echo "  --no-prune                  不清理已删除的远程分支"
                echo "  --dry-run                   只显示操作，不执行"
                echo "  -f, --force                 强制同步"
                echo "  -h, --help                  显示此帮助信息"
                echo ""
                echo "示例:"
                echo "  gs-git-remote-sync                    # 同步默认远程仓库"
                echo "  gs-git-remote-sync origin             # 同步origin远程仓库"
                echo "  gs-git-remote-sync --all              # 同步所有远程仓库"
                echo "  gs-git-remote-sync --dry-run --all    # 预览同步操作"
                return 0
                ;;
            *)
                if [[ -z "$remote_name" ]]; then
                    remote_name="$1"
                else
                    echo "错误: 未知参数 $1"
                    return 1
                fi
                shift
                ;;
        esac
    done
    
    if ! _gs_git_remote_check; then
        return 1
    fi
    
    # 获取远程仓库列表
    local remotes=()
    if [[ "$all_remotes" == true ]]; then
        readarray -t remotes < <(git remote)
    elif [[ -n "$remote_name" ]]; then
        if git remote | grep -q "^${remote_name}$"; then
            remotes=("$remote_name")
        else
            echo "错误: 远程仓库 '$remote_name' 不存在"
            return 1
        fi
    else
        # 使用默认远程仓库
        if git remote | grep -q "^origin$"; then
            remotes=("origin")
        elif [[ $(git remote | wc -l) -eq 1 ]]; then
            remotes=($(git remote))
        else
            echo "错误: 有多个远程仓库，请指定具体的远程仓库名或使用 --all"
            echo "可用的远程仓库:"
            git remote | sed 's/^/  /'
            return 1
        fi
    fi
    
    if [[ ${#remotes[@]} -eq 0 ]]; then
        echo "错误: 没有找到远程仓库"
        return 1
    fi
    
    echo "开始同步远程仓库..."
    echo "==================="
    
    for remote in "${remotes[@]}"; do
        echo ""
        echo "同步远程仓库: $remote"
        echo "URL: $(git remote get-url "$remote")"
        
        if [[ "$dry_run" == true ]]; then
            echo "[DRY RUN] 将执行的操作:"
            echo "  git fetch $remote"
            if [[ "$prune" == true ]]; then
                echo "  git remote prune $remote"
            fi
            continue
        fi
        
        # 获取远程更新
        local fetch_cmd="git fetch $remote"
        if [[ "$prune" == true ]]; then
            fetch_cmd="$fetch_cmd --prune"
        fi
        if [[ "$force" == true ]]; then
            fetch_cmd="$fetch_cmd --force"
        fi
        
        echo "执行: $fetch_cmd"
        if eval "$fetch_cmd"; then
            echo "✓ 同步成功: $remote"
            
            # 显示更新的分支
            local updated_branches=$(git for-each-ref --format='%(refname:short)' refs/remotes/${remote}/)
            if [[ -n "$updated_branches" ]]; then
                echo "远程分支:"
                echo "$updated_branches" | sed 's/^/  /'
            fi
        else
            echo "✗ 同步失败: $remote"
        fi
    done
    
    echo ""
    echo "同步完成！"
    
    # 显示状态摘要
    local current_branch=$(git branch --show-current)
    if [[ -n "$current_branch" ]]; then
        echo ""
        echo "当前分支状态:"
        local upstream=$(git rev-parse --abbrev-ref "$current_branch@{upstream}" 2>/dev/null || echo "无上游分支")
        echo "当前分支: $current_branch"
        echo "上游分支: $upstream"
        
        if [[ "$upstream" != "无上游分支" ]]; then
            local ahead=$(git rev-list --count "$upstream..HEAD" 2>/dev/null || echo "0")
            local behind=$(git rev-list --count "HEAD..$upstream" 2>/dev/null || echo "0")
            echo "领先: $ahead 个提交，落后: $behind 个提交"
        fi
    fi
    
    return 0
}

# 远程仓库镜像管理
gs_git_remote_mirror() {
    local action="$1"
    local source_remote=""
    local target_remote=""
    local mirror_name=""
    
    case $action in
        create)
            shift
            
            # 解析参数
            while [[ $# -gt 0 ]]; do
                case $1 in
                    -s|--source)
                        source_remote="$2"
                        shift 2
                        ;;
                    -t|--target)
                        target_remote="$2"
                        shift 2
                        ;;
                    -n|--name)
                        mirror_name="$2"
                        shift 2
                        ;;
                    -h|--help)
                        echo "用法: gs-git-remote-mirror create [选项]"
                        echo "创建远程仓库镜像"
                        echo ""
                        echo "选项:"
                        echo "  -s, --source REMOTE         源远程仓库"
                        echo "  -t, --target URL            目标镜像仓库URL"
                        echo "  -n, --name NAME             镜像名称"
                        echo "  -h, --help                  显示此帮助信息"
                        return 0
                        ;;
                    *)
                        echo "错误: 未知参数 $1"
                        return 1
                        ;;
                esac
            done
            
            if [[ -z "$source_remote" ]] || [[ -z "$target_remote" ]]; then
                echo "错误: 请指定源远程仓库和目标仓库URL"
                echo "用法: gs-git-remote-mirror create -s <source> -t <target> -n <name>"
                return 1  
            fi
            
            if [[ -z "$mirror_name" ]]; then
                mirror_name="${source_remote}-mirror"
            fi
            
            if ! _gs_git_remote_check; then
                return 1
            fi
            
            echo "创建远程仓库镜像..."
            echo "源仓库: $source_remote"
            echo "目标URL: $target_remote"
            echo "镜像名: $mirror_name"
            
            # 添加镜像远程仓库
            gs_git_remote_add "$mirror_name" "$target_remote" --fetch '+refs/*:refs/*'
            
            # 设置推送镜像
            git config remote.${mirror_name}.mirror true
            git config remote.${mirror_name}.push '+refs/*:refs/*'
            
            echo "镜像仓库 '$mirror_name' 创建成功！"
            ;;
            
        sync)
            shift
            
            # 解析参数
            while [[ $# -gt 0 ]]; do
                case $1 in
                    -n|--name)
                        mirror_name="$2"
                        shift 2
                        ;;
                    -h|--help)
                        echo "用法: gs-git-remote-mirror sync [选项]"
                        echo "同步镜像仓库"
                        echo ""
                        echo "选项:"
                        echo "  -n, --name NAME             镜像名称"
                        echo "  -h, --help                  显示此帮助信息"
                        return 0
                        ;;
                    *)
                        if [[ -z "$mirror_name" ]]; then
                            mirror_name="$1"
                        else
                            echo "错误: 未知参数 $1"
                            return 1
                        fi
                        shift
                        ;;
                esac
            done
            
            if [[ -z "$mirror_name" ]]; then
                echo "错误: 请指定镜像名称"
                echo "用法: gs-git-remote-mirror sync <mirror-name>"
                return 1
            fi
            
            if ! _gs_git_remote_check; then
                return 1
            fi
            
            if ! git remote | grep -q "^${mirror_name}$"; then
                echo "错误: 镜像仓库 '$mirror_name' 不存在"
                return 1
            fi
            
            echo "同步镜像仓库: $mirror_name"
            
            # 获取所有引用
            git fetch --all
            
            # 推送到镜像
            git push --mirror "$mirror_name"
            
            echo "镜像同步完成！"
            ;;
            
        list)
            if ! _gs_git_remote_check; then
                return 1
            fi
            
            echo "镜像仓库列表:"
            echo "============"
            
            for remote in $(git remote); do
                local is_mirror=$(git config --get remote.${remote}.mirror 2>/dev/null || echo "false")
                if [[ "$is_mirror" == "true" ]]; then
                    local url=$(git remote get-url "$remote")
                    echo "  $remote -> $url"
                fi
            done
            ;;
            
        *)
            echo "用法: gs-git-remote-mirror <command> [options]"
            echo ""
            echo "命令:"
            echo "  create              创建镜像仓库"
            echo "  sync <name>         同步镜像仓库"
            echo "  list                列出所有镜像仓库"
            echo ""
            echo "使用 'gs-git-remote-mirror <command> --help' 查看详细帮助"
            return 1
            ;;
    esac
    
    return 0
}

# 清理远程分支
gs_git_remote_prune() {
    local remote_name=""
    local all_remotes=false
    local dry_run=false
    local force=false
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -r|--remote)
                remote_name="$2"
                shift 2
                ;;
            -a|--all)
                all_remotes=true
                shift
                ;;
            --dry-run)
                dry_run=true
                shift
                ;;
            -f|--force)
                force=true
                shift
                ;;
            -h|--help)
                echo "用法: gs-git-remote-prune [选项] [remote]"
                echo "清理已删除的远程分支"
                echo ""
                echo "选项:"
                echo "  -r, --remote REMOTE         指定远程仓库名"
                echo "  -a, --all                   清理所有远程仓库"
                echo "  --dry-run                   只显示将要删除的分支"
                echo "  -f, --force                 强制删除"
                echo "  -h, --help                  显示此帮助信息"
                echo ""
                echo "示例:"
                echo "  gs-git-remote-prune origin              # 清理origin的远程分支"
                echo "  gs-git-remote-prune --all               # 清理所有远程仓库"
                echo "  gs-git-remote-prune --dry-run origin    # 预览要删除的分支"
                return 0
                ;;
            *)
                if [[ -z "$remote_name" ]]; then
                    remote_name="$1"
                else
                    echo "错误: 未知参数 $1"
                    return 1
                fi
                shift
                ;;
        esac
    done
    
    if ! _gs_git_remote_check; then
        return 1
    fi
    
    # 获取远程仓库列表
    local remotes=()
    if [[ "$all_remotes" == true ]]; then
        readarray -t remotes < <(git remote)
    elif [[ -n "$remote_name" ]]; then
        if git remote | grep -q "^${remote_name}$"; then
            remotes=("$remote_name")
        else
            echo "错误: 远程仓库 '$remote_name' 不存在"
            return 1
        fi
    else
        # 使用默认远程仓库
        if git remote | grep -q "^origin$"; then
            remotes=("origin")
        else
            echo "错误: 请指定远程仓库名或使用 --all"
            echo "可用的远程仓库:"
            git remote | sed 's/^/  /'
            return 1
        fi
    fi
    
    if [[ ${#remotes[@]} -eq 0 ]]; then
        echo "错误: 没有找到远程仓库"
        return 1
    fi
    
    echo "清理远程分支..."
    echo "==============="
    
    for remote in "${remotes[@]}"; do
        echo ""
        echo "处理远程仓库: $remote"
        
        if [[ "$dry_run" == true ]]; then
            echo "[DRY RUN] 将要删除的分支:"
            git remote prune "$remote" --dry-run | grep "prune" | sed 's/^/  /'
        else
            echo "清理已删除的远程分支..."
            if git remote prune "$remote"; then
                echo "✓ 清理完成: $remote"
            else
                echo "✗ 清理失败: $remote"
            fi
        fi
    done
    
    echo ""
    echo "清理完成！"
    
    return 0
}

# 远程仓库信息显示
gs_git_remote_info() {
    local remote_name=""
    local show_urls=true
    local show_branches=true
    local show_config=false
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -r|--remote)
                remote_name="$2"
                shift 2
                ;;
            --no-urls)
                show_urls=false
                shift
                ;;
            --no-branches)
                show_branches=false
                shift
                ;;
            --show-config)
                show_config=true
                shift
                ;;
            -h|--help)
                echo "用法: gs-git-remote-info [选项] [remote]"
                echo "显示远程仓库信息"
                echo ""
                echo "选项:"
                echo "  -r, --remote REMOTE         指定远程仓库名"
                echo "  --no-urls                   不显示URL信息"
                echo "  --no-branches               不显示分支信息"
                echo "  --show-config               显示配置信息"
                echo "  -h, --help                  显示此帮助信息"
                return 0
                ;;
            *)
                if [[ -z "$remote_name" ]]; then
                    remote_name="$1"
                else
                    echo "错误: 未知参数 $1"
                    return 1
                fi
                shift
                ;;
        esac
    done
    
    if ! _gs_git_remote_check; then
        return 1
    fi
    
    # 获取远程仓库列表
    local remotes=()
    if [[ -n "$remote_name" ]]; then
        if git remote | grep -q "^${remote_name}$"; then
            remotes=("$remote_name")
        else
            echo "错误: 远程仓库 '$remote_name' 不存在"
            return 1
        fi
    else
        readarray -t remotes < <(git remote)
    fi
    
    if [[ ${#remotes[@]} -eq 0 ]]; then
        echo "没有配置远程仓库"
        return 0
    fi
    
    echo "远程仓库信息"
    echo "============"
    
    for remote in "${remotes[@]}"; do
        echo ""
        echo "远程仓库: $remote"
        echo "$(printf '=%.0s' {1..20})"
        
        if [[ "$show_urls" == true ]]; then
            echo "URL信息:"
            local fetch_url=$(git remote get-url "$remote" 2>/dev/null || echo "未配置")
            local push_url=$(git remote get-url --push "$remote" 2>/dev/null || echo "$fetch_url")
            echo "  Fetch: $fetch_url"  
            echo "  Push:  $push_url"
        fi
        
        if [[ "$show_branches" == true ]]; then
            echo "远程分支:"
            local branches=$(git branch -r | grep "^[[:space:]]*${remote}/" | sed "s/^[[:space:]]*${remote}\///")
            if [[ -n "$branches" ]]; then
                echo "$branches" | sed 's/^/  /'
                echo "  总计: $(echo "$branches" | wc -l) 个分支"
            else
                echo "  无远程分支"
            fi
        fi
        
        if [[ "$show_config" == true ]]; then
            echo "配置信息:"
            local fetch_config=$(git config --get remote.${remote}.fetch 2>/dev/null || echo "默认")
            local push_config=$(git config --get remote.${remote}.push 2>/dev/null || echo "默认")
            local mirror_config=$(git config --get remote.${remote}.mirror 2>/dev/null || echo "false")
            echo "  Fetch配置: $fetch_config"
            echo "  Push配置:  $push_config"
            echo "  镜像模式:  $mirror_config"
        fi
    done
    
    return 0
}

# 帮助信息
gs_git_remote_help() {
    echo "Git Remote 远程仓库管理"
    echo "======================="
    echo ""
    echo "可用命令:"
    echo "  gs-git-remote-add       增强的远程仓库添加"
    echo "  gs-git-remote-sync      远程仓库同步"
    echo "  gs-git-remote-mirror    镜像仓库管理"
    echo "  gs-git-remote-prune     清理远程分支"
    echo "  gs-git-remote-info      显示远程仓库信息"
    echo "  gs-git-remote-help      显示此帮助信息"
    echo ""
    echo "常用操作:"
    echo "  1. 添加远程仓库:"
    echo "     gs-git-remote-add origin https://github.com/user/repo.git"
    echo ""
    echo "  2. 同步所有远程仓库:"
    echo "     gs-git-remote-sync --all"
    echo ""
    echo "  3. 创建镜像仓库:"
    echo "     gs-git-remote-mirror create -s origin -t https://backup.com/repo.git"
    echo ""
    echo "  4. 清理远程分支:"
    echo "     gs-git-remote-prune --all"
    echo ""
    echo "  5. 查看远程仓库信息:"
    echo "     gs-git-remote-info --show-config"
    echo ""
    echo "使用 'gs-git-remote-<command> --help' 查看特定命令的详细帮助"
    
    return 0
}