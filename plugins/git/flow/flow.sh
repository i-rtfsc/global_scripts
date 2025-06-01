#!/bin/bash
# Git Flow管理子模块
# Git Flow Management Submodule
# 提供Git flow工作流管理功能

# 检查git flow是否可用
_gs_git_flow_check() {
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

# 初始化Git flow
gs_git_flow_init() {
    local develop_branch="develop"
    local master_branch="master"
    local feature_prefix="feature/"
    local release_prefix="release/"
    local hotfix_prefix="hotfix/"
    local support_prefix="support/"
    local version_tag_prefix=""
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--develop)
                develop_branch="$2"
                shift 2
                ;;
            -m|--master)
                master_branch="$2"
                shift 2
                ;;
            --feature-prefix)
                feature_prefix="$2"
                shift 2
                ;;
            --release-prefix)
                release_prefix="$2"
                shift 2
                ;;
            --hotfix-prefix)
                hotfix_prefix="$2"
                shift 2
                ;;
            --support-prefix)
                support_prefix="$2"
                shift 2
                ;;
            --version-tag-prefix)
                version_tag_prefix="$2"
                shift 2
                ;;
            -h|--help)
                echo "用法: gs-git-flow-init [选项]"
                echo "初始化Git flow工作流"
                echo ""
                echo "选项:"
                echo "  -d, --develop BRANCH        开发分支名 (默认: develop)"
                echo "  -m, --master BRANCH         主分支名 (默认: master)"
                echo "  --feature-prefix PREFIX     功能分支前缀 (默认: feature/)"
                echo "  --release-prefix PREFIX     发布分支前缀 (默认: release/)"
                echo "  --hotfix-prefix PREFIX      热修复分支前缀 (默认: hotfix/)"
                echo "  --support-prefix PREFIX     支持分支前缀 (默认: support/)"
                echo "  --version-tag-prefix PREFIX 版本标签前缀 (默认: 空)"
                echo "  -h, --help                  显示此帮助信息"
                return 0
                ;;
            *)
                echo "错误: 未知参数 $1"
                return 1
                ;;
        esac
    done
    
    if ! _gs_git_flow_check; then
        return 1
    fi
    
    echo "初始化Git flow工作流..."
    
    # 检查分支是否存在
    if ! git show-ref --verify --quiet refs/heads/$master_branch; then
        echo "创建主分支: $master_branch"
        git checkout -b $master_branch
    else
        git checkout $master_branch
    fi
    
    if ! git show-ref --verify --quiet refs/heads/$develop_branch; then
        echo "创建开发分支: $develop_branch"
        git checkout -b $develop_branch $master_branch
    else
        git checkout $develop_branch
    fi
    
    # 配置Git flow
    git config gitflow.branch.master $master_branch
    git config gitflow.branch.develop $develop_branch
    git config gitflow.prefix.feature $feature_prefix
    git config gitflow.prefix.release $release_prefix
    git config gitflow.prefix.hotfix $hotfix_prefix
    git config gitflow.prefix.support $support_prefix
    git config gitflow.prefix.versiontag $version_tag_prefix
    
    echo "Git flow初始化完成！"
    echo "主分支: $master_branch"
    echo "开发分支: $develop_branch"
    echo "功能分支前缀: $feature_prefix"
    echo "发布分支前缀: $release_prefix"
    echo "热修复分支前缀: $hotfix_prefix"
    
    return 0
}

# 功能分支管理
gs_git_flow_feature() {
    local action="$1"
    local feature_name="$2"
    local feature_prefix="feature/"
    
    if ! _gs_git_flow_check; then
        return 1
    fi
    
    # 获取配置的前缀
    if git config --get gitflow.prefix.feature &> /dev/null; then
        feature_prefix=$(git config --get gitflow.prefix.feature)
    fi
    
    case $action in
        start)
            if [[ -z "$feature_name" ]]; then
                echo "错误: 请指定功能分支名称"
                echo "用法: gs-git-flow-feature start <name>"
                return 1
            fi
            
            local develop_branch=$(git config --get gitflow.branch.develop || echo "develop")
            
            echo "开始功能分支: ${feature_prefix}${feature_name}"
            git checkout $develop_branch
            git pull origin $develop_branch
            git checkout -b ${feature_prefix}${feature_name} $develop_branch
            ;;
            
        finish)
            if [[ -z "$feature_name" ]]; then
                echo "错误: 请指定功能分支名称"
                echo "用法: gs-git-flow-feature finish <name>"
                return 1
            fi
            
            local develop_branch=$(git config --get gitflow.branch.develop || echo "develop")
            local branch_name="${feature_prefix}${feature_name}"
            
            if ! git show-ref --verify --quiet refs/heads/$branch_name; then
                echo "错误: 功能分支 $branch_name 不存在"
                return 1
            fi
            
            echo "完成功能分支: $branch_name"
            git checkout $develop_branch
            git merge --no-ff $branch_name
            
            read -p "是否删除功能分支 $branch_name? (y/N): " confirm
            if [[ $confirm =~ ^[Yy]$ ]]; then
                git branch -d $branch_name
                echo "已删除功能分支: $branch_name"
            fi
            ;;
            
        list)
            echo "功能分支列表:"
            git branch | grep "^[[:space:]]*${feature_prefix}" | sed "s/^[[:space:]]*${feature_prefix}/  /"
            ;;
            
        publish)
            if [[ -z "$feature_name" ]]; then
                echo "错误: 请指定功能分支名称"
                echo "用法: gs-git-flow-feature publish <name>"
                return 1
            fi
            
            local branch_name="${feature_prefix}${feature_name}"
            echo "发布功能分支: $branch_name"
            git push -u origin $branch_name
            ;;
            
        *)
            echo "用法: gs-git-flow-feature <command> [options]"
            echo ""
            echo "命令:"
            echo "  start <name>    开始新的功能分支"
            echo "  finish <name>   完成功能分支并合并到develop"
            echo "  list            列出所有功能分支"
            echo "  publish <name>  发布功能分支到远程"
            return 1
            ;;
    esac
    
    return 0
}

# 发布分支管理
gs_git_flow_release() {
    local action="$1"
    local version="$2"
    local release_prefix="release/"
    
    if ! _gs_git_flow_check; then
        return 1
    fi
    
    # 获取配置的前缀
    if git config --get gitflow.prefix.release &> /dev/null; then
        release_prefix=$(git config --get gitflow.prefix.release)
    fi
    
    case $action in
        start)
            if [[ -z "$version" ]]; then
                echo "错误: 请指定版本号"
                echo "用法: gs-git-flow-release start <version>"
                return 1
            fi
            
            local develop_branch=$(git config --get gitflow.branch.develop || echo "develop")
            
            echo "开始发布分支: ${release_prefix}${version}"
            git checkout $develop_branch
            git pull origin $develop_branch
            git checkout -b ${release_prefix}${version} $develop_branch
            ;;
            
        finish)
            if [[ -z "$version" ]]; then
                echo "错误: 请指定版本号"
                echo "用法: gs-git-flow-release finish <version>"
                return 1
            fi
            
            local master_branch=$(git config --get gitflow.branch.master || echo "master")
            local develop_branch=$(git config --get gitflow.branch.develop || echo "develop")
            local branch_name="${release_prefix}${version}"
            local version_tag_prefix=$(git config --get gitflow.prefix.versiontag || echo "")
            
            if ! git show-ref --verify --quiet refs/heads/$branch_name; then
                echo "错误: 发布分支 $branch_name 不存在"
                return 1
            fi
            
            echo "完成发布分支: $branch_name"
            
            # 合并到master
            git checkout $master_branch
            git merge --no-ff $branch_name
            
            # 创建标签
            echo "创建版本标签: ${version_tag_prefix}${version}"
            git tag -a ${version_tag_prefix}${version} -m "Release ${version}"
            
            # 合并到develop
            git checkout $develop_branch
            git merge --no-ff $branch_name
            
            # 删除发布分支
            read -p "是否删除发布分支 $branch_name? (y/N): " confirm
            if [[ $confirm =~ ^[Yy]$ ]]; then
                git branch -d $branch_name
                echo "已删除发布分支: $branch_name"
            fi
            
            echo "发布完成！"
            echo "请推送更改到远程仓库:"
            echo "  git push origin $master_branch"
            echo "  git push origin $develop_branch"
            echo "  git push origin ${version_tag_prefix}${version}"
            ;;
            
        list)
            echo "发布分支列表:"
            git branch | grep "^[[:space:]]*${release_prefix}" | sed "s/^[[:space:]]*${release_prefix}/  /"
            ;;
            
        *)
            echo "用法: gs-git-flow-release <command> [options]"
            echo ""
            echo "命令:"
            echo "  start <version>    开始新的发布分支"
            echo "  finish <version>   完成发布分支并合并"
            echo "  list               列出所有发布分支"
            return 1
            ;;
    esac
    
    return 0
}

# 热修复分支管理
gs_git_flow_hotfix() {
    local action="$1"
    local version="$2"
    local hotfix_prefix="hotfix/"
    
    if ! _gs_git_flow_check; then
        return 1
    fi
    
    # 获取配置的前缀
    if git config --get gitflow.prefix.hotfix &> /dev/null; then
        hotfix_prefix=$(git config --get gitflow.prefix.hotfix)
    fi
    
    case $action in
        start)
            if [[ -z "$version" ]]; then
                echo "错误: 请指定版本号"
                echo "用法: gs-git-flow-hotfix start <version>"
                return 1
            fi
            
            local master_branch=$(git config --get gitflow.branch.master || echo "master")
            
            echo "开始热修复分支: ${hotfix_prefix}${version}"
            git checkout $master_branch
            git pull origin $master_branch
            git checkout -b ${hotfix_prefix}${version} $master_branch
            ;;
            
        finish)
            if [[ -z "$version" ]]; then
                echo "错误: 请指定版本号"
                echo "用法: gs-git-flow-hotfix finish <version>"
                return 1
            fi
            
            local master_branch=$(git config --get gitflow.branch.master || echo "master")
            local develop_branch=$(git config --get gitflow.branch.develop || echo "develop")
            local branch_name="${hotfix_prefix}${version}"
            local version_tag_prefix=$(git config --get gitflow.prefix.versiontag || echo "")
            
            if ! git show-ref --verify --quiet refs/heads/$branch_name; then
                echo "错误: 热修复分支 $branch_name 不存在"
                return 1
            fi
            
            echo "完成热修复分支: $branch_name"
            
            # 合并到master
            git checkout $master_branch
            git merge --no-ff $branch_name
            
            # 创建标签
            echo "创建版本标签: ${version_tag_prefix}${version}"
            git tag -a ${version_tag_prefix}${version} -m "Hotfix ${version}"
            
            # 合并到develop
            git checkout $develop_branch
            git merge --no-ff $branch_name
            
            # 删除热修复分支
            read -p "是否删除热修复分支 $branch_name? (y/N): " confirm
            if [[ $confirm =~ ^[Yy]$ ]]; then
                git branch -d $branch_name
                echo "已删除热修复分支: $branch_name"
            fi
            
            echo "热修复完成！"
            echo "请推送更改到远程仓库:"
            echo "  git push origin $master_branch"
            echo "  git push origin $develop_branch"
            echo "  git push origin ${version_tag_prefix}${version}"
            ;;
            
        list)
            echo "热修复分支列表:"
            git branch | grep "^[[:space:]]*${hotfix_prefix}" | sed "s/^[[:space:]]*${hotfix_prefix}/  /"
            ;;
            
        *)
            echo "用法: gs-git-flow-hotfix <command> [options]"
            echo ""
            echo "命令:"
            echo "  start <version>    开始新的热修复分支"
            echo "  finish <version>   完成热修复分支并合并"
            echo "  list               列出所有热修复分支"
            return 1
            ;;
    esac
    
    return 0
}

# Git flow状态显示
gs_git_flow_status() {
    if ! _gs_git_flow_check; then
        return 1
    fi
    
    echo "Git Flow 配置状态:"
    echo "=================="
    
    local master_branch=$(git config --get gitflow.branch.master 2>/dev/null || echo "未配置")
    local develop_branch=$(git config --get gitflow.branch.develop 2>/dev/null || echo "未配置")
    local feature_prefix=$(git config --get gitflow.prefix.feature 2>/dev/null || echo "未配置")
    local release_prefix=$(git config --get gitflow.prefix.release 2>/dev/null || echo "未配置")
    local hotfix_prefix=$(git config --get gitflow.prefix.hotfix 2>/dev/null || echo "未配置")
    local version_tag_prefix=$(git config --get gitflow.prefix.versiontag 2>/dev/null || echo "未配置")
    
    echo "主分支: $master_branch"
    echo "开发分支: $develop_branch"
    echo "功能分支前缀: $feature_prefix"
    echo "发布分支前缀: $release_prefix"
    echo "热修复分支前缀: $hotfix_prefix"
    echo "版本标签前缀: $version_tag_prefix"
    echo ""
    
    echo "当前分支状态:"
    echo "=============="
    local current_branch=$(git branch --show-current)
    echo "当前分支: $current_branch"
    
    # 显示功能分支
    local feature_branches=$(git branch | grep "^[[:space:]]*${feature_prefix}" | wc -l)
    if [[ $feature_branches -gt 0 ]]; then
        echo "活跃功能分支: $feature_branches 个"
        git branch | grep "^[[:space:]]*${feature_prefix}" | sed 's/^[[:space:]]*/  /'
    fi
    
    # 显示发布分支
    local release_branches=$(git branch | grep "^[[:space:]]*${release_prefix}" | wc -l)
    if [[ $release_branches -gt 0 ]]; then
        echo "活跃发布分支: $release_branches 个"
        git branch | grep "^[[:space:]]*${release_prefix}" | sed 's/^[[:space:]]*/  /'
    fi
    
    # 显示热修复分支
    local hotfix_branches=$(git branch | grep "^[[:space:]]*${hotfix_prefix}" | wc -l)
    if [[ $hotfix_branches -gt 0 ]]; then
        echo "活跃热修复分支: $hotfix_branches 个"
        git branch | grep "^[[:space:]]*${hotfix_prefix}" | sed 's/^[[:space:]]*/  /'
    fi
    
    return 0
}

# 帮助信息
gs_git_flow_help() {
    echo "Git Flow 工作流管理"
    echo "=================="
    echo ""
    echo "可用命令:"
    echo "  gs-git-flow-init      初始化Git flow工作流"
    echo "  gs-git-flow-feature   管理功能分支"
    echo "  gs-git-flow-release   管理发布分支"
    echo "  gs-git-flow-hotfix    管理热修复分支"
    echo "  gs-git-flow-status    显示Git flow状态"
    echo "  gs-git-flow-help      显示此帮助信息"
    echo ""
    echo "Git Flow 工作流说明:"
    echo "  - master: 主分支，包含生产环境代码"
    echo "  - develop: 开发分支，包含最新开发代码"
    echo "  - feature/*: 功能分支，从develop分出，完成后合并回develop"
    echo "  - release/*: 发布分支，从develop分出，完成后合并到master和develop"
    echo "  - hotfix/*: 热修复分支，从master分出，完成后合并到master和develop"
    echo ""
    echo "使用 'gs-git-flow-<command> --help' 查看特定命令的详细帮助"
    
    return 0
}