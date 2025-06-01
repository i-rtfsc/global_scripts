#!/bin/bash
# Git提交管理子模块
# 作者: Global Scripts Team
# 版本: 1.0.0  
# 描述: 提供Git提交优化、修改、撤销等管理功能

# ============================================================================
# 提交管理核心函数
# ============================================================================

gs_git_commit_enhanced() {
    local message=""
    local add_all=false
    local amend=false
    local no_verify=false
    local sign=false
    local template=""
    local interactive=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_git_commit_enhanced_help
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
            -s|--signoff)
                sign=true
                shift
                ;;
            -t|--template)
                template="$2"
                shift 2
                ;;
            -i|--interactive)
                interactive=true
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
    
    _gs_git_check_git || return 2
    _gs_git_check_repo || return 1
    
    # 交互式提交信息输入
    if $interactive && [[ -z "$message" ]]; then
        echo "=== 交互式提交 ==="
        echo
        
        # 显示当前状态
        echo "当前更改:"
        git status --short | sed 's/^/  /'
        echo
        
        # 获取提交信息
        echo "请输入提交信息 (多行输入，空行结束):"
        local input_message=""
        while IFS= read -r line; do
            [[ -z "$line" ]] && break
            input_message+="$line"$'\n'
        done
        message="${input_message%$'\n'}"
        
        if [[ -z "$message" ]]; then
            echo "取消提交：未输入提交信息"
            return 0
        fi
    elif [[ -z "$message" && -z "$template" && ! $amend ]]; then
        echo "错误: 缺少提交信息" >&2
        echo "使用 -m '信息'、-t 模板文件、--amend 或 -i 交互模式" >&2
        return 1
    fi
    
    # 添加所有文件（如果指定）
    if $add_all; then
        echo "添加所有更改到暂存区..."
        git add -A
    fi
    
    # 检查是否有内容可提交
    if git diff --staged --quiet && ! $amend; then
        echo "错误: 暂存区没有更改可提交" >&2
        echo "使用 git add 添加文件或使用 -a 选项自动添加" >&2
        return 1
    fi
    
    local git_cmd="git commit"
    
    # 添加选项
    if [[ -n "$message" ]]; then
        git_cmd="$git_cmd -m '$message'"
    elif [[ -n "$template" ]]; then
        if [[ ! -f "$template" ]]; then
            echo "错误: 模板文件不存在: $template" >&2
            return 1
        fi
        git_cmd="$git_cmd -t '$template'"
    fi
    
    if $amend; then
        git_cmd="$git_cmd --amend"
    fi
    
    if $no_verify; then
        git_cmd="$git_cmd --no-verify"
    fi
    
    if $sign; then
        git_cmd="$git_cmd --signoff"
    fi
    
    echo "执行增强提交..."
    if [[ -n "$message" ]]; then
        echo "提交信息: $message"
    fi
    
    if eval "$git_cmd"; then
        echo "✅ 提交成功"
        echo
        echo "最新提交:"
        git log --pretty=format:"  %C(yellow)%h%C(reset) %C(blue)%an%C(reset) %C(green)%ar%C(reset) %s" -1
        return 0
    else
        echo "❌ 提交失败" >&2
        return 2
    fi
}

gs_git_commit_fixup() {
    local target_commit=""
    local auto_squash=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_git_commit_fixup_help
                return 0
                ;;
            --autosquash)
                auto_squash=true
                shift
                ;;
            *)
                if [[ -z "$target_commit" ]]; then
                    target_commit="$1"
                fi
                shift
                ;;
        esac
    done
    
    if [[ -z "$target_commit" ]]; then
        echo "错误: 缺少目标提交" >&2
        echo "用法: gs-git-commit-fixup <提交哈希|HEAD~n>" >&2
        return 1
    fi
    
    _gs_git_check_git || return 2
    _gs_git_check_repo || return 1
    
    # 验证目标提交存在
    if ! git cat-file -e "$target_commit" 2>/dev/null; then
        echo "错误: 目标提交不存在: $target_commit" >&2
        return 1
    fi
    
    # 检查是否有更改可提交
    if git diff --staged --quiet; then
        echo "错误: 暂存区没有更改可提交" >&2
        echo "请先使用 git add 添加要修复的更改" >&2
        return 1
    fi
    
    # 显示目标提交信息
    echo "目标提交信息:"
    git log --oneline -1 "$target_commit" | sed 's/^/  /'
    echo
    
    echo "创建fixup提交..."
    
    if git commit --fixup "$target_commit"; then
        echo "✅ Fixup提交创建成功"
        
        if $auto_squash; then
            echo
            echo "执行自动压缩合并..."
            local commit_count
            commit_count=$(git rev-list --count "$target_commit"..HEAD)
            
            if git rebase -i --autosquash "HEAD~$((commit_count + 1))"; then
                echo "✅ 自动压缩合并完成"
            else
                echo "⚠️  自动压缩合并失败，请手动处理" >&2
            fi
        else
            echo
            echo "💡 提示: 使用以下命令进行交互式变基合并fixup提交:"
            local commit_count
            commit_count=$(git rev-list --count "$target_commit"..HEAD)
            echo "  git rebase -i --autosquash HEAD~$((commit_count + 1))"
        fi
        
        return 0
    else
        echo "❌ Fixup提交创建失败" >&2
        return 2
    fi
}

gs_git_commit_amend() {
    local no_edit=false
    local reset_author=false
    local message=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_git_commit_amend_help
                return 0
                ;;
            --no-edit)
                no_edit=true
                shift
                ;;
            --reset-author)
                reset_author=true
                shift
                ;;
            -m|--message)
                message="$2"
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
    
    # 检查是否有提交可修改
    if ! git log --oneline -1 >/dev/null 2>&1; then
        echo "错误: 没有提交可以修改" >&2
        return 1
    fi
    
    echo "当前最后提交:"
    git log --pretty=format:"  %C(yellow)%h%C(reset) %C(blue)%an%C(reset) %C(green)%ar%C(reset) %s" -1
    echo
    
    # 显示将要修改的内容
    if ! git diff --staged --quiet; then
        echo "暂存区的新更改:"
        git diff --staged --name-status | sed 's/^/  /'
        echo
    fi
    
    local git_cmd="git commit --amend"
    
    if $no_edit; then
        git_cmd="$git_cmd --no-edit"
    elif [[ -n "$message" ]]; then
        git_cmd="$git_cmd -m '$message'"
    fi
    
    if $reset_author; then
        git_cmd="$git_cmd --reset-author"
    fi
    
    echo "修改最后一次提交..."
    
    if eval "$git_cmd"; then
        echo "✅ 提交修改成功"
        echo
        echo "修改后的提交:"
        git log --pretty=format:"  %C(yellow)%h%C(reset) %C(blue)%an%C(reset) %C(green)%ar%C(reset) %s" -1
        return 0
    else
        echo "❌ 提交修改失败" >&2
        return 2
    fi
}

gs_git_commit_revert() {
    local target_commit=""
    local no_commit=false
    local no_edit=false
    local mainline=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_git_commit_revert_help
                return 0
                ;;
            --no-commit|-n)
                no_commit=true
                shift
                ;;
            --no-edit)
                no_edit=true
                shift
                ;;
            -m|--mainline)
                mainline="$2"
                shift 2
                ;;
            *)
                if [[ -z "$target_commit" ]]; then
                    target_commit="$1"
                fi
                shift
                ;;
        esac
    done
    
    if [[ -z "$target_commit" ]]; then
        echo "错误: 缺少目标提交" >&2
        echo "用法: gs-git-commit-revert <提交哈希|HEAD~n>" >&2
        return 1
    fi
    
    _gs_git_check_git || return 2
    _gs_git_check_repo || return 1
    
    # 验证目标提交存在
    if ! git cat-file -e "$target_commit" 2>/dev/null; then
        echo "错误: 目标提交不存在: $target_commit" >&2
        return 1
    fi
    
    # 检查工作区状态
    if ! _gs_git_check_clean; then
        echo "错误: 工作区有未提交的更改" >&2
        return 1
    fi
    
    # 显示目标提交信息
    echo "将要撤销的提交:"
    git log --pretty=format:"  %C(yellow)%h%C(reset) %C(blue)%an%C(reset) %C(green)%ar%C(reset) %s" -1 "$target_commit"
    echo
    
    local git_cmd="git revert"
    
    if $no_commit; then
        git_cmd="$git_cmd --no-commit"
    fi
    
    if $no_edit; then
        git_cmd="$git_cmd --no-edit"
    fi
    
    if [[ -n "$mainline" ]]; then
        git_cmd="$git_cmd -m $mainline"
    fi
    
    git_cmd="$git_cmd $target_commit"
    
    echo "执行提交撤销..."
    
    if eval "$git_cmd"; then
        if $no_commit; then
            echo "✅ 撤销更改已应用到工作区"
            echo "请检查更改并手动提交"
            echo
            echo "更改的文件:"
            git diff --name-status | sed 's/^/  /'
        else
            echo "✅ 提交撤销成功"
            echo
            echo "撤销提交:"
            git log --pretty=format:"  %C(yellow)%h%C(reset) %C(blue)%an%C(reset) %C(green)%ar%C(reset) %s" -1
        fi
        return 0
    else
        echo "❌ 提交撤销失败" >&2
        echo "可能存在冲突，请解决冲突后手动完成" >&2
        return 2
    fi
}

gs_git_commit_template() {
    local template_type="conventional"
    local output_file=""
    local edit=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                _show_git_commit_template_help
                return 0
                ;;
            --type|-t)
                template_type="$2"
                shift 2
                ;;
            --output|-o)
                output_file="$2"
                shift 2
                ;;
            --edit|-e)
                edit=true
                shift
                ;;
            *)
                echo "错误: 未知选项 $1" >&2
                return 1
                ;;
        esac
    done
    
    local template_content=""
    
    case "$template_type" in
        "conventional")
            template_content=$(cat << 'EOF'
# <类型>(<范围>): <描述>
#
# 类型说明:
# feat:     新功能
# fix:      bug修复
# docs:     文档更新
# style:    代码格式调整
# refactor: 重构代码
# test:     测试相关
# chore:    构建/工具链更改
#
# 范围: 影响的模块或组件
# 描述: 简洁的更改说明
#
# 详细描述 (可选):
# 
#
# 相关Issue (可选):
# Closes #123
EOF
)
            ;;
        "detailed")
            template_content=$(cat << 'EOF'
# 提交标题 (不超过50字符)

# 详细描述 (每行不超过72字符)
# 解释这次更改的内容、原因和方式
#
# 
#

# 相关信息:
# - 相关Issue: #
# - 破坏性更改: 是/否
# - 测试: 已测试/需要测试
# - 文档: 已更新/需要更新
EOF
)
            ;;
        "simple")
            template_content=$(cat << 'EOF'
# 简洁描述这次更改

# 更改原因 (可选):
#

# 相关Issue (可选):
# Closes #
EOF
)
            ;;
        *)
            echo "错误: 未知模板类型: $template_type" >&2
            echo "支持类型: conventional, detailed, simple" >&2
            return 1
            ;;
    esac
    
    if [[ -n "$output_file" ]]; then
        echo "$template_content" > "$output_file"
        echo "✅ 提交模板已保存到: $output_file"
        
        if $edit && command -v "${EDITOR:-nano}" >/dev/null 2>&1; then
            echo "打开编辑器编辑模板..."
            "${EDITOR:-nano}" "$output_file"
        fi
    else
        echo "=== Git提交模板 ($template_type) ==="
        echo
        echo "$template_content"
        echo
        echo "💡 使用 --output 选项保存到文件"
    fi
    
    return 0
}

# ============================================================================
# 帮助函数
# ============================================================================

_show_git_commit_enhanced_help() {
    cat << 'EOF'
gs_git_commit_enhanced - Git增强提交功能

功能描述:
  提供增强的Git提交功能，支持交互式输入、模板和多种提交选项

使用方式:
  gs-git-commit-enhanced [选项]

选项:
  -m, --message     提交信息
  -a, --all         自动添加所有更改
  --amend           修改最后一次提交
  --no-verify       跳过提交钩子验证
  -s, --signoff     添加签名行
  -t, --template    使用模板文件
  -i, --interactive 交互式输入提交信息
  --help, -h        显示此帮助信息

示例:
  gs-git-commit-enhanced -m "修复登录问题"
  gs-git-commit-enhanced --all --interactive
  gs-git-commit-enhanced --amend --no-edit
  gs-git-commit-enhanced -t commit-template.txt
  gs-git-commit-enhanced --help

依赖:
  系统命令: git
  插件依赖: git

注意事项:
  - 交互模式支持多行输入
  - 自动检查暂存区状态
  - 支持提交模板和签名
EOF
}

_show_git_commit_fixup_help() {
    cat << 'EOF'
gs_git_commit_fixup - 创建修复提交

功能描述:
  为指定提交创建fixup提交，用于后续的交互式变基合并

使用方式:
  gs-git-commit-fixup <目标提交> [选项]

选项:
  --autosquash      自动执行压缩合并
  --help, -h        显示此帮助信息

示例:
  gs-git-commit-fixup HEAD~2
  gs-git-commit-fixup abc123 --autosquash
  gs-git-commit-fixup --help

依赖:
  系统命令: git
  插件依赖: git

注意事项:
  - 暂存区必须有要修复的更改
  - 建议在功能分支上使用
  - 使用 git rebase -i --autosquash 合并
EOF
}

_show_git_commit_amend_help() {
    cat << 'EOF'
gs_git_commit_amend - 修改最后一次提交

功能描述:
  修改最后一次提交的内容或信息，支持添加新更改和修改提交信息

使用方式:
  gs-git-commit-amend [选项]

选项:
  --no-edit         不修改提交信息
  --reset-author    重置提交作者
  -m, --message     新的提交信息
  --help, -h        显示此帮助信息

示例:
  gs-git-commit-amend --no-edit
  gs-git-commit-amend -m "修改后的提交信息"
  gs-git-commit-amend --reset-author
  gs-git-commit-amend --help

依赖:
  系统命令: git
  插件依赖: git

注意事项:
  - 会修改Git历史，避免在共享分支使用
  - 可以添加暂存区的新更改
  - --reset-author 会使用当前用户信息
EOF
}

_show_git_commit_revert_help() {
    cat << 'EOF' 
gs_git_commit_revert - 撤销指定提交

功能描述:
  安全地撤销指定提交的更改，创建新的撤销提交

使用方式:
  gs-git-commit-revert <目标提交> [选项]

选项:
  --no-commit, -n   仅应用撤销更改，不自动提交
  --no-edit         不编辑撤销提交信息
  -m, --mainline    指定合并提交的主线（1或2）
  --help, -h        显示此帮助信息

示例:
  gs-git-commit-revert HEAD~1
  gs-git-commit-revert abc123 --no-commit
  gs-git-commit-revert merge-commit -m 1
  gs-git-commit-revert --help

依赖:
  系统命令: git
  插件依赖: git

注意事项:
  - 不会修改Git历史，安全操作
  - 对于合并提交需要指定主线
  - 可能产生冲突需要手动解决
EOF
}

_show_git_commit_template_help() {
    cat << 'EOF'
gs_git_commit_template - Git提交模板生成

功能描述:
  生成标准化的Git提交信息模板，支持多种格式

使用方式:
  gs-git-commit-template [选项]

选项:
  --type, -t        模板类型（conventional/detailed/simple）
  --output, -o      输出到文件
  --edit, -e        生成后编辑模板
  --help, -h        显示此帮助信息

模板类型:
  conventional      约定式提交格式
  detailed          详细描述格式
  simple            简单格式

示例:
  gs-git-commit-template
  gs-git-commit-template --type detailed
  gs-git-commit-template -t conventional -o .gitmessage
  gs-git-commit-template --output template.txt --edit
  gs-git-commit-template --help

依赖:
  系统命令: git
  插件依赖: git

注意事项:
  - 可以设置为Git全局提交模板
  - 支持自定义编辑器打开
  - 模板包含详细的格式说明
EOF
}

# 如果直接运行此脚本，显示模块信息
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
    echo "Git提交管理子模块"
    echo "版本: 1.0.0"
    echo
    echo "可用命令:"
    echo "  gs-git-commit-enhanced  - 增强提交功能"
    echo "  gs-git-commit-fixup     - 创建修复提交"
    echo "  gs-git-commit-amend     - 修改最后提交"
    echo "  gs-git-commit-revert    - 撤销指定提交"
    echo "  gs-git-commit-template  - 生成提交模板"
    echo
    echo "使用 '<命令> --help' 查看详细帮助"
fi