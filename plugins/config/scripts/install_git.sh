#!/bin/bash

# Git 配置安装脚本
# 安装模块化的Git配置到系统

install_git_config() {
    local force="$1"
    local git_config="$HOME/.gitconfig"
    local template_dir="$(dirname "$0")/../templates/git"
    
    echo "🔧 安装 Git 配置..."
    
    # 检查模板目录
    if [[ ! -d "$template_dir" ]]; then
        echo "❌ 未找到Git配置模板目录: $template_dir" >&2
        return 1
    fi
    
    # 备份现有配置
    if [[ -f "$git_config" ]]; then
        if [[ "$force" == "true" ]]; then
            local backup_dir="$HOME/.config/gs/backups/$(date +%Y%m%d_%H%M%S)"
            mkdir -p "$backup_dir"
            cp "$git_config" "$backup_dir/gitconfig.backup"
            echo "✅ 已备份现有配置: $backup_dir/gitconfig.backup"
        else
            echo "⚠️  Git配置已存在: $git_config" >&2
            echo "   使用 --force 参数强制覆盖" >&2
            return 1
        fi
    fi
    
    # 创建主配置文件
    cat > "$git_config" << EOF
# ============================================================================
# Global Scripts Git 配置文件 - 模块化配置管理
# 自动生成时间: $(date)
# ============================================================================

# 包含各个功能模块的配置
[include]
    path = $template_dir/core.git
    path = $template_dir/alias.git  
    path = $template_dir/color.git
    path = $template_dir/diff.git
    path = $template_dir/push.git
    path = $template_dir/branch.git

# ============================================================================
# 用户信息配置 - 请根据实际情况修改
# ============================================================================
[user]
    name = Your Name Here
    email = your.email@example.com
    # signingkey = YOUR_GPG_KEY_ID

# ============================================================================
# 工作环境配置 - 可选的条件包含
# ============================================================================

# 工作目录特定配置 (取消注释并修改路径)
# [includeIf "gitdir:~/work/"]
#     path = $template_dir/work.git

# 公司项目特定配置
# [includeIf "gitdir:~/company/"]
#     path = $template_dir/company.git

# ============================================================================ 
# 个人自定义配置区域
# 您可以在这里添加个人特定的Git配置，不会被更新覆盖
# ============================================================================

# 示例: 个人偏好设置
# [core]
#     editor = code --wait
#     autocrlf = true

# 示例: 额外的别名
# [alias]
#     myalias = status --short

EOF
    
    echo "✅ Git配置安装完成: $git_config"
    echo ""
    echo "📝 重要提示:"
    echo "   1. 请编辑 $git_config 中的用户信息"
    echo "   2. 根据需要启用工作环境配置"
    echo "   3. 可以在个人自定义区域添加特定配置"
    echo ""
    echo "🎯 推荐配置命令:"
    echo "   git config --global user.name \"Your Name\""
    echo "   git config --global user.email \"your.email@example.com\""
    
    # 验证配置
    echo ""
    echo "🔍 配置验证:"
    if git config --list >/dev/null 2>&1; then
        echo "   ✅ Git配置语法正确"
    else
        echo "   ❌ Git配置存在语法错误" >&2
        return 1
    fi
    
    # 显示一些有用的别名
    echo ""
    echo "🚀 现在可以使用的Git别名 (部分):"
    echo "   git st    # git status"
    echo "   git co    # git checkout" 
    echo "   git br    # git branch"
    echo "   git cm    # git commit -m"
    echo "   git lg    # 图形化日志"
    echo "   git pr    # pull --rebase"
    echo ""
    echo "   查看所有别名: git aliases"
    
    return 0
}

# 主函数
main() {
    local force="$1"
    install_git_config "$force"
}

# 如果直接执行此脚本
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi