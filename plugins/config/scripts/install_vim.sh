#!/bin/bash

# Vim 配置安装脚本
# 安装现代化的Vim/Neovim配置到系统

install_vim_config() {
    local force="$1"
    local template_dir="$(dirname "$0")/../templates/vim"
    
    echo "🔧 安装 Vim 配置..."
    
    # 检查模板目录
    if [[ ! -d "$template_dir" ]]; then
        echo "❌ 未找到Vim配置模板目录: $template_dir" >&2
        return 1
    fi
    
    # 检测Vim类型
    local vim_type=""
    local config_dir=""
    local config_file=""
    
    if command -v nvim >/dev/null; then
        vim_type="neovim"
        config_dir="$HOME/.config/nvim"
        config_file="$config_dir/init.vim"
        echo "📦 检测到 Neovim"
    elif command -v vim >/dev/null; then
        vim_type="vim"
        config_dir="$HOME/.vim"
        config_file="$HOME/.vimrc"
        echo "📦 检测到 Vim"
    else
        echo "❌ 未找到 Vim 或 Neovim" >&2
        return 1
    fi
    
    # 备份现有配置
    local backup_dir="$HOME/.config/gs/backups/$(date +%Y%m%d_%H%M%S)/vim"
    local backed_up=false
    
    if [[ -f "$config_file" ]] || [[ -d "$config_dir" ]]; then
        if [[ "$force" == "true" ]]; then
            mkdir -p "$backup_dir"
            
            if [[ -f "$config_file" ]]; then
                cp "$config_file" "$backup_dir/"
                echo "✅ 已备份配置文件: $config_file"
                backed_up=true
            fi
            
            if [[ -d "$config_dir" ]]; then
                cp -r "$config_dir" "$backup_dir/"
                echo "✅ 已备份配置目录: $config_dir"
                backed_up=true
            fi
            
            # 清理现有配置
            rm -rf "$config_file" "$config_dir"
            
        else
            echo "⚠️  Vim配置已存在" >&2
            echo "   配置文件: $config_file" >&2
            echo "   配置目录: $config_dir" >&2
            echo "   使用 --force 参数强制覆盖" >&2
            return 1
        fi
    fi
    
    # 创建配置目录
    mkdir -p "$config_dir"
    
    # 创建符号链接到模板
    if [[ "$vim_type" == "neovim" ]]; then
        # Neovim 配置
        ln -s "$template_dir/init.vim" "$config_file"
        ln -s "$template_dir/colors" "$config_dir/colors"
        ln -s "$template_dir/conf" "$config_dir/conf"
        
        echo "✅ Neovim配置安装完成"
        
    else
        # Vim 配置
        ln -s "$template_dir/init.vim" "$config_file"
        ln -s "$template_dir/colors" "$config_dir/colors"  
        ln -s "$template_dir/conf" "$config_dir/conf"
        
        echo "✅ Vim配置安装完成"
    fi
    
    echo ""
    echo "📝 配置信息:"
    echo "   配置文件: $config_file"
    echo "   配置目录: $config_dir"
    echo "   颜色主题: $config_dir/colors/"
    echo "   功能模块: $config_dir/conf/"
    
    if [[ "$backed_up" == "true" ]]; then
        echo "   备份位置: $backup_dir"
    fi
    
    echo ""
    echo "🎨 可用颜色主题:"
    if [[ -d "$template_dir/colors" ]]; then
        ls "$template_dir/colors"/*.vim 2>/dev/null | sed 's/.*\//   - /' | sed 's/\.vim$//'
    fi
    
    echo ""
    echo "🔧 配置模块:"
    if [[ -d "$template_dir/conf" ]]; then
        find "$template_dir/conf" -name "*.vim" | sed 's/.*\//   - /' | sed 's/\.vim$//'
    fi
    
    echo ""
    echo "🚀 使用建议:"
    echo "   1. 启动 $vim_type 查看配置是否正常加载"
    echo "   2. 在Vim中使用 :colorscheme <主题名> 切换主题"
    echo "   3. 配置已启用语法高亮、行号、智能缩进等功能"
    echo "   4. 支持鼠标操作和现代化的编辑体验"
    
    # 检查插件管理器
    echo ""
    echo "📦 插件管理器检查:"
    local plug_file=""
    if [[ "$vim_type" == "neovim" ]]; then
        plug_file="$HOME/.local/share/nvim/site/autoload/plug.vim"
    else
        plug_file="$HOME/.vim/autoload/plug.vim"
    fi
    
    if [[ -f "$plug_file" ]]; then
        echo "   ✅ vim-plug 已安装"
    else
        echo "   ❌ vim-plug 未安装"
        echo "   📥 安装命令:"
        if [[ "$vim_type" == "neovim" ]]; then
            echo "      curl -fLo ~/.local/share/nvim/site/autoload/plug.vim --create-dirs \\"
            echo "           https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim"
        else
            echo "      curl -fLo ~/.vim/autoload/plug.vim --create-dirs \\"
            echo "           https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim"
        fi
    fi
    
    return 0
}

# 主函数
main() {
    local force="$1"
    install_vim_config "$force"
}

# 如果直接执行此脚本
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi