#!/bin/bash

# Global Scripts Config Plugin - 开发环境配置管理
# 提供install/backup命令，管理Git、Vim、Tmux、Zsh等开发工具配置
# 基于V2版本conf功能重新设计，保护私有信息，支持模板化部署

# 获取脚本目录（兼容Bash和Zsh）
_gs_get_script_dir() {
    if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
        # Bash环境
        echo "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    elif [[ -n "${(%):-%x}" ]]; then
        # Zsh环境
        echo "$(cd "$(dirname "${(%):-%x}")" && pwd)"
    elif [[ -n "$0" ]]; then
        # 备选方案
        echo "$(cd "$(dirname "$0")" && pwd)"
    else
        # 最后备选
        pwd
    fi
}

# 配置目录定义
PLUGIN_DIR="$(_gs_get_script_dir)"
TEMPLATES_DIR="$PLUGIN_DIR/templates"
SCRIPTS_DIR="$PLUGIN_DIR/scripts"
CONFIG_BASE="${GS_CONFIG_DIR:-$HOME/.config/gs}"
BACKUP_DIR="$CONFIG_BASE/backups"

# 支持的配置工具列表
SUPPORTED_TOOLS=("git" "vim" "nvim" "tmux" "zsh" "cargo")

# 工具函数：检查工具是否已安装
_gs_config_check_tool() {
    local tool="$1"
    command -v "$tool" &> /dev/null
}

# 工具函数：创建备份
_gs_config_backup_file() {
    local source="$1"
    local backup_dir="$2"
    local timestamp="$(date +%Y%m%d_%H%M%S)"
    
    if [[ -e "$source" ]]; then
        mkdir -p "$backup_dir"
        local backup_name="$(basename "$source").backup_$timestamp"
        cp -r "$source" "$backup_dir/$backup_name"
        echo "✅ 已备份: $source -> $backup_dir/$backup_name"
        return 0
    fi
    return 1
}

# 工具函数：安全链接文件
_gs_config_safe_link() {
    local source="$1"
    local target="$2"
    local force="${3:-false}"
    
    # 检查源文件是否存在
    if [[ ! -e "$source" ]]; then
        echo "❌ 源文件不存在: $source" >&2
        return 1
    fi
    
    # 创建目标目录
    local target_dir="$(dirname "$target")"
    mkdir -p "$target_dir"
    
    # 处理现有文件
    if [[ -e "$target" ]]; then
        if [[ "$force" == "true" ]]; then
            _gs_config_backup_file "$target" "$BACKUP_DIR/$(date +%Y%m%d)"
            rm -rf "$target"
        else
            echo "⚠️  目标已存在: $target (使用 --force 强制覆盖)" >&2
            return 1
        fi
    fi
    
    # 创建符号链接
    ln -s "$source" "$target"
    echo "✅ 已链接: $(basename "$source") -> $target"
}

# 主入口函数
gs_config_main() {
    echo "Global Scripts Config Plugin v3.0.0"
    echo "开发环境配置管理工具 - 基于模板化配置的快速部署方案"
    echo ""
    echo "支持的配置工具: ${SUPPORTED_TOOLS[*]}"
    echo ""
    echo "主要功能:"
    echo "  --install <tool>    安装指定工具的配置"
    echo "  --backup <tool>     备份系统配置到工程"
    echo "  --list              列出所有配置状态"
    echo "  --status            显示详细状态信息"
    echo "  --init              初始化配置管理"
    echo ""
    echo "使用方法: gs-config [命令] [选项]"
}

# 初始化配置管理
gs_config_init() {
    echo "🚀 初始化配置管理系统..."
    
    # 创建必要的目录
    mkdir -p "$CONFIG_BASE"/{user,backups}
    
    # 创建用户配置文件
    local user_config="$CONFIG_BASE/user/config.json"
    if [[ ! -f "$user_config" ]]; then
        cat > "$user_config" << 'EOF'
{
  "version": "3.0.0",
  "user": {
    "name": "Your Name",
    "email": "your.email@example.com",
    "github_username": "yourusername"
  },
  "preferences": {
    "git": {
      "default_editor": "vim",
      "default_branch": "main",
      "auto_rebase": true
    },
    "vim": {
      "colorscheme": "default",
      "line_numbers": true,
      "syntax_highlighting": true
    },
    "tmux": {
      "prefix_key": "C-a",
      "mouse_support": true,
      "vi_mode": true
    },
    "zsh": {
      "theme": "robbyrussell",
      "plugins": ["git", "docker", "kubectl"],
      "oh_my_zsh": true
    }
  }
}
EOF
        echo "📝 用户配置模板已创建: $user_config"
        echo "⚠️  请编辑此文件设置您的个人信息"
    fi
    
    # 创建README
    cat > "$CONFIG_BASE/README.md" << 'EOF'
# Global Scripts 配置管理

这个目录包含您的个人配置信息和备份文件。

## 目录结构

- `user/` - 个人配置信息
- `backups/` - 系统配置备份

## 使用方法

1. 编辑 `user/config.json` 设置个人信息
2. 使用 `gs-config --install <tool>` 安装配置
3. 使用 `gs-config --backup <tool>` 备份现有配置

## 安全说明

- 此目录不包含敏感信息（如SSH私钥）
- 备份文件按日期组织，便于恢复
- 所有操作都会先备份现有配置
EOF
    
    echo "✅ 配置管理系统初始化完成"
    echo "📁 配置目录: $CONFIG_BASE"
}

# 安装指定工具的配置
gs_config_install() {
    local tool="$1"
    local force="${2:-false}"
    
    if [[ -z "$tool" ]]; then
        echo "❌ 请指定要安装的配置工具" >&2
        echo "支持的工具: ${SUPPORTED_TOOLS[*]}" >&2
        return 1
    fi
    
    # 检查工具是否支持
    if [[ ! " ${SUPPORTED_TOOLS[*]} " =~ " $tool " ]]; then
        echo "❌ 不支持的工具: $tool" >&2
        echo "支持的工具: ${SUPPORTED_TOOLS[*]}" >&2
        return 1
    fi
    
    # 检查工具是否已安装
    if ! _gs_config_check_tool "$tool"; then
        echo "⚠️  $tool 未安装，配置可能无法正常工作" >&2
    fi
    
    echo "🔧 安装 $tool 配置..."
    
    # 调用工具特定的安装脚本
    local install_script="$SCRIPTS_DIR/install_${tool}.sh"
    if [[ -f "$install_script" ]]; then
        bash "$install_script" "$force"
    else
        # 回退到通用安装逻辑
        _gs_config_install_generic "$tool" "$force"
    fi
}

# 通用安装逻辑
_gs_config_install_generic() {
    local tool="$1"
    local force="$2"
    local template_dir="$TEMPLATES_DIR/$tool"
    
    if [[ ! -d "$template_dir" ]]; then
        echo "❌ 未找到 $tool 的配置模板" >&2
        return 1
    fi
    
    echo "使用通用安装逻辑处理 $tool 配置..."
    
    case "$tool" in
        "git")
            _gs_config_install_git "$force"
            ;;
        "vim")
            _gs_config_install_vim "$force"
            ;;
        "tmux")
            _gs_config_install_tmux "$force"
            ;;
        "zsh")
            _gs_config_install_zsh "$force"
            ;;
        "cargo")
            _gs_config_install_cargo "$force"
            ;;
        *)
            echo "❌ 暂不支持 $tool 的自动安装" >&2
            return 1
            ;;
    esac
}

# Git配置安装
_gs_config_install_git() {
    local force="$1"
    local git_config="$HOME/.gitconfig"
    local template_dir="$TEMPLATES_DIR/git"
    
    echo "安装Git配置..."
    
    # 备份现有配置
    if [[ "$force" == "true" ]] && [[ -f "$git_config" ]]; then
        _gs_config_backup_file "$git_config" "$BACKUP_DIR/$(date +%Y%m%d)"
        rm -f "$git_config"
    elif [[ -f "$git_config" ]]; then
        echo "⚠️  Git配置已存在，使用 --force 强制覆盖" >&2
        return 1
    fi
    
    # 创建主配置文件
    cat > "$git_config" << EOF
# Global Scripts Git Configuration
# 模块化配置管理，基于最佳实践
# 配置文件生成时间: $(date)

[include]
    path = $template_dir/core.git
    path = $template_dir/alias.git
    path = $template_dir/color.git
    path = $template_dir/diff.git
    path = $template_dir/push.git
    path = $template_dir/branch.git

# 用户信息 - 请根据实际情况修改
[user]
    name = Your Name
    email = your.email@example.com

# 工作配置示例 (可选)
# [includeIf "gitdir:~/work/"]
#     path = $template_dir/work.git

# 个人自定义配置
# 您可以在这里添加个人特定的Git配置
EOF
    
    echo "✅ Git配置已安装: $git_config"
    echo "⚠️  请手动编辑用户信息部分"
}

# Vim配置安装
_gs_config_install_vim() {
    local force="$1"
    local vim_config="$HOME/.vimrc"
    local nvim_config="$HOME/.config/nvim/init.vim"
    local template_file="$TEMPLATES_DIR/vim/init.vim"
    
    echo "安装Vim配置..."
    
    # 安装传统Vim配置
    if [[ "$force" == "true" ]] && [[ -f "$vim_config" ]]; then
        _gs_config_backup_file "$vim_config" "$BACKUP_DIR/$(date +%Y%m%d)"
        rm -f "$vim_config"
    elif [[ -f "$vim_config" ]]; then
        echo "⚠️  Vim配置已存在，使用 --force 强制覆盖" >&2
        return 1
    fi
    
    _gs_config_safe_link "$template_file" "$vim_config" "$force"
    
    # 安装Neovim配置
    mkdir -p "$(dirname "$nvim_config")"
    if [[ "$force" == "true" ]] && [[ -f "$nvim_config" ]]; then
        _gs_config_backup_file "$nvim_config" "$BACKUP_DIR/$(date +%Y%m%d)"
        rm -f "$nvim_config"
    elif [[ -f "$nvim_config" ]]; then
        echo "⚠️  Neovim配置已存在，使用 --force 强制覆盖" >&2
    else
        _gs_config_safe_link "$template_file" "$nvim_config" "$force"
    fi
    
    echo "✅ Vim/Neovim配置已安装"
}

# Tmux配置安装
_gs_config_install_tmux() {
    local force="$1"
    local tmux_config="$HOME/.tmux.conf"
    local template_file="$TEMPLATES_DIR/tmux/tmux.conf"
    
    echo "安装Tmux配置..."
    
    if [[ "$force" == "true" ]] && [[ -f "$tmux_config" ]]; then
        _gs_config_backup_file "$tmux_config" "$BACKUP_DIR/$(date +%Y%m%d)"
        rm -f "$tmux_config"
    elif [[ -f "$tmux_config" ]]; then
        echo "⚠️  Tmux配置已存在，使用 --force 强制覆盖" >&2
        return 1
    fi
    
    _gs_config_safe_link "$template_file" "$tmux_config" "$force"
    echo "✅ Tmux配置已安装: $tmux_config"
}

# Zsh配置安装
_gs_config_install_zsh() {
    local force="$1"
    local zsh_config="$HOME/.zshrc"
    local template_file="$TEMPLATES_DIR/zsh/.zshrc"
    
    echo "安装Zsh配置..."
    
    if [[ "$force" == "true" ]] && [[ -f "$zsh_config" ]]; then
        _gs_config_backup_file "$zsh_config" "$BACKUP_DIR/$(date +%Y%m%d)"
        rm -f "$zsh_config"
    elif [[ -f "$zsh_config" ]]; then
        echo "⚠️  Zsh配置已存在，使用 --force 强制覆盖" >&2
        return 1
    fi
    
    _gs_config_safe_link "$template_file" "$zsh_config" "$force"
    echo "✅ Zsh配置已安装: $zsh_config"
}

# Cargo配置安装
_gs_config_install_cargo() {
    local force="$1"
    local cargo_config="$HOME/.cargo/config.toml"
    local template_file="$TEMPLATES_DIR/cargo/config.toml"
    
    echo "安装Cargo配置..."
    
    # 创建.cargo目录
    mkdir -p "$HOME/.cargo"
    
    if [[ "$force" == "true" ]] && [[ -f "$cargo_config" ]]; then
        _gs_config_backup_file "$cargo_config" "$BACKUP_DIR/$(date +%Y%m%d)"
        rm -f "$cargo_config"
    elif [[ -f "$cargo_config" ]]; then
        echo "⚠️  Cargo配置已存在，使用 --force 强制覆盖" >&2
        return 1
    fi
    
    _gs_config_safe_link "$template_file" "$cargo_config" "$force"
    echo "✅ Cargo配置已安装: $cargo_config"
}

# Neovim配置安装
_gs_config_install_nvim() {
    local force="$1"
    local nvim_config_dir="$HOME/.config/nvim"
    local nvim_config="$nvim_config_dir/init.lua"
    local template_file="$TEMPLATES_DIR/nvim/init.lua"
    
    echo "安装Neovim配置..."
    
    # 创建Neovim配置目录
    mkdir -p "$nvim_config_dir"
    
    if [[ "$force" == "true" ]] && [[ -f "$nvim_config" ]]; then
        _gs_config_backup_file "$nvim_config" "$BACKUP_DIR/$(date +%Y%m%d)"
        rm -f "$nvim_config"
    elif [[ -f "$nvim_config" ]]; then
        echo "⚠️  Neovim配置已存在，使用 --force 强制覆盖" >&2
        return 1
    fi
    
    _gs_config_safe_link "$template_file" "$nvim_config" "$force"
    echo "✅ Neovim配置已安装: $nvim_config"
    echo "📝 首次启动时需要安装插件管理器 lazy.nvim"
    echo "🔧 运行: git clone --filter=blob:none --branch=stable https://github.com/folke/lazy.nvim.git ~/.local/share/nvim/lazy/lazy.nvim"
}

# 备份指定工具的配置
gs_config_backup() {
    local tool="$1"
    
    if [[ -z "$tool" ]]; then
        echo "❌ 请指定要备份的配置工具" >&2
        return 1
    fi
    
    local backup_date="$(date +%Y%m%d_%H%M%S)"
    local tool_backup_dir="$BACKUP_DIR/$backup_date/$tool"
    
    echo "📦 备份 $tool 配置到: $tool_backup_dir"
    
    case "$tool" in
        "git")
            [[ -f "$HOME/.gitconfig" ]] && _gs_config_backup_file "$HOME/.gitconfig" "$tool_backup_dir"
            [[ -d "$HOME/.config/git" ]] && _gs_config_backup_file "$HOME/.config/git" "$tool_backup_dir"
            ;;
        "vim")
            [[ -f "$HOME/.vimrc" ]] && _gs_config_backup_file "$HOME/.vimrc" "$tool_backup_dir"
            [[ -d "$HOME/.vim" ]] && _gs_config_backup_file "$HOME/.vim" "$tool_backup_dir"
            [[ -d "$HOME/.config/nvim" ]] && _gs_config_backup_file "$HOME/.config/nvim" "$tool_backup_dir"
            ;;
        "tmux")
            [[ -f "$HOME/.tmux.conf" ]] && _gs_config_backup_file "$HOME/.tmux.conf" "$tool_backup_dir"
            [[ -d "$HOME/.tmux" ]] && _gs_config_backup_file "$HOME/.tmux" "$tool_backup_dir"
            ;;
        "zsh")
            [[ -f "$HOME/.zshrc" ]] && _gs_config_backup_file "$HOME/.zshrc" "$tool_backup_dir"
            [[ -d "$HOME/.oh-my-zsh" ]] && _gs_config_backup_file "$HOME/.oh-my-zsh" "$tool_backup_dir"
            [[ -f "$HOME/.zsh_history" ]] && _gs_config_backup_file "$HOME/.zsh_history" "$tool_backup_dir"
            ;;
        "cargo")
            [[ -d "$HOME/.cargo" ]] && _gs_config_backup_file "$HOME/.cargo" "$tool_backup_dir"
            ;;
        "all")
            for supported_tool in "${SUPPORTED_TOOLS[@]}"; do
                gs_config_backup "$supported_tool"
            done
            return
            ;;
        *)
            echo "❌ 不支持的工具: $tool" >&2
            return 1
            ;;
    esac
    
    echo "✅ $tool 配置备份完成"
}

# 列出配置状态
gs_config_list() {
    echo "📋 配置状态总览"
    echo "=================="
    
    for tool in "${SUPPORTED_TOOLS[@]}"; do
        echo ""
        echo "🔧 $tool:"
        
        # 检查工具是否安装
        if _gs_config_check_tool "$tool"; then
            echo "   ✅ 工具已安装"
        else
            echo "   ❌ 工具未安装"
        fi
        
        # 检查配置文件
        case "$tool" in
            "git")
                [[ -f "$HOME/.gitconfig" ]] && echo "   📄 配置文件: ~/.gitconfig" || echo "   ❌ 无配置文件"
                ;;
            "vim")
                [[ -f "$HOME/.vimrc" ]] && echo "   📄 配置文件: ~/.vimrc"
                [[ -d "$HOME/.config/nvim" ]] && echo "   📄 配置目录: ~/.config/nvim"
                [[ ! -f "$HOME/.vimrc" ]] && [[ ! -d "$HOME/.config/nvim" ]] && echo "   ❌ 无配置文件"
                ;;
            "tmux")
                [[ -f "$HOME/.tmux.conf" ]] && echo "   📄 配置文件: ~/.tmux.conf" || echo "   ❌ 无配置文件"
                ;;
            "zsh")
                [[ -f "$HOME/.zshrc" ]] && echo "   📄 配置文件: ~/.zshrc" || echo "   ❌ 无配置文件"
                [[ -d "$HOME/.oh-my-zsh" ]] && echo "   📦 Oh My Zsh已安装"
                ;;
            "cargo")
                [[ -d "$HOME/.cargo" ]] && echo "   📁 配置目录: ~/.cargo" || echo "   ❌ 无配置目录"
                ;;
        esac
        
        # 检查模板
        if [[ -d "$TEMPLATES_DIR/$tool" ]]; then
            echo "   🎨 模板可用"
        else
            echo "   ⚠️  无模板"
        fi
    done
    
    echo ""
    echo "📁 配置管理目录: $CONFIG_BASE"
    echo "📦 备份目录: $BACKUP_DIR"
}

# 显示详细状态
gs_config_status() {
    echo "🔍 详细状态信息"
    echo "=================="
    echo ""
    
    echo "📂 目录信息:"
    echo "   插件目录: $PLUGIN_DIR"
    echo "   模板目录: $TEMPLATES_DIR"
    echo "   配置目录: $CONFIG_BASE"
    echo "   备份目录: $BACKUP_DIR"
    echo ""
    
    echo "📦 可用模板:"
    if [[ -d "$TEMPLATES_DIR" ]]; then
        for template in "$TEMPLATES_DIR"/*; do
            if [[ -d "$template" ]]; then
                local tool_name="$(basename "$template")"
                local file_count=$(find "$template" -type f | wc -l)
                echo "   $tool_name ($file_count 个文件)"
            fi
        done
    else
        echo "   ❌ 模板目录不存在"
    fi
    echo ""
    
    echo "📋 备份历史:"
    if [[ -d "$BACKUP_DIR" ]]; then
        local backup_count=$(find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d | wc -l)
        echo "   总备份数: $backup_count"
        
        # 显示最近的备份
        local recent_backups=($(ls -1t "$BACKUP_DIR" 2>/dev/null | head -5))
        if [[ ${#recent_backups[@]} -gt 0 ]]; then
            echo "   最近备份:"
            for backup in "${recent_backups[@]}"; do
                echo "     $backup"
            done
        fi
    else
        echo "   📁 暂无备份"
    fi
}

# 命令行参数处理
gs_config_parse_args() {
    local action=""
    local tool=""
    local force=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --install|-i)
                action="install"
                tool="$2"
                shift 2
                ;;
            --backup|-b)
                action="backup"
                tool="$2"
                shift 2
                ;;
            --list|-l)
                action="list"
                shift
                ;;
            --status|-s)
                action="status"
                shift
                ;;
            --init)
                action="init"
                shift
                ;;
            --force|-f)
                force=true
                shift
                ;;
            --help|-h)
                gs_config_help
                return 0
                ;;
            *)
                echo "❌ 未知参数: $1" >&2
                gs_config_help
                return 1
                ;;
        esac
    done
    
    case "$action" in
        "install")
            gs_config_install "$tool" "$force"
            ;;
        "backup")
            gs_config_backup "$tool"
            ;;
        "list")
            gs_config_list
            ;;
        "status")
            gs_config_status
            ;;
        "init")
            gs_config_init
            ;;
        *)
            gs_config_main
            ;;
    esac
}

# 帮助信息
gs_config_help() {
    cat << 'EOF'
Global Scripts Config Plugin - 开发环境配置管理

用法:
    gs-config [命令] [选项]

命令:
    --install, -i <tool>    安装指定工具的配置
    --backup, -b <tool>     备份系统配置到工程
    --list, -l              列出所有配置状态
    --status, -s            显示详细状态信息
    --init                  初始化配置管理

选项:
    --force, -f             强制操作，覆盖现有配置
    --help, -h              显示此帮助信息

支持的工具:
    git     Git版本控制配置
    vim     Vim/Neovim编辑器配置
    tmux    Tmux终端复用器配置
    zsh     Zsh Shell配置
    cargo   Rust Cargo配置

示例:
    gs-config --init                    初始化配置管理
    gs-config --install git             安装Git配置
    gs-config --install git --force     强制安装Git配置
    gs-config --backup all              备份所有工具配置
    gs-config --list                    查看配置状态
    gs-config --status                  查看详细信息

特性:
    ✅ 模板化配置管理
    ✅ 自动备份现有配置
    ✅ 保护私有信息
    ✅ 支持批量操作
    ✅ 跨平台兼容
EOF
}

# 主程序入口
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    gs_config_parse_args "$@"
fi