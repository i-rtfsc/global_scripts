#!/bin/bash
# Global Scripts V3 - 主题管理系统命令
# 版本: 1.0.0
# 描述: 提供终端提示符主题的查看、切换和预览功能

# ============================================================================
# 主题管理 - 系统命令
# ============================================================================

# 主题管理函数
gs_system_theme() {
    # 功能描述: 主题管理系统命令
    # 参数: $1 - 子命令 (字符串) [可选]
    # 参数: $2 - 主题名称 (字符串) [可选]
    # 返回值: 0 - 成功, 1 - 失败
    # 示例: gs-theme list, gs-theme set ocean, gs-theme preview minimalist

    local subcommand="${1:-list}"
    local theme_name="${2:-}"

    case "$subcommand" in
        "list"|"ls")
            _gs_theme_list
            ;;
        "set"|"use"|"switch")
            if [[ -z "$theme_name" ]]; then
                _gs_error "theme" "请指定要设置的主题名"
                _gs_info "theme" "用法: gs-theme set <主题名>"
                return 1
            fi
            _gs_theme_set "$theme_name"
            ;;
        "preview"|"show")
            if [[ -z "$theme_name" ]]; then
                _gs_error "theme" "请指定要预览的主题名"
                _gs_info "theme" "用法: gs-theme preview <主题名>"
                return 1
            fi
            _gs_theme_preview "$theme_name"
            ;;
        "current")
            _gs_theme_current
            ;;
        "help"|"-h"|"--help")
            _gs_theme_help
            ;;
        "version"|"-v"|"--version")
            echo "gs-theme v1.0.0"
            ;;
        *)
            _gs_error "theme" "未知子命令: $subcommand"
            _gs_info "theme" "使用 'gs-theme help' 查看帮助信息"
            return 1
            ;;
    esac
}

# ============================================================================
# 主题管理功能函数
# ============================================================================

# 获取当前主题
_gs_theme_get_current() {
    local config_file="$GS_ROOT/config/.gsconf"
    if [[ -f "$config_file" ]]; then
        grep "^gs_themes_prompt=" "$config_file" | cut -d'=' -f2 | tr -d '"'"'" | head -1
    else
        echo "tech-dev"
    fi
}

# 列出所有可用主题
_gs_theme_list() {
    echo "🎨 可用的提示符主题:"
    echo ""
    
    local current_theme=$(_gs_theme_get_current)
    local themes_dir="$GS_ROOT/themes/prompt"
    
    if [[ ! -d "$themes_dir" ]]; then
        _gs_error "theme" "主题目录不存在: $themes_dir"
        return 1
    fi
    
    for theme_file in "$themes_dir"/*.sh; do
        if [[ -f "$theme_file" ]]; then
            local theme_name=$(basename "$theme_file" .sh)
            local marker=""
            
            if [[ "$theme_name" == "$current_theme" ]]; then
                marker=" ← 当前使用"
            fi
            
            case "$theme_name" in
                "tech-dev")
                    echo "  🔧 tech-dev      - 技术开发者主题：双行显示，Git状态，环境信息$marker"
                    ;;
                "minimalist")
                    echo "  ⚫ minimalist    - 极简主义主题：简洁明了，专注核心信息$marker"
                    ;;
                "powerline")
                    echo "  ⚡ powerline     - 强力线条主题：分段显示，类似Powerline风格$marker"
                    ;;
                "ocean")
                    echo "  🌊 ocean         - 海洋主题：蓝绿色调，清新平静$marker"
                    ;;
                "retro")
                    echo "  📟 retro         - 复古主题：80年代终端风格，绿色边框$marker"
                    ;;
                *)
                    echo "  📝 $theme_name$marker"
                    ;;
            esac
        fi
    done
    
    echo ""
    echo "使用 'gs-theme set <主题名>' 切换主题"
    echo "使用 'gs-theme preview <主题名>' 预览主题效果"
}

# 预览主题
_gs_theme_preview() {
    local theme_name="$1"
    local theme_file="$GS_ROOT/themes/prompt/${theme_name}.sh"
    
    if [[ ! -f "$theme_file" ]]; then
        _gs_error "theme" "主题 '$theme_name' 不存在"
        _gs_info "theme" "使用 'gs-theme list' 查看可用主题"
        return 1
    fi
    
    echo "🎨 预览主题: $theme_name"
    echo ""
    
    case "$theme_name" in
        "tech-dev")
            echo "效果预览:"
            echo "╭─[用户名@192.168.1.100:~/项目路径]➬[2024-08-03 15:30:22]"
            echo "╰─(zsh-conda_env) ⬡ ⬡ ⬡                                              git:main*"
            ;;
        "minimalist")
            echo "效果预览:"
            echo "用户名@100 ~/项目路径 env:conda_env git:main*"
            echo "> "
            ;;
        "powerline")
            echo "效果预览:"
            echo " 用户名@主机 > dir:~/项目路径 > git:main* > env:conda_env >"
            echo "> "
            ;;
        "ocean")
            echo "效果预览:"
            echo "~ 用户名@192.168.1.100 [~/项目路径] py:conda_env git:main*"
            echo "$ "
            ;;
        "retro")
            echo "效果预览:"
            echo "+- cpu:用户名 host:192.168.1.100 -+- dir:~/项目路径 py:conda_env [git:main*]"
            echo "+-> "
            ;;
        *)
            echo "自定义主题预览不可用，请直接切换体验"
            ;;
    esac
    
    echo ""
    echo "使用 'gs-theme set $theme_name' 应用此主题"
}

# 立即应用主题
_gs_theme_apply_now() {
    local theme_name="$1"
    local theme_file="$GS_ROOT/themes/prompt/${theme_name}.sh"
    
    # 检查主题文件
    if [[ ! -f "$theme_file" ]]; then
        return 1
    fi
    
    # 保存当前状态
    local old_prompt="$PROMPT"
    local old_ps1="$PS1"
    local old_rprompt="$RPROMPT"
    
    # 尝试加载新主题
    if source "$theme_file" 2>/dev/null; then
        # 主题加载成功
        echo "📝 新主题 '$theme_name' 加载成功"
        return 0
    else
        # 主题加载失败，恢复原状态
        if [[ -n "$ZSH_VERSION" ]]; then
            PROMPT="$old_prompt"
            RPROMPT="$old_rprompt"
        else
            PS1="$old_ps1"
        fi
        echo "❌ 主题 '$theme_name' 加载失败"
        return 1
    fi
}

# 设置主题
_gs_theme_set() {
    local theme_name="$1"
    local theme_file="$GS_ROOT/themes/prompt/${theme_name}.sh"
    local config_file="$GS_ROOT/config/.gsconf"
    
    if [[ ! -f "$theme_file" ]]; then
        _gs_error "theme" "主题 '$theme_name' 不存在"
        _gs_info "theme" "使用 'gs-theme list' 查看可用主题"
        return 1
    fi
    
    # # 备份配置文件
    # if [[ -f "$config_file" ]]; then
    #     cp "$config_file" "${config_file}.backup.$(date +%Y%m%d_%H%M%S)"
    # fi
    
    # 更新配置文件
    if grep -q "^gs_themes_prompt=" "$config_file" 2>/dev/null; then
        # 替换现有配置
        if [[ "$(uname)" == "Darwin" ]]; then
            sed -i '' "s/^gs_themes_prompt=.*/gs_themes_prompt=$theme_name/" "$config_file"
        else
            sed -i "s/^gs_themes_prompt=.*/gs_themes_prompt=$theme_name/" "$config_file"
        fi
    else
        # 添加新配置
        echo "gs_themes_prompt=$theme_name" >> "$config_file"
    fi
    
    echo "✅ 主题已设置为: $theme_name"
    
    # 立即应用主题
    if _gs_theme_apply_now "$theme_name"; then
        echo "🎨 主题已立即生效"
    else
        echo ""
        echo "⚠️  主题配置已保存，但无法立即应用"
        echo "🔄 请重新加载环境以应用主题:"
        echo "   source ~/.zshrc     # zsh用户"
        echo "   source ~/.bashrc    # bash用户"
        echo ""
        echo "或者重新启动终端"
    fi
}

# 显示当前主题
_gs_theme_current() {
    local current_theme=$(_gs_theme_get_current)
    echo "当前主题: $current_theme"
    
    # 显示当前主题的详细信息
    case "$current_theme" in
        "tech-dev")
            echo "描述: 技术开发者主题 - 双行显示，Git状态，环境信息"
            ;;
        "minimalist")
            echo "描述: 极简主义主题 - 简洁明了，专注核心信息"
            ;;
        "powerline")
            echo "描述: 强力线条主题 - 分段显示，类似Powerline风格"
            ;;
        "ocean")
            echo "描述: 海洋主题 - 蓝绿色调，清新平静"
            ;;
        "retro")
            echo "描述: 复古主题 - 80年代终端风格，绿色边框"
            ;;
        *)
            echo "描述: 自定义主题"
            ;;
    esac
}

# ============================================================================
# 帮助信息
# ============================================================================

_gs_theme_help() {
    cat << 'HELP'
gs-theme - 主题管理系统命令

功能描述:
  提供终端提示符主题的查看、切换和预览功能

用法:
  gs-theme [子命令] [参数]

子命令:
  list              列出所有可用主题 (默认)
  set <主题名>       设置指定主题
  preview <主题名>   预览指定主题效果
  current           显示当前使用的主题

其他选项:
  help, -h, --help  显示此帮助信息
  version, -v       显示命令版本

可用主题:
  tech-dev     - 技术开发者主题（默认）
  minimalist   - 极简主义主题
  powerline    - 强力线条主题
  ocean        - 海洋主题
  retro        - 复古主题

示例:
  gs-theme list              # 列出所有主题
  gs-theme preview ocean     # 预览海洋主题
  gs-theme set minimalist   # 切换到极简主题
  gs-theme current           # 显示当前主题

注意:
  切换主题后需要重新加载Shell配置或重启终端才能生效
HELP
}

# ============================================================================
# 命令自检
# ============================================================================

_gs_system_theme_selfcheck() {
    # 检查必需的环境变量
    if [[ -z "${GS_ROOT:-}" ]]; then
        _gs_error "theme" "GS_ROOT环境变量未设置"
        return 1
    fi
    
    # 检查主题目录
    if [[ ! -d "$GS_ROOT/themes/prompt" ]]; then
        _gs_error "theme" "主题目录不存在: $GS_ROOT/themes/prompt"
        return 1
    fi
    
    # 检查配置文件目录
    if [[ ! -d "$GS_ROOT/config" ]]; then
        _gs_error "theme" "配置目录不存在: $GS_ROOT/config"
        return 1
    fi
    
    return 0
}

# 执行自检
if ! _gs_system_theme_selfcheck; then
    _gs_error "theme" "主题系统命令自检失败"
    return 1
fi

_gs_debug "theme" "gs-theme系统命令加载完成"