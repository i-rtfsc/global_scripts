# ============================================
# Global Scripts - Fish Shell Configuration
# 配置结构:
#   - gs-config/ 目录包含所有模块化配置（按序号加载）
#   - 不要直接修改此文件，使用 local.fish 添加个人配置
# ============================================

# ============================================
# 推荐插件（使用 Fisher 插件管理器）
# ============================================
# 安装 Fisher: curl -sL https://git.io/fisher | source && fisher install jorgebucaran/fisher
#
# 推荐插件列表:
#   fisher install IlanCosman/tide@v6              # 现代化提示符
#   fisher install jethrokuan/z                    # 目录跳转
#   fisher install PatrickF1/fzf.fish             # FZF 集成
#   fisher install franciscolourenco/done         # 长命令完成通知
#   fisher install laughedelic/pisces            # 自动补全括号
#   fisher install gazorby/fish-abbreviation-tips # 缩写提示
#   fisher install edc/bass                       # 支持 bash 脚本

# ============================================
# 环境变量
# ============================================
set -gx EDITOR nvim
set -gx VISUAL nvim
set -gx PAGER less
set -gx LANG en_US.UTF-8
set -gx LC_ALL en_US.UTF-8

# ============================================
# 加载 Global Scripts 配置模块
# ============================================
# 按数字顺序加载 gs-config/ 目录中的所有配置文件
set -l gs_config_dir "$__fish_config_dir/gs-config"

if test -d $gs_config_dir
    # 使用 find 命令查找配置文件（避免 glob 展开问题）
    set -l config_files (find $gs_config_dir -maxdepth 1 -name '[0-9][0-9]-gs-*.fish' -type f 2>/dev/null | sort)

    for file in $config_files
        test -f $file; and source $file
    end
end

# ============================================
# 本地自定义配置
# ============================================
# 如需添加个人配置，请创建 ~/.config/fish/local.fish
test -f ~/.config/fish/local.fish; and source ~/.config/fish/local.fish

# Homebrew 环境变量
eval (/opt/homebrew/bin/brew shellenv)
