# ============================================
# Modern Fish Shell Configuration
# Global Scripts - Fish Configuration
# ============================================
#
# 此配置文件使用模块化结构，所有具体配置在 conf.d/ 目录中
# Configuration structure:
#   - conf.d/00-functions.fish    : 实用函数
#   - conf.d/01-prompt.fish       : Tide 提示符配置
#   - conf.d/02-fzf.fish          : FZF 模糊查找配置
#   - conf.d/03-abbreviations.fish: 命令缩写
#   - conf.d/04-integrations.fish : 工具集成
#   - conf.d/05-greeting.fish     : 欢迎消息
#
# Fish 会自动加载 conf.d/*.fish 文件，无需手动 source
#
# ============================================

# ============================================
# Environment Variables - 基础环境变量
# ============================================
set -gx EDITOR nvim
set -gx VISUAL nvim
set -gx PAGER less

# Set locale
set -gx LANG en_US.UTF-8
set -gx LC_ALL en_US.UTF-8

# ============================================
# Fisher Plugin Manager
# ============================================
# Fisher is a plugin manager for Fish
# Install: curl -sL https://raw.githubusercontent.com/jorgebucaran/fisher/main/functions/fisher.fish | source && fisher install jorgebucaran/fisher
#
# Recommended plugins:
#   fisher install IlanCosman/tide@v6           # Modern prompt
#   fisher install jethrokuan/z                 # Directory jumping
#   fisher install PatrickF1/fzf.fish          # Fuzzy finder integration
#   fisher install franciscolourenco/done      # Notification when long commands finish
#   fisher install laughedelic/pisces         # Auto-close brackets
#   fisher install gazorby/fish-abbreviation-tips  # Show abbreviation tips
#   fisher install edc/bass                    # Source bash scripts

# ============================================
# Local Customizations
# ============================================
# Source local config if it exists (for machine-specific settings)
if test -f ~/.config/fish/local.fish
    source ~/.config/fish/local.fish
end

# ============================================
# 注意事项
# ============================================
# 1. 所有具体配置都在 conf.d/ 目录中，不要在这里添加
# 2. conf.d/ 文件按数字顺序加载（00, 01, 02...）
# 3. 如果需要添加机器特定配置，使用 ~/.config/fish/local.fish
# 4. Global Scripts 的环境变量会在安装时自动添加到末尾
# 5. 使用 'tide configure' 配置提示符样式
# 6. 使用 'reload' 命令重新加载配置
