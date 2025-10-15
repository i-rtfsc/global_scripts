# Modern Fish Shell Configuration
# Global Scripts - Fish Configuration

# ============================================
# Environment Variables
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
# Install manually: curl -sL https://raw.githubusercontent.com/jorgebucaran/fisher/main/functions/fisher.fish | source && fisher install jorgebucaran/fisher


# ============================================
# Recommended Plugins (install with: fisher install <plugin>)
# ============================================
# fisher install jorgebucaran/fisher           # Plugin manager
# fisher install IlanCosman/tide@v6           # Modern prompt
# fisher install jethrokuan/z                 # Directory jumping
# fisher install PatrickF1/fzf.fish          # Fuzzy finder integration
# fisher install franciscolourenco/done      # Notification when long commands finish
# fisher install laughedelic/pisces         # Auto-close brackets
# fisher install gazorby/fish-abbreviation-tips  # Show abbreviation tips
# fisher install edc/bass

# ============================================
# Tide Prompt Configuration
# ============================================
# Run 'tide configure' to customize your prompt
set -g tide_prompt_add_newline_before true
set -g tide_prompt_color_frame_and_connection 6C6C6C
set -g tide_prompt_color_separator_same_color 949494
set -g tide_prompt_icon_connection ' '
set -g tide_prompt_min_cols 34
set -g tide_prompt_pad_items true

set -g tide_context_always_display true
# 自定义 context 显示 IP 地址
function _tide_item_context
    set -l ip (ifconfig | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | head -n 1)
    if test -z "$ip"
        set ip (hostname -I 2>/dev/null | awk '{print $1}')
    end
    if test -z "$ip"
        set ip (hostname)
    end
    _tide_print_item context (set_color $tide_context_color_default)" $USER"@"$ip"
end

# ============================================
# FZF Configuration
# ============================================
set -gx FZF_DEFAULT_OPTS '--height 40% --layout=reverse --border --inline-info'
set -gx FZF_DEFAULT_COMMAND 'fd --type f --hidden --follow --exclude .git'
set -gx FZF_CTRL_T_COMMAND "$FZF_DEFAULT_COMMAND"

# ============================================
# Colors and Syntax
# ============================================
# Fish syntax highlighting colors
set -g fish_color_normal normal
set -g fish_color_command green
set -g fish_color_quote yellow
set -g fish_color_redirection cyan
set -g fish_color_end magenta
set -g fish_color_error red --bold
set -g fish_color_param cyan
set -g fish_color_comment brblack
set -g fish_color_match --background=brblue
set -g fish_color_selection white --bold --background=brblack
set -g fish_color_search_match bryellow --background=brblack
set -g fish_color_operator cyan
set -g fish_color_escape brcyan
set -g fish_color_autosuggestion brblack

# ============================================
# Greeting
# ============================================
function fish_greeting
    # Disable default greeting or customize
    # echo "Welcome to Fish Shell! 🐟"
end

# ============================================
# Completions
# ============================================
# Enable better tab completion
set -g fish_complete_path $fish_complete_path

# ============================================
# Hooks and Events
# ============================================

# Run when changing directory
function __fish_pwd_changed --on-variable PWD
    # Custom actions when directory changes
    # Example: Auto-activate Python venv
    # if test -f .venv/bin/activate.fish
    #     source .venv/bin/activate.fish
    # end
end

# ============================================
# Local Customizations
# ============================================
# Source local config if it exists (for machine-specific settings)
if test -f ~/.config/fish/local.fish
    source ~/.config/fish/local.fish
end

# ============================================
# Startup Message
# ============================================
# Uncomment to show system info on startup
# if status is-interactive
#     echo "Fish $FISH_VERSION | "(uname -s)" "(uname -m)
# end
