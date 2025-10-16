# ============================================
# Greeting Message
# conf.d/05-greeting.fish
# ============================================

# Custom fish greeting
function fish_greeting
    # Disable default greeting and create custom one
    if status is-interactive
        # Clear screen for clean start (optional)
        # clear

        # Display fancy greeting
        set_color cyan
        echo "┌────────────────────────────────────────────────┐"
        set_color brgreen
        echo "│          Welcome to Fish Shell! 🐟             │"
        set_color cyan
        echo "└────────────────────────────────────────────────┘"
        set_color normal

        echo ""

        # System information
        set -l os_name (uname -s)
        set -l os_arch (uname -m)
        set -l ip_addr (get_ip)
        set -l fish_ver $FISH_VERSION
        set -l current_time (date '+%Y-%m-%d %H:%M:%S')

        # Display system info
        set_color yellow
        echo "  System Info:"
        set_color normal
        echo "    OS:       $os_name $os_arch"
        echo "    Shell:    Fish $fish_ver"
        echo "    User:     $USER"
        echo "    IP:       $ip_addr"
        echo "    Time:     $current_time"

        echo ""

        # Quick tips (randomize)
        set -l tips \
            "💡 Tip: Use 'Ctrl+R' to search command history" \
            "💡 Tip: Use 'Alt+E' to edit command in editor" \
            "💡 Tip: Use 'Alt+.' to insert last argument" \
            "💡 Tip: Use 'Ctrl+X' then 'Ctrl+E' for multiline edit" \
            "💡 Tip: Type 'help' for Fish documentation" \
            "💡 Tip: Use 'ff' for fuzzy file search" \
            "💡 Tip: Use 'fcd' to fuzzy find and cd" \
            "💡 Tip: Use 'reload' to reload Fish config" \
            "💡 Tip: Use 'sysinfo' for detailed system info" \
            "💡 Tip: Use 'extract <file>' to extract archives"

        # Select random tip
        set -l random_tip $tips[(random 1 (count $tips))]
        set_color brblack
        echo "  $random_tip"
        set_color normal

        echo ""

        # Git repository check (if in git repo)
        if git rev-parse --git-dir >/dev/null 2>&1
            set -l git_branch (git symbolic-ref HEAD 2>/dev/null | sed -e 's|^refs/heads/||')
            set -l git_status (git status --short 2>/dev/null | wc -l | string trim)

            if test $git_status -gt 0
                set_color yellow
                echo "  📝 Git: On branch '$git_branch' with $git_status changes"
                set_color normal
            else
                set_color green
                echo "  ✓ Git: On branch '$git_branch' (clean)"
                set_color normal
            end
            echo ""
        end

        # Environment warnings
        set -l warnings 0

        # Check for missing recommended tools
        set -l required_tools git curl
        set -l optional_tools fzf bat exa fd ripgrep

        for tool in $required_tools
            if not command -v $tool >/dev/null
                if test $warnings -eq 0
                    set_color red
                    echo "  ⚠️  Warnings:"
                    set_color normal
                    set warnings 1
                end
                echo "    Missing required tool: $tool"
            end
        end

        # Suggest optional tools
        set -l missing_optional
        for tool in $optional_tools
            if not command -v $tool >/dev/null
                set -a missing_optional $tool
            end
        end

        if test (count $missing_optional) -gt 0
            set_color yellow
            if test $warnings -eq 0
                echo "  💡 Suggestions:"
            end
            echo "    Optional tools: "(string join ', ' $missing_optional)
            set_color normal
            echo ""
        end

        # Separator
        set_color brblack
        echo "────────────────────────────────────────────────"
        set_color normal
        echo ""
    end
end

# Optional: Minimal greeting
# Uncomment this and comment the above function for a minimal greeting
# function fish_greeting
#     set_color cyan
#     echo "🐟 Fish Shell $FISH_VERSION"
#     set_color brblack
#     echo "Type 'help' for assistance"
#     set_color normal
# end

# Optional: Disable greeting entirely
# Uncomment this to disable greeting completely
# function fish_greeting
# end
