# ============================================
# Utility Functions
# conf.d/00-functions.fish
# ============================================

# IP Address Detection (Cross-platform)
function get_ip -d 'Get local IP address (cross-platform)'
    set -l ip

    # Try macOS ifconfig first
    if command -v ifconfig >/dev/null
        set ip (ifconfig | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | head -n 1)
    end

    # Try Linux hostname -I
    if test -z "$ip"
        and command -v hostname >/dev/null
        set ip (hostname -I 2>/dev/null | awk '{print $1}')
    end

    # Try Linux ip command
    if test -z "$ip"
        and command -v ip >/dev/null
        set ip (ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' | head -n 1)
    end

    # Fallback to hostname
    if test -z "$ip"
        set ip (hostname)
    end

    echo $ip
end

# Enhanced mkdir with cd
function mkcd -d 'Create directory and change to it'
    mkdir -p $argv
    and cd $argv
end

# Quick extract for archives
function extract -d 'Extract various archive formats'
    set file $argv[1]
    if test -f $file
        switch $file
            case '*.tar.bz2'
                tar xjf $file
            case '*.tar.gz'
                tar xzf $file
            case '*.bz2'
                bunzip2 $file
            case '*.rar'
                unrar x $file
            case '*.gz'
                gunzip $file
            case '*.tar'
                tar xf $file
            case '*.tbz2'
                tar xjf $file
            case '*.tgz'
                tar xzf $file
            case '*.zip'
                unzip $file
            case '*.Z'
                uncompress $file
            case '*.7z'
                7z x $file
            case '*'
                echo "Unknown file type: $file"
        end
    else
        echo "File doesn't exist: $file"
    end
end

# Enhanced ls with colors and icons
function ll -d 'Enhanced ls with details'
    # macOS uses -G for color, GNU uses --color=auto
    if test (uname) = Darwin
        ls -lahG $argv
    else
        ls -lah --color=auto $argv
    end
end

# Quick find with fzf
function ff -d 'Find files with fzf'
    fzf --preview 'bat --style=numbers --color=always {}' $argv
end

# Process search and kill
function pkillf -d 'Search and kill processes'
    set process (ps aux | fzf | awk '{print $2}')
    if test -n "$process"
        kill -9 $process
        echo "Killed process: $process"
    end
end

# Git enhanced status (renamed to avoid conflict with Global Scripts 'gs' command)
function gst -d 'Enhanced git status with shortcuts'
    git status --short --branch $argv
end

# Quick backup
function backup -d 'Quick backup of file or directory'
    set source $argv[1]
    if test -e $source
        cp -r $source $source.backup.(date +%Y%m%d_%H%M%S)
        echo "Backed up: $source"
    else
        echo "File/directory doesn't exist: $source"
    end
end

# Reload fish configuration
function reload -d 'Reload fish configuration'
    source $__fish_config_dir/config.fish
    echo "Fish configuration reloaded!"
end

# System information
function sysinfo -d 'Display system information'
    echo "System Information:"
    echo "OS: "(uname -s)" "(uname -r)
    echo "Kernel: "(uname -v)
    echo "Architecture: "(uname -m)
    echo "Shell: $SHELL"
    echo "Fish: $FISH_VERSION"
    echo "IP: "(get_ip)
    echo "Uptime: "(uptime)
end