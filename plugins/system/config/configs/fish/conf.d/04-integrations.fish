# ============================================
# Tool Integrations
# conf.d/04-integrations.fish
# ============================================

# ============================================
# Conda Integration
# ============================================
if not command -v conda >/dev/null 2>&1
    # Try to find and initialize conda
    set -l conda_bases \
        $HOME/miniconda3 \
        $HOME/anaconda3 \
        $HOME/miniforge3 \
        /opt/miniconda3 \
        /opt/anaconda3 \
        /opt/miniforge3 \
        /usr/local/miniconda3 \
        /usr/local/anaconda3

    for conda_base in $conda_bases
        if test -f "$conda_base/etc/profile.d/conda.sh"
            # For fish, we need bass to source bash scripts
            if functions -q bass
                bass source "$conda_base/etc/profile.d/conda.sh"
            end
            break
        end
    end
end

# ============================================
# Pyenv Integration
# ============================================
if command -v pyenv >/dev/null
    set -gx PYENV_ROOT $HOME/.pyenv
    fish_add_path $PYENV_ROOT/bin
    pyenv init - | source
end

# ============================================
# NVM Integration (Node Version Manager)
# ============================================
if test -d ~/.nvm
    set -gx NVM_DIR $HOME/.nvm
    # Fish has its own nvm plugin, use that instead of sourcing bash script
    # Install with: fisher install jorgebucaran/nvm.fish
end

# ============================================
# Rust/Cargo Integration
# ============================================
if test -d ~/.cargo/bin
    fish_add_path ~/.cargo/bin
end

# ============================================
# Go Integration
# ============================================
if command -v go >/dev/null
    set -gx GOPATH $HOME/go
    fish_add_path $GOPATH/bin
end

# ============================================
# Homebrew Integration (macOS/Linux)
# ============================================
if test (uname) = Darwin
    # Apple Silicon
    if test -d /opt/homebrew
        eval (/opt/homebrew/bin/brew shellenv)
    # Intel Mac
    else if test -d /usr/local/Homebrew
        eval (/usr/local/bin/brew shellenv)
    end
else if test (uname) = Linux
    # Linux Homebrew
    if test -d /home/linuxbrew/.linuxbrew
        eval (/home/linuxbrew/.linuxbrew/bin/brew shellenv)
    end
end

# ============================================
# Direnv Integration
# ============================================
if command -v direnv >/dev/null
    direnv hook fish | source
end

# ============================================
# Zoxide Integration (Better cd)
# ============================================
if command -v zoxide >/dev/null
    zoxide init fish | source
    abbr -a -g cd 'z'
end

# ============================================
# Bat Integration (Better cat)
# ============================================
if command -v bat >/dev/null
    set -gx BAT_THEME "Monokai Extended"
    abbr -a -g cat 'bat'
end

# ============================================
# Exa Integration (Better ls)
# ============================================
if command -v exa >/dev/null
    abbr -a -g ls 'exa --icons'
    abbr -a -g ll 'exa -lah --icons --git'
    abbr -a -g la 'exa -a --icons'
    abbr -a -g lt 'exa -T --icons'
    abbr -a -g tree 'exa -T --icons'
end

# ============================================
# Ripgrep Integration (Better grep)
# ============================================
if command -v rg >/dev/null
    set -gx RIPGREP_CONFIG_PATH $HOME/.ripgreprc
    abbr -a -g grep 'rg'
end

# ============================================
# Delta Integration (Better git diff)
# ============================================
if command -v delta >/dev/null
    set -gx GIT_PAGER 'delta'
end

# ============================================
# Tmux Integration
# ============================================
if command -v tmux >/dev/null
    # Auto-start tmux in interactive shells
    if status is-interactive
        and not set -q TMUX
        # Uncomment to auto-start tmux
        # tmux attach -t default; or tmux new -s default
    end
end

# ============================================
# Starship Integration (Alternative to Tide)
# ============================================
if command -v starship >/dev/null
    # Uncomment to use starship instead of tide
    # starship init fish | source
end

# ============================================
# AWS CLI Integration
# ============================================
if command -v aws >/dev/null
    # AWS CLI completion
    complete -c aws -f -a "(aws_completer)"
end

# ============================================
# Kubectl Integration
# ============================================
if command -v kubectl >/dev/null
    # kubectl completion
    kubectl completion fish | source

    # Abbreviations
    abbr -a -g k 'kubectl'
    abbr -a -g kg 'kubectl get'
    abbr -a -g kd 'kubectl describe'
    abbr -a -g kdel 'kubectl delete'
    abbr -a -g kl 'kubectl logs'
    abbr -a -g ke 'kubectl exec -it'
end

# ============================================
# Terraform Integration
# ============================================
if command -v terraform >/dev/null
    abbr -a -g tf 'terraform'
    abbr -a -g tfi 'terraform init'
    abbr -a -g tfp 'terraform plan'
    abbr -a -g tfa 'terraform apply'
    abbr -a -g tfd 'terraform destroy'
end

# ============================================
# Git LFS Integration
# ============================================
if command -v git-lfs >/dev/null
    git lfs install
end

# ============================================
# SSH Agent
# ============================================
if test -z "$SSH_AUTH_SOCK"
    eval (ssh-agent -c) >/dev/null
    set -gx SSH_AUTH_SOCK $SSH_AUTH_SOCK
    set -gx SSH_AGENT_PID $SSH_AGENT_PID
end

# ============================================
# GPG Agent
# ============================================
if command -v gpg-agent >/dev/null
    set -gx GPG_TTY (tty)
    gpg-connect-agent updatestartuptty /bye >/dev/null 2>&1
end

# ============================================
# Atuin Integration (Shell History Sync)
# ============================================
if command -v atuin >/dev/null
    atuin init fish | source
end

# ============================================
# JQ Integration (JSON processor)
# ============================================
if command -v jq >/dev/null
    # Add custom jq functions or filters here
end

# ============================================
# TheFuck Integration (Correct previous command)
# ============================================
if command -v thefuck >/dev/null
    thefuck --alias | source
end
