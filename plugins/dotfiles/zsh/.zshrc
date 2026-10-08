# Global Scripts ZSH Configuration
export ZSH_DISABLE_COMPFIX=true
# oh-my-zsh 是可选的:没装就不加载(否则每次开终端都报错)
export ZSH="$HOME/.oh-my-zsh"

# Plugin configuration
plugins=(
    git
    zsh-autosuggestions
    zsh-syntax-highlighting
    tmux
    docker
    kubectl
)

# Load Oh My Zsh(存在才加载)
[ -f "$ZSH/oh-my-zsh.sh" ] && source "$ZSH/oh-my-zsh.sh"

# Custom aliases
alias ll='ls -la'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'

# Git aliases(`gst` 而不是 `gs` —— `gs` 是 Global Scripts 的命令名)
alias gst='git status'
alias ga='git add'
alias gc='git commit'
alias gp='git push'
alias gl='git log --oneline'

# Development aliases
alias py='python3'
alias pip='pip3'

# Custom functions
function mkcd() {
    mkdir -p "$1" && cd "$1"
}

function extract() {
    if [ -f $1 ] ; then
        case $1 in
            *.tar.bz2)   tar xjf $1     ;;
            *.tar.gz)    tar xzf $1     ;;
            *.bz2)       bunzip2 $1     ;;
            *.rar)       unrar e $1     ;;
            *.gz)        gunzip $1      ;;
            *.tar)       tar xf $1      ;;
            *.tbz2)      tar xjf $1     ;;
            *.tgz)       tar xzf $1     ;;
            *.zip)       unzip $1       ;;
            *.Z)         uncompress $1  ;;
            *.7z)        7z x $1        ;;
            *)     echo "'$1' cannot be extracted via extract()" ;;
        esac
    else
        echo "'$1' is not a valid file"
    fi
}

# Global Scripts 集成 —— 补全、cd 集成、界面语言。
# 由 install_gs.sh 生成该文件,重装本配置也不会把它冲掉。
[ -f "$HOME/.config/global-scripts/shell/gs-env.zsh" ] && source "$HOME/.config/global-scripts/shell/gs-env.zsh"
