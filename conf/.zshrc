export ZSH_DISABLE_COMPFIX=true

export ZSH=$HOME/.oh-my-zsh

plugins=(git adb tmux)

source $ZSH/oh-my-zsh.sh

# global scripts env
source $HOME/code/github/global_scripts/gs_env.sh
