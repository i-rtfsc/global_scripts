export ZSH_DISABLE_COMPFIX=true

export ZSH=$HOME/.oh-my-zsh

# uos
# sudo ln -s /opt/apps/com.sublimetext.sublime-text-4/files/sublime_text /usr/local/bin/subl
# macos
# sudo ln -s /Applications/Sublime\ Text.app/Contents/SharedSupport/bin/subl /usr/local/bin
#
# git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions
# git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting
plugins=(git
         adb
         tmux
         sublime
         zsh-autosuggestions
         zsh-syntax-highlighting
        )

source $ZSH/oh-my-zsh.sh

# global scripts env
source $HOME/code/github/global_scripts/gs_env.sh
