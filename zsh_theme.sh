machine="$(uname -s)"
case "${machine}" in
    Linux*)     isMac=false;;
    Darwin*)    isMac=true;;
    *)          isMac=false;;
esac

function _gs_get_machine_info() {
    local name="%n"
    if [[ "$USER" == 'root' ]]; then
        name="%{$highlight_bg%}%{$white_bold%}$name%{$reset_color%}"
    fi
    if $isMac ; then
        local ip=$(ipconfig getifaddr en0)
    else
        local ip=$(ip a | grep " `route | grep default | awk 'NR==1{print $NF}'`:" -A2 | tail -n1 | awk '{print $2}' | cut -f1 -d '/')
    fi
    local machine_info=%{$fg[white]%}[%{$fg[magenta]%}$name%{$fg[yellow]%}@%{$fg[red]%}$ip%{$fg[white]%}]
    echo $machine_info
}

function _gs_get_current_dir() {
    local dir=%{$fg[blue]%}[%{$fg[white]%}${PWD/#$HOME/~}%{$fg[blue]%}]
    echo $dir
}

function _gs_get_time() {
    local time=%{$fg[blue]%}[%{$fg[yellow]%}$(date "+%Y-%m-%d %H:%M:%S")%{$fg[blue]%}]
    echo $time
}

PROMPT=$'%{$fg[blue]%}┌─$(_gs_get_machine_info) %{$fg[white]%}-> $(_gs_get_current_dir) %{$fg[white]%}-> $(_gs_get_time)
%{$fg[blue]%}└─%B[%{\e[1;35m%}$%{\e[0;34m%}%B] <$(git_prompt_info)> %{$reset_color%}'
PS2=$' \e[0;34m%}%B>%{\e[0m%}%b '
