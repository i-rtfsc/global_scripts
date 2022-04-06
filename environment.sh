machine="$(uname -s)"
case "${machine}" in
    Linux*)     isMac=false;;
    Darwin*)    isMac=true;;
    *)          isMac=false;;
esac

# update-environment
if $isMac ; then
    ENV_PATH="$HOME/code/github/global_scripts/environment.sh"
else
    ENV_PATH="$HOME/ext-data/code/github/global_scripts/environment.sh"
fi
function update-environment() {
    cp $ENV_PATH $HOME/.zsh_aliases
    source $HOME/.zsh_aliases
}

# ls & grep colored
if $isMac ; then
    alias ls='ls -G'
    alias ll='ls -G -la'
    alias lh='ls -G -lh'
    alias  l='ls -G'
else
    alias ls='ls --color=auto'
    alias ll='ls --color=auto -la'
    alias lh='ls --color=auto -lh'
    alias  l='ls --color=auto'
    alias grep='grep --color=auto'
fi

# 启动pd vm
if $isMac ; then
    alias start-ubuntu='prlctl start ubuntu'
    alias start-deepin='prlctl start deepin'

    alias pd-ssh='ssh solo@10.211.55.13'
    alias pd-mount='sshfs solo@10.211.55.13:$HOME/code/ $HOME/pd/'
    alias pd-umount='sudo diskutil umount force $HOME/pd ; rm -rf $HOME/pd'
fi

# global aosp grep
case `uname -s` in
    Darwin)
        function sgrep()
        {
            find -E . -name .repo -prune -o -name .git -prune -o  -type f -iregex '.*\.(c|h|cc|cpp|hpp|S|java|kt|xml|sh|mk|aidl|vts|proto)' \
                -exec grep --color -n "$@" {} +
        }

        ;;
    *)
        function sgrep()
        {
            find . -name .repo -prune -o -name .git -prune -o  -type f -iregex '.*\.\(c\|h\|cc\|cpp\|hpp\|S\|java\|kt\|xml\|sh\|mk\|aidl\|vts\|proto\)' \
                -exec grep --color -n "$@" {} +
        }
        ;;
esac

function ggrep()
{
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -type f -name "*\.gradle" \
        -exec grep --color -n "$@" {} +
}

function gogrep()
{
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -type f -name "*\.go" \
        -exec grep --color -n "$@" {} +
}

function jgrep()
{
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -type f -name "*\.java" \
        -exec grep --color -n "$@" {} +
}

function rsgrep()
{
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -type f -name "*\.rs" \
        -exec grep --color -n "$@" {} +
}

function ktgrep()
{
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -type f -name "*\.kt" \
        -exec grep --color -n "$@" {} +
}

function cgrep()
{
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -type f \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.h' -o -name '*.hpp' \) \
        -exec grep --color -n "$@" {} +
}

function resgrep()
{
    local dir
    for dir in `find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -name res -type d`; do
        find $dir -type f -name '*\.xml' -exec grep --color -n "$@" {} +
    done
}

function mangrep()
{
    find . -name .repo -prune -o -name .git -prune -o -path ./out -prune -o -type f -name 'AndroidManifest.xml' \
        -exec grep --color -n "$@" {} +
}

function owngrep()
{
    find . -name .repo -prune -o -name .git -prune -o -path ./out -prune -o -type f -name 'OWNERS' \
        -exec grep --color -n "$@" {} +
}

function sepgrep()
{
    find . -name .repo -prune -o -name .git -prune -o -path ./out -prune -o -name sepolicy -type d \
        -exec grep --color -n -r --exclude-dir=\.git "$@" {} +
}

function rcgrep()
{
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -type f -name "*\.rc*" \
        -exec grep --color -n "$@" {} +
}

case `uname -s` in
    Darwin)
        function mgrep()
        {
            find -E . -name .repo -prune -o -name .git -prune -o -path ./out -prune -o \( -iregex '.*/(Makefile|Makefile\..*|.*\.make|.*\.mak|.*\.mk|.*\.bp)' -o -regex '(.*/)?(build|soong)/.*[^/]*\.go' \) -type f \
                -exec grep --color -n "$@" {} +
        }

        function treegrep()
        {
            find -E . -name .repo -prune -o -name .git -prune -o -type f -iregex '.*\.(c|h|cpp|hpp|S|java|kt|xml)' \
                -exec grep --color -n -i "$@" {} +
        }

        ;;
    *)
        function mgrep()
        {
            find . -name .repo -prune -o -name .git -prune -o -path ./out -prune -o \( -regextype posix-egrep -iregex '(.*\/Makefile|.*\/Makefile\..*|.*\.make|.*\.mak|.*\.mk|.*\.bp)' -o -regextype posix-extended -regex '(.*/)?(build|soong)/.*[^/]*\.go' \) -type f \
                -exec grep --color -n "$@" {} +
        }

        function treegrep()
        {
            find . -name .repo -prune -o -name .git -prune -o -regextype posix-egrep -iregex '.*\.(c|h|cpp|hpp|S|java|kt|xml)' -type f \
                -exec grep --color -n -i "$@" {} +
        }

        ;;
esac

function android-ps-grep {
    adb shell ps | grep -v "$1:" | grep "$1"
}

function android-kill-grep {
    adb shell kill $(adb shell ps | grep $1 | awk '{print $2}')
}

function android-log-grep {
    # TODO
    #adb logcat -v time | grep $(adb shell ps | grep -v "$1:" |grep $1 | awk '{print $2}')
    adb logcat -v threadtime | grep -iE "$1"
}

function android-screencap {
    # alias dump-screencap='adb shell screencap -p /sdcard/screenshot.png ; adb pull /sdcard/screenshot.png'
    adb shell screencap -p /sdcard/"$1".png ; adb pull /sdcard/"$1".png
}

function android-dispaysync {
    adb shell dumpsys SurfaceFlinger --dispsync | grep mPeriod
}

if $isMac ; then
    function android-systrace {
        python2 ~/Library/Android/sdk/platform-tools/systrace/systrace.py
    }
else
    function android-systrace {
        # TODO
        python2 ~/Library/Android/sdk/platform-tools/systrace/systrace.py
    }
fi

function android-imei {
    adb shell "service call iphonesubinfo 1 | cut -c 52-66 | tr -d '.[:space:]'"
}

function android-key-home()
{
    adb shell input keyevent 3
}

function android-key-back()
{
    adb shell input keyevent 4
}

function android-key-menu()
{
    adb shell input keyevent 82
}

# global python env
if $isMac ; then
    ROOT_PATH="$HOME/code/github/global_scripts"
else
   ROOT_PATH="$HOME/ext-data/code/github/global_scripts/"
fi
export PATH="$ROOT_PATH:$PATH"


# boxing
alias update-git-global-name-upuphone='git config --global user.email anqi.huang@upuphone.com;git config --global user.name anqi.huang'
alias jumpserver-ssh-all='ssh anqi.huang@jumpserver.upuphone.com -p 2222'
alias jumpserver-ssh='ssh solo@10.164.118.252'
alias jumpserver-mount='sshfs jenkins@10.164.118.252:/data/lineage-19.0-solo/ $HOME/jumpserver'
alias jumpserver-umount='sudo diskutil umount force $HOME/jumpserver ; rm -rf $HOME/jumpserver'

alias bx-service-log-pid='adb logcat --pid=`adb shell pidof com.upuphone.bxservice`'
alias bx-service-kill='adb shell kill -9 `adb shell pidof com.upuphone.bxservice`'
alias bx-service-version='adb shell dumpsys package com.upuphone.bxservice | grep -i version'

##########################################################solo##########################################################
alias update-git-global-name-private='git config --global user.email anqi.huang@outlook.com; git config --global user.name Solo'

alias J007Engine-log-pid='adb logcat --pid=`com.journeyOS.J007engine.hidl@1.0-service`'
alias J007Engine-kill='adb shell killall com.journeyOS.J007engine.hidl@1.0-service'
alias J007Service-log-pid='adb logcat --pid=`adb shell pidof com.journeyOS.J007engine`'
alias J007Service-kill='adb shell killall com.journeyOS.J007engine'
alias J007Service-clear='adb shell pm clear com.journeyOS.J007engine'
alias J007Service-dump='adb shell dumpsys activity service com.journeyOS.J007engine/com.journeyOS.J007engine.service.J007EngineService'

alias J007Test-log-pid='adb logcat --pid=`adb shell pidof com.journeyOS.J007enginetest`'
alias J007Test-kill='adb shell killall com.journeyOS.J007enginetest'
alias J007Test-clear='adb shell pm clear com.journeyOS.J007enginetest'
##########################################################solo##########################################################

#if [ -f ~/global_scripts/environment.sh ]
#then
#    . ~/global_scripts/environment.sh
#fi
#[ -f ~/.vimrc ] || ln -s ~/global_scripts/.vimrc ~/
#[ -f ~/.gitconfig ] || ln -s ~/global_scripts/.gitconfig ~/
