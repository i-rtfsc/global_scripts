alias update-environment='cp /Users/solo/code/github/global_scripts/environment.sh /Users/solo/.zsh_aliases && source /Users/solo/.zsh_aliases'

alias findc='find ${PWD} -name'
alias grep='grep --color=auto'
alias egrep='egrep --color=auto'
alias fgrep='fgrep --color=auto'

alias adb='/Users/solo/Library/Android/sdk/platform-tools/adb'
alias fastboot='/Users/solo/Library/Android/sdk/platform-tools/fastboot'

alias r-ssh='ssh -R 22222:localhost:22 solo@'

alias vm-ssh='ssh -p 22222 localhost'
alias vm-mount='sudo sshfs -o allow_other,port=22222 solo@localhost:/work/solo/ /Users/solo/vm/'
alias vm-mount-all='sudo sshfs -o allow_other,port=22222 solo@localhost:/work/ /Users/solo/vm-all/'
alias vm-umount='sudo umount -f /Users/solo/vm'

alias ssh-gitlab='ssh solo@10.0.12.179'
alias ssh-gitlab-mount='sudo sshfs -o allow_other,port=33333 solo@localhost:/home/solo/work/ /Users/solo/vm-gitlab/'
alias ssh-bot='ssh -l bot raspberrypi.local'
alias ssh-bot-mount='sudo sshfs -o allow_other,port=33335 bot@localhost:/ /Users/solo/bot/'

alias dump-screencap='adb shell screencap -p /sdcard/screenshot.png ; adb pull /sdcard/screenshot.png'
alias dump-systrace='python ~/Library/Android/sdk/platform-tools/systrace/systrace.py'
alias dump-dispaysync='adb shell dumpsys SurfaceFlinger --dispsync | grep mPeriod'

alias dock-show-up='adb shell dumpsys activity service com.blackshark.gamedock/.GameDockService show game_dock_view 3'
alias dock-show-left='adb shell dumpsys activity service com.blackshark.gamedock/.GameDockService show game_dock_view 1'
alias dock-show-right='adb shell dumpsys activity service com.blackshark.gamedock/.GameDockService show game_dock_view 2'
alias dock-clear='adb shell pm clear com.blackshark.gamedock'
alias dock-kill='adb shell kill -9 `adb shell pidof com.blackshark.gamedock`'
alias dock-guide='adb shell dumpsys activity service com.blackshark.gamedock/.GameDockService put gamedocksp first_guide bool false'
alias dock-version='adb shell dumpsys package com.blackshark.gamedock | grep -i version'
alias dock-log-tag='adb logcat -v threadtime | grep -iE'
alias dock-log-pid='adb logcat --pid=`adb shell pidof com.blackshark.gamedock`'
alias dock-dump='adb shell dumpsys activity service com.blackshark.gamedock/.GameDockService'
alias dock-pull-db='rm -rf databases ; adb pull /data/data/com.blackshark.gamedock/databases/ .'
alias dock-install='adb install -r -d ~/vm/blackshark/BsGameDock/build/out_product_branch/ZsGameDock_unsigned.apk'
alias dock-uninstall='adb uninstall com.blackshark.gamedock'

#alias adb-imei='adb shell "service call iphonesubinfo 1 | cut -c 52-66 | tr -d '.[:space:]'"'

export GOPATH="/Users/solo/go"
export PATH="/Users/solo/code/github/global_scripts/:$PATH"
export PATH="/Users/solo/code/github/global_scripts/base/:$PATH"
export PATH="/Users/solo/code/github/global_scripts/config/:$PATH"
export PATH="/Users/solo/code/github/global_scripts/issues/:$PATH"
export PATH="/Users/solo/code/github/global_scripts/gerrit/:$PATH"
export PATH="/Users/solo/code/github/global_scripts/im/:$PATH"

