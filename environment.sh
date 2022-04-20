machine="$(uname -s)"
case "${machine}" in
    Linux*)     isMac=false;;
    Darwin*)    isMac=true;;
    *)          isMac=false;;
esac

# global python env
ROOT_PATH="$HOME/code/github/global_scripts"
export PATH="$ROOT_PATH:$PATH"

# update_environment
function update_environment() {
    local env_path="$HOME/code/github/global_scripts/environment.sh"
    cp $env_path $HOME/.zsh_aliases
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
        function sgrep() {
            find -E . -name .repo -prune -o -name .git -prune -o  -type f -iregex '.*\.(c|h|cc|cpp|hpp|S|java|kt|xml|sh|mk|aidl|vts|proto)' \
                -exec grep --color -n "$@" {} +
        }

        ;;
    *)
        function sgrep() {
            find . -name .repo -prune -o -name .git -prune -o  -type f -iregex '.*\.\(c\|h\|cc\|cpp\|hpp\|S\|java\|kt\|xml\|sh\|mk\|aidl\|vts\|proto\)' \
                -exec grep --color -n "$@" {} +
        }
        ;;
esac

function ggrep() {
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -type f -name "*\.gradle" \
        -exec grep --color -n "$@" {} +
}

function gogrep() {
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -type f -name "*\.go" \
        -exec grep --color -n "$@" {} +
}

function jgrep() {
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -type f -name "*\.java" \
        -exec grep --color -n "$@" {} +
}

function rsgrep() {
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -type f -name "*\.rs" \
        -exec grep --color -n "$@" {} +
}

function ktgrep() {
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -type f -name "*\.kt" \
        -exec grep --color -n "$@" {} +
}

function cgrep() {
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -type f \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.h' -o -name '*.hpp' \) \
        -exec grep --color -n "$@" {} +
}

function resgrep() {
    local dir
    for dir in `find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -name res -type d`; do
        find $dir -type f -name '*\.xml' -exec grep --color -n "$@" {} +
    done
}

function mangrep() {
    find . -name .repo -prune -o -name .git -prune -o -path ./out -prune -o -type f -name 'AndroidManifest.xml' \
        -exec grep --color -n "$@" {} +
}

function owngrep() {
    find . -name .repo -prune -o -name .git -prune -o -path ./out -prune -o -type f -name 'OWNERS' \
        -exec grep --color -n "$@" {} +
}

function sepgrep() {
    find . -name .repo -prune -o -name .git -prune -o -path ./out -prune -o -name sepolicy -type d \
        -exec grep --color -n -r --exclude-dir=\.git "$@" {} +
}

function rcgrep() {
    find . -name .repo -prune -o -name .git -prune -o -name out -prune -o -type f -name "*\.rc*" \
        -exec grep --color -n "$@" {} +
}

case `uname -s` in
    Darwin)
        function mgrep() {
            find -E . -name .repo -prune -o -name .git -prune -o -path ./out -prune -o \( -iregex '.*/(Makefile|Makefile\..*|.*\.make|.*\.mak|.*\.mk|.*\.bp)' -o -regex '(.*/)?(build|soong)/.*[^/]*\.go' \) -type f \
                -exec grep --color -n "$@" {} +
        }

        function treegrep() {
            find -E . -name .repo -prune -o -name .git -prune -o -type f -iregex '.*\.(c|h|cpp|hpp|S|java|kt|xml)' \
                -exec grep --color -n -i "$@" {} +
        }

        ;;
    *)
        function mgrep() {
            find . -name .repo -prune -o -name .git -prune -o -path ./out -prune -o \( -regextype posix-egrep -iregex '(.*\/Makefile|.*\/Makefile\..*|.*\.make|.*\.mak|.*\.mk|.*\.bp)' -o -regextype posix-extended -regex '(.*/)?(build|soong)/.*[^/]*\.go' \) -type f \
                -exec grep --color -n "$@" {} +
        }

        function treegrep() {
            find . -name .repo -prune -o -name .git -prune -o -regextype posix-egrep -iregex '.*\.(c|h|cpp|hpp|S|java|kt|xml)' -type f \
                -exec grep --color -n -i "$@" {} +
        }

        ;;
esac

function android_hidden_api_enable {
    adb shell settings put global hidden_api_policy_pre_p_apps 1
    adb shell settings put global hidden_api_policy_p_apps 1
}

function android_hidden_api_disable {
    adb shell settings delete global hidden_api_policy_pre_p_apps
    adb shell settings delete global hidden_api_policy_p_apps
}

function android_ps_grep {
    adb shell ps | grep -v "$1:" | grep "$1"
}

function android_kill_grep {
    adb shell kill $(adb shell ps | grep $1 | awk '{print $2}')
}

function android_log_grep {
    # TODO
    #adb logcat -v time | grep $(adb shell ps | grep -v "$1:" |grep $1 | awk '{print $2}')
    adb logcat -v threadtime | grep -iE "$1"
}

function android_screencap {
    # alias dump-screencap='adb shell screencap -p /sdcard/screenshot.png ; adb pull /sdcard/screenshot.png'
    adb shell screencap -p /sdcard/"$1".png
    adb pull /sdcard/"$1".png
}

function android_dispaysync {
    adb shell dumpsys SurfaceFlinger --dispsync | grep mPeriod
}

if $isMac ; then
    function android_systrace {
        python2 ~/Library/Android/sdk/platform-tools/systrace/systrace.py
    }
else
    function android_systrace {
        # TODO
        python2 ~/Library/Android/sdk/platform-tools/systrace/systrace.py
    }
fi

function android_imei {
    adb shell "service call iphonesubinfo 1 | cut -c 52-66 | tr -d '.[:space:]'"
}

function android_key() {
    adb shell input keyevent "$1"
}

function android_key_home() {
    adb shell input keyevent 3
}

function android_key_back() {
    adb shell input keyevent 4
}

function android_key_menu() {
    adb shell input keyevent 82
}

function _android_build_with_ccache() {
    export USE_CCACHE=1
    export CCACHE_EXEC=/usr/bin/ccache
    #set ccache dir
    export CCACHE_DIR=/home/solo/ext-data/.ccache
    ccache -M 50G
}

function _android_build_lunch() {
    TOP=`pwd`
    local building_log_dir=$TOP/build_log
    # check if the building log dir exists
    if [ ! -d ${building_log_dir} ]; then
        mkdir ${building_log_dir}
    fi
    export _BUILD_LOG_DIR=${building_log_dir}

    local LOCAL_TARGET_PRODUCT=${TARGET_PRODUCT}
    if [ -z ${LOCAL_TARGET_PRODUCT} ]; then
        LOCAL_TARGET_PRODUCT=$1
    fi

    if [ -z ${LOCAL_TARGET_PRODUCT} ]; then
        LOCAL_TARGET_PRODUCT="lineage_lemonadep-userdebug"
    fi

    source build/envsetup.sh
    lunch ${LOCAL_TARGET_PRODUCT}
}

function android_build() {
    #_android_build_with_ccache

    # lunch target
    _android_build_lunch

    # log file
    local building_time=$(date "+%Y-%m-%d-%H-%M-%S")
    local building_log=${_BUILD_LOG_DIR}/build_full_${building_time}.log

    # full build
    m -j $(nproc) 2>&1 | tee ${building_log}
}

function android_build_ota() {
    #_android_build_with_ccache

    # lunch target
    _android_build_lunch

    # log file
    local building_time=$(date "+%Y-%m-%d-%H-%M-%S")
    local building_log=${_BUILD_LOG_DIR}/build_full_${building_time}.log
    local building_ota_log=${_BUILD_LOG_DIR}/build_ota_${building_time}.log

    # full build
    m -j $(nproc) 2>&1 | tee ${building_log}
    # make ota
    make otapackage -j $(nproc) 2>&1 | tee ${building_ota_log}
}

function _android_build_system() {
    #_android_build_with_ccache

    # lunch target
    _android_build_lunch

    local goals=$1

    # log file
    local building_time=$(date "+%Y-%m-%d-%H-%M-%S")
    local building_log=${_BUILD_LOG_DIR}/build_${goals}_${building_time}.log
    local building_ota_log=${_BUILD_LOG_DIR}/build_ota_${building_time}.log

    # build
    m -j $(nproc) ${goals} 2>&1 | tee ${building_log}
}

function android_build_system() {
    _android_build_system "snod"
}

function android_build_system_ext() {
    _android_build_system "senod"
}

function android_build_vendor() {
    _android_build_system "vnod"
}

function lineage_build() {
    #_android_build_with_ccache

    local LOCAL_TARGET_PRODUCT=
    if [ -z ${LOCAL_TARGET_PRODUCT} ]; then
        LOCAL_TARGET_PRODUCT=$1
    fi

    if [ -z ${LOCAL_TARGET_PRODUCT} ]; then
        LOCAL_TARGET_PRODUCT="lemonadep"
    fi

    source build/envsetup.sh
    breakfast ${LOCAL_TARGET_PRODUCT}

    TOP=`pwd`
    local building_log_dir=$TOP/build_log
    # check if the building log dir exists
    if [ ! -d ${building_log_dir} ]; then
        mkdir ${building_log_dir}
    fi

    # log file
    local building_time=$(date "+%Y-%m-%d-%H-%M-%S")
    local building_log=${building_log_dir}/build_lineage_${building_time}.log

    # lineage build
    brunch ${LOCAL_TARGET_PRODUCT} 2>&1 | tee ${building_log}
}

function _show_and_choose_combo() {
    unset _BUILD_COMBO

    local user_input=$1
    local title=$2
    local choices=(`echo $3 | tr ',' ' '` )

    local index=1
    local default_index=1

    if [ -z ${_LAST_BUILD_COMBO} ]; then
        _LAST_BUILD_COMBO=${choices[default_index]}
    fi

    local answer=${_LAST_BUILD_COMBO}
    local selection=${_LAST_BUILD_COMBO}

    if [ "${user_input}" ] ; then
        answer=${user_input}
    else
        # print combo menu,
        for item in ${choices[@]}; do
            echo $index.  ${item}
            index=$(($index+1))
        done
        printf "Which would you like? [ %s ] " ${answer}
        read answer

        if [ -z "$answer" ]; then
            answer=${selection}
        fi
    fi

    if [ -z "$answer" ] ; then
        echo "error: get null answer."
    elif (echo -n $answer | grep -q -e "^[0-9][0-9]*$") ; then
        selection=${choices[answer]}
    else
        selection=${answer}
    fi
    printf "\n    selected: %s\n\n" ${selection}
    export _BUILD_COMBO=${selection}
    export _LAST_BUILD_COMBO=${_BUILD_COMBO}
}

function android_build_ninja() {
    local title="select modules(ninja)"
    local modules=(
                  "bx-framework"
                  "framework"
                  "services"
                  "UMS"
                  "UMSTest"
                  "surfaceflinger"
                  "android.hardware.power-service"
                  "SystemUI"
                  "Settings"
                  )

    # lunch target
    _android_build_lunch

    # select module
    _show_and_choose_combo  "$1" "${title}" "${modules}"
    selection=${_BUILD_COMBO}

    # log file
    local building_time=$(date "+%Y-%m-%d-%H-%M-%S")
    building_log=${_BUILD_LOG_DIR}/ninja_build_${selection}_${building_time}.log
    echo "selection = "${selection} ", building log =" ${building_log}

    # ninja build
    time prebuilts/build-tools/linux-x86/bin/ninja -f out/combined-${TARGET_PRODUCT}.ninja ${selection} -j $(nproc) | tee ${building_log}
}

function android_build_make() {
    local title="select modules(make)"
    local modules=(
                  "bx-framework"
                  "framework"
                  "services"
                  "UMS"
                  "UMSTest"
                  "surfaceflinger"
                  "android.hardware.power-service"
                  "SystemUI"
                  "Settings"
                  )

    # lunch target
    _android_build_lunch

    # select module
    _show_and_choose_combo "$1" "${title}" "${modules}"
    selection=${_BUILD_COMBO}

    # log file
    local building_time=$(date "+%Y-%m-%d-%H-%M-%S")
    building_log=${_BUILD_LOG_DIR}/make_build_${selection}_${building_time}.log
    echo "selection = "${selection} ", building log =" ${building_log}

    # make build
    make ${selection} -j $(nproc) | tee ${building_log}
}

function android_push_bx-framework {
    adb push out/target/product/${TARGET_PRODUCT}/system/framework/arm/boot-bx-framework.art /system/framework/arm/
    adb push out/target/product/${TARGET_PRODUCT}/system/framework/arm/boot-bx-framework.oat /system/framework/arm/
    adb push out/target/product/${TARGET_PRODUCT}/system/framework/arm/boot-bx-framework.vdex /system/framework/arm/

    adb push out/target/product/${TARGET_PRODUCT}/system/framework/arm64/boot-bx-framework.art /system/framework/arm64/
    adb push out/target/product/${TARGET_PRODUCT}/system/framework/arm64/boot-bx-framework.oat /system/framework/arm64/
    adb push out/target/product/${TARGET_PRODUCT}/system/framework/arm64/boot-bx-framework.vdex /system/framework/arm64/

    adb push out/target/product/${TARGET_PRODUCT}/system/framework/bx-framework.jar /system/framework/
}

function android_push_framework {
    adb push out/target/product/${TARGET_PRODUCT}/system/framework/arm/boot-framework.art /system/framework/arm/
    adb push out/target/product/${TARGET_PRODUCT}/system/framework/arm/boot-framework.oat /system/framework/arm/
    adb push out/target/product/${TARGET_PRODUCT}/system/framework/arm/boot-framework.vdex /system/framework/arm/

    adb push out/target/product/${TARGET_PRODUCT}/system/framework/arm64/boot-framework.art /system/framework/arm64/
    adb push out/target/product/${TARGET_PRODUCT}/system/framework/arm64/boot-framework.oat /system/framework/arm64/
    adb push out/target/product/${TARGET_PRODUCT}/system/framework/arm64/boot-framework.vdex /system/framework/arm64/

    adb push out/target/product/${TARGET_PRODUCT}/system/framework/framework.jar /system/framework/
}

# boxing
alias update-git-global-name-upuphone='git config --global user.email anqi.huang@upuphone.com;git config --global user.name anqi.huang'
alias jumpserver-ssh-all='ssh anqi.huang@jumpserver.upuphone.com -p 2222'
alias jumpserver-ssh='ssh solo@10.164.118.252'
alias jumpserver-mount='sshfs solo@10.164.118.252:/data/lineage/ $HOME/jumpserver'
alias jumpserver-umount='sudo diskutil umount force $HOME/jumpserver ; rm -rf $HOME/jumpserver'

alias ums-log-pid='adb logcat --pid=`adb shell pidof com.upuphone.bxservice`'
alias ums-kill='adb shell kill -9 `adb shell pidof com.upuphone.bxservice`'
alias ums-version='adb shell dumpsys package com.upuphone.bxservice | grep -i version'
alias ums-version-test='adb shell dumpsys package com.upuphone.bxservicetest | grep -i version'

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
