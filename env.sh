# global python env
ROOT_PATH="$HOME/code/github/global_scripts"
export PATH="$ROOT_PATH:$PATH"

# gs update environment
function gs_update_env() {
#    source ${ROOT_PATH}/env.sh
    source ${ROOT_PATH}/adb.sh
    source ${ROOT_PATH}/android_build.sh
    source ${ROOT_PATH}/android_grep.sh
    source ${ROOT_PATH}/android_push.sh
    source ${ROOT_PATH}/common_alias.sh
    source ${ROOT_PATH}/private_alias.sh
    source ${ROOT_PATH}/zsh_theme.sh
}

gs_update_env