# global python env
ROOT_PATH="$HOME/code/github/global_scripts"
export PATH="$ROOT_PATH:$PATH"

export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8

function gs_conda_initialize() {
    # <<< conda initialize <<<
    _GS_CONDA_ROOT_DIR="$HOME/anaconda3"
    if [ ! -d ${_GS_CONDA_ROOT_DIR} ]; then
        _GS_CONDA_ROOT_DIR="$HOME/miniconda"
    fi

    if [ ! -d ${_GS_CONDA_ROOT_DIR} ]; then
        return 0
    fi

    __conda_setup="$('$_GS_CONDA_ROOT_DIR/bin/conda' 'shell.zsh' 'hook' 2> /dev/null)"
    if [ $? -eq 0 ]; then
        eval "$__conda_setup"
    else
        if [ -f "$_GS_CONDA_ROOT_DIR/etc/profile.d/conda.sh" ]; then
            . "$_GS_CONDA_ROOT_DIR/etc/profile.d/conda.sh"
        else
            export PATH="$_GS_CONDA_ROOT_DIR/bin:$PATH"
        fi
    fi
    unset __conda_setup
    # <<< conda initialize <<<

    conda config --set changeps1 False

    case `uname -s` in
        Darwin)
            conda activate py39tf2.x
            ;;
        *)
            conda activate py36tf1.15
            ;;
    esac

}

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

gs_conda_initialize
gs_update_env
