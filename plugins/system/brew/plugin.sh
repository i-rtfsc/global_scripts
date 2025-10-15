#!/bin/bash
# System Brew Subplugin
# - Homebrew 镜像源管理
# - 支持多个国内镜像源切换

# 镜像源配置
declare -A MIRROR_NAMES=(
    ["github"]="GitHub 官方源"
    ["ustc"]="中科大镜像源"
    ["tsinghua"]="清华大学镜像源"
    ["aliyun"]="阿里云镜像源"
)

declare -A MIRROR_BREW=(
    ["github"]="https://github.com/Homebrew/brew.git"
    ["ustc"]="https://mirrors.ustc.edu.cn/brew.git"
    ["tsinghua"]="https://mirrors.tuna.tsinghua.edu.cn/git/homebrew/brew.git"
    ["aliyun"]="https://mirrors.aliyun.com/homebrew/brew.git"
)

declare -A MIRROR_CORE=(
    ["github"]="https://github.com/Homebrew/homebrew-core.git"
    ["ustc"]="https://mirrors.ustc.edu.cn/homebrew-core.git"
    ["tsinghua"]="https://mirrors.tuna.tsinghua.edu.cn/git/homebrew/homebrew-core.git"
    ["aliyun"]="https://mirrors.aliyun.com/homebrew/homebrew-core.git"
)

declare -A MIRROR_CASK=(
    ["github"]="https://github.com/Homebrew/homebrew-cask.git"
    ["ustc"]="https://mirrors.ustc.edu.cn/homebrew-cask.git"
    ["tsinghua"]="https://mirrors.tuna.tsinghua.edu.cn/git/homebrew/homebrew-cask.git"
    ["aliyun"]="https://mirrors.aliyun.com/homebrew/homebrew-cask.git"
)

declare -A MIRROR_BOTTLES=(
    ["github"]=""
    ["ustc"]="https://mirrors.ustc.edu.cn/homebrew-bottles"
    ["tsinghua"]="https://mirrors.tuna.tsinghua.edu.cn/git/homebrew/homebrew-bottles"
    ["aliyun"]="https://mirrors.aliyun.com/homebrew/homebrew-bottles"
)

# 设置镜像源的通用函数
_gs_system_brew_set_mirror() {
    local mirror_key="$1"
    local mirror_name="${MIRROR_NAMES[$mirror_key]}"
    local brew_url="${MIRROR_BREW[$mirror_key]}"
    local core_url="${MIRROR_CORE[$mirror_key]}"
    local cask_url="${MIRROR_CASK[$mirror_key]}"
    local bottles_url="${MIRROR_BOTTLES[$mirror_key]}"

    if [[ -z "$mirror_name" ]]; then
        echo "❌ 未知的镜像源: $mirror_key"
        return 1
    fi

    echo "🔄 正在切换到 $mirror_name..."

    # 设置brew.git源
    if ! git -C "$(brew --repo)" remote set-url origin "$brew_url" 2>&1; then
        echo "❌ 设置brew源失败"
        return 1
    fi
    echo "  ✅ brew.git 源已设置"

    # 设置homebrew-core.git源
    if ! git -C "$(brew --repo homebrew/core)" remote set-url origin "$core_url" 2>&1; then
        echo "❌ 设置homebrew-core源失败"
        return 1
    fi
    echo "  ✅ homebrew-core.git 源已设置"

    # 设置homebrew-cask.git源
    if ! git -C "$(brew --repo homebrew/cask)" remote set-url origin "$cask_url" 2>&1; then
        echo "❌ 设置homebrew-cask源失败"
        return 1
    fi
    echo "  ✅ homebrew-cask.git 源已设置"

    # 设置bottles域名
    if [[ -n "$bottles_url" ]]; then
        export HOMEBREW_BOTTLE_DOMAIN="$bottles_url"
        echo "  ✅ HOMEBREW_BOTTLE_DOMAIN 已设置为 $bottles_url"
    else
        unset HOMEBREW_BOTTLE_DOMAIN
        echo "  ℹ️  HOMEBREW_BOTTLE_DOMAIN 已清除"
    fi

    # 执行brew update
    echo ""
    echo "🔄 执行 brew update..."
    if brew update; then
        echo "✅ 已成功切换到 $mirror_name"
    else
        echo "⚠️  切换到 $mirror_name 完成，但 brew update 执行失败"
    fi
}

# @plugin_function
# name: remote
# description:
#   zh: 查看当前镜像源配置
#   en: Show current mirror configuration
# usage: gs system brew remote
# examples:
#   - gs system brew remote
gs_system_brew_remote() {
    echo "🔍 当前Homebrew镜像源配置:"
    echo ""

    # 显示brew.git源
    echo "📦 brew.git:"
    git -C "$(brew --repo)" remote -v 2>&1 | sed 's/^/  /'
    echo ""

    # 显示homebrew-core.git源
    echo "📦 homebrew-core.git:"
    git -C "$(brew --repo homebrew/core)" remote -v 2>&1 | sed 's/^/  /'
    echo ""

    # 显示homebrew-cask.git源
    echo "📦 homebrew-cask.git:"
    git -C "$(brew --repo homebrew/cask)" remote -v 2>&1 | sed 's/^/  /'
    echo ""

    # 显示bottles域名配置
    echo "🍾 HOMEBREW_BOTTLE_DOMAIN:"
    if [[ -n "$HOMEBREW_BOTTLE_DOMAIN" ]]; then
        echo "  $HOMEBREW_BOTTLE_DOMAIN"
    else
        echo "  未设置"
    fi
}

# @plugin_function
# name: github
# description:
#   zh: 切换到GitHub官方源
#   en: Switch to GitHub official source
# usage: gs system brew github
# examples:
#   - gs system brew github
gs_system_brew_github() {
    _gs_system_brew_set_mirror "github"
}

# @plugin_function
# name: ustc
# description:
#   zh: 切换到中科大镜像源
#   en: Switch to USTC mirror
# usage: gs system brew ustc
# examples:
#   - gs system brew ustc
gs_system_brew_ustc() {
    _gs_system_brew_set_mirror "ustc"
}

# @plugin_function
# name: tsinghua
# description:
#   zh: 切换到清华大学镜像源
#   en: Switch to Tsinghua mirror
# usage: gs system brew tsinghua
# examples:
#   - gs system brew tsinghua
gs_system_brew_tsinghua() {
    _gs_system_brew_set_mirror "tsinghua"
}

# @plugin_function
# name: aliyun
# description:
#   zh: 切换到阿里云镜像源
#   en: Switch to Aliyun mirror
# usage: gs system brew aliyun
# examples:
#   - gs system brew aliyun
gs_system_brew_aliyun() {
    _gs_system_brew_set_mirror "aliyun"
}