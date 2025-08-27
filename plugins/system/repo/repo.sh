#!/bin/bash
# Git Repo工具管理子模块
# Git Repo Tool Management Submodule
# 提供Android Repo工具配置和管理功能

# 检查Repo工具依赖
_gs_system_repo_check_deps() {
    local missing_deps=()
    
    if ! command -v git &> /dev/null; then
        missing_deps+=("git")
    fi
    
    if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
        missing_deps+=("python")
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        echo "错误: 缺少依赖工具: ${missing_deps[*]}"
        echo "请安装缺少的工具后重试"
        return 1
    fi
    
    return 0
}

# 检查Repo工具是否已安装
_gs_system_repo_check_installation() {
    if command -v repo &> /dev/null; then
        return 0
    else
        return 1
    fi
}

# 获取当前Repo URL设置
_gs_system_repo_get_current_url() {
    if [[ -n "$REPO_URL" ]]; then
        echo "$REPO_URL"
    else
        echo "未设置 (使用默认)"
    fi
}

# 显示Repo状态和配置
gs_system_repo_status() {
    local output_format="table"
    local show_detailed=false
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            --json)
                output_format="json"
                shift
                ;;
            -d|--detailed)
                show_detailed=true
                shift
                ;;
            -h|--help)
                echo "用法: gs-system-repo-status [选项]"
                echo "显示Android Repo工具状态"
                echo ""
                echo "选项:"
                echo "  --json                  JSON格式输出"
                echo "  -d, --detailed          显示详细信息"
                echo "  -h, --help              显示此帮助信息"
                return 0
                ;;
            *)
                echo "错误: 未知参数 $1"
                return 1
                ;;
        esac
    done
    
    if ! _gs_system_repo_check_deps; then
        return 1
    fi
    
    # 收集状态信息
    local repo_installed=false
    local repo_version="未安装"
    local repo_url
    local git_version
    local python_version
    
    if _gs_system_repo_check_installation; then
        repo_installed=true
        repo_version=$(repo version 2>/dev/null | head -1 | grep -o 'repo-[0-9][0-9.]*' || echo "未知版本")
    fi
    
    repo_url=$(_gs_system_repo_get_current_url)
    git_version=$(git --version 2>/dev/null | cut -d' ' -f3 || echo "未知")
    
    if command -v python3 >/dev/null 2>&1; then
        python_version=$(python3 --version 2>&1 | cut -d' ' -f2)
    elif command -v python >/dev/null 2>&1; then
        python_version=$(python --version 2>&1 | cut -d' ' -f2)
    else
        python_version="未安装"
    fi
    
    if [[ "$output_format" == "json" ]]; then
        # JSON格式输出
        cat <<EOF
{
  "repo_status": {
    "installed": $repo_installed,
    "version": "$repo_version",
    "repo_url": "$repo_url",
    "git_version": "$git_version",
    "python_version": "$python_version"
  }
}
EOF
    else
        # 表格格式输出
        echo "Android Repo 工具状态"
        echo "===================="
        
        if [[ "$repo_installed" == true ]]; then
            echo "Repo状态:    ✅ 已安装"
            echo "Repo版本:    $repo_version"
        else
            echo "Repo状态:    ❌ 未安装"
        fi
        
        echo "Repo URL:    $repo_url"
        echo "Git版本:     $git_version"
        echo "Python版本:  $python_version"
        
        if [[ "$show_detailed" == true ]]; then
            echo ""
            echo "详细信息"
            echo "========"
            
            # 显示Repo URL的详细信息
            echo "可用的Repo镜像源:"
            echo "  Google官方:    https://gerrit.googlesource.com/git-repo"
            echo "  清华大学:      https://mirrors.tuna.tsinghua.edu.cn/git/git-repo"
            echo "  Intel:         https://gerrit.intel.com/git-repo"
            
            # 如果Repo已安装，显示更多信息
            if [[ "$repo_installed" == true ]]; then
                echo ""
                echo "Repo安装路径:"
                which repo 2>/dev/null | sed 's/^/  /'
                
                # 显示当前目录的Repo项目信息
                if [[ -d ".repo" ]]; then
                    echo ""
                    echo "当前目录Repo项目信息:"
                    echo "  项目根目录: $PWD"
                    echo "  .repo目录:  存在"
                    
                    if [[ -f ".repo/manifest.xml" ]]; then
                        echo "  Manifest:   存在"
                        
                        # 尝试获取项目信息
                        local remote_url
                        remote_url=$(grep 'default.*remote=' .repo/manifest.xml 2>/dev/null | sed 's/.*remote="\([^"]*\)".*/\1/' | head -1 || echo "未知")
                        echo "  远程地址:   $remote_url"
                    fi
                else
                    echo ""
                    echo "当前目录: 非Repo项目目录"
                fi
            else
                echo ""
                echo "💡 安装Repo工具:"
                echo "  1. mkdir -p ~/bin"
                echo "  2. curl https://storage.googleapis.com/git-repo-downloads/repo > ~/bin/repo"
                echo "  3. chmod a+x ~/bin/repo"
                echo "  4. export PATH=~/bin:\$PATH"
            fi
        fi
        
        # 显示当前环境变量
        if [[ -n "$REPO_URL" ]]; then
            echo ""
            echo "环境变量:"
            echo "  REPO_URL=$REPO_URL"
        fi
    fi
    
    return 0
}

# 设置Google官方源
gs_system_repo_url_google() {
    local permanent=false
    local show_info=true
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            --permanent)
                permanent=true
                shift
                ;;
            -q|--quiet)
                show_info=false
                shift
                ;;
            -h|--help)
                echo "用法: gs-system-repo-url-google [选项]"
                echo "设置Repo为Google官方源"
                echo ""
                echo "选项:"
                echo "  --permanent             写入Shell配置文件(永久生效)"
                echo "  -q, --quiet             静默模式"
                echo "  -h, --help              显示此帮助信息"
                echo ""
                echo "官方源信息:"
                echo "  URL: https://gerrit.googlesource.com/git-repo"
                echo "  特点: Google官方维护，功能最新最全"
                echo "  适用: 网络条件良好的环境"
                return 0
                ;;
            *)
                echo "错误: 未知参数 $1"
                return 1
                ;;
        esac
    done
    
    local repo_url="https://gerrit.googlesource.com/git-repo"
    
    # 设置环境变量
    unset REPO_URL
    export REPO_URL="$repo_url"
    
    if [[ "$show_info" == true ]]; then
        echo "✅ Repo URL已设置为Google官方源"
        echo "   URL: $repo_url"
    fi
    
    # 永久设置
    if [[ "$permanent" == true ]]; then
        local shell_config=""
        if [[ "$SHELL" == *"zsh"* ]]; then
            shell_config="$HOME/.zshrc"
        elif [[ "$SHELL" == *"bash"* ]]; then
            shell_config="$HOME/.bashrc"
        fi
        
        if [[ -n "$shell_config" ]]; then
            # 移除旧的REPO_URL设置
            if [[ -f "$shell_config" ]]; then
                sed -i.bak '/export REPO_URL=/d' "$shell_config" 2>/dev/null
            fi
            
            # 添加新的设置
            echo "export REPO_URL='$repo_url'" >> "$shell_config"
            
            if [[ "$show_info" == true ]]; then
                echo "   已写入: $shell_config"
                echo "   重启终端或执行 'source $shell_config' 生效"
            fi
        else
            echo "警告: 无法识别Shell类型，永久设置失败"
        fi
    fi
    
    return 0
}

# 设置清华大学镜像源
gs_system_repo_url_tsinghua() {
    local permanent=false
    local show_info=true
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            --permanent)
                permanent=true
                shift
                ;;
            -q|--quiet)
                show_info=false
                shift
                ;;
            -h|--help)
                echo "用法: gs-system-repo-url-tsinghua [选项]"
                echo "设置Repo为清华大学(TUNA)镜像源"
                echo ""
                echo "选项:"
                echo "  --permanent             写入Shell配置文件(永久生效)"
                echo "  -q, --quiet             静默模式"
                echo "  -h, --help              显示此帮助信息"
                echo ""
                echo "镜像源信息:"
                echo "  URL: https://mirrors.tuna.tsinghua.edu.cn/git/git-repo"
                echo "  特点: 清华大学维护，国内访问速度快"
                echo "  适用: 国内开发环境，网络加速"
                return 0
                ;;
            *)
                echo "错误: 未知参数 $1"
                return 1
                ;;
        esac
    done
    
    local repo_url="https://mirrors.tuna.tsinghua.edu.cn/git/git-repo"
    
    # 设置环境变量
    unset REPO_URL
    export REPO_URL="$repo_url"
    
    if [[ "$show_info" == true ]]; then
        echo "✅ Repo URL已设置为清华大学镜像源"
        echo "   URL: $repo_url"
    fi
    
    # 永久设置
    if [[ "$permanent" == true ]]; then
        local shell_config=""
        if [[ "$SHELL" == *"zsh"* ]]; then
            shell_config="$HOME/.zshrc"
        elif [[ "$SHELL" == *"bash"* ]]; then
            shell_config="$HOME/.bashrc"
        fi
        
        if [[ -n "$shell_config" ]]; then
            # 移除旧的REPO_URL设置
            if [[ -f "$shell_config" ]]; then
                sed -i.bak '/export REPO_URL=/d' "$shell_config" 2>/dev/null
            fi
            
            # 添加新的设置
            echo "export REPO_URL='$repo_url'" >> "$shell_config"
            
            if [[ "$show_info" == true ]]; then
                echo "   已写入: $shell_config"
                echo "   重启终端或执行 'source $shell_config' 生效"
            fi
        else
            echo "警告: 无法识别Shell类型，永久设置失败"
        fi
    fi
    
    return 0
}

# 重置为默认设置
gs_system_repo_url_reset() {
    local permanent=false
    local show_info=true
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            --permanent)
                permanent=true
                shift
                ;;
            -q|--quiet)
                show_info=false
                shift
                ;;
            -h|--help)
                echo "用法: gs-system-repo-url-reset [选项]"
                echo "重置Repo URL为默认设置"
                echo ""
                echo "选项:"
                echo "  --permanent             从Shell配置文件中移除设置"
                echo "  -q, --quiet             静默模式"
                echo "  -h, --help              显示此帮助信息"
                return 0
                ;;
            *)
                echo "错误: 未知参数 $1"
                return 1
                ;;
        esac
    done
    
    # 清除环境变量
    unset REPO_URL
    
    if [[ "$show_info" == true ]]; then
        echo "✅ Repo URL已重置为默认设置"
        echo "   将使用Repo工具的内置默认源"
    fi
    
    # 永久移除
    if [[ "$permanent" == true ]]; then
        local shell_config=""
        if [[ "$SHELL" == *"zsh"* ]]; then
            shell_config="$HOME/.zshrc"
        elif [[ "$SHELL" == *"bash"* ]]; then
            shell_config="$HOME/.bashrc"
        fi
        
        if [[ -n "$shell_config" ]] && [[ -f "$shell_config" ]]; then
            # 移除REPO_URL设置
            sed -i.bak '/export REPO_URL=/d' "$shell_config" 2>/dev/null
            
            if [[ "$show_info" == true ]]; then
                echo "   已从配置文件中移除: $shell_config"
                echo "   重启终端或执行 'source $shell_config' 生效"
            fi
        fi
    fi
    
    return 0
}

# Repo工具安装
gs_system_repo_install() {
    local install_path="$HOME/bin"
    local force=false
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            --path)
                install_path="$2"
                shift 2
                ;;
            --force)
                force=true
                shift
                ;;
            -h|--help)
                echo "用法: gs-system-repo-install [选项]"
                echo "安装Android Repo工具"
                echo ""
                echo "选项:"
                echo "  --path PATH             安装路径 (默认: $HOME/bin)"
                echo "  --force                 强制重新安装"
                echo "  -h, --help              显示此帮助信息"
                return 0
                ;;
            *)
                echo "错误: 未知参数 $1"
                return 1
                ;;
        esac
    done
    
    if ! _gs_system_repo_check_deps; then
        return 1
    fi
    
    # 检查是否已安装
    if _gs_system_repo_check_installation && [[ "$force" != true ]]; then
        echo "Repo工具已安装"
        echo "版本: $(repo version 2>/dev/null | head -1 || echo '未知')"
        echo "路径: $(which repo)"
        echo ""
        echo "使用 --force 选项强制重新安装"
        return 0
    fi
    
    echo "正在安装Android Repo工具..."
    
    # 创建安装目录
    if ! mkdir -p "$install_path"; then
        echo "错误: 无法创建安装目录: $install_path"
        return 1
    fi
    
    # 下载Repo工具
    local repo_file="$install_path/repo"
    local download_url="https://storage.googleapis.com/git-repo-downloads/repo"
    
    # 如果设置了REPO_URL，使用对应的下载链接
    if [[ -n "$REPO_URL" ]]; then
        case "$REPO_URL" in
            *"tsinghua"*)
                download_url="https://mirrors.tuna.tsinghua.edu.cn/git/git-repo/+/refs/heads/main/repo?format=TEXT"
                ;;
        esac
    fi
    
    echo "下载中: $download_url"
    if command -v curl >/dev/null 2>&1; then
        if ! curl -o "$repo_file" "$download_url"; then
            echo "错误: 下载失败"
            return 1
        fi
    elif command -v wget >/dev/null 2>&1; then
        if ! wget -O "$repo_file" "$download_url"; then
            echo "错误: 下载失败"
            return 1
        fi
    else
        echo "错误: 需要curl或wget来下载Repo工具"
        return 1
    fi
    
    # 设置可执行权限
    chmod a+x "$repo_file"
    
    # 检查安装是否成功
    if [[ -x "$repo_file" ]]; then
        echo "✅ Repo工具安装成功"
        echo "   安装路径: $repo_file"
        
        # 检查PATH设置
        if [[ ":$PATH:" != *":$install_path:"* ]]; then
            echo ""
            echo "💡 将以下内容添加到 ~/.bashrc 或 ~/.zshrc:"
            echo "   export PATH=\"$install_path:\$PATH\""
            echo ""
            echo "然后重启终端或执行:"
            echo "   source ~/.bashrc  # 或 source ~/.zshrc"
        fi
    else
        echo "❌ Repo工具安装失败"
        return 1
    fi
    
    return 0
}

# 帮助信息
gs_system_repo_help() {
    echo "System Repo 子模块 - Android Repo工具管理"
    echo "======================================="
    echo ""
    echo "可用命令:"
    echo "  gs-system-repo-status         显示Repo工具状态"
    echo "  gs-system-repo-url-google     设置Google官方源"
    echo "  gs-system-repo-url-tsinghua   设置清华大学镜像源"
    echo "  gs-system-repo-url-intel      设置Intel镜像源"
    echo "  gs-system-repo-url-reset      重置为默认设置"
    echo "  gs-system-repo-install        安装Repo工具"
    echo "  gs-system-repo-help           显示此帮助信息"
    echo ""
    echo "常用操作:"
    echo "  1. 检查Repo状态:"
    echo "     gs-system-repo-status"
    echo "     gs-system-repo-status --detailed"
    echo ""
    echo "  2. 设置镜像源（推荐国内用户）:"
    echo "     gs-system-repo-url-tsinghua --permanent"
    echo ""
    echo "  3. 恢复官方源:"
    echo "     gs-system-repo-url-google --permanent"
    echo ""
    echo "  4. 安装Repo工具:"
    echo "     gs-system-repo-install"
    echo ""
    echo "  5. 重置配置:"
    echo "     gs-system-repo-url-reset --permanent"
    echo ""
    echo "关于Android Repo:"
    echo "  Repo是Google开发的用于管理多个Git仓库的工具"
    echo "  主要用于Android源码(AOSP)的下载和管理"
    echo "  通过REPO_URL环境变量可以指定Repo工具的下载源"
    echo ""
    echo "环境变量:"
    echo "  REPO_URL                      指定Repo工具下载源"
    echo ""
    echo "注意事项:"
    echo "  - 使用--permanent选项可以永久保存设置"
    echo "  - 国内用户建议使用清华镜像源以获得更快的下载速度"
    echo "  - Repo工具需要Python环境支持"
    
    return 0
}