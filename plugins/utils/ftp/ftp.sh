#!/bin/bash

# FTP文件传输工具
# 基于V2版本的FTP工具功能实现，支持上传、下载、目录操作

# FTP上传文件
gs_utils_ftp_upload() {
    local local_file="$1"
    local remote_path="$2"
    local ftp_host="$3"
    local ftp_user="$4"
    local ftp_pass="$5"
    local ftp_port="${6:-21}"
    
    if [[ -z "$local_file" ]] || [[ -z "$ftp_host" ]] || [[ -z "$ftp_user" ]]; then
        echo "错误: 缺少必要参数" >&2
        return 1
    fi
    
    if [[ ! -f "$local_file" ]]; then
        echo "错误: 本地文件不存在: $local_file" >&2
        return 1
    fi
    
    local remote_file="${remote_path:-$(basename "$local_file")}"
    local ftp_url="ftp://${ftp_host}:${ftp_port}/${remote_file}"
    
    echo "正在上传文件到FTP服务器..."
    echo "本地文件: $local_file"
    echo "远程路径: $remote_file"
    
    if curl -T "$local_file" -u "${ftp_user}:${ftp_pass}" "$ftp_url" --silent --show-error; then
        echo "✅ 文件上传成功"
        return 0
    else
        echo "❌ 文件上传失败" >&2
        return 1
    fi
}

# FTP下载文件
gs_utils_ftp_download() {
    local remote_file="$1"
    local local_path="$2"
    local ftp_host="$3"
    local ftp_user="$4"
    local ftp_pass="$5"
    local ftp_port="${6:-21}"
    
    if [[ -z "$remote_file" ]] || [[ -z "$ftp_host" ]] || [[ -z "$ftp_user" ]]; then
        echo "错误: 缺少必要参数" >&2
        return 1
    fi
    
    local local_file="${local_path:-$(basename "$remote_file")}"
    local ftp_url="ftp://${ftp_host}:${ftp_port}/${remote_file}"
    
    echo "正在从FTP服务器下载文件..."
    echo "远程文件: $remote_file"
    echo "本地路径: $local_file"
    
    if curl -o "$local_file" -u "${ftp_user}:${ftp_pass}" "$ftp_url" --silent --show-error; then
        echo "✅ 文件下载成功"
        return 0
    else
        echo "❌ 文件下载失败" >&2
        return 1
    fi
}

# FTP列出目录
gs_utils_ftp_list() {
    local remote_dir="$1"
    local ftp_host="$2"
    local ftp_user="$3"
    local ftp_pass="$4"
    local ftp_port="${5:-21}"
    
    if [[ -z "$ftp_host" ]] || [[ -z "$ftp_user" ]]; then
        echo "错误: 缺少必要参数" >&2
        return 1
    fi
    
    local ftp_url="ftp://${ftp_host}:${ftp_port}/${remote_dir:-}"
    
    echo "FTP目录列表: ${remote_dir:-/}"
    echo "========================="
    
    if curl -l -u "${ftp_user}:${ftp_pass}" "$ftp_url" --silent --show-error; then
        return 0
    else
        echo "❌ 获取目录列表失败" >&2
        return 1
    fi
}

# FTP删除文件
gs_utils_ftp_delete() {
    local remote_file="$1"
    local ftp_host="$2"
    local ftp_user="$3"
    local ftp_pass="$4"
    local ftp_port="${5:-21}"
    
    if [[ -z "$remote_file" ]] || [[ -z "$ftp_host" ]] || [[ -z "$ftp_user" ]]; then
        echo "错误: 缺少必要参数" >&2
        return 1
    fi
    
    local ftp_url="ftp://${ftp_host}:${ftp_port}/"
    
    echo "正在删除远程文件: $remote_file"
    
    # 使用curl发送FTP DELE命令
    if curl -Q "DELE $remote_file" -u "${ftp_user}:${ftp_pass}" "$ftp_url" --silent --show-error; then
        echo "✅ 文件删除成功"
        return 0
    else
        echo "❌ 文件删除失败" >&2
        return 1
    fi
}

# 从配置文件读取FTP配置
_gs_ftp_get_config() {
    local config_name="$1"
    local config_file="${GS_CONFIG_DIR:-$HOME/.config/gs}/ftp.conf"
    
    if [[ -f "$config_file" ]] && [[ -n "$config_name" ]]; then
        local prefix="${config_name}_"
        grep "^${prefix}" "$config_file" | while IFS='=' read -r key value; do
            local var_name="${key#${prefix}}"
            echo "${var_name}=${value}"
        done
    fi
}

# 设置FTP配置
gs_utils_ftp_config() {
    local config_name="$1"
    local host="$2"
    local user="$3"
    local pass="$4"
    local port="${5:-21}"
    
    if [[ -z "$config_name" ]] || [[ -z "$host" ]] || [[ -z "$user" ]]; then
        echo "错误: 请指定配置名称、主机和用户名" >&2
        return 1
    fi
    
    local config_file="${GS_CONFIG_DIR:-$HOME/.config/gs}/ftp.conf"
    mkdir -p "$(dirname "$config_file")"
    
    # 移除旧配置
    if [[ -f "$config_file" ]]; then
        grep -v "^${config_name}_" "$config_file" > "${config_file}.tmp" || true
        mv "${config_file}.tmp" "$config_file"
    fi
    
    # 添加新配置
    cat >> "$config_file" << EOF
${config_name}_HOST=${host}
${config_name}_USER=${user}
${config_name}_PASS=${pass}
${config_name}_PORT=${port}
EOF
    
    echo "✅ FTP配置已保存: $config_name"
}

# 批量操作：同步目录
gs_utils_ftp_sync() {
    local local_dir="$1"
    local remote_dir="$2"
    local ftp_host="$3"
    local ftp_user="$4"
    local ftp_pass="$5"
    local ftp_port="${6:-21}"
    
    if [[ ! -d "$local_dir" ]]; then
        echo "错误: 本地目录不存在: $local_dir" >&2
        return 1
    fi
    
    echo "开始同步目录: $local_dir -> $remote_dir"
    
    local success_count=0
    local fail_count=0
    
    # 遍历本地目录文件
    find "$local_dir" -type f | while read -r file; do
        local relative_path="${file#${local_dir}/}"
        local remote_file="${remote_dir}/${relative_path}"
        
        echo "上传: $relative_path"
        if gs_utils_ftp_upload "$file" "$remote_file" "$ftp_host" "$ftp_user" "$ftp_pass" "$ftp_port" >/dev/null 2>&1; then
            ((success_count++))
        else
            ((fail_count++))
            echo "  ❌ 上传失败: $relative_path"
        fi
    done
    
    echo "同步完成: 成功 $success_count 个，失败 $fail_count 个"
}

# 主入口函数
gs_utils_ftp_main() {
    local action=""
    local local_file=""
    local remote_file=""
    local ftp_host=""
    local ftp_user=""
    local ftp_pass=""
    local ftp_port="21"
    local config_name=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --upload|-u)
                action="upload"
                shift
                ;;
            --download|-d)
                action="download"
                shift
                ;;
            --list|-l)
                action="list"
                shift
                ;;
            --delete|--del)
                action="delete"
                shift
                ;;
            --sync|-s)
                action="sync"
                shift
                ;;
            --config|-c)
                action="config"
                shift
                ;;
            --host|-h)
                ftp_host="$2"
                shift 2
                ;;
            --user|--username)
                ftp_user="$2"
                shift 2
                ;;
            --pass|--password)
                ftp_pass="$2"
                shift 2
                ;;
            --port|-p)
                ftp_port="$2"
                shift 2
                ;;
            --profile)
                config_name="$2"
                shift 2
                ;;
            --local)
                local_file="$2"
                shift 2
                ;;
            --remote)
                remote_file="$2"
                shift 2
                ;;
            --json)
                export GS_OUTPUT_JSON=true
                shift
                ;;
            --help)
                gs_utils_ftp_help
                return 0
                ;;
            *)
                if [[ -z "$local_file" ]] && [[ "$action" == "upload" ]]; then
                    local_file="$1"
                elif [[ -z "$remote_file" ]] && [[ "$action" == "download" ]]; then
                    remote_file="$1"
                fi
                shift
                ;;
        esac
    done
    
    # 如果指定了配置名称，加载配置
    if [[ -n "$config_name" ]]; then
        eval "$(_gs_ftp_get_config "$config_name")"
        ftp_host="${HOST:-$ftp_host}"
        ftp_user="${USER:-$ftp_user}"
        ftp_pass="${PASS:-$ftp_pass}"
        ftp_port="${PORT:-$ftp_port}"
    fi
    
    case "$action" in
        "upload")
            gs_utils_ftp_upload "$local_file" "$remote_file" "$ftp_host" "$ftp_user" "$ftp_pass" "$ftp_port"
            ;;
        "download")
            gs_utils_ftp_download "$remote_file" "$local_file" "$ftp_host" "$ftp_user" "$ftp_pass" "$ftp_port"
            ;;
        "list")
            gs_utils_ftp_list "$remote_file" "$ftp_host" "$ftp_user" "$ftp_pass" "$ftp_port"
            ;;
        "delete")
            gs_utils_ftp_delete "$remote_file" "$ftp_host" "$ftp_user" "$ftp_pass" "$ftp_port"
            ;;
        "sync")
            gs_utils_ftp_sync "$local_file" "$remote_file" "$ftp_host" "$ftp_user" "$ftp_pass" "$ftp_port"
            ;;
        "config")
            gs_utils_ftp_config "$config_name" "$ftp_host" "$ftp_user" "$ftp_pass" "$ftp_port"
            ;;
        *)
            gs_utils_ftp_help
            ;;
    esac
}

# 帮助函数
gs_utils_ftp_help() {
    cat << 'EOF'
FTP文件传输工具

用法:
    gs-utils-ftp [操作] [选项] [文件路径]

操作:
    --upload, -u        上传文件
    --download, -d      下载文件
    --list, -l          列出目录
    --delete, --del     删除远程文件
    --sync, -s          同步目录
    --config, -c        配置FTP连接

连接选项:
    --host, -h <主机>       FTP服务器地址
    --user <用户名>         FTP用户名
    --pass <密码>          FTP密码
    --port, -p <端口>      FTP端口(默认21)
    --profile <配置名>      使用保存的配置

文件选项:
    --local <路径>         本地文件/目录路径
    --remote <路径>        远程文件/目录路径
    --json                 JSON格式输出
    --help                 显示此帮助信息

示例:
    # 配置FTP连接
    gs-utils-ftp --config --profile myserver --host ftp.example.com --user admin --pass secret
    
    # 上传文件
    gs-utils-ftp --upload --local file.txt --remote /upload/file.txt --profile myserver
    gs-utils-ftp --upload file.txt --host ftp.example.com --user admin --pass secret
    
    # 下载文件
    gs-utils-ftp --download --remote /data/file.txt --local ./file.txt --profile myserver
    
    # 列出目录
    gs-utils-ftp --list --remote /data --profile myserver
    
    # 删除文件
    gs-utils-ftp --delete --remote /temp/old_file.txt --profile myserver
    
    # 同步目录
    gs-utils-ftp --sync --local ./local_dir --remote /remote_dir --profile myserver

注意:
    - 首次使用建议先配置连接信息
    - 密码会保存在配置文件中，注意安全
    - 同步操作会上传本地目录的所有文件
EOF
}

# 如果直接执行此脚本
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    gs_utils_ftp_main "$@"
fi