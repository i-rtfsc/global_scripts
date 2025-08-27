#!/bin/bash

# IM集成工具 - 支持钉钉、飞书、微信等
# 基于V2版本的IM工具功能实现

# 发送钉钉消息
gs_utils_im_ding() {
    local webhook_url="$1"
    local message="$2"
    local msg_type="${3:-text}"
    
    if [[ -z "$webhook_url" ]] || [[ -z "$message" ]]; then
        echo "错误: 缺少webhook URL或消息内容" >&2
        return 1
    fi
    
    local json_data
    case "$msg_type" in
        "text")
            json_data=$(cat << EOF
{
    "msgtype": "text",
    "text": {
        "content": "$message"
    }
}
EOF
)
            ;;
        "markdown")
            json_data=$(cat << EOF
{
    "msgtype": "markdown",
    "markdown": {
        "title": "通知",
        "text": "$message"
    }
}
EOF
)
            ;;
        *)
            echo "错误: 不支持的消息类型 '$msg_type'" >&2
            return 1
            ;;
    esac
    
    local response
    response=$(curl -s -X POST "$webhook_url" \
        -H "Content-Type: application/json" \
        -d "$json_data")
    
    if [[ $? -eq 0 ]]; then
        if [[ "${GS_OUTPUT_JSON:-false}" == "true" ]]; then
            echo "$response"
        else
            echo "✅ 钉钉消息发送成功"
        fi
        return 0
    else
        echo "❌ 钉钉消息发送失败" >&2
        return 1
    fi
}

# 发送飞书消息
gs_utils_im_feishu() {
    local webhook_url="$1"
    local message="$2"
    local msg_type="${3:-text}"
    
    if [[ -z "$webhook_url" ]] || [[ -z "$message" ]]; then
        echo "错误: 缺少webhook URL或消息内容" >&2
        return 1
    fi
    
    local json_data
    case "$msg_type" in
        "text")
            json_data=$(cat << EOF
{
    "msg_type": "text",
    "content": {
        "text": "$message"
    }
}
EOF
)
            ;;
        "rich_text")
            json_data=$(cat << EOF
{
    "msg_type": "rich_text",
    "content": {
        "rich_text": {
            "elements": [
                {
                    "tag": "text",
                    "text": "$message"
                }
            ]
        }
    }
}
EOF
)
            ;;
        *)
            echo "错误: 不支持的消息类型 '$msg_type'" >&2
            return 1
            ;;
    esac
    
    local response
    response=$(curl -s -X POST "$webhook_url" \
        -H "Content-Type: application/json" \
        -d "$json_data")
    
    if [[ $? -eq 0 ]]; then
        if [[ "${GS_OUTPUT_JSON:-false}" == "true" ]]; then
            echo "$response"
        else
            echo "✅ 飞书消息发送成功"
        fi
        return 0
    else
        echo "❌ 飞书消息发送失败" >&2
        return 1
    fi
}

# 发送企业微信消息
gs_utils_im_wechat() {
    local webhook_url="$1"
    local message="$2"
    local msg_type="${3:-text}"
    
    if [[ -z "$webhook_url" ]] || [[ -z "$message" ]]; then
        echo "错误: 缺少webhook URL或消息内容" >&2
        return 1
    fi
    
    local json_data
    case "$msg_type" in
        "text")
            json_data=$(cat << EOF
{
    "msgtype": "text",
    "text": {
        "content": "$message"
    }
}
EOF
)
            ;;
        "markdown")
            json_data=$(cat << EOF
{
    "msgtype": "markdown",
    "markdown": {
        "content": "$message"
    }
}
EOF
)
            ;;
        *)
            echo "错误: 不支持的消息类型 '$msg_type'" >&2
            return 1
            ;;
    esac
    
    local response
    response=$(curl -s -X POST "$webhook_url" \
        -H "Content-Type: application/json" \
        -d "$json_data")
    
    if [[ $? -eq 0 ]]; then
        if [[ "${GS_OUTPUT_JSON:-false}" == "true" ]]; then
            echo "$response"
        else
            echo "✅ 企业微信消息发送成功"
        fi
        return 0
    else
        echo "❌ 企业微信消息发送失败" >&2
        return 1
    fi
}

# 从配置文件读取webhook
_gs_im_get_webhook() {
    local platform="$1"
    local config_file="${GS_CONFIG_DIR:-$HOME/.config/gs}/im.conf"
    
    if [[ -f "$config_file" ]]; then
        case "$platform" in
            "ding"|"dingding")
                grep "^DING_WEBHOOK=" "$config_file" | cut -d'=' -f2- | tr -d '"'"'"
                ;;
            "feishu"|"lark")
                grep "^FEISHU_WEBHOOK=" "$config_file" | cut -d'=' -f2- | tr -d '"'"'"
                ;;
            "wechat"|"wecom")
                grep "^WECHAT_WEBHOOK=" "$config_file" | cut -d'=' -f2- | tr -d '"'"'"
                ;;
        esac
    fi
}

# 设置webhook配置
gs_utils_im_config() {
    local platform="$1"
    local webhook_url="$2"
    local config_file="${GS_CONFIG_DIR:-$HOME/.config/gs}/im.conf"
    
    if [[ -z "$platform" ]] || [[ -z "$webhook_url" ]]; then
        echo "错误: 请指定平台和webhook URL" >&2
        echo "支持的平台: ding, feishu, wechat" >&2
        return 1
    fi
    
    # 创建配置目录
    mkdir -p "$(dirname "$config_file")"
    
    # 更新配置
    local var_name
    case "$platform" in
        "ding"|"dingding")
            var_name="DING_WEBHOOK"
            ;;
        "feishu"|"lark")
            var_name="FEISHU_WEBHOOK"
            ;;
        "wechat"|"wecom")
            var_name="WECHAT_WEBHOOK"
            ;;
        *)
            echo "错误: 不支持的平台 '$platform'" >&2
            return 1
            ;;
    esac
    
    # 移除旧配置
    if [[ -f "$config_file" ]]; then
        grep -v "^${var_name}=" "$config_file" > "${config_file}.tmp" || true
        mv "${config_file}.tmp" "$config_file"
    fi
    
    # 添加新配置
    echo "${var_name}=\"${webhook_url}\"" >> "$config_file"
    echo "✅ 配置已保存: $platform webhook"
}

# 主入口函数
gs_utils_im_main() {
    local platform=""
    local webhook_url=""
    local message=""
    local msg_type="text"
    local action="send"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --ding|--dingding)
                platform="ding"
                shift
                ;;
            --feishu|--lark)
                platform="feishu"
                shift
                ;;
            --wechat|--wecom)
                platform="wechat"
                shift
                ;;
            --webhook|-w)
                webhook_url="$2"
                shift 2
                ;;
            --message|-m)
                message="$2"
                shift 2
                ;;
            --type|-t)
                msg_type="$2"
                shift 2
                ;;
            --config|-c)
                action="config"
                shift
                ;;
            --json)
                export GS_OUTPUT_JSON=true
                shift
                ;;
            --help|-h)
                gs_utils_im_help
                return 0
                ;;
            *)
                if [[ -z "$message" ]]; then
                    message="$1"
                fi
                shift
                ;;
        esac
    done
    
    case "$action" in
        "config")
            gs_utils_im_config "$platform" "$webhook_url"
            ;;
        "send")
            if [[ -z "$platform" ]]; then
                echo "错误: 请指定平台 (--ding, --feishu, --wechat)" >&2
                gs_utils_im_help
                return 1
            fi
            
            if [[ -z "$message" ]]; then
                echo "错误: 请指定消息内容" >&2
                return 1
            fi
            
            # 如果没有指定webhook，尝试从配置读取
            if [[ -z "$webhook_url" ]]; then
                webhook_url=$(_gs_im_get_webhook "$platform")
                if [[ -z "$webhook_url" ]]; then
                    echo "错误: 未配置 $platform webhook，请先使用 --config 配置" >&2
                    return 1
                fi
            fi
            
            case "$platform" in
                "ding")
                    gs_utils_im_ding "$webhook_url" "$message" "$msg_type"
                    ;;
                "feishu")
                    gs_utils_im_feishu "$webhook_url" "$message" "$msg_type"
                    ;;
                "wechat")
                    gs_utils_im_wechat "$webhook_url" "$message" "$msg_type"
                    ;;
            esac
            ;;
        *)
            gs_utils_im_help
            ;;
    esac
}

# 帮助函数
gs_utils_im_help() {
    cat << 'EOF'
IM集成工具 - 即时通讯平台消息发送

用法:
    gs-utils-im [平台选项] [选项] <消息内容>

平台选项:
    --ding, --dingding      钉钉平台
    --feishu, --lark        飞书平台
    --wechat, --wecom       企业微信平台

选项:
    --webhook, -w <URL>     指定webhook URL
    --message, -m <内容>    指定消息内容
    --type, -t <类型>       消息类型(text,markdown等)
    --config, -c            配置webhook
    --json                  JSON格式输出
    --help, -h              显示此帮助信息

示例:
    # 配置webhook
    gs-utils-im --ding --config --webhook "https://..."
    
    # 发送文本消息
    gs-utils-im --ding --message "Hello World"
    gs-utils-im --feishu "测试消息"
    
    # 发送markdown消息
    gs-utils-im --ding --type markdown --message "# 标题\n内容"
    
    # 使用自定义webhook
    gs-utils-im --wechat --webhook "https://..." --message "临时消息"

支持的消息类型:
    钉钉: text, markdown
    飞书: text, rich_text
    企业微信: text, markdown
EOF
}

# 如果直接执行此脚本
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    gs_utils_im_main "$@"
fi