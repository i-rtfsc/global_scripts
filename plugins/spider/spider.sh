#!/bin/bash
# Spider爬虫管理插件
# Spider Crawler Management Plugin
# 提供网站爬虫工具管理功能

# 检查Python环境
_gs_spider_check_python() {
    if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
        echo "错误: Python环境未安装"
        echo "请安装Python3后重试"
        return 1
    fi
    return 0
}

# 检查爬虫脚本是否存在
_gs_spider_check_script() {
    local script_name="$1"
    local script_path=""
    
    # 查找脚本路径
    if command -v "$script_name" &> /dev/null; then
        script_path=$(which "$script_name")
    elif [[ -f "./$script_name" ]]; then
        script_path="./$script_name"
    elif [[ -f "$HOME/bin/$script_name" ]]; then
        script_path="$HOME/bin/$script_name"
    else
        return 1
    fi
    
    echo "$script_path"
    return 0
}

# CSDN爬虫
gs_spider_csdn() {
    local users=()
    local urls=()
    local batch_mode=false
    local output_dir=""
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -u|--user)
                users+=("$2")
                shift 2
                ;;
            --url)
                urls+=("$2")
                shift 2
                ;;
            -b|--batch)
                batch_mode=true
                shift
                ;;
            -o|--output)
                output_dir="$2"
                shift 2
                ;;
            -h|--help)
                echo "用法: gs-spider-csdn [选项]"
                echo "CSDN网站爬虫工具"
                echo ""
                echo "选项:"
                echo "  -u, --user USER         指定CSDN用户名"
                echo "  --url URL               指定文章URL"
                echo "  -b, --batch             批量模式(使用预设列表)"
                echo "  -o, --output DIR        输出目录"
                echo "  -h, --help              显示此帮助信息"
                return 0
                ;;
            *)
                echo "错误: 未知参数 $1"
                return 1
                ;;
        esac
    done
    
    if ! _gs_spider_check_python; then
        return 1
    fi
    
    local csdn_script
    if ! csdn_script=$(_gs_spider_check_script "csdn.py"); then
        echo "错误: 找不到csdn.py脚本"
        echo "请确保csdn.py在PATH中或当前目录"
        return 1
    fi
    
    # 构建命令参数
    local cmd_args=""
    if [[ -n "$output_dir" ]]; then
        cmd_args="$cmd_args --output $output_dir"
    fi
    
    local total_tasks=$((${#users[@]} + ${#urls[@]}))
    local current_task=0
    
    echo "开始CSDN爬虫任务..."
    echo "用户数: ${#users[@]}, URL数: ${#urls[@]}"
    echo "==================="
    
    # 处理用户
    for user in "${users[@]}"; do
        current_task=$((current_task + 1))
        echo "[$current_task/$total_tasks] 处理用户: $user"
        
        if python3 "$csdn_script" --url "$user" $cmd_args; then
            echo "✅ 用户 $user 处理完成"
        else
            echo "❌ 用户 $user 处理失败"
        fi
        echo ""
    done
    
    # 处理URL
    for url in "${urls[@]}"; do
        current_task=$((current_task + 1))
        echo "[$current_task/$total_tasks] 处理URL: $url"
        
        if python3 "$csdn_script" --url "$url" $cmd_args; then
            echo "✅ URL处理完成"
        else
            echo "❌ URL处理失败"
        fi
        echo ""
    done
    
    echo "CSDN爬虫任务完成！"
    return 0
}

# 博客园爬虫
gs_spider_cnblogs() {
    local users=()
    local urls=()
    local batch_mode=false
    local output_dir=""
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -u|--user)
                users+=("$2")
                shift 2
                ;;
            --url)
                urls+=("$2")
                shift 2
                ;;
            -b|--batch)
                batch_mode=true
                shift
                ;;
            -o|--output)
                output_dir="$2"
                shift 2
                ;;
            -h|--help)
                echo "用法: gs-spider-cnblogs [选项]"
                echo "博客园网站爬虫工具"
                echo ""
                echo "选项:"
                echo "  -u, --user USER         指定博客园用户名"
                echo "  --url URL               指定文章URL"
                echo "  -b, --batch             批量模式(使用预设列表)"
                echo "  -o, --output DIR        输出目录"
                echo "  -h, --help              显示此帮助信息"
                return 0
                ;;
            *)
                echo "错误: 未知参数 $1"
                return 1
                ;;
        esac
    done
    
    if ! _gs_spider_check_python; then
        return 1
    fi
    
    local cnblogs_script
    if ! cnblogs_script=$(_gs_spider_check_script "cnblogs.py"); then
        echo "错误: 找不到cnblogs.py脚本"
        echo "请确保cnblogs.py在PATH中或当前目录"
        return 1
    fi
    
    # 构建命令参数
    local cmd_args=""
    if [[ -n "$output_dir" ]]; then
        cmd_args="$cmd_args --output $output_dir"
    fi
    
    local total_tasks=$((${#users[@]} + ${#urls[@]}))
    local current_task=0
    local start_time=$(date +%s)
    
    echo "开始博客园爬虫任务..."
    echo "用户数: ${#users[@]}, URL数: ${#urls[@]}"
    echo "开始时间: $(date)"
    echo "==================="
    
    # 处理用户
    for user in "${users[@]}"; do
        current_task=$((current_task + 1))
        echo "[$current_task/$total_tasks] 处理用户: $user"
        
        if python3 "$cnblogs_script" --url "$user" $cmd_args; then
            echo "✅ 用户 $user 处理完成"
        else
            echo "❌ 用户 $user 处理失败"
        fi
        echo ""
    done
    
    # 处理URL
    for url in "${urls[@]}"; do
        current_task=$((current_task + 1))
        echo "[$current_task/$total_tasks] 处理URL: $url"
        
        if python3 "$cnblogs_script" --url "$url" $cmd_args; then
            echo "✅ URL处理完成"
        else
            echo "❌ URL处理失败"
        fi
        echo ""
    done
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    echo "博客园爬虫任务完成！"
    echo "总耗时: ${duration}秒"
    return 0
}

# 简书爬虫
gs_spider_jianshu() {
    local users=()
    local urls=()
    local batch_mode=false
    local output_dir=""
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -u|--user)
                users+=("$2")
                shift 2
                ;;
            --url)
                urls+=("$2")
                shift 2
                ;;
            -b|--batch)
                batch_mode=true
                shift
                ;;
            -o|--output)
                output_dir="$2"
                shift 2
                ;;
            -h|--help)
                echo "用法: gs-spider-jianshu [选项]"
                echo "简书网站爬虫工具"
                echo ""
                echo "选项:"
                echo "  -u, --user USER         指定简书用户名"
                echo "  --url URL               指定文章URL"
                echo "  -b, --batch             批量模式(使用预设列表)"
                echo "  -o, --output DIR        输出目录"
                echo "  -h, --help              显示此帮助信息"
                return 0
                ;;
            *)
                echo "错误: 未知参数 $1"
                return 1
                ;;
        esac
    done
    
    if ! _gs_spider_check_python; then
        return 1
    fi
    
    local jianshu_script
    if ! jianshu_script=$(_gs_spider_check_script "jianshu.py"); then
        echo "错误: 找不到jianshu.py脚本"
        echo "请确保jianshu.py在PATH中或当前目录"
        return 1
    fi
    
    # 构建命令参数
    local cmd_args=""
    if [[ -n "$output_dir" ]]; then
        cmd_args="$cmd_args --output $output_dir"
    fi
    
    local total_tasks=$((${#users[@]} + ${#urls[@]}))
    local current_task=0
    local start_time=$(date +%s)
    
    echo "开始简书爬虫任务..."
    echo "用户数: ${#users[@]}, URL数: ${#urls[@]}"
    echo "开始时间: $(date)"
    echo "==================="
    
    # 处理用户
    for user in "${users[@]}"; do
        current_task=$((current_task + 1))
        echo "[$current_task/$total_tasks] 处理用户: $user"
        
        if python3 "$jianshu_script" --url "$user" $cmd_args; then
            echo "✅ 用户 $user 处理完成"
        else
            echo "❌ 用户 $user 处理失败"
        fi
        echo ""
    done
    
    # 处理URL
    for url in "${urls[@]}"; do
        current_task=$((current_task + 1))
        echo "[$current_task/$total_tasks] 处理URL: $url"
        
        if python3 "$jianshu_script" --url "$url" $cmd_args; then
            echo "✅ URL处理完成"
        else
            echo "❌ URL处理失败"
        fi
        echo ""
    done
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    echo "简书爬虫任务完成！"
    echo "总耗时: ${duration}秒"
    return 0
}

# 爬虫任务管理
gs_spider_task() {
    local action="$1"
    local task_file="spider_tasks.txt"
    
    case $action in
        create)
            local site="$2"
            local target="$3"
            local task_type="$4"
            
            if [[ -z "$site" ]] || [[ -z "$target" ]]; then
                echo "错误: 请指定网站和目标"
                echo "用法: gs-spider-task create <site> <target> [type]"
                echo "示例: gs-spider-task create csdn vviccc user"
                return 1
            fi
            
            task_type="${task_type:-auto}"
            local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
            
            echo "$timestamp|$site|$target|$task_type|pending" >> "$task_file"
            echo "✅ 任务已创建: $site -> $target ($task_type)"
            ;;
            
        list)
            if [[ ! -f "$task_file" ]]; then
                echo "没有找到任务文件"
                return 0
            fi
            
            echo "爬虫任务列表"
            echo "============"
            printf "%-20s %-10s %-30s %-8s %-10s\n" "时间" "网站" "目标" "类型" "状态"
            echo "$(printf '%.0s-' {1..80})"
            
            while IFS='|' read -r timestamp site target task_type status; do
                printf "%-20s %-10s %-30s %-8s %-10s\n" "$timestamp" "$site" "$target" "$task_type" "$status"
            done < "$task_file"
            ;;
            
        run)
            if [[ ! -f "$task_file" ]]; then
                echo "没有找到任务文件"
                return 1
            fi
            
            echo "开始执行爬虫任务..."
            local temp_file="/tmp/spider_tasks_temp.txt"
            
            while IFS='|' read -r timestamp site target task_type status; do
                if [[ "$status" == "pending" ]]; then
                    echo "执行任务: $site -> $target"
                    
                    case $site in
                        csdn)
                            if gs_spider_csdn --user "$target"; then
                                status="completed"
                            else
                                status="failed"
                            fi
                            ;;
                        cnblogs)
                            if gs_spider_cnblogs --user "$target"; then
                                status="completed"
                            else
                                status="failed"
                            fi
                            ;;
                        jianshu)
                            if gs_spider_jianshu --user "$target"; then
                                status="completed"
                            else
                                status="failed"
                            fi
                            ;;
                        *)
                            echo "警告: 未知网站类型 $site"
                            status="skipped"
                            ;;
                    esac
                fi
                
                echo "$timestamp|$site|$target|$task_type|$status" >> "$temp_file"
            done < "$task_file"
            
            mv "$temp_file" "$task_file"
            echo "任务执行完成！"
            ;;
            
        clear)
            if [[ -f "$task_file" ]]; then
                rm "$task_file"
                echo "✅ 任务列表已清空"
            else
                echo "任务列表为空"
            fi
            ;;
            
        *)
            echo "用法: gs-spider-task <command> [options]"
            echo ""
            echo "命令:"
            echo "  create <site> <target> [type]  创建爬虫任务"
            echo "  list                           显示任务列表"
            echo "  run                            执行待处理任务"
            echo "  clear                          清空任务列表"
            echo ""
            echo "支持的网站: csdn, cnblogs, jianshu"
            return 1
            ;;
    esac
    
    return 0
}

# 帮助信息
gs_spider_help() {
    echo "Spider 爬虫管理插件"
    echo "=================="
    echo ""
    echo "可用命令:"
    echo "  gs-spider-csdn        CSDN网站爬虫"
    echo "  gs-spider-cnblogs     博客园网站爬虫"
    echo "  gs-spider-jianshu     简书网站爬虫"
    echo "  gs-spider-task        爬虫任务管理"
    echo "  gs-spider-help        显示此帮助信息"
    echo ""
    echo "常用操作:"
    echo "  1. 单个网站爬虫:"
    echo "     gs-spider-csdn -u 用户名"
    echo "     gs-spider-cnblogs --url '网址'"
    echo "     gs-spider-jianshu -b                    # 批量模式"
    echo ""
    echo "  2. 批量爬虫:"
    echo "     gs-spider-batch                         # 执行所有网站批量爬虫"
    echo ""
    echo "  3. 任务管理:"
    echo "     gs-spider-task create csdn vviccc user  # 创建任务"
    echo "     gs-spider-task list                     # 查看任务"
    echo "     gs-spider-task run                      # 执行任务"
    echo ""
    echo "支持的网站:"
    echo "  - CSDN (blog.csdn.net)"
    echo "  - 博客园 (cnblogs.com)"
    echo "  - 简书 (jianshu.com)"
    echo ""
    echo "依赖要求:"
    echo "  - Python 3.x"
    echo "  - 对应的爬虫脚本 (csdn.py, cnblogs.py, jianshu.py)"
    echo ""
    echo "使用 'gs-spider-<command> --help' 查看特定命令的详细帮助"
    
    return 0
}