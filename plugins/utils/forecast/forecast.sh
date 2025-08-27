#!/bin/bash

# 天气预报查询工具
# 基于V2版本的gs_forecast功能实现

# 城市代码映射
declare -A CITY_CODES=(
    ["beijing"]="101010100"
    ["shanghai"]="101020100"
    ["guangzhou"]="101280101"
    ["shenzhen"]="101280601"
    ["hangzhou"]="101210101"
    ["nanjing"]="101190101"
    ["wuhan"]="101200101"
    ["chengdu"]="101270101"
    ["xian"]="101110101"
    ["tianjin"]="101030100"
    ["chongqing"]="101040100"
    ["harbin"]="101050101"
    ["shenyang"]="101070101"
    ["changchun"]="101060101"
    ["jinan"]="101120101"
    ["qingdao"]="101120201"
    ["zhengzhou"]="101180101"
    ["taiyuan"]="101100101"
    ["shijiazhuang"]="101090101"
    ["hohhot"]="101080101"
    ["yinchuan"]="101170101"
    ["xining"]="101150101"
    ["lanzhou"]="101160101"
    ["urumqi"]="101130101"
    ["lhasa"]="101140101"
    ["kunming"]="101290101"
    ["guiyang"]="101260101"
    ["nanning"]="101300101"
    ["haikou"]="101310101"
    ["sanya"]="101310201"
    ["fuzhou"]="101230101"
    ["xiamen"]="101230201"
    ["nanchang"]="101240101"
    ["changsha"]="101250101"
    ["hefei"]="101220101"
]

# 获取城市代码
_gs_forecast_get_city_code() {
    local city="$1"
    local city_lower
    city_lower=$(echo "$city" | tr '[:upper:]' '[:lower:]')
    
    if [[ -n "${CITY_CODES[$city_lower]}" ]]; then
        echo "${CITY_CODES[$city_lower]}"
    else
        echo ""
    fi
}

# 查询天气信息
gs_utils_forecast_weather() {
    local city="$1"
    local days="${2:-3}"
    
    if [[ -z "$city" ]]; then
        echo "错误: 请指定城市名称" >&2
        return 1
    fi
    
    local city_code
    city_code=$(_gs_forecast_get_city_code "$city")
    
    if [[ -z "$city_code" ]]; then
        echo "错误: 不支持的城市 '$city'" >&2
        echo "支持的城市: ${!CITY_CODES[*]}" >&2
        return 1
    fi
    
    echo "正在查询 $city 的天气信息..."
    
    # 使用免费天气API
    local api_url="http://t.weather.sojson.com/api/weather/city/$city_code"
    local response
    
    response=$(curl -s --connect-timeout 10 "$api_url")
    
    if [[ $? -ne 0 ]] || [[ -z "$response" ]]; then
        echo "错误: 无法获取天气数据" >&2
        return 1
    fi
    
    # 检查API响应状态
    local status
    status=$(echo "$response" | jq -r '.status // empty')
    
    if [[ "$status" != "200" ]]; then
        echo "错误: API返回错误状态" >&2
        return 1
    fi
    
    if [[ "${GS_OUTPUT_JSON:-false}" == "true" ]]; then
        echo "$response" | jq '.'
    else
        _gs_forecast_format_output "$response" "$days"
    fi
}

# 格式化输出
_gs_forecast_format_output() {
    local response="$1"
    local days="$2"
    
    # 当前天气
    local city_name temp weather date
    city_name=$(echo "$response" | jq -r '.cityInfo.city // "未知"')
    temp=$(echo "$response" | jq -r '.data.wendu // "N/A"')
    weather=$(echo "$response" | jq -r '.data.forecast[0].type // "N/A"')
    date=$(echo "$response" | jq -r '.date // "N/A"')
    
    echo "===================="
    echo "📍 城市: $city_name"
    echo "📅 日期: $date"
    echo "🌡️  当前温度: ${temp}°C"
    echo "☁️  天气状况: $weather"
    echo "===================="
    echo ""
    
    # 未来几天预报
    echo "📊 未来${days}天预报:"
    echo "--------------------"
    
    local i=0
    while [[ $i -lt $days ]]; do
        local forecast_date forecast_weather forecast_high forecast_low forecast_wind
        
        forecast_date=$(echo "$response" | jq -r ".data.forecast[$i].date // \"N/A\"")
        forecast_weather=$(echo "$response" | jq -r ".data.forecast[$i].type // \"N/A\"")
        forecast_high=$(echo "$response" | jq -r ".data.forecast[$i].high // \"N/A\"" | sed 's/高温 //')
        forecast_low=$(echo "$response" | jq -r ".data.forecast[$i].low // \"N/A\"" | sed 's/低温 //')
        forecast_wind=$(echo "$response" | jq -r ".data.forecast[$i].fx // \"N/A\"")
        
        if [[ "$forecast_date" == "N/A" ]]; then
            break
        fi
        
        echo "$forecast_date | $forecast_weather | $forecast_low~$forecast_high | $forecast_wind"
        ((i++))
    done
    
    echo "--------------------"
    
    # 生活指数
    local ganmao
    ganmao=$(echo "$response" | jq -r '.data.ganmao // "N/A"')
    if [[ "$ganmao" != "N/A" ]]; then
        echo "💡 生活提示: $ganmao"
    fi
}

# 列出支持的城市
gs_utils_forecast_cities() {
    echo "支持的城市列表:"
    echo "==============="
    
    local cities=()
    for city in "${!CITY_CODES[@]}"; do
        cities+=("$city")
    done
    
    # 排序输出
    IFS=$'\n' sorted=($(sort <<<"${cities[*]}"))
    unset IFS
    
    local count=0
    for city in "${sorted[@]}"; do
        printf "%-12s" "$city"
        ((count++))
        if [[ $((count % 6)) -eq 0 ]]; then
            echo ""
        fi
    done
    echo ""
    echo "==============="
    echo "总计: ${#CITY_CODES[@]} 个城市"
}

# 主入口函数
gs_utils_forecast_main() {
    local city=""
    local days=3
    local action="weather"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --city|-c)
                city="$2"
                shift 2
                ;;
            --days|-d)
                days="$2"
                shift 2
                ;;
            --list|-l)
                action="list"
                shift
                ;;
            --json)
                export GS_OUTPUT_JSON=true
                shift
                ;;
            --help|-h)
                gs_utils_forecast_help
                return 0
                ;;
            *)
                if [[ -z "$city" ]]; then
                    city="$1"
                fi
                shift
                ;;
        esac
    done
    
    case "$action" in
        "list")
            gs_utils_forecast_cities
            ;;
        "weather")
            if [[ -z "$city" ]]; then
                echo "错误: 请指定城市名称" >&2
                gs_utils_forecast_help
                return 1
            fi
            gs_utils_forecast_weather "$city" "$days"
            ;;
        *)
            gs_utils_forecast_help
            ;;
    esac
}

# 帮助函数
gs_utils_forecast_help() {
    cat << 'EOF'
天气预报查询工具

用法:
    gs-utils-forecast [选项] [城市名]
    gs-utils-forecast --city <城市名> [选项]

选项:
    --city, -c <城市>   指定城市名称
    --days, -d <天数>   预报天数(1-7，默认3)
    --list, -l          列出支持的城市
    --json              JSON格式输出
    --help, -h          显示此帮助信息

示例:
    gs-utils-forecast beijing           查询北京天气
    gs-utils-forecast --city shanghai   查询上海天气
    gs-utils-forecast --city guangzhou --days 7  查询广州7天天气
    gs-utils-forecast --list            列出支持的城市
    gs-utils-forecast --json beijing    JSON格式输出

支持的主要城市:
    beijing, shanghai, guangzhou, shenzhen, hangzhou,
    nanjing, wuhan, chengdu, xian, tianjin 等

使用 --list 查看完整城市列表。
EOF
}

# 如果直接执行此脚本
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    gs_utils_forecast_main "$@"
fi