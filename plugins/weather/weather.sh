#!/bin/bash
# -*- coding: utf-8 -*-

# 天气查询插件 - Shell封装脚本
# Weather Query Plugin - Shell Wrapper

# 获取脚本目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="$SCRIPT_DIR/weather.py"

# 默认使用python3
PYTHON_CMD="python3"

# 检查Python环境
check_python() {
    if ! command -v python3 &> /dev/null; then
        if command -v python &> /dev/null; then
            PYTHON_CMD="python"
        else
            echo "错误: 未找到Python环境，请安装Python 3.x"
            exit 1
        fi
    fi
}

# 显示帮助信息
show_help() {
    cat << EOF
天气查询插件 - GlobalScripts Weather Plugin

用法:
    gs-weather [选项] [城市名]

参数:
    城市名              要查询的城市名称 (默认: 上海)

选项:
    --simple           简化显示模式
    --debug            显示调试信息（包括API响应时间）
    --help, -h         显示此帮助信息
    --version, -v      显示版本信息

示例:
    gs-weather                    # 查询上海天气
    gs-weather 北京               # 查询北京天气  
    gs-weather 深圳南山           # 查询深圳南山天气
    gs-weather --simple 广州      # 简化模式查询广州天气
    gs-weather --debug 上海       # 显示调试信息

支持的城市格式:
    - 城市名: 北京, 上海, 广州
    - 区县名: 海淀, 朝阳, 浦东
    - 组合名: 北京海淀, 上海浦东, 深圳南山
    - 英文名: Beijing, Shanghai (避免地名歧义)

注意:
    - 使用Open-Meteo API提供准确的全球天气数据
    - 显示效果模仿wttr.in的ASCII艺术风格，支持彩色显示
    - 首次查询较慢，后续查询使用缓存，速度很快
    - 需要网络连接获取实时天气数据
EOF
}

# 显示版本信息
show_version() {
    echo "GlobalScripts Weather Plugin v1.0.0"
    echo "使用Open-Meteo API - https://open-meteo.com/"
}

# 主函数
main() {
    # 检查Python环境
    check_python
    
    # 解析参数
    case "$1" in
        --help|-h)
            show_help
            exit 0
            ;;
        --version|-v)
            show_version
            exit 0
            ;;
        --simple)
            shift
            exec "$PYTHON_CMD" "$PYTHON_SCRIPT" --simple "$@"
            ;;
        --debug)
            shift
            exec "$PYTHON_CMD" "$PYTHON_SCRIPT" --debug "$@"
            ;;
        *)
            exec "$PYTHON_CMD" "$PYTHON_SCRIPT" "$@"
            ;;
    esac
}

# 执行主函数
main "$@"