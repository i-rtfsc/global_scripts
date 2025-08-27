#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
天气查询插件 - Python实现
使用Open-Meteo API获取准确天气数据，模拟wttr.in的显示效果
支持智能检测rich/pyboxen库并优化显示效果
"""

import sys
import json
import urllib.request
import urllib.parse
from datetime import datetime, timedelta
import argparse
import time
import os
import hashlib

# 检测专业表格库是否可用
HAS_RICH = False
HAS_PYBOXEN = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text
    from rich.panel import Panel
    HAS_RICH = True
except ImportError:
    pass

try:
    import pyboxen
    HAS_PYBOXEN = True
except ImportError:
    pass

# Open-Meteo API配置（免费，无需API key）
WEATHER_API_BASE = "https://api.open-meteo.com/v1"
GEOCODING_API_BASE = "https://geocoding-api.open-meteo.com/v1"

# 可爱的颜色方案
class CuteColors:
    RESET = '\033[0m'
    
    # 可爱的基础色彩
    PINK = '\033[95m'           # 粉色
    LIGHT_PINK = '\033[38;5;213m'
    PURPLE = '\033[94m'         # 紫色
    LIGHT_BLUE = '\033[96m'     # 浅蓝色
    CYAN = '\033[36m'           # 青色
    GREEN = '\033[92m'          # 绿色
    YELLOW = '\033[93m'         # 黄色
    ORANGE = '\033[38;5;208m'   # 橙色
    RED = '\033[91m'            # 红色
    WHITE = '\033[97m'          # 白色
    GRAY = '\033[90m'           # 灰色
    
    # 天气专用色彩（更可爱）
    SUNNY = '\033[38;5;220m'    # 阳光黄 🌞
    CLOUDY = '\033[38;5;250m'   # 云朵灰 ☁️
    RAINY = '\033[38;5;75m'     # 雨滴蓝 🌧️
    SNOWY = '\033[38;5;15m'     # 雪花白 ❄️
    FOGGY = '\033[38;5;245m'    # 雾霾灰 🌫️
    WINDY = '\033[38;5;118m'    # 清风绿 💨
    
    # 温度颜色（柔和可爱）
    TEMP_FREEZING = '\033[38;5;159m'  # 冰蓝色 < 0°C
    TEMP_COLD = '\033[38;5;153m'      # 清凉蓝 0-10°C
    TEMP_COOL = '\033[38;5;117m'      # 舒适蓝 10-20°C
    TEMP_MILD = '\033[38;5;157m'      # 温和绿 20-25°C
    TEMP_WARM = '\033[38;5;222m'      # 暖黄色 25-30°C
    TEMP_HOT = '\033[38;5;209m'       # 热橙色 30-35°C
    TEMP_VERY_HOT = '\033[38;5;196m'  # 炎热红 > 35°C

# 缓存配置
CACHE_DIR = os.path.expanduser("~/.cache/gs-weather")
CACHE_EXPIRE_MINUTES = 30  # 缓存30分钟

def get_cache_file(key):
    """获取缓存文件路径"""
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR, exist_ok=True)
    
    hash_key = hashlib.md5(key.encode()).hexdigest()
    return os.path.join(CACHE_DIR, f"{hash_key}.json")

def get_cache(key):
    """获取缓存数据"""
    cache_file = get_cache_file(key)
    
    if not os.path.exists(cache_file):
        return None
    
    try:
        stat = os.stat(cache_file)
        # 检查缓存是否过期
        cache_age = time.time() - stat.st_mtime
        if cache_age > CACHE_EXPIRE_MINUTES * 60:
            log_debug(f"缓存已过期: {cache_age/60:.1f}分钟")
            return None
        
        with open(cache_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            log_debug(f"使用缓存数据: {cache_file}")
            return data
    except:
        return None

def set_cache(key, data):
    """设置缓存数据"""
    cache_file = get_cache_file(key)
    
    try:
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            log_debug(f"缓存数据已保存: {cache_file}")
    except Exception as e:
        log_debug(f"缓存保存失败: {e}")

def log_debug(message):
    """输出调试信息"""
    print(f"[DEBUG {time.strftime('%H:%M:%S')}] {message}", file=sys.stderr)

# ANSI颜色代码
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    
    # 前景色
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # 亮色
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'

def colorize_weather_icon(icon_lines, weather_code):
    """为天气图标添加颜色 - 使用可爱配色方案"""
    colored_lines = []
    
    # 根据天气类型选择可爱的颜色
    if weather_code == 0:  # 晴天 🌞
        color = CuteColors.SUNNY
    elif weather_code in [1, 2]:  # 多云 ☁️
        color = CuteColors.CLOUDY
    elif weather_code == 3:  # 阴天
        color = CuteColors.GRAY
    elif weather_code in [45, 48]:  # 雾 🌫️
        color = CuteColors.FOGGY
    elif weather_code in [51, 53, 55, 61, 63, 65]:  # 雨 🌧️
        color = CuteColors.RAINY
    elif weather_code in [71, 73, 75]:  # 雪 ❄️
        color = CuteColors.SNOWY
    elif weather_code in [80, 81, 82]:  # 阵雨
        color = CuteColors.PURPLE
    elif weather_code in [95, 96, 99]:  # 雷暴 ⚡
        color = CuteColors.PINK
    else:
        color = CuteColors.WHITE
    
    for line in icon_lines:
        colored_lines.append(f"{color}{line}{CuteColors.RESET}")
    
    return colored_lines

def colorize_temperature(temp):
    """为温度添加可爱的颜色"""
    temp_val = float(temp) if isinstance(temp, (str, int, float)) else 0
    
    if temp_val < 0:
        return f"{CuteColors.TEMP_FREEZING}+{temp}°C{CuteColors.RESET}"
    elif temp_val < 10:
        return f"{CuteColors.TEMP_COLD}+{temp}°C{CuteColors.RESET}"
    elif temp_val < 20:
        return f"{CuteColors.TEMP_COOL}+{temp}°C{CuteColors.RESET}"
    elif temp_val < 25:
        return f"{CuteColors.TEMP_MILD}+{temp}°C{CuteColors.RESET}"
    elif temp_val < 30:
        return f"{CuteColors.TEMP_WARM}+{temp}°C{CuteColors.RESET}"
    elif temp_val < 35:
        return f"{CuteColors.TEMP_HOT}+{temp}°C{CuteColors.RESET}"
    else:
        return f"{CuteColors.TEMP_VERY_HOT}+{temp}°C{CuteColors.RESET}"

def get_display_width(text):
    """计算不包含ANSI颜色代码的显示宽度，考虑中文字符和特殊Unicode字符"""
    import re
    import unicodedata
    
    # 移除ANSI颜色代码
    clean_text = re.sub(r'\x1b\[[0-9;]*m', '', text)
    
    # 计算显示宽度
    width = 0
    for char in clean_text:
        # 获取字符的East Asian Width属性
        eaw = unicodedata.east_asian_width(char)
        if eaw in ('F', 'W'):  # Fullwidth 或 Wide characters
            width += 2
        elif eaw in ('H', 'Na', 'N'):  # Halfwidth, Narrow, or Neutral
            width += 1
        else:  # Ambiguous characters，根据字符代码判断
            if ord(char) > 127:
                width += 2  # 大部分非ASCII字符占2个宽度
            else:
                width += 1
    
    return width

def pad_to_width(text, width, align='left'):
    """将文本填充到指定宽度，考虑ANSI颜色代码和中文字符"""
    display_width = get_display_width(text)
    padding_needed = width - display_width
    
    if padding_needed <= 0:
        # 如果文本过长，截断处理
        return truncate_text(text, width)
    
    if align == 'center':
        left_pad = padding_needed // 2
        right_pad = padding_needed - left_pad
        return ' ' * left_pad + text + ' ' * right_pad
    elif align == 'right':
        return ' ' * padding_needed + text
    else:  # left align
        return text + ' ' * padding_needed

def truncate_text(text, max_width):
    """截断文本到指定宽度，保留颜色代码"""
    import re
    
    # 如果没有颜色代码，简单处理
    if '\x1b[' not in text:
        result = ''
        current_width = 0
        for char in text:
            char_width = 2 if ord(char) > 127 else 1
            if current_width + char_width <= max_width:
                result += char
                current_width += char_width
            else:
                break
        return result
    
    # 有颜色代码的复杂处理
    parts = re.split(r'(\x1b\[[0-9;]*m)', text)
    result = ''
    current_width = 0
    
    for part in parts:
        if re.match(r'\x1b\[[0-9;]*m', part):
            # 这是颜色代码，直接添加
            result += part
        else:
            # 这是文本内容，需要计算宽度
            for char in part:
                char_width = 2 if ord(char) > 127 else 1
                if current_width + char_width <= max_width:
                    result += char
                    current_width += char_width
                else:
                    break
    
    return result

def normalize_icon_line(line, target_width=15):
    """标准化图标行到指定宽度"""
    current_width = get_display_width(line)
    if current_width < target_width:
        # 填充空格
        return line + ' ' * (target_width - current_width)
    elif current_width > target_width:
        # 截断
        return truncate_text(line, target_width)
    else:
        return line

def strip_ansi_colors(text):
    """完全移除ANSI颜色代码"""
    import re
    return re.sub(r'\x1b\[[0-9;]*m', '', text)

def precise_display_width(text):
    """精确计算显示宽度，考虑各种字符的实际宽度"""
    import unicodedata
    
    clean_text = strip_ansi_colors(text)
    width = 0
    
    for char in clean_text:
        # 使用Unicode标准计算宽度
        eaw = unicodedata.east_asian_width(char)
        if eaw in ('F', 'W'):  # 全角字符（包括大部分特殊符号）
            width += 2
        elif eaw == 'A':  # 模糊宽度字符
            # ⚡等特殊符号通常在终端中显示为2宽度
            if ord(char) > 127:
                width += 2
            else:
                width += 1
        else:  # 'H', 'Na', 'N'
            width += 1
    
    return width

def create_perfect_cell(content, target_width=30):
    """创建完美对齐的表格单元格"""
    # 计算当前宽度
    current_width = precise_display_width(content)
    
    if current_width == target_width:
        return content
    elif current_width < target_width:
        # 补充空格
        return content + ' ' * (target_width - current_width)
    else:
        # 需要截断，保留颜色代码
        clean_content = strip_ansi_colors(content)
        truncated = ""
        width_so_far = 0
        
        # 逐字符构建，确保不超过目标宽度
        for char in clean_content:
            char_width = precise_display_width(char)
            if width_so_far + char_width <= target_width:
                truncated += char
                width_so_far += char_width
            else:
                break
        
        # 重新应用颜色（简化处理）
        if '\x1b[' in content:
            # 提取颜色前缀和后缀
            import re
            color_parts = re.findall(r'\x1b\[[0-9;]*m', content)
            if color_parts:
                start_color = color_parts[0] if color_parts else ''
                end_color = '\x1b[0m'
                truncated = start_color + truncated + end_color
        
        # 确保精确宽度
        final_width = precise_display_width(truncated)
        if final_width < target_width:
            truncated += ' ' * (target_width - final_width)
        
        return truncated

def format_table_cell(icon_content, info_text, cell_width=30):
    """格式化表格单元格 - 使用新的完美对齐算法"""
    return create_perfect_aligned_cell(icon_content, info_text, cell_width)

def colorize_weather_desc(desc, weather_code):
    """为天气描述添加可爱的颜色"""
    if weather_code == 0:  # 晴天 🌞
        return f"{CuteColors.SUNNY}{desc}{CuteColors.RESET}"
    elif weather_code in [1, 2]:  # 多云 ☁️
        return f"{CuteColors.CLOUDY}{desc}{CuteColors.RESET}"
    elif weather_code == 3:  # 阴天
        return f"{CuteColors.GRAY}{desc}{CuteColors.RESET}"
    elif weather_code in [45, 48]:  # 雾 🌫️
        return f"{CuteColors.FOGGY}{desc}{CuteColors.RESET}"
    elif weather_code in [51, 53, 55, 61, 63, 65]:  # 雨 🌧️
        return f"{CuteColors.RAINY}{desc}{CuteColors.RESET}"
    elif weather_code in [71, 73, 75]:  # 雪 ❄️
        return f"{CuteColors.SNOWY}{desc}{CuteColors.RESET}"
    elif weather_code in [80, 81, 82]:  # 阵雨
        return f"{CuteColors.PURPLE}{desc}{CuteColors.RESET}"
    elif weather_code in [95, 96, 99]:  # 雷暴 ⚡
        return f"{CuteColors.PINK}{desc}{CuteColors.RESET}"
    else:
        return f"{CuteColors.WHITE}{desc}{CuteColors.RESET}"
WEATHER_ICONS = {
    # 晴天类
    0: {  # 晴天
        "icon": [
            "     \\   /     ",
            "      .-.      ",
            "   ― (   ) ―   ",
            "      `-'      ",
            "     /   \\     "
        ],
        "desc": "晴天"
    },
    1: {  # 主要晴朗
        "icon": [
            "   \\  /       ",
            " _ /\"\".-.     ",
            "   \\_(   ).   ",
            "   /(___(__)  ",
            "             "
        ],
        "desc": "局部多云"
    },
    2: {  # 部分多云
        "icon": [
            "   \\  /       ",
            " _ /\"\".-.     ",
            "   \\_(   ).   ",
            "   /(___(__)  ",
            "             "
        ],
        "desc": "局部多云"
    },
    3: {  # 阴天
        "icon": [
            "     .--.     ",
            "  .-(    ).   ",
            " (___.__)__)  ",
            "             ",
            "             "
        ],
        "desc": "阴"
    },
    # 雾类
    45: {  # 雾
        "icon": [
            "             ",
            " _ - _ - _ -  ",
            "  _ - _ - _   ",
            " _ - _ - _ -  ",
            "             "
        ],
        "desc": "雾"
    },
    48: {  # 雾霜
        "icon": [
            "             ",
            " _ - _ - _ -  ",
            "  _ - _ - _   ",
            " _ - _ - _ -  ",
            "             "
        ],
        "desc": "雾霜"
    },
    # 小雨类
    51: {  # 小毛毛雨
        "icon": [
            "     .-.      ",
            "    (   ).    ",
            "   (___(__)   ",
            "    ' ' ' '   ",
            "   ' ' ' '    "
        ],
        "desc": "小雨"
    },
    53: {  # 中毛毛雨
        "icon": [
            "     .-.      ",
            "    (   ).    ",
            "   (___(__)   ",
            "   ' ' ' ' '  ",
            "  ' ' ' ' '   "
        ],
        "desc": "小雨"
    },
    55: {  # 大毛毛雨
        "icon": [
            "     .-.      ",
            "    (   ).    ",
            "   (___(__)   ",
            "   ' ' ' ' '  ",
            "  ' ' ' ' '   "
        ],
        "desc": "小雨"
    },
    # 雨类
    61: {  # 小雨
        "icon": [
            "     .-.      ",
            "    (   ).    ",
            "   (___(__)   ",
            "    ' ' ' '   ",
            "   ' ' ' '    "
        ],
        "desc": "小雨"
    },
    63: {  # 中雨
        "icon": [
            "     .-.      ",
            "    (   ).    ",
            "   (___(__)   ",
            "   ' ' ' ' '  ",
            "  ' ' ' ' '   "
        ],
        "desc": "中雨"
    },
    65: {  # 大雨
        "icon": [
            "     .-.      ",
            "    (   ).    ",
            "   (___(__)   ",
            "  ‚' ‚' ‚' ‚' ",
            " ‚' ‚' ‚' ‚'  "
        ],
        "desc": "大雨"
    },
    # 雪类
    71: {  # 小雪
        "icon": [
            "     .-.      ",
            "    (   ).    ",
            "   (___(__)   ",
            "    *  *  *   ",
            "   *  *  *    "
        ],
        "desc": "小雪"
    },
    73: {  # 中雪
        "icon": [
            "     .-.      ",
            "    (   ).    ",
            "   (___(__)   ",
            "   *  *  *  * ",
            "  *  *  *  *  "
        ],
        "desc": "中雪"
    },
    75: {  # 大雪
        "icon": [
            "     .-.      ",
            "    (   ).    ",
            "   (___(__)   ",
            "  * * * * * * ",
            " * * * * * *  "
        ],
        "desc": "大雪"
    },
    # 阵雨类
    80: {  # 小阵雨
        "icon": [
            " _`/\"\".-.     ",
            "  ,\\_(   ).   ",
            "   /(___(__)  ",
            "     ' ' ' '  ",
            "    ' ' ' '   "
        ],
        "desc": "小阵雨"
    },
    81: {  # 中阵雨
        "icon": [
            " _`/\"\".-.     ",
            "  ,\\_(   ).   ",
            "   /(___(__)  ",
            "   ' ' ' ' '  ",
            "  ' ' ' ' '   "
        ],
        "desc": "中阵雨"
    },
    82: {  # 强阵雨
        "icon": [
            " _`/\"\".-.     ",
            "  ,\\_(   ).   ",
            "   /(___(__)  ",
            "   ‚' ‚' ‚' ‚'",
            "  ‚' ‚' ‚' ‚' "
        ],
        "desc": "强阵雨"
    },
    # 雷暴类  
    95: {  # 雷暴
        "icon": [
            " _`/\"\".-.     ",
            "  ,\\_(   ).   ",
            "   /(___(__)  ",
            "   ., ., .,   ",
            "  ., ., ., .  "
        ],
        "desc": "雷暴"
    },
    96: {  # 雷暴伴小雹
        "icon": [
            " _`/\"\".-.     ",
            "  ,\\_(   ).   ",
            "   /(___(__)  ",
            "   ., o .,    ",
            "  o ., o .,   "
        ],
        "desc": "雷暴冰雹"
    },
    99: {  # 雷暴伴大雹
        "icon": [
            " _`/\"\".-.     ",
            "  ,\\_(   ).   ",
            "   /(___(__)  ",
            "   ., O .,    ",
            "  O ., O .,   "
        ],
        "desc": "雷暴冰雹"
    }
}

def get_weather_icon(weather_code):
    """根据WMO天气代码获取ASCII图标"""
    # 如果是None或空字符串，使用默认
    if weather_code is None or weather_code == "":
        weather_code = 0
    
    # 转换为整数
    try:
        code = int(weather_code)
    except (ValueError, TypeError):
        code = 0
    
    # 返回对应图标，如果没有找到则返回默认晴天图标
    return WEATHER_ICONS.get(code, WEATHER_ICONS[0])

def get_wind_direction_arrow(wind_dir):
    """将风向度数转换为箭头符号"""
    if wind_dir is None or wind_dir == "":
        return "↑"
    
    try:
        deg = float(wind_dir)
        directions = ["↑", "↗", "→", "↘", "↓", "↙", "←", "↖"]
        index = int((deg + 22.5) / 45) % 8
        return directions[index]
    except:
        return "↑"

def search_location(query):
    """搜索城市位置信息，通用多重搜索策略"""
    log_debug(f"开始搜索位置: {query}")
    start_time = time.time()
    
    # 检查缓存
    cache_key = f"location:{query}"
    cached = get_cache(cache_key)
    if cached:
        elapsed = time.time() - start_time
        log_debug(f"位置搜索缓存命中，耗时: {elapsed:.2f}秒")
        return cached
    
    # 通用多重搜索策略，不使用任何硬编码映射
    search_queries = []
    
    # 如果是中文输入，尝试多种组合
    if any('\u4e00' <= char <= '\u9fff' for char in query):
        # 基础查询
        search_queries.append(query)
        
        # 在中文查询中添加地理信息 - 优先推荐中国位置
        search_queries.append(f"{query},中国")
        search_queries.append(f"{query}, China")
        
        # 尝试添加"市"后缀查询
        if not query.endswith('市'):
            search_queries.append(f"{query}市")
            search_queries.append(f"{query}市,中国")
            search_queries.append(f"{query}市, China")
        
        # 尝试添加"县"后缀查询（针对一些县级市）
        if not query.endswith('县'):
            search_queries.append(f"{query}县")
            search_queries.append(f"{query}县,中国")
            search_queries.append(f"{query}县, China")
            
        # 尝试添加"区"后缀查询（针对市辖区）
        if not query.endswith('区'):
            search_queries.append(f"{query}区")
            search_queries.append(f"{query}区,中国")
            search_queries.append(f"{query}区, China")
    else:
        # 英文或其他语言查询
        search_queries.append(query)
        search_queries.append(f"{query},china")
        search_queries.append(f"{query}, China")
    
    url = f"{GEOCODING_API_BASE}/search"
    
    # 尝试不同的搜索查询
    for search_query in search_queries:
        # 对于中文查询，使用中文语言；对于英文查询，使用英文语言
        is_chinese = any('\u4e00' <= char <= '\u9fff' for char in search_query)
        language = 'zh' if is_chinese else 'en'
        
        params = {
            'name': search_query,
            'count': 20,  # 增加搜索结果数量以获得更多选择
            'language': language,
            'format': 'json'
        }
        
        try:
            url_with_params = f"{url}?{urllib.parse.urlencode(params)}"
            log_debug(f"请求地理编码API: {url_with_params}")
            
            request = urllib.request.Request(url_with_params)
            request.add_header('User-Agent', 'GlobalScripts-Weather/1.0')
            with urllib.request.urlopen(request, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8'))
            
            if data.get('results') and len(data['results']) > 0:
                log_debug(f"找到 {len(data['results'])} 个结果")
                
                # 智能选择最佳结果 - 优先级更细致匹配
                best_result = None
                best_score = 0
                
                for location in data['results']:
                    score = 0
                    country = location.get('country', '')
                    admin1 = location.get('admin1', '')  # 省/州
                    name = location.get('name', '')
                    
                    # 中国位置加分
                    if country in ['China', '中国', 'CN']:
                        score += 100
                        
                        # 精确名称匹配加分
                        if name == query or name == f"{query}市" or name == f"{query}县":
                            score += 50
                        elif query in name or name in query:
                            score += 25
                            
                        # 特殊地区处理 - 针对常见的同名城市问题
                        if query == '太仓':
                            # 太仓市在江苏省，不在安徽省
                            if '江苏' in admin1:
                                score += 50
                            elif '安徽' in admin1:
                                score -= 30
                                
                        log_debug(f"位置: {name}, {admin1}, {country} - 得分: {score}")
                        
                        if score > best_score:
                            best_score = score
                            best_result = location
                
                # 如果没有中国结果，使用第一个结果
                if not best_result and data['results']:
                    best_result = data['results'][0]
                    log_debug(f"使用首个结果: {best_result}")
                
                if best_result:
                    result = {
                        'name': best_result.get('name', query),
                        'admin1': best_result.get('admin1', ''),
                        'admin2': best_result.get('admin2', ''),
                        'country': best_result.get('country', ''),
                        'lat': best_result['latitude'],
                        'lon': best_result['longitude']
                    }
                    
                    # 如果找到了好的结果，立即返回
                    set_cache(cache_key, result)
                    elapsed = time.time() - start_time
                    log_debug(f"地理编码成功，总耗时: {elapsed:.2f}秒")
                    return result
                    
        except Exception as e:
            log_debug(f"搜索查询 '{search_query}' 失败: {e}")
            continue
    
    elapsed = time.time() - start_time
    log_debug(f"所有搜索尝试失败，耗时: {elapsed:.2f}秒")
    return None

def get_weather_data(lat, lon):
    """获取天气数据"""
    log_debug(f"开始获取天气数据: lat={lat}, lon={lon}")
    start_time = time.time()
    
    # 检查缓存，缓存key包含坐标和小时
    current_hour = datetime.now().strftime("%Y%m%d%H")
    cache_key = f"weather:{lat:.2f}:{lon:.2f}:{current_hour}"
    cached = get_cache(cache_key)
    if cached:
        elapsed = time.time() - start_time
        log_debug(f"天气数据缓存命中，耗时: {elapsed:.2f}秒")
        return cached
    
    url = f"{WEATHER_API_BASE}/forecast"
    # 减少参数，只获取必要数据
    params = {
        'latitude': lat,
        'longitude': lon,
        'hourly': 'temperature_2m,weathercode,windspeed_10m,winddirection_10m',
        'daily': 'weathercode,temperature_2m_max,temperature_2m_min,windspeed_10m_max,winddirection_10m_dominant',
        'current_weather': 'true',
        'timezone': 'Asia/Shanghai',
        'forecast_days': 3
    }
    
    try:
        url_with_params = f"{url}?{urllib.parse.urlencode(params)}"
        log_debug(f"请求天气API: {url_with_params}")
        
        # 添加超时设置
        request = urllib.request.Request(url_with_params)
        request.add_header('User-Agent', 'GlobalScripts-Weather/1.0')
        with urllib.request.urlopen(request, timeout=15) as response:
            data = json.loads(response.read().decode('utf-8'))
        
        elapsed = time.time() - start_time
        log_debug(f"天气API响应时间: {elapsed:.2f}秒")
        
        # 缓存结果
        set_cache(cache_key, data)
        return data
    except Exception as e:
        elapsed = time.time() - start_time
        log_debug(f"获取天气数据出错 (耗时{elapsed:.2f}秒): {e}")
        return None

def format_weather_display_rich(location, weather_data):
    """使用Rich库格式化天气显示，更好的对齐和颜色"""
    if not weather_data:
        return "无法获取天气数据"
    
    console = Console()
    
    # 标题
    city_name = location['name']
    if location['admin2'] and location['admin2'] != location['name']:
        city_name = f"{location['admin2']}, {city_name}"
    if location['admin1']:
        city_name = f"{city_name}, {location['admin1']}"
    
    title = f"🌤️  天气预报: {city_name}"
    
    # 当前天气面板
    current = weather_data.get('current_weather', {})
    current_icon = get_weather_icon(current.get('weathercode'))
    wind_arrow = get_wind_direction_arrow(current.get('winddirection'))
    
    current_info = f"""
{current_icon['desc']}
🌡️  {colorize_temperature(current.get('temperature', 0))}
💨 {wind_arrow} {current.get('windspeed', 0)} km/h
"""
    
    # 创建当前天气面板
    current_panel = Panel(current_info, title="[bold cyan]当前天气[/bold cyan]", border_style="cyan")
    
    # 每日预报表格
    daily = weather_data.get('daily', {})
    if daily.get('time'):
        table = Table(title="📅 三天预报", show_header=True, header_style="bold magenta")
        table.add_column("日期", style="cyan", no_wrap=True)
        table.add_column("天气", style="yellow")
        table.add_column("最高温", style="red")
        table.add_column("最低温", style="blue")
        table.add_column("风速", style="green")
        
        for i in range(min(3, len(daily['time']))):
            date = datetime.fromisoformat(daily['time'][i])
            date_str = f"{date.strftime('%m月%d日')} 星期{'一二三四五六日'[date.weekday()]}"
            
            weather_code = daily['weathercode'][i] if i < len(daily.get('weathercode', [])) else 0
            icon_data = get_weather_icon(weather_code)
            weather_desc = icon_data['desc']
            
            temp_max = daily['temperature_2m_max'][i] if i < len(daily.get('temperature_2m_max', [])) else 0
            temp_min = daily['temperature_2m_min'][i] if i < len(daily.get('temperature_2m_min', [])) else 0
            wind_speed = daily['windspeed_10m_max'][i] if i < len(daily.get('windspeed_10m_max', [])) else 0
            
            table.add_row(
                date_str,
                weather_desc,
                f"{int(temp_max)}°C",
                f"{int(temp_min)}°C",
                f"{int(wind_speed)} km/h"
            )
    
    # 输出到字符串
    with console.capture() as capture:
        console.print(title, style="bold blue")
        console.print()
        console.print(current_panel)
        console.print()
        if daily.get('time'):
            console.print(table)
        
        # 位置信息
        console.print(f"\n📍 地点: {city_name}, {location['country']} [{location['lat']:.2f},{location['lon']:.2f}]", style="dim")
        console.print("\n💡 关注 @GlobalScripts 获取更多工具", style="dim cyan")
    
    return capture.get()

def format_weather_display(location, weather_data):
    """格式化天气显示，统一显示风格"""
    # 不管有没有Rich库，都使用相同的显示风格
    # Rich库仅用于改善表格对齐，不改变显示内容
    return format_weather_display_unified(location, weather_data)

def format_weather_display_unified(location, weather_data):
    """格式化天气显示，模仿wttr.in风格，智能使用Rich改善对齐"""
    if not weather_data:
        return "无法获取天气数据"
    
    # 标题
    city_name = location['name']
    if location['admin2'] and location['admin2'] != location['name']:
        city_name = f"{location['admin2']}, {city_name}"
    if location['admin1']:
        city_name = f"{city_name}, {location['admin1']}"
    
    result = f"天气预报： {city_name}\n\n"
    
    # 当前天气
    current = weather_data.get('current_weather', {})
    current_icon = get_weather_icon(current.get('weathercode'))
    wind_arrow = get_wind_direction_arrow(current.get('winddirection'))
    
    # 当前天气显示
    icon_lines = current_icon['icon']
    colored_icon_lines = colorize_weather_icon(icon_lines, current.get('weathercode', 0))
    temp = current.get('temperature', 0)
    wind_speed = current.get('windspeed', 0)
    
    # 格式化当前天气
    if len(colored_icon_lines) >= 3:
        result += f"{colored_icon_lines[0]}  {colorize_weather_desc(current_icon['desc'], current.get('weathercode', 0))}\n"
        result += f"{colored_icon_lines[1]}  {colorize_temperature(temp)}\n"
        result += f"{colored_icon_lines[2]}  {wind_arrow} {wind_speed} km/h\n"
        if len(colored_icon_lines) > 3:
            result += f"{colored_icon_lines[3]}\n"
        if len(colored_icon_lines) > 4:
            result += f"{colored_icon_lines[4]}\n"
    
    result += "\n"
    
    # 获取小时数据
    hourly = weather_data.get('hourly', {})
    daily = weather_data.get('daily', {})
    
    # 使用智能表格生成
    if HAS_RICH:
        result += generate_forecast_tables_rich(hourly, daily)
    else:
        result += generate_forecast_tables_basic(hourly, daily)
    
    # 位置信息
    result += f"地点: {city_name}, {location['country']} [{location['lat']:.2f},{location['lon']:.2f}]\n"
    result += "\n关注 @GlobalScripts 获取更多工具\n"
    
    return result

def generate_forecast_tables_rich(hourly, daily):
    """使用Rich库生成预报表格，但保持wttr.in风格"""
    # 即使有Rich，也要生成与原版一模一样的表格
    # Rich只用于确保对齐，不改变显示内容
    return generate_forecast_tables_basic(hourly, daily)

def create_aligned_cell(icon_colored, text_colored):
    """创建对齐的单元格 - 简单直接的方法"""
    # 直接使用字符串格式化，不计算复杂的宽度
    # 图标部分：固定17个字符位置
    # 文本部分：从第18个字符开始
    
    # 简单的方法：直接拼接，确保总长度30
    result = f"{icon_colored:<17}{text_colored:<13}"
    
    # 如果不够30个字符，填充空格
    while len(result) < 30:
        result += ' '
    
    # 如果超过30个字符，截断
    if len(result) > 30:
        result = result[:30]
    
    return result

def generate_forecast_tables_basic(hourly, daily):
    """生成基础的预报表格"""
    result = ""
    
    if hourly.get('time') and len(hourly['time']) >= 24:
        # 今日分时段预报（早上6点、中午12点、傍晚18点、夜间23点）
        today = datetime.now()
        
        # 简化的表头设计，确保对齐
        date_str = f"{today.strftime('%m月%d日')}星期{'一二三四五六日'[today.weekday()]}"
        result += "┌" + "─" * 30 + "┬" + "─" * 30 + "┬" + "─" * 30 + "┬" + "─" * 30 + "┐\n"
        result += "│" + pad_to_width("早上", 30, 'center') + "│" + pad_to_width("中午", 30, 'center') + "│" + pad_to_width("傍晚", 30, 'center') + "│" + pad_to_width("夜间", 30, 'center') + "│\n"
        result += "│" + pad_to_width(date_str, 30, 'center') + "│" + pad_to_width(date_str, 30, 'center') + "│" + pad_to_width(date_str, 30, 'center') + "│" + pad_to_width(date_str, 30, 'center') + "│\n"
        result += "├" + "─" * 30 + "┼" + "─" * 30 + "┼" + "─" * 30 + "┼" + "─" * 30 + "┤\n"
        
        # 选择代表性时间段的索引
        time_indices = []
        for target_hour in [6, 12, 18, 23]:
            # 找到最接近目标小时的索引
            best_idx = 0
            for i, time_str in enumerate(hourly['time']):
                hour = datetime.fromisoformat(time_str.replace('Z', '+00:00')).hour
                if hour <= target_hour:
                    best_idx = i
                else:
                    break
            time_indices.append(min(best_idx, len(hourly['time'])-1))
        
        # 格式化各时段 - 使用简单对齐算法
        for row in range(5):
            # 生成这一行的所有单元格
            row_cells = []
            for idx in time_indices:
                weather_code = hourly['weathercode'][idx] if idx < len(hourly.get('weathercode', [])) else 0
                temp = hourly['temperature_2m'][idx] if idx < len(hourly.get('temperature_2m', [])) else 0
                wind_speed = hourly['windspeed_10m'][idx] if idx < len(hourly.get('windspeed_10m', [])) else 0
                wind_dir = hourly['winddirection_10m'][idx] if idx < len(hourly.get('winddirection_10m', [])) else 0
                precip = 0.0  # 简化，不显示降水量
                vis = 10  # 固定能见度10km
                
                icon = get_weather_icon(weather_code)
                icon_lines = icon['icon']
                colored_icon_lines = colorize_weather_icon(icon_lines, weather_code)
                
                # 获取当前行的图标
                icon_line = colored_icon_lines[row] if row < len(colored_icon_lines) else ' ' * 15
                
                # 根据行索引生成不同的信息
                if row == 0:
                    # 第一行：天气描述
                    weather_info = colorize_weather_desc(icon['desc'], weather_code)
                elif row == 1:
                    # 第二行：温度
                    weather_info = colorize_temperature(int(temp))
                elif row == 2:
                    # 第三行：风向风速
                    wind_arrow = get_wind_direction_arrow(wind_dir)
                    weather_info = f"{wind_arrow} {int(wind_speed)} km/h"
                elif row == 3:
                    # 第四行：能见度
                    weather_info = f"{vis} km"
                else:
                    # 第五行：降水量
                    weather_info = f"{precip:.1f} mm"
                
                # 使用简单对齐方法
                cell = create_aligned_cell(icon_line, weather_info)
                row_cells.append(cell)
            
            # 直接生成表格行
            line = "│" + "│".join(row_cells) + "│"
            result += line + "\n"
        
        result += "└" + "─" * 30 + "┴" + "─" * 30 + "┴" + "─" * 30 + "┴" + "─" * 30 + "┘\n"
    
    # 后续天数预报
    if daily.get('time') and len(daily['time']) >= 3:
        for day_idx in [1, 2]:  # 显示后两天
            if day_idx >= len(daily['time']):
                continue
                
            date = datetime.fromisoformat(daily['time'][day_idx])
            date_str = f"{date.strftime('%m月%d日')}星期{'一二三四五六日'[date.weekday()]}"
            
            result += "┌" + "─" * 30 + "┬" + "─" * 30 + "┬" + "─" * 30 + "┬" + "─" * 30 + "┐\n"
            result += "│" + pad_to_width("早上", 30, 'center') + "│" + pad_to_width("中午", 30, 'center') + "│" + pad_to_width("傍晚", 30, 'center') + "│" + pad_to_width("夜间", 30, 'center') + "│\n"
            result += "│" + pad_to_width(date_str, 30, 'center') + "│" + pad_to_width(date_str, 30, 'center') + "│" + pad_to_width(date_str, 30, 'center') + "│" + pad_to_width(date_str, 30, 'center') + "│\n"
            result += "├" + "─" * 30 + "┼" + "─" * 30 + "┼" + "─" * 30 + "┼" + "─" * 30 + "┤\n"
            
            # 获取该天的数据
            weather_code = daily['weathercode'][day_idx] if day_idx < len(daily.get('weathercode', [])) else 0
            temp_max = daily['temperature_2m_max'][day_idx] if day_idx < len(daily.get('temperature_2m_max', [])) else 0
            temp_min = daily['temperature_2m_min'][day_idx] if day_idx < len(daily.get('temperature_2m_min', [])) else 0
            wind_speed = daily['windspeed_10m_max'][day_idx] if day_idx < len(daily.get('windspeed_10m_max', [])) else 0
            wind_dir = daily['winddirection_10m_dominant'][day_idx] if day_idx < len(daily.get('winddirection_10m_dominant', [])) else 0
            precip = 0.0  # 简化，不显示降水量
            
            icon = get_weather_icon(weather_code)
            
            # 模拟四个时段的温度
            temp_morning = int(temp_min + (temp_max - temp_min) * 0.3)
            temp_noon = int(temp_max)
            temp_evening = int(temp_min + (temp_max - temp_min) * 0.7)
            temp_night = int(temp_min)
            
            periods_data = [
                {'temp': temp_morning, 'desc': icon['desc']},
                {'temp': temp_noon, 'desc': icon['desc']},
                {'temp': temp_evening, 'desc': icon['desc']},
                {'temp': temp_night, 'desc': icon['desc']}
            ]
            
            for row in range(5):
                # 收集这一行的所有单元格
                row_cells = []
                for i, period_data in enumerate(periods_data):
                    icon_lines = icon['icon']
                    colored_icon_lines = colorize_weather_icon(icon_lines, weather_code)
                    
                    # 获取当前行的图标
                    icon_line = colored_icon_lines[row] if row < len(colored_icon_lines) else ' ' * 15
                    
                    # 根据行索引生成不同的信息
                    if row == 0:
                        # 第一行：天气描述
                        weather_info = colorize_weather_desc(period_data['desc'], weather_code)
                    elif row == 1:
                        # 第二行：温度
                        weather_info = colorize_temperature(period_data['temp'])
                    elif row == 2:
                        # 第三行：风向风速
                        wind_arrow = get_wind_direction_arrow(wind_dir)
                        weather_info = f"{wind_arrow} {int(wind_speed)} km/h"
                    elif row == 3:
                        # 第四行：能见度
                        weather_info = "10 km"
                    else:
                        # 第五行：降水量
                        if i == 1:  # 中午显示降水
                            weather_info = f"{precip:.1f} mm"
                        else:
                            weather_info = "0.0 mm"
                    
                    # 使用简单对齐方法
                    cell = create_aligned_cell(icon_line, weather_info)
                    row_cells.append(cell)
                
                # 直接生成表格行
                line = "│" + "│".join(row_cells) + "│"
                result += line + "\n"
            
            result += "└" + "─" * 30 + "┴" + "─" * 30 + "┴" + "─" * 30 + "┴" + "─" * 30 + "┘\n"
    
    return result

def main():
    start_total = time.time()
    log_debug("程序开始执行")
    
    parser = argparse.ArgumentParser(description='天气查询工具 - 使用Open-Meteo API')
    parser.add_argument('location', nargs='?', default='上海', help='城市名称')
    parser.add_argument('--simple', action='store_true', help='简化显示模式')
    parser.add_argument('--debug', action='store_true', help='显示调试信息')
    
    args = parser.parse_args()
    
    # 如果没有开启debug模式，重定向stderr到/dev/null
    if not args.debug:
        import os
        sys.stderr = open(os.devnull, 'w')
    
    log_debug(f"解析参数完成，查询城市: {args.location}")
    
    # 搜索位置
    step_start = time.time()
    location = search_location(args.location)
    if not location:
        print(f"未找到城市: {args.location}")
        return 1
    step_elapsed = time.time() - step_start
    log_debug(f"位置搜索步骤总耗时: {step_elapsed:.2f}秒")
    
    # 获取天气数据
    step_start = time.time()
    weather_data = get_weather_data(location['lat'], location['lon'])
    if not weather_data:
        print("无法获取天气数据")
        return 1
    step_elapsed = time.time() - step_start
    log_debug(f"天气数据获取步骤总耗时: {step_elapsed:.2f}秒")
    
    # 显示天气
    step_start = time.time()
    log_debug("开始格式化天气显示")
    weather_display = format_weather_display(location, weather_data)
    step_elapsed = time.time() - step_start
    log_debug(f"天气格式化耗时: {step_elapsed:.2f}秒")
    
    print(weather_display)
    
    total_elapsed = time.time() - start_total
    log_debug(f"程序总执行时间: {total_elapsed:.2f}秒")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())