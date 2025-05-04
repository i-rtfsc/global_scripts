#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Global Scripts V3 - Python辅助脚本
作者: Solo
版本: 1.0.0
描述: 兼容Python 2.7和Python 3.x，处理JSON、关联数组等复杂操作
"""
from __future__ import print_function, unicode_literals
import sys
import json
import os
import re

# Python 2/3兼容性处理
if sys.version_info[0] == 2:
    import codecs
    def open_file(filename, mode='r', encoding='utf-8'):
        return codecs.open(filename, mode, encoding=encoding)
    string_types = (str, unicode)
else:
    def open_file(filename, mode='r', encoding='utf-8'):
        return open(filename, mode, encoding=encoding)
    string_types = (str,)

class GlobalScriptsHelper:
    """Python辅助功能类"""
    
    def json_get(self, file_path, key, default=""):
        """获取JSON配置值，支持嵌套键访问如 'database.host'"""
        try:
            if not os.path.exists(file_path):
                print(default)
                return 0
            
            with open_file(file_path, 'r') as f:
                data = json.load(f)
            
            # 支持嵌套键访问，如 "database.host"
            keys = key.split('.')
            value = data
            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                else:
                    value = default
                    break
            
            print(self._safe_str(value))
            return 0
        except Exception as e:
            print(default)
            return 0  # 静默失败，返回默认值
    
    def json_set(self, file_path, key, value):
        """设置JSON配置值，支持嵌套键设置"""
        try:
            # 读取现有配置
            data = {}
            if os.path.exists(file_path):
                with open_file(file_path, 'r') as f:
                    data = json.load(f)
            
            # 设置嵌套键值
            keys = key.split('.')
            current = data
            for k in keys[:-1]:
                if k not in current:
                    current[k] = {}
                current = current[k]
            
            # 类型转换
            current[keys[-1]] = self._convert_value(value)
            
            # 确保目录存在
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            # 写回文件
            with open_file(file_path, 'w') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            return 0
        except Exception as e:
            print("Error: " + str(e), file=sys.stderr)
            return 1
    
    def json_validate(self, file_path):
        """验证JSON格式"""
        try:
            if not os.path.exists(file_path):
                print("File not found", file=sys.stderr)
                return 1
                
            with open_file(file_path, 'r') as f:
                json.load(f)
            
            return 0
        except Exception as e:
            print("JSON validation failed: " + str(e), file=sys.stderr)
            return 1
    
    def json_has_key(self, file_path, key):
        """检查JSON中是否存在指定键"""
        try:
            if not os.path.exists(file_path):
                return 1
                
            with open_file(file_path, 'r') as f:
                data = json.load(f)
            
            # 支持嵌套键检查
            keys = key.split('.')
            current = data
            for k in keys:
                if isinstance(current, dict) and k in current:
                    current = current[k]
                else:
                    return 1
            
            return 0
        except Exception:
            return 1
    
    def json_keys(self, file_path, prefix=""):
        """获取JSON所有键，支持前缀过滤"""
        try:
            if not os.path.exists(file_path):
                return 1
                
            with open_file(file_path, 'r') as f:
                data = json.load(f)
            
            def get_all_keys(obj, current_prefix=""):
                keys = []
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        full_key = current_prefix + "." + key if current_prefix else key
                        if not prefix or full_key.startswith(prefix):
                            keys.append(full_key)
                        if isinstance(value, dict):
                            keys.extend(get_all_keys(value, full_key))
                return keys
            
            for key in get_all_keys(data):
                print(key)
            
            return 0
        except Exception:
            return 1
    
    def array_get(self, array_data, key):
        """从序列化的数组数据中获取值"""
        try:
            data = json.loads(array_data)
            if key in data:
                print(self._safe_str(data[key]))
                return 0
            return 1
        except Exception:
            return 1
    
    def array_set(self, array_data, key, value):
        """设置数组值并返回序列化数据"""
        try:
            if array_data:
                data = json.loads(array_data)
            else:
                data = {}
            
            data[key] = self._convert_value(value)
            print(json.dumps(data, ensure_ascii=False))
            return 0
        except Exception:
            return 1
    
    def array_has_key(self, array_data, key):
        """检查数组中是否存在键"""
        try:
            if not array_data:
                return 1
            data = json.loads(array_data)
            return 0 if key in data else 1
        except Exception:
            return 1
    
    def array_keys(self, array_data):
        """获取数组所有键"""
        try:
            if not array_data:
                return 1
            data = json.loads(array_data)
            for key in data.keys():
                print(key)
            return 0
        except Exception:
            return 1
    
    def string_replace(self, text, pattern, replacement, is_regex="false"):
        """字符串替换，支持正则"""
        try:
            if is_regex == "true":
                result = re.sub(pattern, replacement, text)
            else:
                result = text.replace(pattern, replacement)
            print(result)
            return 0
        except Exception:
            return 1
    
    def string_match(self, text, pattern):
        """字符串匹配检查"""
        try:
            if re.search(pattern, text):
                return 0
            return 1
        except Exception:
            return 1
    
    def validate_format(self, value, format_type):
        """数据格式验证"""
        try:
            if format_type == "email":
                pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
                return 0 if re.match(pattern, value) else 1
            elif format_type == "url":
                pattern = r'^https?://[^\s/$.?#].[^\s]*$'
                return 0 if re.match(pattern, value) else 1
            elif format_type == "number":
                try:
                    float(value)
                    return 0
                except ValueError:
                    return 1
            elif format_type == "integer":
                try:
                    int(value)
                    return 0
                except ValueError:
                    return 1
            else:
                return 1
        except Exception:
            return 1
    
    def _safe_str(self, value):
        """安全的字符串转换，兼容py2/py3"""
        if isinstance(value, string_types):
            return value
        return str(value)
    
    def _convert_value(self, value):
        """智能类型转换"""
        # 尝试转换为数字
        try:
            if '.' in value:
                return float(value)
            return int(value)
        except ValueError:
            pass
        
        # 尝试转换为布尔值
        if value.lower() in ('true', 'false'):
            return value.lower() == 'true'
        
        # 尝试转换为JSON
        try:
            return json.loads(value)
        except ValueError:
            pass
        
        # 默认返回字符串
        return value

def main():
    """主入口函数"""
    if len(sys.argv) < 2:
        print("Usage: gs_helper.py <operation> [args...]", file=sys.stderr)
        sys.exit(1)
    
    helper = GlobalScriptsHelper()
    operation = sys.argv[1]
    args = sys.argv[2:]
    
    # 命令分发
    method_map = {
        'json_get': helper.json_get,
        'json_set': helper.json_set,
        'json_validate': helper.json_validate,
        'json_has_key': helper.json_has_key,
        'json_keys': helper.json_keys,
        'array_get': helper.array_get,
        'array_set': helper.array_set,
        'array_has_key': helper.array_has_key,
        'array_keys': helper.array_keys,
        'string_replace': helper.string_replace,
        'string_match': helper.string_match,
        'validate_format': helper.validate_format,
    }
    
    if operation in method_map:
        try:
            exit_code = method_map[operation](*args)
            sys.exit(exit_code)
        except Exception as e:
            print("Error: " + str(e), file=sys.stderr)
            sys.exit(1)
    else:
        print("Unknown operation: " + operation, file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()