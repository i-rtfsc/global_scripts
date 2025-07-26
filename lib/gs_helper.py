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
    
    def json_validate(self, file_path, schema_file=None):
        """验证JSON格式和Schema"""
        try:
            if not os.path.exists(file_path):
                print("File not found", file=sys.stderr)
                return 1
                
            with open_file(file_path, 'r') as f:
                data = json.load(f)
            
            # 基础JSON格式验证通过
            if schema_file and os.path.exists(schema_file):
                # 尝试Schema验证（如果有jsonschema库）
                try:
                    import jsonschema
                    with open_file(schema_file, 'r') as f:
                        schema = json.load(f)
                    jsonschema.validate(data, schema)
                    print("JSON validation passed with schema")
                except ImportError:
                    print("JSON format valid (jsonschema not available)")
                except Exception as e:
                    print("Schema validation failed: " + str(e), file=sys.stderr)
                    return 1
            else:
                print("JSON format valid")
            
            return 0
        except Exception as e:
            print("JSON validation failed: " + str(e), file=sys.stderr)
            return 1
    
    def config_validate(self, config_file, schema_file=None):
        """验证配置文件，包含基础检查和Schema验证"""
        try:
            if not os.path.exists(config_file):
                print("Configuration file not found: " + config_file, file=sys.stderr)
                return 1
            
            # 基础JSON格式验证
            with open_file(config_file, 'r') as f:
                config_data = json.load(f)
            
            # 检查必需字段
            required_fields = ['version', 'system', 'paths', 'cache', 'logging']
            missing_fields = []
            for field in required_fields:
                if field not in config_data:
                    missing_fields.append(field)
            
            if missing_fields:
                print("Missing required fields: " + ", ".join(missing_fields), file=sys.stderr)
                return 1
            
            # 验证版本格式
            version = config_data.get('version', '')
            if not re.match(r'^\d+\.\d+\.\d+$', version):
                print("Invalid version format: " + version, file=sys.stderr)
                return 1
            
            # 验证日志级别
            system_log_level = config_data.get('system', {}).get('log_level', '')
            logging_level = config_data.get('logging', {}).get('level', '')
            valid_levels = ['DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL']
            
            if system_log_level and system_log_level not in valid_levels:
                print("Invalid system.log_level: " + system_log_level, file=sys.stderr)
                return 1
                
            if logging_level and logging_level not in valid_levels:
                print("Invalid logging.level: " + logging_level, file=sys.stderr)
                return 1
            
            # Schema验证（如果提供了schema文件）
            if schema_file and os.path.exists(schema_file):
                try:
                    import jsonschema
                    with open_file(schema_file, 'r') as f:
                        schema = json.load(f)
                    jsonschema.validate(config_data, schema)
                    print("Configuration validation passed with schema")
                except ImportError:
                    print("Configuration format valid (jsonschema not available for detailed validation)")
                except Exception as e:
                    print("Schema validation failed: " + str(e), file=sys.stderr)
                    return 1
            else:
                print("Configuration format valid (basic validation)")
            
            return 0
        except Exception as e:
            print("Configuration validation failed: " + str(e), file=sys.stderr)
            return 1
    
    def config_merge(self, base_file, override_file, output_file=None):
        """合并配置文件，override覆盖base"""
        try:
            # 读取基础配置
            base_data = {}
            if os.path.exists(base_file):
                with open_file(base_file, 'r') as f:
                    base_data = json.load(f)
            
            # 读取覆盖配置
            override_data = {}
            if os.path.exists(override_file):
                with open_file(override_file, 'r') as f:
                    override_data = json.load(f)
            
            # 深度合并
            def deep_merge(base, override):
                if isinstance(base, dict) and isinstance(override, dict):
                    result = base.copy()
                    for key, value in override.items():
                        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                            result[key] = deep_merge(result[key], value)
                        else:
                            result[key] = value
                    return result
                else:
                    return override
            
            merged_data = deep_merge(base_data, override_data)
            
            # 输出结果
            if output_file:
                os.makedirs(os.path.dirname(output_file), exist_ok=True)
                with open_file(output_file, 'w') as f:
                    json.dump(merged_data, f, indent=2, ensure_ascii=False)
                print("Configuration merged successfully: " + output_file)
            else:
                print(json.dumps(merged_data, indent=2, ensure_ascii=False))
            
            return 0
        except Exception as e:
            print("Configuration merge failed: " + str(e), file=sys.stderr)
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
        'config_validate': helper.config_validate,
        'config_merge': helper.config_merge,
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