"""
Full Hybrid Plugin - Python Component (subplugin: python)
Works alongside JSON (subplugin: config / commands.json) and Shell (subplugin: shell / plugin.sh)
No main function - uses decorators for plugin functions.
"""

import sys
import os
import json
import time
import hashlib
import statistics
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any

# Add project root to sys.path for imports
project_root = Path(__file__).resolve().parents[2]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from gscripts.plugins.decorators import plugin_function
from gscripts.plugins.base import BasePlugin, CommandResult


class FullHybridPlugin(BasePlugin):
    """Full hybrid plugin - Python component"""
    
    def __init__(self):
        super().__init__("full-hybrid")
        self.version = "1.0.0"
        self.start_time = datetime.now()
        self.execution_count = 0
    
    @plugin_function(
        name="python_data_analysis",
        description={
            "zh": "Python数据分析工具",
            "en": "Python data analysis tool"
        },
        usage="gs full-hybrid python_data_analysis <operation> [data]",
        examples=[
            "gs full-hybrid python_data_analysis statistics 1,2,3,4,5,6,7,8,9,10",
            "gs full-hybrid python_data_analysis hash_analysis sample_text",
            "gs full-hybrid python_data_analysis time_analysis"
        ]
    )
    def python_data_analysis(self, args: List[str]) -> CommandResult:
        """Advanced data analysis using Python"""
        self.execution_count += 1
        
        if not args:
            return CommandResult(False, error="Operation required: statistics, hash_analysis, time_analysis")
        
        operation = args[0]
        data = args[1] if len(args) > 1 else ""
        
        try:
            print(f"🐍 Full Hybrid: Python Data Analysis")
            print(f"Operation: {operation} | Execution #{self.execution_count}")
            print("=" * 45)
            
            if operation == "statistics":
                if not data:
                    return CommandResult(False, error="Data required for statistics analysis")
                
                try:
                    numbers = [float(x.strip()) for x in data.split(',') if x.strip()]
                    if not numbers:
                        return CommandResult(False, error="No valid numbers found in data")
                    
                    stats = {
                        "count": len(numbers),
                        "sum": sum(numbers),
                        "mean": statistics.mean(numbers),
                        "median": statistics.median(numbers),
                        "mode": statistics.mode(numbers) if len(set(numbers)) < len(numbers) else None,
                        "std_dev": statistics.stdev(numbers) if len(numbers) > 1 else 0,
                        "variance": statistics.variance(numbers) if len(numbers) > 1 else 0,
                        "min": min(numbers),
                        "max": max(numbers),
                        "range": max(numbers) - min(numbers)
                    }
                    
                    output = "📊 Statistical Analysis Results:\n"
                    output += f"  Dataset: {data}\n"
                    output += f"  Count: {stats['count']}\n"
                    output += f"  Sum: {stats['sum']:.2f}\n"
                    output += f"  Mean: {stats['mean']:.2f}\n"
                    output += f"  Median: {stats['median']:.2f}\n"
                    if stats['mode'] is not None:
                        output += f"  Mode: {stats['mode']:.2f}\n"
                    output += f"  Std Deviation: {stats['std_dev']:.2f}\n"
                    output += f"  Variance: {stats['variance']:.2f}\n"
                    output += f"  Range: {stats['min']:.2f} to {stats['max']:.2f} (span: {stats['range']:.2f})\n"
                    
                    return CommandResult(True, output=output, metadata=stats)
                    
                except ValueError as e:
                    return CommandResult(False, error=f"Invalid numeric data: {str(e)}")
                except statistics.StatisticsError as e:
                    return CommandResult(False, error=f"Statistics error: {str(e)}")
            
            elif operation == "hash_analysis":
                if not data:
                    return CommandResult(False, error="Text data required for hash analysis")
                
                # Generate various hash types
                text_bytes = data.encode('utf-8')
                
                hash_results = {
                    "original_text": data,
                    "text_length": len(data),
                    "byte_length": len(text_bytes),
                    "md5": hashlib.md5(text_bytes).hexdigest(),
                    "sha1": hashlib.sha1(text_bytes).hexdigest(),
                    "sha256": hashlib.sha256(text_bytes).hexdigest(),
                    "character_frequency": {}
                }
                
                # Character frequency analysis
                for char in data.lower():
                    if char.isalnum():
                        hash_results["character_frequency"][char] = hash_results["character_frequency"].get(char, 0) + 1
                
                # Sort by frequency
                sorted_chars = sorted(hash_results["character_frequency"].items(), key=lambda x: x[1], reverse=True)
                
                output = f"🔐 Hash Analysis Results for: '{data}'\n"
                output += f"  Text Length: {hash_results['text_length']} characters\n"
                output += f"  Byte Length: {hash_results['byte_length']} bytes\n"
                output += f"  MD5: {hash_results['md5']}\n"
                output += f"  SHA1: {hash_results['sha1']}\n"
                output += f"  SHA256: {hash_results['sha256'][:32]}...\n"
                output += f"  Character Frequency (top 5):\n"
                
                for char, count in sorted_chars[:5]:
                    output += f"    '{char}': {count} times\n"
                
                return CommandResult(True, output=output, metadata=hash_results)
            
            elif operation == "time_analysis":
                current_time = datetime.now()
                
                # Calculate various time metrics
                uptime = current_time - self.start_time
                
                time_info = {
                    "current_time": {
                        "local": current_time.isoformat(),
                        "utc": current_time.utctimetuple(),
                        "timestamp": current_time.timestamp(),
                        "formatted": current_time.strftime("%Y-%m-%d %H:%M:%S %Z")
                    },
                    "plugin_uptime": {
                        "seconds": uptime.total_seconds(),
                        "formatted": str(uptime)
                    },
                    "execution_stats": {
                        "total_executions": self.execution_count,
                        "start_time": self.start_time.isoformat()
                    },
                    "time_zones": {
                        "local_offset": time.timezone,
                        "daylight_saving": time.daylight
                    }
                }
                
                output = "⏰ Time Analysis Results:\n"
                output += f"  Current Time: {current_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                output += f"  UTC Timestamp: {current_time.timestamp()}\n"
                output += f"  Plugin Uptime: {uptime}\n"
                output += f"  Total Executions: {self.execution_count}\n"
                output += f"  Average Exec/Min: {self.execution_count / max(uptime.total_seconds() / 60, 1):.2f}\n"
                
                return CommandResult(True, output=output, metadata=time_info)
            
            else:
                return CommandResult(False, error=f"Unknown operation: {operation}")
                
        except Exception as e:
            return CommandResult(False, error=f"Python analysis error: {str(e)}")
    
    @plugin_function(
        name="python_file_manager",
        description={
            "zh": "Python文件管理器",
            "en": "Python file manager"
        },
        usage="gs full-hybrid python_file_manager <action> <path> [options]",
        examples=[
            "gs full-hybrid python_file_manager scan /tmp",
            "gs full-hybrid python_file_manager analyze /etc/passwd",
            "gs full-hybrid python_file_manager tree /usr/local --max-depth 2"
        ]
    )
    def python_file_manager(self, args: List[str]) -> CommandResult:
        """Advanced file management using Python"""
        if len(args) < 2:
            return CommandResult(False, error="Action and path required")
        
        action = args[0]
        path_str = args[1]
        path = Path(path_str)
        
        print(f"📁 Full Hybrid: Python File Manager")
        print(f"Action: {action} | Path: {path}")
        print("=" * 40)
        
        try:
            if action == "scan":
                if not path.exists():
                    return CommandResult(False, error=f"Path does not exist: {path}")
                
                scan_results = {
                    "path": str(path.absolute()),
                    "total_files": 0,
                    "total_dirs": 0,
                    "total_size": 0,
                    "file_types": {},
                    "largest_files": [],
                    "recent_files": []
                }
                
                if path.is_file():
                    scan_results["total_files"] = 1
                    scan_results["total_size"] = path.stat().st_size
                else:
                    # Scan directory recursively
                    for item in path.rglob("*"):
                        try:
                            if item.is_file():
                                scan_results["total_files"] += 1
                                size = item.stat().st_size
                                scan_results["total_size"] += size
                                
                                # Track file types
                                suffix = item.suffix.lower() or "no_extension"
                                scan_results["file_types"][suffix] = scan_results["file_types"].get(suffix, 0) + 1
                                
                                # Track largest files
                                scan_results["largest_files"].append((str(item), size))
                                
                                # Track recent files
                                mtime = datetime.fromtimestamp(item.stat().st_mtime)
                                scan_results["recent_files"].append((str(item), mtime))
                                
                            elif item.is_dir():
                                scan_results["total_dirs"] += 1
                        except (PermissionError, OSError):
                            continue
                
                # Sort and limit results
                scan_results["largest_files"] = sorted(scan_results["largest_files"], key=lambda x: x[1], reverse=True)[:5]
                scan_results["recent_files"] = sorted(scan_results["recent_files"], key=lambda x: x[1], reverse=True)[:5]
                
                output = f"🔍 Directory Scan Results:\n"
                output += f"  Path: {scan_results['path']}\n"
                output += f"  Files: {scan_results['total_files']}\n"
                output += f"  Directories: {scan_results['total_dirs']}\n"
                output += f"  Total Size: {scan_results['total_size'] / (1024*1024):.2f} MB\n"
                
                output += "  File Types:\n"
                for ext, count in sorted(scan_results["file_types"].items(), key=lambda x: x[1], reverse=True)[:5]:
                    output += f"    {ext}: {count}\n"
                
                output += "  Largest Files:\n"
                for file_path, size in scan_results["largest_files"]:
                    output += f"    {Path(file_path).name}: {size / 1024:.1f} KB\n"
                
                return CommandResult(True, output=output, metadata=scan_results)
            
            elif action == "tree":
                max_depth = 3
                # Parse max-depth option
                if "--max-depth" in args:
                    try:
                        idx = args.index("--max-depth")
                        if idx + 1 < len(args):
                            max_depth = int(args[idx + 1])
                    except (ValueError, IndexError):
                        pass
                
                tree_data = self._build_tree(path, max_depth)
                
                output = f"🌳 Directory Tree (max depth: {max_depth}):\n"
                output += self._format_tree(tree_data, path)
                
                return CommandResult(True, output=output, metadata=tree_data)
            
            else:
                return CommandResult(False, error=f"Unknown action: {action}")
                
        except Exception as e:
            return CommandResult(False, error=f"File manager error: {str(e)}")
    
    def _build_tree(self, path: Path, max_depth: int, current_depth: int = 0) -> Dict[str, Any]:
        """Build directory tree structure"""
        tree = {
            "name": path.name,
            "type": "directory" if path.is_dir() else "file",
            "children": []
        }
        
        if current_depth < max_depth and path.is_dir():
            try:
                for item in sorted(path.iterdir()):
                    if item.is_dir() or item.is_file():
                        child_tree = self._build_tree(item, max_depth, current_depth + 1)
                        tree["children"].append(child_tree)
            except PermissionError:
                tree["error"] = "Permission denied"
        
        return tree
    
    def _format_tree(self, tree: Dict[str, Any], base_path: Path, prefix: str = "") -> str:
        """Format tree structure as text"""
        output = f"{prefix}{tree['name']}"
        
        if tree["type"] == "directory":
            output += "/\n"
        else:
            output += "\n"
        
        children = tree.get("children", [])
        for i, child in enumerate(children):
            is_last = i == len(children) - 1
            child_prefix = prefix + ("└── " if is_last else "├── ")
            next_prefix = prefix + ("    " if is_last else "│   ")
            
            output += child_prefix + self._format_tree(child, base_path, next_prefix).split('\n', 1)[0] + "\n"
            
            # Recursively format children
            if child.get("children"):
                for line in self._format_tree(child, base_path, next_prefix).split('\n')[1:]:
                    if line.strip():
                        output += line + "\n"
        
        return output.rstrip()


# Plugin instance (no main function needed)
plugin = FullHybridPlugin()
