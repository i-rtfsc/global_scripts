"""
Android Winscope Subplugin
- Start Winscope HTML tool with priority file search
- Start proxy server for device data collection
"""

import sys
import os
import subprocess
from pathlib import Path
from typing import List, Optional
import asyncio

project_root = Path(__file__).resolve().parents[3]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from gscripts.plugins.decorators import plugin_function, subplugin
from gscripts.plugins.base import BasePlugin
from gscripts.models.result import CommandResult


@subplugin("winscope")
class AndroidWinscopeSubplugin(BasePlugin):
    def __init__(self):
        self.name = "winscope"
        self.parent_plugin = "android"
        self._plugin_dir = Path(__file__).resolve().parent
        self._default_html = self._plugin_dir / "winscope.html"
        self._aosp_html = self._plugin_dir / "winscope-aosp.html"
        self._proxy_script = self._plugin_dir / "winscope_proxy.py"

    def _find_html_file(self, html_file: str) -> Optional[Path]:
        """
        Find HTML file with priority:
        1. Current working directory
        2. Plugin directory
        3. Absolute path
        """
        # If absolute path, use directly
        if os.path.isabs(html_file):
            path = Path(html_file)
            return path if path.exists() else None
        
        # 1. Priority: current working directory
        cwd_path = Path.cwd() / html_file
        if cwd_path.exists():
            return cwd_path
            
        # 2. Fallback: plugin directory
        plugin_path = self._plugin_dir / html_file
        if plugin_path.exists():
            return plugin_path
            
        return None

    def _get_open_command(self) -> Optional[str]:
        """Get the appropriate command to open HTML files"""
        commands = ["open", "xdg-open", "start"]  # macOS, Linux, Windows
        for cmd in commands:
            if subprocess.run(["which", cmd], capture_output=True).returncode == 0:
                return cmd
        return None

    @plugin_function(
        name="start",
        description={"zh": "启动Winscope UI分析工具", "en": "Start Winscope UI analysis tool"},
        usage="gs android winscope start [-f <html_file>]",
        examples=[
            "gs android winscope start",
            "gs android winscope start -f winscope.html",
            "gs android winscope start -f winscope-aosp.html"
        ]
    )
    async def start(self, args: List[str] = None) -> CommandResult:
        args = args or []
        html_file = None
        
        # Parse arguments
        i = 0
        while i < len(args):
            if args[i] == "-f" and i + 1 < len(args):
                html_file = args[i + 1]
                i += 2
            else:
                i += 1
        
        # Use default if no file specified
        if html_file is None:
            html_file = "winscope.html"
        
        # Priority file search: 1. Current working directory, 2. Plugin directory
        html_path = None
        if not Path(html_file).is_absolute():
            # 1. First try current working directory
            cwd_candidate = Path.cwd() / html_file
            if cwd_candidate.exists():
                html_path = cwd_candidate
            # 2. Then try plugin directory  
            else:
                plugin_candidate = self._plugin_dir / html_file
                if plugin_candidate.exists():
                    html_path = plugin_candidate
        else:
            # Absolute path
            html_path = Path(html_file)
        
        if not html_path or not html_path.exists():
            available_files = list(self._plugin_dir.glob("*.html"))
            files_list = ", ".join([f.name for f in available_files])
            return CommandResult(
                False, 
                error=f"HTML file not found: {html_file}\n"
                      f"Searched: {Path.cwd() / html_file} and {self._plugin_dir / html_file}\n"
                      f"Available files: {files_list}"
            )
        
        # Get command to open HTML
        open_cmd = self._get_open_command()
        if not open_cmd:
            return CommandResult(
                False,
                error="No command found to open HTML files (tried: open, xdg-open, start)"
            )
        
        try:
            # Open HTML file
            subprocess.Popen([open_cmd, str(html_path)])
            
            # Start proxy server if available
            output = f"✅ Winscope started with: {html_path}\n"
            if self._proxy_script.exists():
                try:
                    subprocess.Popen([sys.executable, str(self._proxy_script)])
                    output += "🌐 Proxy server started\n"
                except Exception as e:
                    output += f"⚠️ Failed to start proxy server: {str(e)}\n"
            else:
                output += "⚠️ Proxy server script not found, some features may not work\n"
            
            return CommandResult(True, output=output)
            
        except Exception as e:
            return CommandResult(False, error=f"Failed to start Winscope: {str(e)}")

    @plugin_function(
        name="aosp",
        description={"zh": "启动AOSP版Winscope", "en": "Start AOSP version Winscope"},
        usage="gs android winscope aosp",
        examples=["gs android winscope aosp"]
    )
    async def aosp(self, args: List[str] = None) -> CommandResult:
        """Start AOSP version of Winscope"""
        return await self.start(["-f", "winscope-aosp.html"])

    @plugin_function(
        name="proxy",
        description={"zh": "独立启动代理服务器", "en": "Start proxy server standalone"},
        usage="gs android winscope proxy",
        examples=["gs android winscope proxy"]
    )
    async def proxy(self, args: List[str] = None) -> CommandResult:
        """Start proxy server standalone"""
        if not self._proxy_script.exists():
            return CommandResult(
                False, 
                error=f"Proxy server script not found: {self._proxy_script}"
            )
        
        try:
            # Start proxy server in foreground
            result = subprocess.run([sys.executable, str(self._proxy_script)], 
                                  capture_output=True, text=True)
            return CommandResult(
                result.returncode == 0,
                output=result.stdout,
                error=result.stderr
            )
        except Exception as e:
            return CommandResult(False, error=f"Failed to start proxy server: {str(e)}")

    @plugin_function(
        name="files",
        description={"zh": "列出可用的HTML文件", "en": "List available HTML files"},
        usage="gs android winscope files",
        examples=["gs android winscope files"]
    )
    async def files(self, args: List[str] = None) -> CommandResult:
        """List available HTML files"""
        output = "📁 Available Winscope HTML files:\n"
        output += "=" * 35 + "\n\n"
        
        # Check current directory
        current_dir = Path.cwd()
        output += f"📁 Current directory ({current_dir}):\n"
        current_htmls = list(current_dir.glob("*.html"))
        if current_htmls:
            for html in current_htmls:
                size = html.stat().st_size
                size_str = f"{size/1024/1024:.1f}MB" if size > 1024*1024 else f"{size/1024:.1f}KB"
                output += f"  • {html.name} ({size_str})\n"
        else:
            output += "  📭 No HTML files found\n"
        
        # Check plugin directory
        output += f"\n📁 Plugin directory ({self._plugin_dir}):\n"
        plugin_htmls = list(self._plugin_dir.glob("*.html"))
        if plugin_htmls:
            for html in plugin_htmls:
                size = html.stat().st_size
                size_str = f"{size/1024/1024:.1f}MB" if size > 1024*1024 else f"{size/1024:.1f}KB"
                output += f"  • {html.name} ({size_str})"
                if "aosp" in html.name.lower():
                    output += " (AOSP version)"
                output += "\n"
        else:
            output += "  📭 No HTML files found\n"
        
        output += "\n💡 Usage:\n"
        output += "  • gs android winscope start [-f <html_file>]\n"
        output += "  • gs android winscope aosp (for AOSP version)\n"
        
        return CommandResult(True, output=output)

    @plugin_function(
        name="status",
        description={"zh": "检查Winscope环境状态", "en": "Check Winscope environment status"},
        usage="gs android winscope status",
        examples=["gs android winscope status"]
    )
    async def status(self, args: List[str] = None) -> CommandResult:
        """Check Winscope environment status"""
        output = "🔍 Winscope environment status:\n"
        output += "=" * 30 + "\n"
        
        # Check open command
        open_cmd = self._get_open_command()
        if open_cmd:
            output += f"✅ Browser open command: {open_cmd}\n"
        else:
            output += "❌ No browser open command found\n"
        
        # Check Python
        try:
            python_version = subprocess.run([sys.executable, "--version"], 
                                          capture_output=True, text=True).stdout.strip()
            output += f"✅ Python: {python_version}\n"
        except:
            output += "❌ Python not available\n"
        
        # Check HTML files
        html_count = len(list(self._plugin_dir.glob("*.html")))
        output += f"✅ HTML files in plugin directory: {html_count}\n"
        
        # Check proxy script
        if self._proxy_script.exists():
            output += "✅ Proxy server script available\n"
        else:
            output += "⚠️ Proxy server script not found\n"
        
        # Check ADB for future data collection features
        try:
            adb_result = subprocess.run(["adb", "version"], capture_output=True)
            if adb_result.returncode == 0:
                output += "✅ ADB available for data collection\n"
            else:
                output += "⚠️ ADB not available\n"
        except:
            output += "⚠️ ADB not found\n"
        
        output += "\n🎯 Winscope environment check complete!"
        
        return CommandResult(True, output=output)