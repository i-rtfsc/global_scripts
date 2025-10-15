"""
Android Frida Subplugin
- Inject JavaScript into processes with priority file search
- Manage frida-server and frida-inject automatically
"""

import sys
import os
import urllib.request
from pathlib import Path
from typing import List, Optional
import asyncio

project_root = Path(__file__).resolve().parents[3]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from gscripts.plugins.decorators import plugin_function, subplugin
from gscripts.plugins.base import BasePlugin
from gscripts.core.config_manager import CommandResult
from plugins.android.common import get_selected_device as _get_dev


@subplugin("frida")
class AndroidFridaSubplugin(BasePlugin):
    def __init__(self):
        self.name = "frida"
        self.parent_plugin = "android"
        self._plugin_dir = Path(__file__).resolve().parent
        self._frida_inject_path = self._plugin_dir / "frida-inject"
        self._frida_server_path = self._plugin_dir / "frida-server"
        # Frida GitHub releases URL
        self._frida_releases_url = "https://github.com/frida/frida/releases"

    async def _active_device(self) -> Optional[str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                "adb", "devices",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            out, _ = await proc.communicate()
            lines = out.decode(errors="ignore").strip().splitlines()[1:]
            devices = [l.split()[0] for l in lines if l.strip() and 'device' in l]
            if not devices:
                return None
            sel = _get_dev()
            return sel if sel in devices else devices[0]
        except Exception:
            return None

    async def _run(self, args: List[str]) -> CommandResult:
        serial = await self._active_device()
        cmd = ["adb"] + (["-s", serial] if serial else []) + args
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await proc.communicate()
            ok = proc.returncode == 0
            return CommandResult(ok, output=out.decode(errors="ignore"), error=err.decode(errors="ignore"), exit_code=proc.returncode or 0)
        except Exception as e:
            return CommandResult(False, error=str(e))

    def _find_js_file(self, js_file: str) -> Optional[Path]:
        """
        Find JavaScript file with priority:
        1. Current working directory
        2. Plugin directory
        3. Absolute path
        """
        # If absolute path, use directly
        if os.path.isabs(js_file):
            path = Path(js_file)
            return path if path.exists() else None
        
        # 1. Priority: current working directory
        cwd_path = Path.cwd() / js_file
        if cwd_path.exists():
            return cwd_path
            
        # 2. Fallback: plugin directory
        plugin_path = self._plugin_dir / js_file
        if plugin_path.exists():
            return plugin_path
            
        return None

    async def _ensure_frida_inject(self) -> CommandResult:
        """Ensure frida-inject is available, download if needed"""
        # Check if already exists on device
        check_result = await self._run(["shell", "test", "-x", "/data/local/frida/frida-inject"])
        if check_result.success:
            return CommandResult(True, output="frida-inject already exists on device")
        
        # Check if local file exists
        if not self._frida_inject_path.exists():
            return CommandResult(
                False, 
                error=f"frida-inject not found: {self._frida_inject_path}\n"
                      f"Please download frida-inject for your architecture from:\n"
                      f"{self._frida_releases_url}\n"
                      f"And place it in: {self._plugin_dir}/"
            )
        
        # Push to device
        await self._run(["root"])
        await self._run(["remount"])
        await self._run(["shell", "mkdir", "-p", "/data/local/frida"])
        
        push_result = await self._run(["push", str(self._frida_inject_path), "/data/local/frida/frida-inject"])
        if not push_result.success:
            return push_result
        
        chmod_result = await self._run(["shell", "chmod", "a+x", "/data/local/frida/frida-inject"])
        if chmod_result.success:
            return CommandResult(True, output="frida-inject installed successfully")
        else:
            return chmod_result

    @plugin_function(
        name="inject",
        description={"zh": "注入JavaScript脚本到进程", "en": "Inject JavaScript into process"},
        usage="gs android frida inject -p <process> -f <script.js>",
        examples=[
            "gs android frida inject -p system_server -f android-trace.js",
            "gs android frida inject -p com.example.app -f hook.js"
        ]
    )
    async def inject(self, args: List[str] = None) -> CommandResult:
        args = args or []
        process_name = "system_server"  # default
        js_file = None
        
        # Parse arguments
        i = 0
        while i < len(args):
            if args[i] == "-p" and i + 1 < len(args):
                process_name = args[i + 1]
                i += 2
            elif args[i] == "-f" and i + 1 < len(args):
                js_file = args[i + 1]
                i += 2
            elif args[i] in ["-h", "--help"]:
                return CommandResult(
                    True,
                    output="Usage: gs android frida inject -p <process> -f <script.js>\n"
                           "  -p: process name (default: system_server)\n"
                           "  -f: JavaScript file path (searches current dir first, then plugin dir)\n"
                           "Examples:\n"
                           "  gs android frida inject -p system_server -f android-trace.js\n"
                           "  gs android frida inject -p com.example.app -f hook.js"
                )
            else:
                return CommandResult(False, error=f"Unknown argument: {args[i]}")
        
        if not js_file:
            return CommandResult(False, error="JavaScript file (-f) is required")
        
        # Priority file search: 1. Current working directory, 2. Plugin directory
        js_path = None
        if not Path(js_file).is_absolute():
            # 1. First try current working directory
            cwd_candidate = Path.cwd() / js_file
            if cwd_candidate.exists():
                js_path = cwd_candidate
            # 2. Then try plugin directory  
            else:
                plugin_candidate = self._plugin_dir / js_file
                if plugin_candidate.exists():
                    js_path = plugin_candidate
        else:
            # Absolute path
            js_path = Path(js_file)
        
        if not js_path or not js_path.exists():
            available_js = list(self._plugin_dir.glob("*.js"))
            js_list = ", ".join([f.name for f in available_js])
            return CommandResult(
                False,
                error=f"JavaScript file not found: {js_file}\n"
                      f"Searched: {Path.cwd() / js_file} and {self._plugin_dir / js_file}\n"
                      f"Available JS files: {js_list}"
            )
        
        print(f"📱 Process: {process_name}")
        print(f"📜 Script: {js_path}")
        
        # Ensure frida-inject is available
        inject_result = await self._ensure_frida_inject()
        if not inject_result.success:
            return inject_result
        
        # Get process PID
        pid_result = await self._run(["shell", "pidof", process_name])
        if not pid_result.success or not pid_result.output.strip():
            return CommandResult(
                False,
                error=f"Process not found: {process_name}\n"
                       f"Make sure the process is running on the device"
            )
        
        pid = pid_result.output.strip()
        print(f"🎯 PID: {pid}")
        
        # Push JavaScript file to device
        js_filename = js_path.name
        device_js_path = f"/data/local/frida/{js_filename}"
        
        push_result = await self._run(["push", str(js_path), device_js_path])
        if not push_result.success:
            return CommandResult(False, error=f"Failed to push JS file: {push_result.error}")
        
        # Inject script
        inject_cmd = ["shell", f"/data/local/frida/frida-inject -p {pid} -s {device_js_path}"]
        result = await self._run(inject_cmd)
        
        if result.success:
            return CommandResult(
                True,
                output=f"✅ Successfully injected {js_filename} into {process_name} (PID: {pid})\n"
                       f"Output: {result.output}"
            )
        else:
            return CommandResult(
                False,
                error=f"Injection failed: {result.error}"
            )

    @plugin_function(
        name="server",
        description={"zh": "管理frida-server", "en": "Manage frida-server"},
        usage="gs android frida server <start|stop|status>",
        examples=[
            "gs android frida server start",
            "gs android frida server stop",
            "gs android frida server status"
        ]
    )
    async def server(self, args: List[str] = None) -> CommandResult:
        args = args or ["start"]
        action = args[0] if args else "start"
        
        if action == "start":
            # Check if already running
            check_result = await self._run(["shell", "pgrep", "frida-server"])
            if check_result.success and check_result.output.strip():
                return CommandResult(True, output="frida-server is already running")
            
            # Check if frida-server exists
            if not self._frida_server_path.exists():
                return CommandResult(
                    False,
                    error=f"frida-server not found: {self._frida_server_path}\n"
                          f"Please download frida-server for your architecture from:\n"
                          f"{self._frida_releases_url}\n"
                          f"And place it in: {self._plugin_dir}/"
                )
            
            # Setup and start server
            await self._run(["root"])
            await self._run(["remount"])
            await self._run(["shell", "mkdir", "-p", "/data/local/frida"])
            
            # Push frida-server if not exists on device
            check_device = await self._run(["shell", "test", "-x", "/data/local/frida/frida-server"])
            if not check_device.success:
                push_result = await self._run(["push", str(self._frida_server_path), "/data/local/frida/frida-server"])
                if not push_result.success:
                    return push_result
                
                chmod_result = await self._run(["shell", "chmod", "a+x", "/data/local/frida/frida-server"])
                if not chmod_result.success:
                    return chmod_result
            
            # Start server in background
            start_result = await self._run(["shell", "/data/local/frida/frida-server &"])
            return CommandResult(
                True,
                output="✅ frida-server started successfully"
            )
        
        elif action in ["stop", "kill"]:
            # Kill all frida processes
            kill_result = await self._run(["shell", "pkill", "frida"])
            return CommandResult(
                True,
                output="✅ frida-server stopped"
            )
        
        elif action == "status":
            # Check if running
            check_result = await self._run(["shell", "pgrep", "frida-server"])
            if check_result.success and check_result.output.strip():
                pids = check_result.output.strip().split('\n')
                return CommandResult(
                    True,
                    output=f"✅ frida-server is running (PID: {', '.join(pids)})"
                )
            else:
                return CommandResult(
                    True,
                    output="⚠️ frida-server is not running"
                )
        
        else:
            return CommandResult(
                False,
                error=f"Unknown action: {action}\nAvailable actions: start, stop, status"
            )

    @plugin_function(
        name="scripts",
        description={"zh": "列出可用的JavaScript脚本", "en": "List available JavaScript scripts"},
        usage="gs android frida scripts",
        examples=["gs android frida scripts"]
    )
    async def scripts(self, args: List[str] = None) -> CommandResult:
        """List available JavaScript scripts"""
        output = "📜 Available Frida JavaScript scripts:\n"
        output += "=" * 40 + "\n\n"
        
        # Check current directory
        current_dir = Path.cwd()
        output += f"📁 Current directory ({current_dir}):\n"
        current_js = list(current_dir.glob("*.js"))
        if current_js:
            for js in current_js:
                size = js.stat().st_size
                size_str = f"{size/1024:.1f}KB" if size > 1024 else f"{size}B"
                output += f"  • {js.name} ({size_str})\n"
                
                # Try to extract description from comments
                try:
                    with open(js, 'r') as f:
                        first_lines = f.read(500)
                        for line in first_lines.split('\n')[:10]:
                            if line.strip().startswith('//') and len(line) > 10:
                                desc = line.strip()[2:].strip()
                                output += f"    └─ {desc}\n"
                                break
                except:
                    pass
        else:
            output += "  📭 No JavaScript files found\n"
        
        # Check plugin directory
        output += f"\n📁 Plugin directory ({self._plugin_dir}):\n"
        plugin_js = list(self._plugin_dir.glob("*.js"))
        if plugin_js:
            for js in plugin_js:
                size = js.stat().st_size
                size_str = f"{size/1024:.1f}KB" if size > 1024 else f"{size}B"
                output += f"  • {js.name} ({size_str})\n"
                
                # Try to extract description from comments
                try:
                    with open(js, 'r') as f:
                        first_lines = f.read(500)
                        for line in first_lines.split('\n')[:10]:
                            if line.strip().startswith('//') and len(line) > 10:
                                desc = line.strip()[2:].strip()
                                output += f"    └─ {desc}\n"
                                break
                except:
                    pass
        else:
            output += "  📭 No JavaScript files found\n"
        
        output += "\n💡 Usage:\n"
        output += "  • gs android frida inject -p <process> -f <script.js>\n"
        
        return CommandResult(True, output=output)

    @plugin_function(
        name="status",
        description={"zh": "检查Frida环境状态", "en": "Check Frida environment status"},
        usage="gs android frida status",
        examples=["gs android frida status"]
    )
    async def status(self, args: List[str] = None) -> CommandResult:
        """Check Frida environment status"""
        output = "🔍 Frida environment status:\n"
        output += "=" * 30 + "\n"
        
        # Check device connection
        device = await self._active_device()
        if device:
            output += f"✅ Device connected: {device}\n"
            
            # Check frida-inject
            if self._frida_inject_path.exists():
                size = self._frida_inject_path.stat().st_size / (1024*1024)
                output += f"✅ frida-inject available ({size:.1f}MB)\n"
            else:
                output += "❌ frida-inject not found\n"
            
            # Check frida-server
            if self._frida_server_path.exists():
                size = self._frida_server_path.stat().st_size / (1024*1024)
                output += f"✅ frida-server available ({size:.1f}MB)\n"
            else:
                output += "⚠️ frida-server not found\n"
            
            # Check if frida-server is running on device
            server_check = await self._run(["shell", "pgrep", "frida-server"])
            if server_check.success and server_check.output.strip():
                pids = server_check.output.strip().split('\n')
                output += f"✅ frida-server running on device (PID: {', '.join(pids)})\n"
            else:
                output += "⚠️ frida-server not running on device\n"
            
            # Check if frida-inject exists on device
            inject_check = await self._run(["shell", "test", "-x", "/data/local/frida/frida-inject"])
            if inject_check.success:
                output += "✅ frida-inject installed on device\n"
            else:
                output += "⚠️ frida-inject not installed on device\n"
        else:
            output += "❌ No Android device detected\n"
        
        # Check JavaScript files
        current_js = len(list(Path.cwd().glob("*.js")))
        plugin_js = len(list(self._plugin_dir.glob("*.js")))
        
        output += f"\n📜 JavaScript files:\n"
        output += f"  Current directory: {current_js} files\n"
        output += f"  Plugin directory: {plugin_js} files\n"
        
        if not self._frida_inject_path.exists() or not self._frida_server_path.exists():
            output += f"\n💡 Download Frida binaries from: {self._frida_releases_url}\n"
            output += f"   Place them in: {self._plugin_dir}/\n"
        
        output += "\n🎯 Environment check complete!"
        
        return CommandResult(True, output=output)