#!/usr/bin/env python3
"""
Global Scripts Plugin Template Generator
Creates plugin templates that match the current v6 data structure
"""

import sys
import json
from pathlib import Path
from typing import Optional, List, Dict

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from gscripts.utils.i18n import get_i18n_manager

# Colors
class Color:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'


class PluginGenerator:
    """Plugin template generator"""

    def __init__(self):
        self.i18n = get_i18n_manager()
        self.plugin_name = ""
        self.plugin_type = ""
        self.has_subplugins = False
        self.subplugins = []

    def run(self):
        """Run the generator"""
        print(f"\n{Color.BOLD}{Color.CYAN}🚀 Global Scripts v6 - Plugin Template Generator{Color.END}\n")

        # Get plugin name
        self.plugin_name = self._get_input("Plugin name (lowercase, e.g., 'myapp'): ")
        if not self.plugin_name or not self.plugin_name.replace('_', '').replace('-', '').isalnum():
            print(f"{Color.RED}❌ Invalid plugin name{Color.END}")
            return

        # Get plugin type
        self.plugin_type = self._select_type()

        # Ask about subplugins
        if self.plugin_type == "python":
            has_sub = self._get_input("Does this plugin have subplugins? (y/N): ").lower()
            self.has_subplugins = has_sub == 'y'

            if self.has_subplugins:
                self._collect_subplugins()

        # Get output directory
        output_dir = self._get_input(f"Output directory (default: ./plugins/{self.plugin_name}): ") or f"./plugins/{self.plugin_name}"

        # Generate
        self._generate_plugin(Path(output_dir))

    def _get_input(self, prompt: str) -> str:
        """Get user input"""
        return input(f"{Color.YELLOW}{prompt}{Color.END}").strip()

    def _select_type(self) -> str:
        """Select plugin type"""
        print(f"\n{Color.CYAN}Select plugin type:{Color.END}")
        types = [
            ("python", "Python plugin (with @plugin_function decorators)"),
            ("shell", "Shell script plugin"),
            ("json", "JSON configuration plugin (direct commands)")
        ]

        for i, (key, desc) in enumerate(types, 1):
            print(f"  {i}. {desc}")

        choice = self._get_input(f"Choose type (1-{len(types)}): ")
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(types):
                return types[idx][0]
        except:
            pass
        return "python"

    def _collect_subplugins(self):
        """Collect subplugin names"""
        print(f"\n{Color.CYAN}Enter subplugin names (one per line, empty to finish):{Color.END}")
        while True:
            name = self._get_input(f"Subplugin name: ")
            if not name:
                break
            if name and name.replace('_', '').replace('-', '').isalnum():
                self.subplugins.append(name)
            else:
                print(f"{Color.RED}Invalid name, skipped{Color.END}")

    def _generate_plugin(self, output_dir: Path):
        """Generate plugin files"""
        # Create directory
        output_dir.mkdir(parents=True, exist_ok=True)

        # Generate plugin.json
        self._generate_plugin_json(output_dir)

        # Generate plugin file based on type
        if self.plugin_type == "python":
            self._generate_python_plugin(output_dir)
        elif self.plugin_type == "shell":
            self._generate_shell_plugin(output_dir)

        # Generate subplugins
        if self.has_subplugins:
            for subplugin in self.subplugins:
                self._generate_subplugin(output_dir, subplugin)

        # Generate README
        self._generate_readme(output_dir)

        print(f"\n{Color.GREEN}✅ Plugin template generated successfully!{Color.END}")
        print(f"{Color.CYAN}📁 Location: {output_dir}{Color.END}\n")
        print(f"{Color.YELLOW}Next steps:{Color.END}")
        print(f"  1. Review and modify {output_dir}/plugin.json")
        print(f"  2. Implement your plugin functions")
        print(f"  3. Run: gs refresh")
        print(f"  4. Test: gs {self.plugin_name} --help\n")

    def _generate_plugin_json(self, output_dir: Path):
        """Generate plugin.json"""
        data = {
            "name": self.plugin_name,
            "version": "1.0.0",
            "author": "Your Name",
            "homepage": "https://github.com/yourname/global_scripts-v6",
            "description": {
                "zh": f"{self.plugin_name} 插件",
                "en": f"{self.plugin_name} plugin"
            },
            "type": self.plugin_type,
            "entry": "plugin.py" if self.plugin_type == "python" else "plugin.sh",
            "enabled": True,
            "license": "MIT",
            "category": "utility",
            "keywords": [self.plugin_name, "tool"],
            "priority": 50
        }

        # Add subplugins
        if self.has_subplugins:
            data["subplugins"] = [
                {
                    "name": sub,
                    "type": "python",
                    "entry": "plugin.py"
                }
                for sub in self.subplugins
            ]

        # Write JSON
        with open(output_dir / "plugin.json", 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _generate_python_plugin(self, output_dir: Path):
        """Generate Python plugin file"""
        if not self.has_subplugins:
            # Simple plugin
            content = f'''"""
{self.plugin_name} plugin - Main plugin file
"""

import sys
from pathlib import Path
from typing import List

# Add src to Python path
project_root = Path(__file__).resolve().parents[2]
if str(project_root / 'src') not in sys.path:
    sys.path.insert(0, str(project_root / 'src'))

from gscripts.plugins.decorators import plugin_function
from gscripts.plugins.base import BasePlugin
from gscripts.core.config_manager import CommandResult


class {self.plugin_name.capitalize()}Plugin(BasePlugin):
    """Main {self.plugin_name} plugin"""

    def __init__(self):
        self.name = "{self.plugin_name}"

    @plugin_function(
        name="info",
        description={{"zh": "显示插件信息", "en": "Show plugin info"}},
        usage="gs {self.plugin_name} info",
        examples=["gs {self.plugin_name} info"]
    )
    async def info(self, args: List[str] = None) -> CommandResult:
        """Show plugin information"""
        return CommandResult(
            True,
            output=f"📦 {self.plugin_name} plugin v1.0.0"
        )
'''
        else:
            # Plugin with subplugins - no direct functions
            content = f'''"""
{self.plugin_name} plugin - Main plugin file with subplugins
"""

import sys
from pathlib import Path

# Add src to Python path
project_root = Path(__file__).resolve().parents[2]
if str(project_root / 'src') not in sys.path:
    sys.path.insert(0, str(project_root / 'src'))

from gscripts.plugins.base import BasePlugin


class {self.plugin_name.capitalize()}Plugin(BasePlugin):
    """Main {self.plugin_name} plugin (container for subplugins)"""

    def __init__(self):
        self.name = "{self.plugin_name}"
        # This plugin has subplugins defined in plugin.json
'''

        with open(output_dir / "plugin.py", 'w', encoding='utf-8') as f:
            f.write(content)

    def _generate_shell_plugin(self, output_dir: Path):
        """Generate Shell plugin file"""
        content = f'''#!/bin/bash
# {self.plugin_name} plugin - Shell implementation

# @plugin_function
# name: info
# description: Show plugin info
# usage: gs {self.plugin_name} info
{self.plugin_name}_info() {{
    echo "📦 {self.plugin_name} plugin v1.0.0"
}}

# @plugin_function
# name: status
# description: Check plugin status
# usage: gs {self.plugin_name} status
{self.plugin_name}_status() {{
    echo "✅ {self.plugin_name} is active"
}}
'''

        script_file = output_dir / "plugin.sh"
        with open(script_file, 'w', encoding='utf-8') as f:
            f.write(content)
        script_file.chmod(0o755)

    def _generate_subplugin(self, output_dir: Path, subplugin: str):
        """Generate subplugin directory and file"""
        sub_dir = output_dir / subplugin
        sub_dir.mkdir(exist_ok=True)

        content = f'''"""
{self.plugin_name}.{subplugin} subplugin
"""

import sys
from pathlib import Path
from typing import List

# Add src to Python path
project_root = Path(__file__).resolve().parents[3]
if str(project_root / 'src') not in sys.path:
    sys.path.insert(0, str(project_root / 'src'))

from gscripts.plugins.decorators import plugin_function, subplugin
from gscripts.plugins.base import BasePlugin
from gscripts.core.config_manager import CommandResult


@subplugin("{subplugin}")
class {subplugin.capitalize()}Subplugin(BasePlugin):
    """{self.plugin_name}.{subplugin} subplugin"""

    def __init__(self):
        self.name = "{subplugin}"
        self.parent_plugin = "{self.plugin_name}"

    @plugin_function(
        name="run",
        description={{"zh": "运行{subplugin}功能", "en": "Run {subplugin} function"}},
        usage="gs {self.plugin_name} {subplugin} run",
        examples=["gs {self.plugin_name} {subplugin} run"]
    )
    async def run(self, args: List[str] = None) -> CommandResult:
        """Run {subplugin} function"""
        return CommandResult(
            True,
            output=f"🚀 {subplugin} executed successfully"
        )

    @plugin_function(
        name="status",
        description={{"zh": "查看{subplugin}状态", "en": "Check {subplugin} status"}},
        usage="gs {self.plugin_name} {subplugin} status",
        examples=["gs {self.plugin_name} {subplugin} status"]
    )
    async def status(self, args: List[str] = None) -> CommandResult:
        """Check {subplugin} status"""
        return CommandResult(
            True,
            output=f"✅ {subplugin} is ready"
        )
'''

        with open(sub_dir / "plugin.py", 'w', encoding='utf-8') as f:
            f.write(content)

    def _generate_readme(self, output_dir: Path):
        """Generate README.md"""
        subplugins_section = ""
        if self.has_subplugins:
            subplugins_section = "\n## Subplugins\n\n" + "\n".join(
                f"- `{sub}`: Description of {sub} subplugin"
                for sub in self.subplugins
            )

        content = f'''# {self.plugin_name} Plugin

## Description

{self.plugin_name} plugin for Global Scripts v6.

## Type

{self.plugin_type.capitalize()} plugin

## Usage

```bash
# Show plugin info
gs {self.plugin_name} info
```
{subplugins_section}

## Installation

This plugin is automatically loaded when placed in the `plugins/` directory.

## Configuration

Edit `plugin.json` to customize:
- Description (zh/en)
- Version
- Author information
- Keywords and category

## Development

1. Modify `plugin.py` to implement your functions
2. Use `@plugin_function` decorator for each command
3. Run `gs refresh` to reload
4. Test with `gs {self.plugin_name} <command>`

## License

MIT
'''

        with open(output_dir / "README.md", 'w', encoding='utf-8') as f:
            f.write(content)


def main():
    """Main entry point"""
    try:
        generator = PluginGenerator()
        generator.run()
    except KeyboardInterrupt:
        print(f"\n{Color.YELLOW}⚠️  Cancelled{Color.END}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Color.RED}❌ Error: {{e}}{Color.END}")
        sys.exit(1)


if __name__ == "__main__":
    main()
