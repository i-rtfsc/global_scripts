# Frequently Asked Questions (FAQ)

Global Scripts common questions and solutions.

## Installation

### Q: Commands not available after installation?

**A:** Make sure you have loaded the environment configuration:

```bash
# For Bash
source ~/.bashrc

# For Zsh
source ~/.zshrc

# For Fish
source ~/.config/fish/config.fish

# Or load directly
source $GS_ROOT/env.sh
```

### Q: Python version incompatible?

**A:** Global Scripts requires Python 3.7+:

```bash
# Check Python version
python3 --version

# If version is too old, install a newer Python
# macOS:
brew install python@3.11

# Ubuntu:
sudo apt install python3.11
```

### Q: Permission errors?

**A:** Ensure you have execute permissions:

```bash
chmod +x /path/to/global_scripts-v6/env.sh
chmod +x /path/to/global_scripts-v6/scripts/setup.py
```

## Configuration

### Q: How to change the language?

**A:** Edit the configuration file `~/.config/global-scripts/config/gs.json`:

```json
{
  "language": "en"  // "zh" or "en"
}
```

Or set the environment variable:

```bash
export GS_LANGUAGE="en"
```

### Q: Where are the configuration files?

**A:** Configuration file priority:

1. `~/.config/global-scripts/config/gs.json` (user configuration)
2. `/path/to/global_scripts-v6/config/gs.json` (project configuration)

### Q: How to reset configuration?

**A:** Delete the user configuration file and rerun the installation:

```bash
rm ~/.config/global-scripts/config/gs.json
python3 scripts/setup.py
```

## Plugins

### Q: Plugin not showing?

**A:** Check the following:

1. Does the plugin have a `plugin.json` file?
2. Is the `name` field in `plugin.json` correct?
3. Is the plugin enabled?

```bash
gs plugin list
gs plugin enable <plugin-name>
```

### Q: Plugin command execution fails?

**A:** View detailed error information:

```bash
# Enable debug mode
export GS_DEBUG=1
gs <plugin> <command>

# View logs
tail -f ~/.config/global-scripts/logs/gs.log
```

### Q: How to develop my own plugin?

**A:** Refer to the [Plugin Development Guide](./plugin-development.md)

The simplest way - create a JSON plugin:

```json
{
  "name": "myplugin",
  "version": "1.0.0",
  "commands": {
    "hello": {
      "command": "echo 'Hello!'",
      "description": "Say hello"
    }
  }
}
```

## Execution

### Q: Command timeout?

**A:** Modify the timeout settings:

1. In the configuration file:
```json
{
  "default_timeout": 60  // seconds
}
```

2. Or in the function definition:
```python
@plugin_function(name="long-task", timeout=300)
```

### Q: Command output garbled?

**A:** Set the correct encoding:

```bash
export LANG=zh_CN.UTF-8
export LC_ALL=zh_CN.UTF-8
```

### Q: Concurrent execution limits?

**A:** Modify the concurrency number:

```json
{
  "max_concurrent_commands": 20
}
```

## Performance

### Q: Plugin loading slow?

**A:**

1. Disable unneeded plugins:
```bash
gs plugin disable <unneeded-plugin>
```

2. Don't show example plugins:
```json
{
  "show_examples": false
}
```

3. Clean up log files:
```bash
rm ~/.config/global-scripts/logs/gs.log
```

### Q: Command response slow?

**A:**

1. Check router index:
```bash
gs refresh  # Rebuild index
```

2. Enable cache (if available):
```json
{
  "enable_cache": true
}
```

## Completion

### Q: Tab completion not working?

**A:**

1. Ensure completion scripts are generated:
```bash
ls ~/.config/global-scripts/completions/
```

2. Regenerate completions:
```bash
gs refresh
```

3. Reload the shell:
```bash
# Bash
source ~/.bashrc

# Zsh
source ~/.zshrc

# Fish
source ~/.config/fish/config.fish
```

### Q: Completion list incomplete?

**A:** Run `gs refresh` to rebuild the completion scripts.

## Logging

### Q: How to view logs?

**A:**

```bash
# View in real-time
tail -f ~/.config/global-scripts/logs/gs.log

# View all
cat ~/.config/global-scripts/logs/gs.log

# Clear logs
> ~/.config/global-scripts/logs/gs.log
```

### Q: How to adjust log level?

**A:**

```json
{
  "logging_level": "DEBUG"  // NANO/ERROR/WARNING/INFO/DEBUG/VERBOSE
}
```

Or via environment variable:
```bash
export GS_LOG_LEVEL="DEBUG"
```

## Error Handling

### Q: "Plugin not found" error?

**A:**

1. Check if the plugin name is correct:
```bash
gs plugin list
```

2. Check if the plugin is enabled:
```bash
gs plugin enable <plugin-name>
```

### Q: "Command not found" error?

**A:**

1. Confirm the command path:
```bash
gs plugin info <plugin-name>
```

2. Check router index:
```bash
gs refresh
```

### Q: "Permission denied" error?

**A:**

```bash
# Grant execute permission
chmod +x /path/to/script.sh

# Or use sudo (not recommended unless necessary)
sudo gs <command>
```

### Q: "Timeout expired" error?

**A:** Increase the timeout or check if the command is stuck:

```bash
# Debug mode to view details
GS_DEBUG=1 gs <command>
```

## Development

### Q: How to debug plugins?

**A:**

```bash
# 1. Enable debug mode
export GS_DEBUG=1

# 2. View detailed logs
tail -f ~/.config/global-scripts/logs/gs.log

# 3. Use print debugging (in Python plugins)
print(f"Debug: variable = {variable}")

# 4. Check return values
gs plugin info myplugin
```

### Q: Python import errors?

**A:**

Ensure PYTHONPATH is correct:

```bash
export PYTHONPATH="/path/to/global_scripts-v6:$PYTHONPATH"
```

Or use absolute imports in plugins:

```python
from gs_system.models import CommandResult
```

### Q: Shell script not executing?

**A:**

1. Check the shebang:
```bash
#!/usr/bin/env bash
```

2. Check execute permissions:
```bash
chmod +x script.sh
```

3. Check shell annotation format:
```bash
# @plugin_function
# name: function-name
# description: Description
```

## System

### Q: How to uninstall?

**A:**

1. Remove from shell configuration:
```bash
# Bash users edit ~/.bashrc
# Zsh users edit ~/.zshrc
# Fish users edit ~/.config/fish/config.fish
# Delete: source /path/to/global_scripts-v6/env.sh
```

2. Delete configuration files (optional):
```bash
rm -rf ~/.config/global-scripts
```

3. Delete project directory:
```bash
rm -rf /path/to/global_scripts-v6
```

### Q: Multiple versions coexisting?

**A:** Use different GS_ROOT:

```bash
# Version 5
export GS_ROOT="/path/to/global_scripts-v5"
source "$GS_ROOT/env.sh"

# Version 6
export GS_ROOT="/path/to/global_scripts-v6"
source "$GS_ROOT/env.sh"
```

### Q: How to contribute code?

**A:** Refer to the [Contributing Guide](./contributing.md)

## More Help

### Get Community Support

- GitHub Issues: Submit bugs or feature requests
- Discussion Forum: Participate in community discussions
- Documentation: View complete documentation

### Report Bugs

When submitting an issue, please include:

1. System information: `gs doctor`
2. Error logs: `~/.config/global-scripts/logs/gs.log`
3. Steps to reproduce
4. Expected behavior vs actual behavior

### Request Features

Clearly describe:

1. Use case
2. Expected functionality
3. Optional implementation approaches

---

**Can't find an answer?**

- View the [complete documentation](./README.md)
- Submit a [GitHub Issue](https://github.com/i-rtfsc/global_scripts/issues)
- Ask in the discussion forum
