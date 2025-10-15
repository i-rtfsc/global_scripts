# YAML Parser Extension for Global Scripts

This is an example third-party parser extension that enables YAML-based plugin definitions in Global Scripts.

## Features

- Parse plugin functions from YAML files
- Supports function metadata (name, description, command, type)
- Supports arguments and options
- Supports examples
- Automatic discovery via Python Entry Points

## Installation

### From Source

```bash
# Clone or copy this directory
cd custom_parser

# Install using uv (recommended)
uv pip install .

# Or using pip
pip install .
```

### Development Mode

```bash
# Install in editable mode
uv pip install -e .
```

## Usage

Once installed, the YAML parser will be automatically discovered by Global Scripts.

### Creating YAML Plugins

Create a `.yaml` or `.yml` file in your plugin directory:

```yaml
functions:
  - name: hello
    description: Say hello to someone
    command: echo "Hello, {{args[0]}}!"
    type: shell
    args:
      - name
    options:
      greeting:
        description: Custom greeting message
        default: Hello
    examples:
      - hello world
      - hello --greeting=Hi Alice
```

### Verification

Check if the parser is registered:

```bash
gs parser list
```

You should see `yaml` in the list of available parsers.

## YAML Format Specification

### Required Fields

- `name`: Function name (string)
- `description`: Function description (string)
- `command`: Command to execute (string)

### Optional Fields

- `type`: Function type (default: "shell")
- `args`: List of argument names
- `options`: Dictionary of option definitions
- `examples`: List of usage examples

### Example with All Fields

```yaml
functions:
  - name: greet
    description: Greet someone with a custom message
    command: |
      if [ -n "{{options.formal}}" ]; then
        echo "Good day, {{args[0]}}!"
      else
        echo "Hey {{args[0]}}!"
      fi
    type: shell
    args:
      - name
    options:
      formal:
        description: Use formal greeting
        type: boolean
        default: false
    examples:
      - greet Alice
      - greet --formal Bob
```

## Testing

Run the included test:

```bash
python yaml_parser.py
```

## Uninstallation

```bash
uv pip uninstall gscripts-yaml-parser
```

## Development

### Project Structure

```
custom_parser/
├── yaml_parser.py          # Parser implementation
├── example_plugin.yaml     # Example YAML plugin
├── pyproject.toml          # Package configuration
└── README.md               # This file
```

### Making Modifications

1. Edit `yaml_parser.py` to customize the parser behavior
2. Update metadata in the `@parser_metadata` decorator
3. Test your changes with `python yaml_parser.py`
4. Reinstall the package to apply changes

## License

MIT License - This is example code for educational purposes.

## Contributing

This is an example extension. Feel free to use it as a template for your own parsers!

## Resources

- [Global Scripts Documentation](https://github.com/i-rtfsc/global_scripts)
- [Custom Parser Development Guide](../../extensibility/custom-parsers.md)
