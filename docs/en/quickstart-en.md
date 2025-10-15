# Quick Start Guide

This guide will help you quickly get started with Global Scripts.

## Prerequisites

Make sure you have completed the [Installation](installation.md).

## Basic Usage

### View Available Scripts

```bash
# List all available scripts
gs list

# Filter scripts by tag
gs list --tag git

# View script details
gs show script-name
```

### Execute Scripts

```bash
# Execute script
gs run script-name

# Pass parameters
gs run script-name --param value

# Execute with debug mode
gs run --debug script-name
```

### Search Scripts

```bash
# Search by name
gs search keyword

# Search by tag
gs search --tag tag-name

# Search by description
gs search --description keyword
```

## Common Use Cases

### 1. Git Operations

```bash
# Quick commit
gs run git-quick-commit

# View branch status
gs run git-status

# Clean branches
gs run git-clean-branches
```

### 2. Environment Management

```bash
# Activate Python environment
gs run activate-env

# View environment information
gs run env-info
```

### 3. System Tools

```bash
# Clean cache
gs run clean-cache

# View system information
gs run system-info
```

## Create Your First Script

### 1. Create Script File

Create a new YAML file in the `scripts/` directory:

```bash
touch scripts/my-first-script.yaml
```

### 2. Write Script Configuration

Edit `scripts/my-first-script.yaml`:

```yaml
name: my-first-script
description: My first Global Script
version: 1.0.0
tags:
  - example
  - demo

parameters:
  - name: message
    description: Message to display
    type: string
    default: "Hello, World!"

steps:
  - name: Display message
    action: shell
    command: echo "{{ message }}"
```

### 3. Test Script

```bash
# Test with default parameters
gs run my-first-script

# Pass custom parameters
gs run my-first-script --message "Hello, Global Scripts!"
```

## Advanced Features

### Parameter Handling

Scripts support multiple parameter types:

```yaml
parameters:
  # String type
  - name: text
    type: string
    default: "default value"

  # Numeric type
  - name: count
    type: integer
    default: 1

  # Boolean type
  - name: verbose
    type: boolean
    default: false

  # List type
  - name: items
    type: array
    default: ["item1", "item2"]
```

### Environment Variables

Use environment variables in scripts:

```yaml
steps:
  - name: Use environment variable
    action: shell
    command: echo "User: $USER, Home: $HOME"

  - name: Set environment variable
    action: shell
    command: export MY_VAR="value"
```

### Conditional Execution

Use conditions to control script execution flow:

```yaml
steps:
  - name: Conditional step
    action: shell
    command: echo "This is Linux"
    when: "{{ platform == 'linux' }}"

  - name: Another conditional step
    action: shell
    command: echo "This is macOS"
    when: "{{ platform == 'darwin' }}"
```

### Error Handling

Configure error handling behavior:

```yaml
steps:
  - name: Might fail
    action: shell
    command: some-command
    ignore_errors: true  # Continue even if failed

  - name: Must succeed
    action: shell
    command: important-command
    ignore_errors: false  # Stop if failed (default)
```

## Best Practices

1. **Naming Standards**
   - Use lowercase with hyphens: `my-script-name`
   - Name should be descriptive and clear

2. **Add Description**
   - Write clear descriptions
   - Describe script purpose and usage

3. **Use Tags**
   - Add relevant tags for classification
   - Facilitate script searching and filtering

4. **Parameter Validation**
   - Set appropriate parameter types
   - Provide default values
   - Add parameter descriptions

5. **Error Handling**
   - Handle possible errors appropriately
   - Provide meaningful error messages

6. **Documentation**
   - Add comments to complex scripts
   - Provide usage examples

## Next Steps

- [Plugin Development Guide](plugin-development.md) - Learn how to develop complex plugins
- [Architecture Documentation](architecture.md) - Understand system architecture
- [FAQ](faq.md) - Find answers to common questions
- [API Reference](api-reference.md) - View detailed API documentation
