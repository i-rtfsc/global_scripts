# Contributing Guide

Thank you for considering contributing to Global Scripts!

[中文](contributing.md) | [English](contributing_EN.md)

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Environment Setup](#development-environment-setup)
- [Code Standards](#code-standards)
- [Commit Conventions](#commit-conventions)
- [Pull Request Process](#pull-request-process)
- [Plugin Contributions](#plugin-contributions)
- [Documentation Contributions](#documentation-contributions)
- [Bug Reports](#bug-reports)
- [Feature Requests](#feature-requests)

## Code of Conduct

### Our Pledge

To foster an open and welcoming environment, we pledge to:

- Respect differing viewpoints and experiences
- Gracefully accept constructive criticism
- Focus on what is best for the community
- Show empathy towards other community members

### Unacceptable Behavior

- Use of sexualized language or imagery
- Personal attacks or insulting comments
- Public or private harassment
- Publishing others' private information without permission
- Other unethical or unprofessional conduct

## How to Contribute

### Types of Contributions

We welcome the following types of contributions:

- **Code**: Bug fixes, new features, performance optimizations
- **Plugins**: New plugins or improvements to existing plugins
- **Documentation**: Improving documentation, adding examples, fixing errors
- **Tests**: Increasing test coverage
- **Bug Reports**: Reporting issues and errors
- **Feature Requests**: Suggesting new features
- **Code Review**: Reviewing others' PRs

### Getting Started

1. **Fork the repository**: Fork this project on GitHub
2. **Clone locally**: `git clone https://github.com/YOUR_USERNAME/global_scripts.git`
3. **Create a branch**: `git checkout -b feature/your-feature-name`
4. **Make changes**: Write code, tests, documentation
5. **Commit changes**: `git commit -m "Add some feature"`
6. **Push to GitHub**: `git push origin feature/your-feature-name`
7. **Create Pull Request**: Create a PR on GitHub

## Development Environment Setup

### Prerequisites

- Python 3.8+
- Git
- UV (recommended)
- jq (for testing completions)

### Installation Steps

```bash
# 1. Clone repository
git clone https://github.com/i-rtfsc/global_scripts.git
cd global_scripts

# 2. Install UV (if not installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# 3. Create virtual environment and install dependencies
uv sync --group dev

# 4. Activate virtual environment
source .venv/bin/activate

# 5. Install pre-commit hooks
pre-commit install

# 6. Run setup script
python3 scripts/setup.py
```

### Verify Installation

```bash
# Run tests
pytest tests/ -v

# Check code style
ruff check src/

# Type checking
mypy src/

# Run gs command
gs version
gs doctor
```

## Code Standards

### Python Code Style

We follow [PEP 8](https://pep8.org/) and project-specific conventions:

#### 1. Formatting

Use **Black** for code formatting:

```bash
# Format all code
black src/ tests/

# Check formatting
black --check src/ tests/
```

#### 2. Linting

Use **Ruff** for code checking:

```bash
# Check code
ruff check src/

# Auto-fix
ruff check --fix src/
```

#### 3. Type Annotations

Use **MyPy** for type checking:

```bash
mypy src/
```

**Requirements**:
- All public functions must have type annotations
- Use types from the typing module
- Use TypeAlias for complex types

Example:

```python
from typing import List, Dict, Optional
from gscripts.models import CommandResult

def execute_command(
    command: str,
    args: List[str],
    timeout: int = 30
) -> CommandResult:
    """Execute a command

    Args:
        command: Command name
        args: Argument list
        timeout: Timeout in seconds

    Returns:
        Command execution result
    """
    pass
```

#### 4. Docstrings

Use **Google style** docstrings:

```python
def complex_function(param1: str, param2: int) -> Dict[str, Any]:
    """One-line brief description.

    More detailed description, can be multi-line.

    Args:
        param1: Description of param1
        param2: Description of param2

    Returns:
        Description of return value

    Raises:
        ValueError: Raised when parameters are invalid

    Examples:
        >>> complex_function("test", 42)
        {"result": "success"}
    """
    pass
```

#### 5. Naming Conventions

- **Modules and packages**: `lowercase_with_underscores`
- **Classes**: `CapitalizedWords`
- **Functions and variables**: `lowercase_with_underscores`
- **Constants**: `UPPERCASE_WITH_UNDERSCORES`
- **Private members**: `_leading_underscore`

#### 6. Import Order

```python
# 1. Standard library
import os
import sys
from pathlib import Path

# 2. Third-party libraries
import aiofiles
from jinja2 import Template

# 3. Local modules
from gscripts.models import CommandResult
from gscripts.core import PluginManager
```

### Shell Script Conventions

#### 1. Shebang

```bash
#!/usr/bin/env bash
```

#### 2. Strict Mode

```bash
set -euo pipefail
```

#### 3. Function Definition

```bash
# Good practice
function_name() {
    local arg1="$1"
    local arg2="$2"

    # Parameter validation
    if [[ -z "$arg1" ]]; then
        echo "Error: arg1 is required" >&2
        return 1
    fi

    # Function logic
    echo "Processing..."
}
```

#### 4. Comments

```bash
# @plugin_function
# name: function-name
# description: Clear description
# usage: gs plugin function-name <args>

function_name() {
    # Implementation
}
```

### JSON Conventions

#### 1. Formatting

Use 2-space indentation:

```json
{
  "name": "plugin-name",
  "version": "1.0.0",
  "description": {
    "zh": "中文描述",
    "en": "English description"
  }
}
```

#### 2. Required Fields

plugin.json must contain:

```json
{
  "name": "string (required)",
  "version": "string (required)",
  "description": "string or i18n object (required)",
  "author": "string (optional)",
  "enabled": "boolean (optional, default: true)"
}
```

## Commit Conventions

### Commit Message Format

Use [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Type Categories

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation update
- `style`: Code formatting (does not affect functionality)
- `refactor`: Refactoring
- `perf`: Performance optimization
- `test`: Testing related
- `chore`: Build/tooling related
- `ci`: CI configuration

### Examples

```
feat(android): add device screenshot command

Add a new command to capture device screenshots with
optional file path parameter.

Closes #123
```

```
fix(plugin-loader): handle missing plugin.json gracefully

Previously, the loader would crash if plugin.json was missing.
Now it logs a warning and skips the plugin.

Fixes #456
```

### Commit Best Practices

- Each commit should do one thing
- Use present tense: "Add feature" not "Added feature"
- Use lowercase for first letter
- Don't end with a period
- Body explains "why" not "what"
- Reference related issues

## Pull Request Process

### Before Creating a PR

1. **Ensure code passes all checks**:

```bash
# Run tests
pytest tests/ -v

# Code formatting
black src/ tests/

# Linting
ruff check --fix src/

# Type checking
mypy src/
```

2. **Update documentation**:
   - If adding new features, update README and related documentation
   - Add docstrings
   - Update CHANGELOG.md

3. **Write tests**:
   - New features must have tests
   - Bug fixes need regression tests
   - Goal: Maintain 80%+ coverage

### PR Template

When creating a PR, please include:

```markdown
## Description
Briefly describe the purpose and content of this PR.

## Type
- [ ] Bug fix
- [ ] New feature
- [ ] Refactoring
- [ ] Documentation update
- [ ] Other (please specify)

## Changes
- List all changes in detail
- Use checklist format

## Testing
- [ ] Added new tests
- [ ] All tests pass
- [ ] Manual testing passed

## Documentation
- [ ] Updated README
- [ ] Updated related documentation
- [ ] Added docstrings

## Screenshots (if applicable)
Add screenshots or recordings

## Related Issues
Closes #issue_number
```

### PR Review Process

1. **Automated checks**: CI will automatically run tests and code checks
2. **Manual review**: Maintainers will review the code
3. **Feedback**: Make changes based on feedback
4. **Merge**: After review approval, merge into main branch

### Review Criteria

- Code style conforms to standards
- Tests are adequate and passing
- Documentation is complete
- No breaking changes (or clearly documented)
- Performance impact is acceptable
- Security considerations addressed

## Plugin Contributions

### New Plugin Checklist

- [ ] `plugin.json` is properly formatted and complete
- [ ] Includes Chinese and English descriptions
- [ ] Version follows SemVer
- [ ] All functions are documented
- [ ] Usage examples added
- [ ] Tests written
- [ ] README.md added
- [ ] LICENSE added (if standalone plugin)

### Plugin Directory Structure

```
plugins/yourplugin/
├── plugin.json          # Required: Plugin metadata
├── README.md            # Recommended: Plugin documentation
├── plugin.py            # Python plugin
├── utils.sh             # Shell scripts
├── tests/               # Tests
│   └── test_yourplugin.py
└── docs/                # Detailed documentation (optional)
    └── guide.md
```

### Plugin Examples

Refer to existing plugins:

- `plugins/android/` - Complex plugin example
- `plugins/system/` - System-level plugin
- `examples/python-simple/` - Simple Python plugin
- `examples/config-simple/` - Config plugin

## Documentation Contributions

### Documentation Types

- **User documentation**: README, quickstart, usage guides
- **Developer documentation**: Architecture design, API reference, plugin development
- **Maintenance documentation**: Contributing guide, release process

### Documentation Standards

1. **Use Markdown**
2. **Provide both Chinese and English versions**
3. **Include code examples**
4. **Add table of contents (for long documents)**
5. **Link to related documentation**

### Documentation Checklist

- [ ] No spelling errors
- [ ] Code examples are runnable
- [ ] Screenshots are clear and up-to-date
- [ ] Links are valid
- [ ] Formatting is consistent
- [ ] Appropriate heading hierarchy

## Bug Reports

### Bug Report Template

```markdown
## Description
Clear and concise description of the bug.

## Steps to Reproduce
1. Execute '...'
2. Click '....'
3. Scroll to '....'
4. See error

## Expected Behavior
Describe what should happen.

## Actual Behavior
Describe what actually happened.

## Environment
- OS: [e.g. macOS 13.0]
- Python version: [e.g. 3.11.0]
- Global Scripts version: [e.g. 5.0.0]
- Shell: [e.g. bash 5.1]

## Logs
Paste relevant log output.

## Screenshots
If applicable, add screenshots.

## Additional Information
Any other relevant information.
```

### Bug Report Best Practices

- Search existing issues to avoid duplicates
- Use a clear title
- Provide minimal reproducible example
- Include complete error messages
- Explain the impact

## Feature Requests

### Feature Request Template

```markdown
## Problem Description
What problem does this feature solve?

## Proposed Solution
Describe in detail the feature you want.

## Alternatives
Describe alternative solutions you've considered.

## Additional Information
Any other relevant information or screenshots.

## Willing to Contribute
- [ ] I'm willing to implement this feature
- [ ] I'm willing to help test
- [ ] I'm willing to write documentation
```

### Feature Request Guidelines

- Explain the use case
- Explain why it's important
- Consider backward compatibility
- Provide examples
- Discuss implementation approaches

## Release Process

### Version Numbers

Follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Incompatible API changes
- **MINOR**: Backward-compatible new features
- **PATCH**: Backward-compatible bug fixes

### Release Checklist

- [ ] Update version number (VERSION file)
- [ ] Update CHANGELOG.md
- [ ] Run full test suite
- [ ] Update documentation
- [ ] Create Git tag
- [ ] Push to GitHub
- [ ] Create GitHub Release
- [ ] Publish announcement

## Getting Help

### Communication Channels

- **GitHub Issues**: Report problems, feature requests
- **GitHub Discussions**: General discussions, questions
- **Pull Requests**: Code review

### Contact Maintainers

- Create an Issue or Discussion
- Mention `@maintainer` in PR
- Check contact information in [README](../README.md)

## Acknowledgments

Thank you to all contributors! Your contributions make Global Scripts better.

Contributors list: [CONTRIBUTORS.md](./CONTRIBUTORS.md)

---

**Ready to contribute?** Check out [Good First Issues](https://github.com/i-rtfsc/global_scripts/labels/good%20first%20issue)

**Back to**: [Documentation Home](./README.md)
