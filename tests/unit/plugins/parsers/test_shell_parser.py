"""Tests for the Shell function parser."""

import pytest

from gscripts.plugins.parsers.shell_parser import ShellFunctionParser


@pytest.mark.asyncio
async def test_annotated_function_stores_callable_name_in_command(tmp_path):
    """Regression: the parser must keep the real bash function name in
    `command` so the executor can `source file && <command>`. Previously it
    stored an empty command, which broke `gs grep help`."""
    script = tmp_path / "plugin.sh"
    script.write_text(
        "\n".join(
            [
                "# @plugin_function",
                "# name: help",
                "# description:",
                "#   zh: 显示帮助",
                "#   en: Show help",
                "# usage: gs grep help",
                "help() {",
                "    echo hi",
                "}",
            ]
        ),
        encoding="utf-8",
    )

    parser = ShellFunctionParser()
    functions = await parser.parse(script, plugin_name="grep")

    assert len(functions) == 1
    func = functions[0]
    assert func.name == "help"
    # The callable bash function name must be preserved for execution.
    assert func.command == "help"
    assert func.script_file == script


def _write(tmp_path, body):
    script = tmp_path / "plugin.sh"
    script.write_text("#!/bin/bash\n" + body, encoding="utf-8")
    return script


@pytest.mark.asyncio
async def test_canonical_format_parses_description_and_examples(tmp_path):
    """Canonical `# name:` / `# description:` / `# examples:` block (the
    format used by built-in plugins) is parsed in full."""
    script = _write(
        tmp_path,
        "\n".join(
            [
                "# @plugin_function",
                "# name: search",
                "# description:",
                "#   zh: 搜索",
                "#   en: Search",
                "# usage: gs demo search <pat>",
                "# examples:",
                "#   - gs demo search foo",
                "#   - gs demo search bar",
                "search() {",
                "    echo search",
                "}",
            ]
        ),
    )
    func = (await ShellFunctionParser().parse(script, plugin_name="demo"))[0]
    assert func.name == "search"
    assert func.command == "search"
    assert func.description == {"zh": "搜索", "en": "Search"}
    assert func.usage == "gs demo search <pat>"
    assert func.examples == ["gs demo search foo", "gs demo search bar"]


@pytest.mark.asyncio
async def test_at_style_alias_with_inline_json_description(tmp_path):
    """The `# @key` alias style with inline-JSON description and the
    `function name()` definition syntax are also accepted."""
    script = _write(
        tmp_path,
        "\n".join(
            [
                "# @plugin_function",
                "# @name hello",
                '# @description {"zh": "打招呼", "en": "Say hello"}',
                "# @usage gs demo hello",
                "function hello() {",
                "    echo hi",
                "}",
            ]
        ),
    )
    func = (await ShellFunctionParser().parse(script, plugin_name="demo"))[0]
    assert func.name == "hello"
    assert func.command == "hello"
    assert func.description == {"zh": "打招呼", "en": "Say hello"}
    assert func.usage == "gs demo hello"


@pytest.mark.asyncio
async def test_explicit_name_overrides_bash_function_name(tmp_path):
    """`# name:` sets the user-facing command; the bash function name is kept
    as the executable `command`."""
    script = _write(
        tmp_path,
        "\n".join(
            [
                "# @plugin_function",
                "# name: search",
                "gs_demo_search() {",
                "    echo search",
                "}",
            ]
        ),
    )
    func = (await ShellFunctionParser().parse(script, plugin_name="demo"))[0]
    assert func.name == "search"  # user-facing
    assert func.command == "gs_demo_search"  # actual bash function to source+call

