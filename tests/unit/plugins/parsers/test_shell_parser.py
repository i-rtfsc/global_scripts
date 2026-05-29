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
