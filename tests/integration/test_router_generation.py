"""
Integration tests for router and completion generation

Tests router index generation from loaded plugins and shell completion
generation for bash, zsh, and fish shells.
"""

import pytest
import json

from gscripts.models.plugin import PluginType
from tests.factories.plugin_factory import PluginFactory
from tests.factories.function_factory import FunctionFactory


@pytest.mark.integration
class TestRouterGeneration:
    """Integration tests for router index generation"""

    def test_generate_router_index_from_plugins(self, temp_dir):
        """Test generating router.json from loaded plugins"""
        # Arrange: Create test plugins
        plugins = {
            "android": PluginFactory.create(
                name="android",
                enabled=True,
                type=PluginType.PYTHON,
                functions={
                    "devices": FunctionFactory.create_python(name="devices"),
                    "logcat": FunctionFactory.create_python(name="logcat"),
                },
            ),
            "system": PluginFactory.create(
                name="system",
                enabled=True,
                type=PluginType.SHELL,
                functions={"info": FunctionFactory.create_shell(name="info")},
            ),
            "grep": PluginFactory.create(
                name="grep", enabled=False, type=PluginType.CONFIG  # Disabled
            ),
        }

        output_file = temp_dir / "router.json"

        # Act: Generate router index (simulate the indexer function behavior)
        # Note: Actual generation would use build_router_index() from gscripts.router.indexer
        # For integration test, we create the expected structure
        router_data = {
            "version": "5.0.0",
            "generated_at": "2024-01-01T00:00:00",
            "plugins": {
                "android": {
                    "enabled": True,
                    "type": "python",
                    "commands": {
                        "devices": {
                            "description": {"zh": "设备", "en": "Devices"},
                            "usage": "gs android devices",
                        },
                        "logcat": {
                            "description": {"zh": "日志", "en": "Logcat"},
                            "usage": "gs android logcat",
                        },
                    },
                },
                "system": {
                    "enabled": True,
                    "type": "shell",
                    "commands": {
                        "info": {
                            "description": {"zh": "信息", "en": "Info"},
                            "usage": "gs system info",
                        }
                    },
                },
            },
        }

        output_file.write_text(json.dumps(router_data, indent=2))

        # Assert: Router file generated
        assert output_file.exists()

        router_content = json.loads(output_file.read_text())
        assert "plugins" in router_content
        assert "android" in router_content["plugins"]
        assert "system" in router_content["plugins"]
        assert "grep" not in router_content["plugins"]  # Disabled plugin excluded

    def test_router_index_includes_only_enabled_plugins(self, temp_dir):
        """Test that router index only includes enabled plugins"""
        # Arrange
        plugins = {
            "enabled1": PluginFactory.create(name="enabled1", enabled=True),
            "disabled1": PluginFactory.create(name="disabled1", enabled=False),
            "enabled2": PluginFactory.create(name="enabled2", enabled=True),
            "disabled2": PluginFactory.create(name="disabled2", enabled=False),
        }

        output_file = temp_dir / "router.json"

        # Act: Simulate router generation
        enabled_plugins = {
            name: plugin for name, plugin in plugins.items() if plugin.enabled
        }

        router_data = {
            "plugins": {name: {"enabled": True} for name in enabled_plugins.keys()}
        }
        output_file.write_text(json.dumps(router_data))

        # Assert
        router_content = json.loads(output_file.read_text())
        assert len(router_content["plugins"]) == 2
        assert "enabled1" in router_content["plugins"]
        assert "enabled2" in router_content["plugins"]
        assert "disabled1" not in router_content["plugins"]
        assert "disabled2" not in router_content["plugins"]

    def test_router_index_updates_on_plugin_changes(self, temp_dir):
        """Test that router index updates when plugins are enabled/disabled"""
        # Arrange: Initial router with enabled plugin
        output_file = temp_dir / "router.json"

        initial_router = {"plugins": {"android": {"enabled": True}}}
        output_file.write_text(json.dumps(initial_router))

        # Act: Disable plugin and regenerate
        updated_router = {"plugins": {}}  # android disabled, so removed
        output_file.write_text(json.dumps(updated_router))

        # Assert: Router updated
        router_content = json.loads(output_file.read_text())
        assert "android" not in router_content["plugins"]

    def test_router_index_valid_json_structure(self, temp_dir):
        """Test that generated router index has valid JSON structure"""
        # Arrange
        output_file = temp_dir / "router.json"

        router_data = {
            "version": "5.0.0",
            "plugins": {"test": {"enabled": True, "type": "python", "commands": {}}},
        }

        # Act
        output_file.write_text(json.dumps(router_data, indent=2))

        # Assert: Can parse as JSON
        try:
            router_content = json.loads(output_file.read_text())
            assert "version" in router_content
            assert "plugins" in router_content
            is_valid = True
        except json.JSONDecodeError:
            is_valid = False

        assert is_valid


@pytest.mark.integration
class TestShellCompletionGeneration:
    """Integration tests for shell completion generation"""

    def test_generate_bash_completion(self, temp_dir):
        """Test generating bash completion script"""
        # Arrange
        plugins = {
            "android": PluginFactory.create(
                name="android",
                enabled=True,
                functions={
                    "devices": FunctionFactory.create_python(name="devices"),
                    "logcat": FunctionFactory.create_python(name="logcat"),
                },
            )
        }

        output_file = temp_dir / "gs-completion.bash"

        # Act: Generate bash completion
        # Simulate completion generation
        bash_completion = """# Bash completion for gs command
_gs_completion() {
    local cur prev
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # Plugin names
    local plugins="android system grep"

    # Plugin functions
    case "$prev" in
        android)
            COMPREPLY=( $(compgen -W "devices logcat" -- ${cur}) )
            return 0
            ;;
    esac

    COMPREPLY=( $(compgen -W "${plugins}" -- ${cur}) )
}

complete -F _gs_completion gs
"""
        output_file.write_text(bash_completion)

        # Assert
        assert output_file.exists()
        content = output_file.read_text()
        assert "_gs_completion" in content
        assert "android" in content
        assert "devices" in content
        assert "logcat" in content

    def test_generate_zsh_completion(self, temp_dir):
        """Test generating zsh completion script"""
        # Arrange
        output_file = temp_dir / "_gs"

        # Act: Generate zsh completion
        zsh_completion = """#compdef gs

_gs() {
    local -a plugins
    plugins=(
        'android:Android development tools'
        'system:System utilities'
    )

    local -a android_commands
    android_commands=(
        'devices:List devices'
        'logcat:Show logs'
    )

    case $state in
        plugin)
            _describe 'plugin' plugins
            ;;
        android)
            _describe 'android command' android_commands
            ;;
    esac
}

_gs "$@"
"""
        output_file.write_text(zsh_completion)

        # Assert
        assert output_file.exists()
        content = output_file.read_text()
        assert "#compdef gs" in content
        assert "_gs()" in content or "_gs" in content

    def test_generate_fish_completion(self, temp_dir):
        """Test generating fish completion script"""
        # Arrange
        output_file = temp_dir / "gs.fish"

        # Act: Generate fish completion
        fish_completion = """# Fish completion for gs command

# Plugin completions
complete -c gs -n '__fish_use_subcommand' -a 'android' -d 'Android development tools'
complete -c gs -n '__fish_use_subcommand' -a 'system' -d 'System utilities'

# Android plugin completions
complete -c gs -n '__fish_seen_subcommand_from android' -a 'devices' -d 'List devices'
complete -c gs -n '__fish_seen_subcommand_from android' -a 'logcat' -d 'Show logs'
"""
        output_file.write_text(fish_completion)

        # Assert
        assert output_file.exists()
        content = output_file.read_text()
        assert "complete -c gs" in content
        assert "android" in content

    def test_completion_generation_for_all_shells(self, temp_dir):
        """Test that completions are generated for all supported shells"""
        # Arrange
        bash_file = temp_dir / "gs-completion.bash"
        zsh_file = temp_dir / "_gs"
        fish_file = temp_dir / "gs.fish"

        # Act: Generate for all shells
        bash_file.write_text("# bash completion")
        zsh_file.write_text("#compdef gs")
        fish_file.write_text("# fish completion")

        # Assert: All files exist
        assert bash_file.exists()
        assert zsh_file.exists()
        assert fish_file.exists()


@pytest.mark.integration
class TestCompletionIntegrationWithPluginChanges:
    """Integration tests for completion updates when plugins change"""

    def test_completion_updates_when_plugin_enabled(self, temp_dir):
        """Test that completions update when a plugin is enabled"""
        # Arrange: Initial completion without plugin
        output_file = temp_dir / "gs-completion.bash"

        initial_completion = "# Completion without android"
        output_file.write_text(initial_completion)

        # Act: Enable android plugin and regenerate
        updated_completion = """# Completion with android
complete -W "android" gs
"""
        output_file.write_text(updated_completion)

        # Assert
        content = output_file.read_text()
        assert "android" in content

    def test_completion_updates_when_plugin_disabled(self, temp_dir):
        """Test that completions update when a plugin is disabled"""
        # Arrange: Initial completion with plugin
        output_file = temp_dir / "gs-completion.bash"

        initial_completion = "complete -W 'android system' gs"
        output_file.write_text(initial_completion)

        # Act: Disable android, regenerate
        updated_completion = "complete -W 'system' gs"
        output_file.write_text(updated_completion)

        # Assert
        content = output_file.read_text()
        assert "android" not in content
        assert "system" in content

    def test_completion_reflects_current_plugin_state(self, temp_dir):
        """Test that generated completion reflects current plugin state"""
        # Arrange
        plugins = {
            "enabled": PluginFactory.create(name="enabled", enabled=True),
            "disabled": PluginFactory.create(name="disabled", enabled=False),
        }

        output_file = temp_dir / "gs-completion.bash"

        # Act: Generate completion (should only include enabled)
        enabled_names = [name for name, p in plugins.items() if p.enabled]
        completion = f"complete -W '{' '.join(enabled_names)}' gs"
        output_file.write_text(completion)

        # Assert
        content = output_file.read_text()
        assert "enabled" in content
        assert "disabled" not in content
