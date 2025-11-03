"""
Plugin Executor Service
Handles plugin command execution
"""

import asyncio
import shlex
from pathlib import Path
from typing import List, Optional, Dict, Any
from ...models import CommandResult
from ...domain.interfaces import IPluginLoader, IProcessExecutor
from ...core.logger import get_logger
from ...core.constants import GlobalConstants
from ...utils.logging_utils import correlation_id, duration
from ...plugins.interfaces import PluginEvent, PluginEventData

logger = get_logger(tag="APP.PLUGIN_EXECUTOR", name=__name__)


class PluginExecutor:
    """
    Plugin executor service

    Handles execution of plugin commands with security features:
    - Command validation (forbidden patterns, length limits)
    - Argument sanitization (shlex.quote)
    - Concurrent execution limiting (semaphore)
    - Config-based commands
    - Shell script commands
    - Python function commands
    """

    def __init__(
        self,
        plugin_loader: IPluginLoader,
        process_executor: IProcessExecutor,
        max_concurrent: int = 10
    ):
        """
        Initialize plugin executor

        Args:
            plugin_loader: Plugin loader for accessing loaded plugins
            process_executor: Process executor for running commands
            max_concurrent: Maximum concurrent executions (default: 10)
        """
        self._loader = plugin_loader
        self._executor = process_executor
        self._observers = []
        self._semaphore = asyncio.Semaphore(max_concurrent)
        logger.info(f"PluginExecutor initialized with max_concurrent={max_concurrent}")

    def register_observer(self, observer) -> None:
        """Register observer for execution events"""
        if observer not in self._observers:
            self._observers.append(observer)

    def unregister_observer(self, observer) -> None:
        """Unregister observer"""
        if observer in self._observers:
            self._observers.remove(observer)

    def _notify(self, event: PluginEvent, plugin_name: str, **kwargs) -> None:
        """Notify observers of events"""
        event_data = PluginEventData(
            event=event,
            plugin_name=plugin_name,
            metadata=kwargs
        )
        for observer in self._observers:
            try:
                observer.on_plugin_event(event_data)
            except Exception as e:
                logger.error(f"Observer {observer} failed: {e}")

    def _validate_command(self, command: str) -> bool:
        """
        Validate command safety

        Args:
            command: Command string to validate

        Returns:
            bool: True if command is safe
        """
        return GlobalConstants.validate_command_safety(command)

    def _sanitize_args(self, args: List[str]) -> List[str]:
        """
        Sanitize command arguments to prevent injection

        Args:
            args: List of arguments

        Returns:
            List[str]: Sanitized arguments
        """
        return [shlex.quote(arg) for arg in args]

    async def execute_plugin_function(
        self,
        plugin_name: str,
        function_name: str,
        args: List[str] = None
    ) -> CommandResult:
        """
        Execute a plugin function

        Args:
            plugin_name: Name of the plugin
            function_name: Name of the function to execute
            args: Command arguments

        Returns:
            CommandResult: Execution result
        """
        # Acquire semaphore for concurrent execution limiting
        async with self._semaphore:
            return await self._execute_plugin_function_internal(
                plugin_name,
                function_name,
                args
            )

    async def _execute_plugin_function_internal(
        self,
        plugin_name: str,
        function_name: str,
        args: List[str] = None
    ) -> CommandResult:
        """
        Internal execution method (runs under semaphore)

        Args:
            plugin_name: Name of the plugin
            function_name: Name of the function to execute
            args: Command arguments

        Returns:
            CommandResult: Execution result
        """
        cid = correlation_id()
        from time import monotonic
        start_ts = monotonic()

        if args is None:
            args = []

        # Sanitize arguments to prevent injection
        sanitized_args = self._sanitize_args(args)

        logger.debug(
            f"cid={cid} exec enter plugin={plugin_name} function={function_name} args_len={len(args)}"
        )

        # Notify EXECUTING event
        self._notify(PluginEvent.EXECUTING, plugin_name, function=function_name, args=args)

        try:
            # Get loaded plugins
            loaded_plugins = self._loader.get_loaded_plugins()

            if plugin_name not in loaded_plugins:
                took = duration(start_ts)
                logger.warning(f"cid={cid} exec plugin_not_found plugin={plugin_name} took_ms={took}")
                result = CommandResult(
                    success=False,
                    error=f"Plugin '{plugin_name}' not found or not loaded",
                    exit_code=1
                )
                self._notify(PluginEvent.EXECUTED, plugin_name, success=False, error=result.error)
                return result

            plugin = loaded_plugins[plugin_name]
            functions = plugin.get('functions', {})

            if function_name not in functions:
                took = duration(start_ts)
                logger.warning(
                    f"cid={cid} exec function_not_found plugin={plugin_name} function={function_name} took_ms={took}"
                )
                result = CommandResult(
                    success=False,
                    error=f"Function '{function_name}' not found in plugin '{plugin_name}'",
                    exit_code=1
                )
                self._notify(PluginEvent.EXECUTED, plugin_name, success=False, error=result.error)
                return result

            function_info = functions[function_name]
            function_type = function_info.get('type', 'unknown')

            # Route to appropriate execution method
            if function_type == 'config':
                result = await self._execute_config_function(function_info, sanitized_args)
            elif function_type in ('script', 'shell', 'shell_annotated'):
                result = await self._execute_script_function(function_info, sanitized_args)
            elif function_type in ('python', 'python_decorated'):
                result = await self._execute_python_function(function_info, args)  # Python functions get unsanitized args
            else:
                took = duration(start_ts)
                logger.error(
                    f"cid={cid} exec unknown_type plugin={plugin_name} function={function_name} type={function_type} took_ms={took}"
                )
                result = CommandResult(
                    success=False,
                    error=f"Unknown function type: {function_type}",
                    exit_code=1
                )

            took = duration(start_ts)
            if result.success:
                logger.info(
                    f"cid={cid} exec ok plugin={plugin_name} function={function_name} took_ms={took} exit_code={result.exit_code}"
                )
            else:
                logger.error(
                    f"cid={cid} exec fail plugin={plugin_name} function={function_name} took_ms={took} error={result.error}"
                )

            # Notify EXECUTED event
            self._notify(
                PluginEvent.EXECUTED,
                plugin_name,
                success=result.success,
                exit_code=result.exit_code,
                error=result.error if not result.success else None
            )

            return result

        except Exception as e:
            took = duration(start_ts)
            logger.error(
                f"cid={cid} exec exception plugin={plugin_name} function={function_name} took_ms={took} error={type(e).__name__}: {e}"
            )
            result = CommandResult(
                success=False,
                error=f"Execution failed: {str(e)}",
                exit_code=1
            )
            self._notify(PluginEvent.EXECUTED, plugin_name, success=False, error=str(e))
            return result

    async def _execute_config_function(
        self,
        function_info: dict,
        args: List[str]
    ) -> CommandResult:
        """
        Execute config-based command

        Config functions are defined in plugin.json with a command string
        """
        command_template = function_info.get('command', '')
        if not command_template:
            return CommandResult(
                success=False,
                error="Config function missing 'command' field",
                exit_code=1
            )

        # Replace {args} placeholder with actual arguments (already sanitized)
        if '{args}' in command_template:
            command_str = command_template.replace('{args}', ' '.join(args))
        else:
            # Append args if no placeholder
            command_str = f"{command_template} {' '.join(args)}".strip()

        # Validate command safety
        if not self._validate_command(command_str):
            logger.warning(f"Command validation failed: {command_str}")
            return CommandResult(
                success=False,
                error=f"Command rejected by security policy: contains forbidden patterns or exceeds length limit",
                exit_code=1
            )

        # Execute as shell command
        return await self._executor.execute_shell(command_str)

    async def _execute_script_function(
        self,
        function_info: dict,
        args: List[str]
    ) -> CommandResult:
        """
        Execute shell script command

        Script functions point to .sh files with shell functions
        """
        command_template = function_info.get('command', '')
        shell_file = function_info.get('shell_file')

        if not command_template:
            return CommandResult(
                success=False,
                error="Script function missing 'command' field",
                exit_code=1
            )

        # For shell functions, we need to source the file and call the function
        if shell_file and Path(shell_file).exists():
            # Build command: source file && call function with args (already sanitized)
            function_call = command_template
            if args:
                function_call = f"{function_call} {' '.join(args)}"

            command_str = f"source {shell_file} && {function_call}"
        else:
            # Direct command execution
            if args:
                command_str = f"{command_template} {' '.join(args)}"
            else:
                command_str = command_template

        # Validate command safety
        if not self._validate_command(command_str):
            logger.warning(f"Command validation failed: {command_str}")
            return CommandResult(
                success=False,
                error=f"Command rejected by security policy: contains forbidden patterns or exceeds length limit",
                exit_code=1
            )

        return await self._executor.execute_shell(command_str)

    async def _execute_python_function(
        self,
        function_info: dict,
        args: List[str]
    ) -> CommandResult:
        """
        Execute Python function command - with full decorated function support

        Python functions can be:
        1. Decorated functions in plugin.py (@plugin_function)
        2. Methods in BasePlugin subclasses
        3. Standalone Python scripts
        """
        python_file = function_info.get('python_file')

        if not python_file:
            return CommandResult(
                success=False,
                error="Python function missing 'python_file' field",
                exit_code=1
            )

        python_file = Path(python_file)

        if not python_file.exists():
            return CommandResult(
                success=False,
                error=f"Python file not found: {python_file}",
                exit_code=1
            )

        try:
            # Dynamic import of plugin module
            import importlib.util
            import sys
            import inspect
            import asyncio

            resolved_path = python_file.resolve()

            # Find project root containing src/gscripts
            project_root = None
            for parent in [resolved_path.parent, *resolved_path.parents]:
                if (parent / 'src' / 'gscripts').exists():
                    project_root = parent
                    break
            if project_root and str(project_root / 'src') not in sys.path:
                sys.path.insert(0, str(project_root / 'src'))

            # Dynamic module import
            module_name = f"plugin_{resolved_path.stem}_{resolved_path.parent.name}"
            spec = importlib.util.spec_from_file_location(module_name, python_file)
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)

            target_name = function_info.get('name', '')

            # 1) Look for module-level @plugin_function decorated functions
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if callable(attr) and hasattr(attr, '_function_info'):
                    info = getattr(attr, '_function_info', None)
                    if info and getattr(info, 'name', None) == target_name:
                        # Call decorated function
                        try:
                            sig = inspect.signature(attr)
                            if len(sig.parameters) == 0:
                                ret = await attr() if asyncio.iscoroutinefunction(attr) else attr()
                            else:
                                ret = await attr(args) if asyncio.iscoroutinefunction(attr) else attr(args)

                            # Normalize return value
                            from ...models import CommandResult as CR
                            if isinstance(ret, CR):
                                return ret
                            if ret is None:
                                return CR(True)
                            return CR(True, output=str(ret))
                        except Exception as e:
                            return CommandResult(False, error=f"Python function error: {str(e)}", exit_code=1)

            # 2) Look for BasePlugin subclasses
            try:
                from ...plugins.base import BasePlugin
            except Exception:
                BasePlugin = None

            class_candidates = []
            if BasePlugin:
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if isinstance(attr, type):
                        if issubclass(attr, BasePlugin) and attr is not BasePlugin and getattr(attr, '__module__', '') == module.__name__:
                            class_candidates.append(attr)

            # Prioritize classes with @subplugin decorator
            def class_priority(cls):
                return 0 if getattr(cls, '_is_subplugin_class', False) else 1
            class_candidates.sort(key=class_priority)

            # 3) Instantiate and find method
            for plugin_class in class_candidates:
                try:
                    plugin_instance = plugin_class()
                except Exception:
                    # Can't instantiate without args, skip
                    continue

                # If loader provided method name, use it
                method = None
                if 'method' in function_info:
                    candidate_name = function_info['method']
                    if hasattr(plugin_instance, candidate_name):
                        method = getattr(plugin_instance, candidate_name)

                # Match by decorator info
                if not method:
                    for name in dir(plugin_instance):
                        member = getattr(plugin_instance, name)
                        if callable(member):
                            info = getattr(member, '_function_info', None)
                            if info is None and hasattr(member, '__func__'):
                                info = getattr(member.__func__, '_function_info', None)
                            if info and getattr(info, 'name', None) == target_name:
                                method = member
                                break

                # Common naming fallback
                if not method:
                    for candidate in [
                        target_name,
                        f"{target_name}_command",
                        f"execute_{target_name}",
                        f"handle_{target_name}"
                    ]:
                        if hasattr(plugin_instance, candidate):
                            method = getattr(plugin_instance, candidate)
                            break

                if not method:
                    continue

                # Call method
                try:
                    sig = inspect.signature(method)
                    params = [p for p in sig.parameters.values() if p.name != 'self']
                    if len(params) == 0:
                        ret = await method() if asyncio.iscoroutinefunction(method) else method()
                    else:
                        ret = await method(args) if asyncio.iscoroutinefunction(method) else method(args)

                    from ...models import CommandResult as CR
                    if isinstance(ret, CR):
                        return ret
                    if ret is None:
                        return CR(True)
                    return CR(True, output=str(ret))
                except Exception as e:
                    return CommandResult(False, error=f"Python method error: {str(e)}", exit_code=1)

            # No entry point found
            return CommandResult(
                success=False,
                error=f"No callable found for '{target_name}' in {python_file}",
                exit_code=1
            )

        except Exception as e:
            return CommandResult(
                success=False,
                error=f"Python execution error: {str(e)}",
                exit_code=1
            )


__all__ = ['PluginExecutor']
