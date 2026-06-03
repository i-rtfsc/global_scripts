"""Global Scripts 6.0 Python plugin SDK.

A stdlib-only helper for writing T2 ("script" tier) plugins that speak
JSON-RPC 2.0 over stdio with LSP-style ``Content-Length`` framing, as
defined in ``tmp/phase0-plugin-protocol.md``.

Typical usage::

    from gs_plugin import Plugin

    plugin = Plugin(name="demo")

    @plugin.command(
        name="greet",
        summary={"zh": "打招呼", "en": "Greet"},
        args=[{"name": "name", "type": "string", "required": True}],
    )
    def greet(ctx):
        name = ctx.args.get("name", "world")
        ctx.emit_progress(pct=50, stage="greeting", message="building")
        ctx.emit_output("stdout", "Hello, {}!\n".format(name))
        return 0

    @plugin.completer(source="colors")
    def colors(params):
        return ["red", "green", "blue"]

    if __name__ == "__main__":
        plugin.run()
"""

from __future__ import annotations

import sys
import traceback
from typing import Any, Callable, Dict, List, Optional

from .framing import read_message, write_message

# JSON-RPC error codes (subset used here).
METHOD_NOT_FOUND = -32601
INTERNAL_ERROR = -32603
INVALID_PARAMS = -32602


class InvokeContext:
    """Passed to invoke handlers. Carries the parsed request and provides
    helpers to stream ``progress``/``log``/``output`` event notifications.

    Emitted events are also collected into ``self.events`` so they can be
    echoed back in the final ``invoke`` result (useful for non-interactive /
    record scenarios per protocol §5.2).
    """

    def __init__(
        self,
        command: str,
        args: Dict[str, Any],
        cwd: Optional[str],
        env: Dict[str, Any],
        context: Dict[str, Any],
        capabilities: Dict[str, Any],
        out_stream,
    ) -> None:
        self.command = command
        self.args = args or {}
        self.cwd = cwd
        self.env = env or {}
        self.context = context or {}
        self.capabilities = capabilities or {}
        self.events: List[Dict[str, Any]] = []
        self._out = out_stream

    def emit(self, params: Dict[str, Any]) -> None:
        """Emit a raw ``event`` notification (no ``id``) and record it."""
        self.events.append(dict(params))
        write_message(
            self._out,
            {"jsonrpc": "2.0", "method": "event", "params": params},
        )

    def emit_progress(
        self,
        message: str = "",
        pct: Optional[int] = None,
        stage: Optional[str] = None,
    ) -> None:
        params: Dict[str, Any] = {"type": "progress"}
        if pct is not None:
            params["pct"] = pct
        if stage is not None:
            params["stage"] = stage
        if message:
            params["message"] = message
        self.emit(params)

    def emit_log(self, message: str, level: str = "info") -> None:
        self.emit({"type": "log", "level": level, "message": message})

    def emit_output(self, stream: str, chunk: str) -> None:
        """Stream output. ``stream`` is ``"stdout"`` or ``"stderr"``."""
        self.emit({"type": "output", "stream": stream, "chunk": chunk})


class Plugin:
    """A registry of commands and completion sources plus a stdio run loop."""

    def __init__(self, name: str, protocol: int = 1) -> None:
        self.name = name
        self.protocol = protocol
        # name -> {"spec": {...describe command...}, "handler": callable}
        self._commands: Dict[str, Dict[str, Any]] = {}
        # source -> callable(params) -> list
        self._completers: Dict[str, Callable[[Dict[str, Any]], Any]] = {}

    # ----- registration ---------------------------------------------------

    def command(
        self,
        name: str,
        summary: Dict[str, str],
        usage: Optional[str] = None,
        examples: Optional[List[str]] = None,
        args: Optional[List[Dict[str, Any]]] = None,
        hidden: bool = False,
    ) -> Callable:
        """Decorator registering a command handler.

        ``args`` is a list of dicts matching the describe arg schema
        (``name``/``type``/``required``/``variadic``/``flag``/``default``/
        ``description``/``complete``). The decorated handler is called as
        ``handler(ctx: InvokeContext)`` and should return an ``int`` exit
        code (or ``None`` for 0), or a dict to merge into the result.
        """

        spec: Dict[str, Any] = {"name": name, "summary": summary}
        if usage is not None:
            spec["usage"] = usage
        if examples is not None:
            spec["examples"] = examples
        spec["args"] = list(args) if args else []
        if hidden:
            spec["hidden"] = True

        def decorator(fn: Callable[[InvokeContext], Any]) -> Callable:
            self._commands[name] = {"spec": spec, "handler": fn}
            return fn

        return decorator

    def completer(self, source: str) -> Callable:
        """Decorator registering a dynamic-completion handler for ``source``.

        The handler is called as ``handler(params: dict) -> list`` and may
        return either value-objects ``[{"value":..,"description"?:..}]`` or a
        plain list of strings (which are normalized).
        """

        def decorator(fn: Callable[[Dict[str, Any]], Any]) -> Callable:
            self._completers[source] = fn
            return fn

        return decorator

    # ----- describe --------------------------------------------------------

    def _describe_result(self) -> Dict[str, Any]:
        commands = [entry["spec"] for entry in self._commands.values()]
        return {
            "protocol": self.protocol,
            "name": self.name,
            "commands": commands,
        }

    # ----- complete --------------------------------------------------------

    @staticmethod
    def _normalize_values(raw: Any) -> List[Dict[str, Any]]:
        """Normalize a handler return into a list of value-objects."""
        values: List[Dict[str, Any]] = []
        if raw is None:
            return values
        items = raw
        # Allow handlers to return {"values": [...], "ttl": N} directly.
        if isinstance(raw, dict) and "values" in raw:
            items = raw["values"]
        for item in items:
            if isinstance(item, str):
                values.append({"value": item})
            elif isinstance(item, dict):
                # Pass through value/description (and any extra keys ignored
                # by the core are harmless).
                obj: Dict[str, Any] = {"value": item.get("value")}
                if item.get("description") is not None:
                    obj["description"] = item["description"]
                values.append(obj)
            else:
                values.append({"value": str(item)})
        return values

    def _complete_result(self, params: Dict[str, Any]) -> Dict[str, Any]:
        source = params.get("source")
        handler = self._completers.get(source)
        if handler is None:
            # Unknown source: return an empty candidate set (a valid, empty
            # completion is not an error per §3.1).
            return {"values": []}
        raw = handler(params)
        result: Dict[str, Any] = {"values": self._normalize_values(raw)}
        if isinstance(raw, dict) and "ttl" in raw:
            result["ttl"] = raw["ttl"]
        return result

    # ----- invoke ----------------------------------------------------------

    def _invoke_result(self, params: Dict[str, Any], out_stream) -> Dict[str, Any]:
        command = params.get("command")
        entry = self._commands.get(command)
        if entry is None:
            raise _HandlerError(
                METHOD_NOT_FOUND, "unknown command: {!r}".format(command)
            )

        ctx = InvokeContext(
            command=command,
            args=params.get("args") or {},
            cwd=params.get("cwd"),
            env=params.get("env") or {},
            context=params.get("context") or {},
            capabilities=params.get("capabilities") or {},
            out_stream=out_stream,
        )

        ret = entry["handler"](ctx)

        result: Dict[str, Any] = {"exit_code": 0}
        if isinstance(ret, dict):
            result.update(ret)
            result.setdefault("exit_code", 0)
        elif isinstance(ret, int):
            result["exit_code"] = ret
        # else: None -> exit_code 0.

        if ctx.events and "events" not in result:
            result["events"] = ctx.events
        return result

    # ----- run loop --------------------------------------------------------

    def run(self, stdin=None, stdout=None) -> int:
        """Run the request loop until stdin EOF, then return 0."""
        if stdin is None:
            stdin = sys.stdin.buffer
        if stdout is None:
            stdout = sys.stdout.buffer

        while True:
            try:
                request = read_message(stdin)
            except EOFError:
                # Truncated frame: treat as end of input.
                break
            if request is None:
                break  # clean EOF
            self._handle_one(request, stdout)
        return 0

    def _handle_one(self, request: Dict[str, Any], stdout) -> None:
        req_id = request.get("id")
        method = request.get("method")
        params = request.get("params") or {}

        try:
            if method == "describe":
                result = self._describe_result()
            elif method == "complete":
                result = self._complete_result(params)
            elif method == "invoke":
                result = self._invoke_result(params, stdout)
            else:
                self._send_error(
                    stdout,
                    req_id,
                    METHOD_NOT_FOUND,
                    "unknown method: {!r}".format(method),
                )
                return
        except _HandlerError as exc:
            self._send_error(stdout, req_id, exc.code, exc.message)
            return
        except Exception as exc:  # noqa: BLE001 - report any handler crash
            # Log the traceback to stderr (free log channel) for debugging.
            traceback.print_exc(file=sys.stderr)
            self._send_error(
                stdout, req_id, INTERNAL_ERROR, "{}: {}".format(type(exc).__name__, exc)
            )
            return

        write_message(stdout, {"jsonrpc": "2.0", "id": req_id, "result": result})

    @staticmethod
    def _send_error(stdout, req_id: Any, code: int, message: str) -> None:
        write_message(
            stdout,
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": code, "message": message},
            },
        )


class _HandlerError(Exception):
    """Internal carrier for a JSON-RPC error to surface from a handler."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
