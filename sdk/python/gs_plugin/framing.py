"""LSP-style ``Content-Length`` framing for JSON-RPC over stdio.

Each message on the wire is::

    Content-Length: <N>\r\n
    \r\n
    <N bytes of UTF-8 JSON>

Extra headers (if any) are accepted and ignored. The transport is binary:
callers should pass binary streams (e.g. ``sys.stdin.buffer`` /
``sys.stdout.buffer``).
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional


def read_message(stream) -> Optional[Dict[str, Any]]:
    """Read one framed JSON message from a binary ``stream``.

    Returns the decoded object as a ``dict``, or ``None`` at a clean EOF
    (i.e. EOF reached before any header bytes of a new message).

    Raises ``EOFError`` if EOF is hit mid-message (truncated frame) and
    ``ValueError`` if a malformed header is encountered.
    """
    content_length: Optional[int] = None
    saw_any_header = False

    # Read headers line by line until the blank separator line.
    while True:
        line = _read_line(stream)
        if line is None:
            # EOF.
            if not saw_any_header:
                # Clean EOF between messages.
                return None
            raise EOFError("unexpected EOF while reading message headers")

        if line in (b"\r\n", b"\n", b""):
            # Blank line terminates the header block.
            if not saw_any_header:
                # A stray blank line before any header: skip it gracefully.
                continue
            break

        saw_any_header = True
        # Strip trailing CRLF/LF.
        header = line.rstrip(b"\r\n")
        if b":" not in header:
            # Tolerate unknown / malformed header lines by ignoring them.
            continue
        name, _, value = header.partition(b":")
        if name.strip().lower() == b"content-length":
            try:
                content_length = int(value.strip())
            except ValueError as exc:
                raise ValueError("invalid Content-Length header") from exc
        # All other headers are accepted and ignored.

    if content_length is None:
        raise ValueError("missing Content-Length header")

    body = _read_exact(stream, content_length)
    if body is None:
        raise EOFError("unexpected EOF while reading message body")

    return json.loads(body.decode("utf-8"))


def write_message(stream, obj: Dict[str, Any]) -> None:
    """Serialize ``obj`` as JSON and write it as one framed message.

    Flushes the stream so the peer sees the message promptly (important for
    streaming notifications during ``invoke``).
    """
    data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    header = "Content-Length: {}\r\n\r\n".format(len(data)).encode("ascii")
    stream.write(header)
    stream.write(data)
    try:
        stream.flush()
    except (AttributeError, ValueError):
        pass


def _read_line(stream) -> Optional[bytes]:
    """Read a single line (including the trailing newline) from a binary
    stream. Returns ``None`` at EOF if nothing was read."""
    if hasattr(stream, "readline"):
        line = stream.readline()
        if line == b"":
            return None
        return line

    # Fallback: byte-by-byte.
    buf = bytearray()
    while True:
        ch = stream.read(1)
        if not ch:
            return bytes(buf) if buf else None
        buf += ch
        if ch == b"\n":
            return bytes(buf)


def _read_exact(stream, n: int) -> Optional[bytes]:
    """Read exactly ``n`` bytes; return ``None`` if EOF is hit early."""
    if n == 0:
        return b""
    buf = bytearray()
    remaining = n
    while remaining > 0:
        chunk = stream.read(remaining)
        if not chunk:
            return None
        buf += chunk
        remaining -= len(chunk)
    return bytes(buf)
