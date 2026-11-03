"""stdio smoke test: run the server as a real subprocess and prove that stdout
carries only JSON-RPC (nothing else may be written to stdout over stdio).

We drive the handshake interactively — writing each request and reading its
response before sending the next — rather than dumping all input and closing
stdin, which would race the server's EOF-triggered shutdown.
"""

from __future__ import annotations

import json
import os
import selectors
import shutil
import subprocess
import sys
import time

from mcp.types.version import LATEST_HANDSHAKE_VERSION


def _command() -> list[str]:
    script = shutil.which("maltiverse-mcp")
    return [script] if script else [sys.executable, "-m", "maltiverse_mcp"]


def _read_until(proc: subprocess.Popen[str], want_ids: set[int], timeout: float) -> list[str]:
    """Read newline-delimited stdout until every id in ``want_ids`` is seen."""
    assert proc.stdout is not None
    sel = selectors.DefaultSelector()
    sel.register(proc.stdout, selectors.EVENT_READ)
    lines: list[str] = []
    seen: set[int] = set()
    deadline = time.monotonic() + timeout
    while not want_ids <= seen:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not sel.select(timeout=remaining):
            break
        line = proc.stdout.readline()
        if line == "":  # EOF
            break
        if line.strip():
            lines.append(line)
            obj = json.loads(line)  # fails the test if stdout isn't JSON-RPC
            if isinstance(obj.get("id"), int):
                seen.add(obj["id"])
    return lines


def test_stdout_is_pure_jsonrpc() -> None:
    # No API key on purpose: startup must still succeed. DEBUG makes the server
    # chatty — all of it must go to stderr, never stdout.
    env = {**os.environ, "MALTIVERSE_API_KEY": "", "MALTIVERSE_LOG_LEVEL": "DEBUG"}
    proc = subprocess.Popen(
        _command(),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        env=env,
    )
    assert proc.stdin is not None

    def send(msg: dict[str, object]) -> None:
        assert proc.stdin is not None
        proc.stdin.write(json.dumps(msg) + "\n")
        proc.stdin.flush()

    lines: list[str] = []
    try:
        send(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": LATEST_HANDSHAKE_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "smoke", "version": "0"},
                },
            }
        )
        lines += _read_until(proc, {1}, timeout=15)
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        lines += _read_until(proc, {2}, timeout=15)
    finally:
        proc.stdin.close()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover
            proc.kill()

    ids: set[int] = set()
    for line in lines:
        obj = json.loads(line)
        assert obj.get("jsonrpc") == "2.0", obj
        if isinstance(obj.get("id"), int):
            ids.add(obj["id"])

    assert {1, 2} <= ids, f"missing responses; got ids={ids}"
    assert any("maltiverse_check_ip" in line for line in lines)
