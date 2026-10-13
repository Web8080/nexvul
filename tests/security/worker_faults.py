"""Fault-injecting parse-worker entry points for tests (architecture §5.2; SR-03).

Each function has the signature of ``nexvul.core.workers.worker_main`` and runs inside a spawned
worker process. They are module-level so ``spawn`` can import them by name (this directory is on
``sys.path`` via pytest's ``pythonpath`` setting, which the spawned child inherits).
"""

from __future__ import annotations

import json
import os
import pickle  # test-only: proves the supervisor rejects a pickle reply (SR-01)
import resource
import signal
import sys
import time
from multiprocessing.connection import Connection
from typing import Any

from nexvul.core import workers


def _next_task(conn: Connection) -> dict[str, Any] | None:
    try:
        raw = conn.recv_bytes(workers.MAX_TASK_BYTES)
    except (EOFError, OSError):
        return None
    task: dict[str, Any] = json.loads(raw)
    return task if task.get("op") == "parse" else None


def hang(conn: Connection, memory_limit_bytes: int) -> None:
    """Accepts a task and never answers (stands in for a parser stuck in C code)."""
    if _next_task(conn) is not None:
        while True:
            time.sleep(3600)


def hang_on_marker(conn: Connection, memory_limit_bytes: int) -> None:
    """Hangs only for files whose name contains ``HANG``; parses the rest normally."""
    while (task := _next_task(conn)) is not None:
        if "HANG" in task["path"]:
            while True:
                time.sleep(3600)
        conn.send_bytes(workers.handle_task(task))


def segfault(conn: Connection, memory_limit_bytes: int) -> None:
    """Dies by SIGSEGV on its first task (stands in for an AST-compiler crash, MF-17)."""
    if _next_task(conn) is not None:
        os.kill(os.getpid(), signal.SIGSEGV)


def crash_on_marker(conn: Connection, memory_limit_bytes: int) -> None:
    """Exits abruptly for files whose name contains ``CRASH``; parses the rest normally."""
    while (task := _next_task(conn)) is not None:
        if "CRASH" in task["path"]:
            os._exit(70)
        conn.send_bytes(workers.handle_task(task))


def reply_pickle(conn: Connection, memory_limit_bytes: int) -> None:
    """A compromised worker that answers with a pickle payload instead of JSON."""
    while (task := _next_task(conn)) is not None:
        conn.send_bytes(pickle.dumps({"id": task["id"], "module": None}))


def reply_garbage(conn: Connection, memory_limit_bytes: int) -> None:
    """Answers with valid JSON that violates the reply schema in a different way per file."""
    while (task := _next_task(conn)) is not None:
        name = task["path"]
        if "wrongid" in name:
            reply: Any = {"id": task["id"] + 1000, "module": None}
        elif "extra" in name:
            reply = {"id": task["id"], "module": None, "x": 1}
        elif "badmodule" in name:
            reply = {"id": task["id"], "module": {"schema_version": "0.1.0"}}
        elif "list" in name:
            reply = [task["id"]]
        elif "otherpath" in name:
            good = json.loads(workers.handle_task(task))
            good["module"]["path"] = "elsewhere.py"
            reply = good
        else:
            conn.send_bytes(b"[" * 200_000 + b"]" * 200_000)
            continue
        conn.send_bytes(json.dumps(reply).encode())


def reply_oversized(conn: Connection, memory_limit_bytes: int) -> None:
    """Sends a reply larger than any sane result cap."""
    while _next_task(conn) is not None:
        conn.send_bytes(b" " * (4 * 1024 * 1024))


def reply_internal_error(conn: Connection, memory_limit_bytes: int) -> None:
    while (task := _next_task(conn)) is not None:
        conn.send_bytes(json.dumps({"id": task["id"], "error": "internal"}).encode())


def reply_fatal(conn: Connection, memory_limit_bytes: int) -> None:
    while (task := _next_task(conn)) is not None:
        conn.send_bytes(json.dumps({"id": task["id"], "fatal": "module_shadowing"}).encode())


def probe(conn: Connection, memory_limit_bytes: int) -> None:
    """Applies the real worker hardening, then reports what the worker can see."""
    workers._harden_process(memory_limit_bytes)
    report = {
        "env": sorted(os.environ),
        "safe_path": bool(sys.flags.safe_path),
        "core": resource.getrlimit(resource.RLIMIT_CORE),
        "fsize": resource.getrlimit(resource.RLIMIT_FSIZE),
        "nofile": resource.getrlimit(resource.RLIMIT_NOFILE),
        "as": resource.getrlimit(resource.RLIMIT_AS),
        "cwd_on_path": "" in sys.path,
    }
    conn.send_bytes(json.dumps(report).encode())


class _CanaryOnUnpickle:
    """Unpickling this object creates ``$NEXVUL_CANARY_DIR/MF-pickle-reply``."""

    def __reduce__(self) -> tuple[Any, ...]:
        target = os.path.join(os.environ.get("NEXVUL_CANARY_DIR", "/nonexistent"), "MF-pickle")
        return (os.mkdir, (target,))


def reply_pickle_canary(conn: Connection, memory_limit_bytes: int) -> None:
    """A compromised worker whose reply would run code if the supervisor unpickled it."""
    while _next_task(conn) is not None:
        conn.send_bytes(pickle.dumps(_CanaryOnUnpickle()))
