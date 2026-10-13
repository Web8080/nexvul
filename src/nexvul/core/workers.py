"""Process-isolated parse workers (architecture §5.1-5.2; SR-01, SR-03, SR-04, SR-05, T-19).

The supervisor (this module, in the parent process) owns a small pool of worker **processes**
started with the ``spawn`` method (never ``fork``: no copy of the supervisor's memory, locks or
open files leaks into a process that handles hostile bytes). Each worker parses **one file at a
time**; the assignment is recorded before dispatch, so a worker death is always attributable to a
specific file.

Bounds:

* **Wall clock** per file (read + decode + parse + IR): enforced by the supervisor. On expiry the
  worker is killed with ``SIGKILL`` (``Process.kill``); the file is recorded as ``timeout`` and a
  fresh worker is started. No in-process cancellation and no ``signal.alarm`` (architecture §5.1).
* **Crash**: non-zero exit, signal or EOF before a reply => ``parser_crashed``. A file that kills
  ``MAX_CRASH_ATTEMPTS_PER_FILE`` workers is not retried again.
* **Resource limits** set inside the worker before any untrusted byte is read: ``RLIMIT_CORE=0``,
  ``RLIMIT_FSIZE=0`` (workers write no files), small ``RLIMIT_NOFILE``, a per-file
  ``RLIMIT_CPU`` backstop, and ``RLIMIT_AS`` on **Linux only**. macOS does not enforce
  ``RLIMIT_AS`` reliably, so on macOS memory is bounded only by the pre-parse limits (file size,
  nesting, node count) - open risk R-3. On Linux the supervisor also polls ``/proc/<pid>/statm``
  and kills a worker above the RSS cap (``memory_limit``). Windows is not supported (discovery
  already needs POSIX).
* **IPC is JSON only.** Tasks and results are sent with ``Connection.send_bytes`` and read with
  ``recv_bytes(maxlength)``; results are decoded with a strict JSON + schema check
  (:mod:`nexvul.ir.codec`). ``pickle`` is never used for data in either direction. (The ``spawn``
  bootstrap itself pickles the trusted ``Process`` object parent -> child; that is
  :mod:`multiprocessing` start-up, not data exchange, and never flows worker -> supervisor.)
* **Reduced environment**: workers are started with only locale, ``TZ`` and ``NEXVUL_*``
  variables (architecture §5.2, T-19), and prune again on start.
* Workers run the module-origin assertion (SR-02) for the scan root before each file.

Process isolation contains crashes and hangs; it is not a sandbox against memory-corruption
exploits in the parser (T-28, open risk R-2).
"""

from __future__ import annotations

import contextlib
import errno
import json
import multiprocessing
import os
import resource
import stat
import sys
import time
from collections import deque
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from multiprocessing.connection import Connection, wait
from multiprocessing.context import SpawnContext, SpawnProcess
from typing import Any, Final

from nexvul.core import limits
from nexvul.core.completeness import Completeness, SkipReason
from nexvul.core.discovery import DiscoveredFile, Language, detect_language
from nexvul.core.sanitize import display_path
from nexvul.core.startup import ModuleShadowingError, assert_no_module_from_roots
from nexvul.ir.codec import IRDecodeError, loads_strict, module_from_dict, module_to_json
from nexvul.ir.model import FailureReason, ModuleIR, failed_module
from nexvul.parser.python import LANGUAGE as PYTHON
from nexvul.parser.python import ParseLimits, module_name_for, parse_python

_CLOEXEC: Final = getattr(os, "O_CLOEXEC", 0)
_FILE_FLAGS: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | _CLOEXEC
_DIR_FLAGS: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | _CLOEXEC
_ROOT_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | _CLOEXEC

#: Maximum size of one task message (supervisor -> worker). Tasks are tiny; paths are capped by
#: discovery (4 KiB git paths, PATH_MAX-ish walk paths).
MAX_TASK_BYTES: Final = 1 * limits.MIB

#: How often the supervisor wakes to check deadlines and (Linux) RSS while workers are busy.
_POLL_SECONDS: Final = 0.05

#: Seconds a worker gets to exit after a ``stop`` message before it is killed.
_STOP_GRACE_SECONDS: Final = 1.0

_ENV_EXACT: Final = frozenset({"LANG", "LANGUAGE", "TZ", "SYSTEMROOT"})
_ENV_PREFIXES: Final = ("LC_", "NEXVUL_")

_CHANGED_ERRNOS: Final = frozenset(
    {errno.ELOOP, errno.ENOENT, errno.ENOTDIR, errno.EMLINK, errno.ENXIO}
)


class WorkerStartupError(RuntimeError):
    """A worker refused to run (module-origin assertion tripped). The scan must fail closed
    (exit code 4, SR-02)."""


class OutcomeStatus(StrEnum):
    SCANNED = "scanned"
    FAILED = "failed"  # parse-stage failure with a typed reason (incl. read-time checks)
    TIMED_OUT = "timed_out"
    CRASHED = "crashed"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class FileOutcome:
    """What happened to one requested file. ``detail`` is trusted text composed by nexvul."""

    path: str
    status: OutcomeStatus
    reason: SkipReason | None = None
    detail: str = ""
    module: ModuleIR | None = None


@dataclass
class AnalysisResult:
    outcomes: tuple[FileOutcome, ...]
    completeness: Completeness
    memory_limit_enforced: bool

    @property
    def modules(self) -> tuple[ModuleIR, ...]:
        """IR of every file that parsed successfully, in input order."""
        return tuple(o.module for o in self.outcomes if o.module is not None and o.module.ok)


def default_worker_count() -> int:
    return max(1, min(os.cpu_count() or 1, limits.DEFAULT_MAX_WORKERS))


def _is_linux() -> bool:
    return sys.platform.startswith("linux")


@dataclass(frozen=True)
class WorkerOptions:
    """Pool and per-file limits. Callers derive them from the resolved config (trusted)."""

    max_workers: int = field(default_factory=default_worker_count)
    timeout_seconds: float = limits.DEFAULT_PARSE_TIMEOUT_SECONDS
    max_file_size: int = limits.DEFAULT_MAX_FILE_SIZE
    max_nesting: int = limits.MAX_NESTING
    max_ast_nodes: int = limits.MAX_AST_NODES
    max_literal_chars: int = limits.MAX_LITERAL_CHARS
    memory_limit_bytes: int = limits.WORKER_MEMORY_LIMIT_BYTES
    max_result_bytes: int = limits.MAX_WORKER_RESULT_BYTES
    max_crash_attempts: int = limits.MAX_CRASH_ATTEMPTS_PER_FILE
    #: Poll ``/proc/<pid>/statm`` for RSS. ``None`` means "on Linux only".
    rss_poll: bool | None = None

    def __post_init__(self) -> None:
        if self.max_workers < 1:
            raise ValueError("max_workers must be >= 1")
        if not 0 < self.timeout_seconds <= limits.HARD_MAX_PARSE_TIMEOUT_SECONDS:
            raise ValueError("timeout_seconds out of range")
        if not 0 < self.max_file_size <= limits.HARD_MAX_FILE_SIZE:
            raise ValueError("max_file_size out of range")
        if min(self.max_nesting, self.max_ast_nodes, self.max_literal_chars) < 1:
            raise ValueError("parse limits must be positive")
        if self.max_crash_attempts < 1 or self.max_result_bytes < 1024:
            raise ValueError("invalid worker limits")


# =============================================================================================
# Worker side (runs in the spawned process)
# =============================================================================================


def _env_allowed(key: str) -> bool:
    return key in _ENV_EXACT or key.startswith(_ENV_PREFIXES)


def worker_environment(environ: dict[str, str]) -> dict[str, str]:
    """The reduced environment a worker may see (architecture §5.2, T-19)."""
    return {k: v for k, v in environ.items() if _env_allowed(k)}


def _harden_process(memory_limit_bytes: int) -> None:  # pragma: no cover - worker process only
    """Applied once at worker start, before any untrusted byte is read. Runs in the child only:
    applying it to the supervisor (or the test runner) would break it. Its effect is asserted by
    ``tests/security/test_mf_workers.py::test_worker_hardening`` through a probe worker."""
    for key in [k for k in os.environ if not _env_allowed(k)]:
        del os.environ[key]
    # Tracebacks or warnings must never reach the user's terminal with file content (MF-161).
    devnull = os.open(os.devnull, os.O_RDWR)
    for fd in (0, 1, 2):
        os.dup2(devnull, fd)
    os.close(devnull)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    want = limits.WORKER_MAX_OPEN_FILES
    if soft == resource.RLIM_INFINITY or soft > want:
        resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
    if _is_linux():
        resource.setrlimit(resource.RLIMIT_AS, (memory_limit_bytes, memory_limit_bytes))


def _set_cpu_budget(seconds: float) -> None:  # pragma: no cover - worker process only
    """``RLIMIT_CPU`` backstop: CPU used so far + this file's wall-clock + a margin. The soft
    limit is moved per file because one worker parses many files sequentially."""
    used = resource.getrusage(resource.RUSAGE_SELF)
    spent = int(used.ru_utime + used.ru_stime) + 1
    budget = spent + int(seconds) + limits.WORKER_CPU_MARGIN_SECONDS
    _, hard = resource.getrlimit(resource.RLIMIT_CPU)
    if hard != resource.RLIM_INFINITY:
        budget = min(budget, hard)
    resource.setrlimit(resource.RLIMIT_CPU, (budget, hard))


def worker_main(conn: Connection, memory_limit_bytes: int) -> None:  # pragma: no cover
    """Entry point of a spawned parse worker (child process only)."""
    _harden_process(memory_limit_bytes)
    serve(conn, limit_cpu=True)


def serve(conn: Connection, *, limit_cpu: bool = False) -> None:
    """Request loop: one JSON task in, one JSON reply out, until ``stop`` or EOF."""
    while True:
        try:
            raw = conn.recv_bytes(MAX_TASK_BYTES)
        except (EOFError, OSError):
            return
        task = json.loads(raw.decode("utf-8"))  # from the trusted supervisor
        if task.get("op") != "parse":
            return
        if limit_cpu:  # pragma: no cover - worker process only
            _set_cpu_budget(float(task["timeout"]))
        conn.send_bytes(handle_task(task))


def handle_task(task: dict[str, Any]) -> bytes:
    """Read, parse and serialise one file. Always returns a JSON reply (bytes)."""
    task_id = task["id"]
    try:
        assert_no_module_from_roots([task["root"]])
    except ModuleShadowingError:
        return _reply({"id": task_id, "fatal": "module_shadowing"})
    try:
        module = _read_and_parse(task)
        payload = module_to_json(module)
        if len(payload) > int(task["max_result_bytes"]) - 256:
            module = failed_module(
                language=PYTHON,
                path=task["path"],
                module_name=module.module_name,
                is_package=module.is_package,
                reason=FailureReason.MAX_AST_NODES,
                detail="IR larger than the worker result cap",
                sha256=module.sha256,
                size_bytes=module.size_bytes,
            )
            payload = module_to_json(module)
    except Exception:  # nexvul bug: report it without content; the file is marked crashed
        return _reply({"id": task_id, "error": "internal"})
    return b'{"id":' + str(int(task_id)).encode() + b',"module":' + payload + b"}"


def _reply(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, ensure_ascii=True).encode("ascii")


def _read_and_parse(task: dict[str, Any]) -> ModuleIR:
    path: str = task["path"]
    module_name, is_package = module_name_for(path)
    expect = task.get("expect")
    data = read_file(
        task["root"],
        path,
        expect=(int(expect[0]), int(expect[1])) if expect else None,
        max_file_size=int(task["max_file_size"]),
    )
    if isinstance(data, tuple):
        reason, detail = data
        return failed_module(
            language=PYTHON,
            path=path,
            module_name=module_name,
            is_package=is_package,
            reason=reason,
            detail=detail,
        )
    lim = ParseLimits(
        max_nesting=int(task["max_nesting"]),
        max_ast_nodes=int(task["max_ast_nodes"]),
        max_literal_chars=int(task["max_literal_chars"]),
    )
    return parse_python(data, path, parse_limits=lim)


def read_file(
    root: str, path: str, *, expect: tuple[int, int] | None, max_file_size: int
) -> bytes | tuple[FailureReason, str]:
    """Re-open ``root/path`` through an ``O_NOFOLLOW`` fd chain and read at most
    ``max_file_size + 1`` bytes. Returns the bytes or ``(reason, detail)``.

    ``expect`` is the ``(device, inode)`` discovery saw; a mismatch means the file was swapped
    after discovery (TOCTOU, MF-54) and it is not read.
    """
    comps = os.fsencode(path).split(b"/")
    try:
        fd = os.open(os.fsencode(root), _ROOT_FLAGS)
    except OSError:
        return FailureReason.OPEN_FAILED, "scan root not openable"
    try:
        for comp in comps[:-1]:
            nfd = os.open(comp, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = nfd
        ffd = os.open(comps[-1], _FILE_FLAGS, dir_fd=fd)
    except OSError as exc:
        if exc.errno in _CHANGED_ERRNOS:
            return FailureReason.CHANGED_DURING_SCAN, "changed before open"
        return FailureReason.OPEN_FAILED, errno.errorcode.get(exc.errno or 0, "open failed")
    finally:
        os.close(fd)
    try:
        st = os.fstat(ffd)
        if not stat.S_ISREG(st.st_mode):
            return FailureReason.CHANGED_DURING_SCAN, "not a regular file at open"
        if expect is not None and (st.st_dev, st.st_ino) != expect:
            return FailureReason.CHANGED_DURING_SCAN, "different file at open"
        if st.st_size > max_file_size:
            return FailureReason.MAX_FILE_SIZE, f"{st.st_size} > {max_file_size}"
        chunks: list[bytes] = []
        remaining = max_file_size + 1
        while remaining > 0:
            chunk = os.read(ffd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    except OSError:
        return FailureReason.OPEN_FAILED, "read failed"
    finally:
        os.close(ffd)
    data = b"".join(chunks)
    if len(data) > max_file_size:
        return FailureReason.MAX_FILE_SIZE, f"grew beyond {max_file_size} during scan"
    return data


# =============================================================================================
# Supervisor side
# =============================================================================================


@dataclass
class _Task:
    index: int
    path: str
    expect: tuple[int, int] | None
    attempts: int = 0


@dataclass
class _Worker:
    proc: SpawnProcess
    conn: Connection
    task: _Task | None = None
    deadline: float = 0.0


@contextlib.contextmanager
def _reduced_environ() -> Iterator[None]:
    """Temporarily reduce ``os.environ`` while a worker is spawned, so the child process starts
    with the reduced environment (``spawn`` inherits the parent's C environment). The supervisor
    is single-threaded while it starts workers; the original environment is always restored."""
    saved = dict(os.environ)
    try:
        os.environ.clear()
        os.environ.update(worker_environment(saved))
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)


def _rss_bytes(pid: int, proc_root: str = "/proc") -> int | None:
    """Resident set size from ``/proc/<pid>/statm`` (Linux). ``None`` if unavailable."""
    try:
        with open(os.path.join(proc_root, str(pid), "statm"), "rb") as fh:
            fields = fh.read(256).split()
        return int(fields[1]) * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError, IndexError):
        return None


WorkerEntry = Callable[[Connection, int], None]


class _Pool:
    def __init__(
        self,
        root: str,
        options: WorkerOptions,
        entry: WorkerEntry,
        clock: Callable[[], float],
    ) -> None:
        self.root = root
        self.opt = options
        self.entry = entry
        self.clock = clock
        self.ctx: SpawnContext = multiprocessing.get_context("spawn")
        self.workers: list[_Worker] = []
        self.rss_poll = _is_linux() if options.rss_poll is None else options.rss_poll

    # -- lifecycle -----------------------------------------------------------------------------

    def _spawn(self) -> _Worker:
        parent_conn, child_conn = self.ctx.Pipe(duplex=True)
        proc = self.ctx.Process(
            target=self.entry,
            args=(child_conn, self.opt.memory_limit_bytes),
            name="nexvul-parse-worker",
            daemon=True,
        )
        with _reduced_environ():
            proc.start()
        child_conn.close()
        worker = _Worker(proc=proc, conn=parent_conn)
        self.workers.append(worker)
        return worker

    def _discard(self, worker: _Worker) -> None:
        if worker.proc.is_alive():
            worker.proc.kill()
        worker.proc.join(timeout=5)
        worker.conn.close()
        with contextlib.suppress(ValueError):
            worker.proc.close()
        self.workers.remove(worker)

    def shutdown(self) -> None:
        for worker in list(self.workers):
            with contextlib.suppress(OSError, ValueError):
                worker.conn.send_bytes(b'{"op":"stop"}')
        deadline = self.clock() + _STOP_GRACE_SECONDS
        for worker in list(self.workers):
            worker.proc.join(timeout=max(0.0, deadline - self.clock()))
            self._discard(worker)

    # -- dispatch ------------------------------------------------------------------------------

    def _task_message(self, task: _Task) -> bytes:
        message = {
            "op": "parse",
            "id": task.index,
            "root": self.root,
            "path": task.path,
            "expect": list(task.expect) if task.expect else None,
            "timeout": self.opt.timeout_seconds,
            "max_file_size": self.opt.max_file_size,
            "max_nesting": self.opt.max_nesting,
            "max_ast_nodes": self.opt.max_ast_nodes,
            "max_literal_chars": self.opt.max_literal_chars,
            "max_result_bytes": self.opt.max_result_bytes,
        }
        return json.dumps(message, ensure_ascii=True).encode("ascii")

    def run(self, tasks: list[_Task]) -> dict[int, FileOutcome]:
        pending: deque[_Task] = deque(tasks)
        outcomes: dict[int, FileOutcome] = {}
        while pending or any(w.task is not None for w in self.workers):
            self._assign(pending)
            busy = [w for w in self.workers if w.task is not None]
            now = self.clock()
            next_deadline = min(w.deadline for w in busy)
            wait_for = max(0.0, min(next_deadline - now, _POLL_SECONDS if self.rss_poll else 1.0))
            ready = set(wait([w.conn for w in busy] + [w.proc.sentinel for w in busy], wait_for))
            for worker in busy:
                self._check(worker, ready, pending, outcomes)
        return outcomes

    def _assign(self, pending: deque[_Task]) -> None:
        idle = [w for w in self.workers if w.task is None]
        while pending and (idle or len(self.workers) < self.opt.max_workers):
            worker = idle.pop() if idle else self._spawn()
            task = pending.popleft()
            task.attempts += 1
            worker.task = task
            worker.deadline = self.clock() + self.opt.timeout_seconds
            # If the worker already died, the crash is detected on this round.
            with contextlib.suppress(OSError):
                worker.conn.send_bytes(self._task_message(task))

    def _check(
        self,
        worker: _Worker,
        ready: set[Any],
        pending: deque[_Task],
        outcomes: dict[int, FileOutcome],
    ) -> None:
        task = worker.task
        assert task is not None  # noqa: S101 - invariant: only busy workers are checked
        if worker.conn in ready:
            try:
                raw = worker.conn.recv_bytes(self.opt.max_result_bytes)
            except (EOFError, OSError):
                self._crashed(worker, task, pending, outcomes, "worker died before replying")
                return
            outcome = self._decode(task, raw)
            if outcome is None:
                self._discard(worker)
                outcomes[task.index] = FileOutcome(
                    task.path,
                    OutcomeStatus.CRASHED,
                    SkipReason.PARSER_CRASHED,
                    "protocol violation by parse worker",
                )
                return
            outcomes[task.index] = outcome
            worker.task = None
            return
        if worker.proc.sentinel in ready or not worker.proc.is_alive():
            self._crashed(worker, task, pending, outcomes, "worker exited")
            return
        if self.clock() >= worker.deadline:
            self._discard(worker)
            outcomes[task.index] = FileOutcome(
                task.path,
                OutcomeStatus.TIMED_OUT,
                SkipReason.TIMEOUT,
                f"exceeded {self.opt.timeout_seconds:g} s; worker killed",
            )
            return
        if self.rss_poll and worker.proc.pid is not None:
            rss = _rss_bytes(worker.proc.pid)
            if rss is not None and rss > self.opt.memory_limit_bytes:
                self._discard(worker)
                outcomes[task.index] = FileOutcome(
                    task.path,
                    OutcomeStatus.FAILED,
                    SkipReason.MEMORY_LIMIT,
                    f"worker RSS above {self.opt.memory_limit_bytes} bytes; worker killed",
                )

    def _crashed(
        self,
        worker: _Worker,
        task: _Task,
        pending: deque[_Task],
        outcomes: dict[int, FileOutcome],
        why: str,
    ) -> None:
        exitcode = worker.proc.exitcode
        self._discard(worker)
        if task.attempts < self.opt.max_crash_attempts:
            pending.appendleft(task)
            return
        detail = f"{why} (exit code {exitcode}) after {task.attempts} attempt(s)"
        outcomes[task.index] = FileOutcome(
            task.path, OutcomeStatus.CRASHED, SkipReason.PARSER_CRASHED, detail
        )

    def _decode(self, task: _Task, raw: bytes) -> FileOutcome | None:
        """Strictly validate one worker reply. ``None`` means protocol violation."""
        try:
            reply = loads_strict(raw)
        except IRDecodeError:
            return None
        if not isinstance(reply, dict) or reply.get("id") != task.index:
            return None
        keys = set(reply)
        if keys == {"id", "fatal"} and reply["fatal"] == "module_shadowing":
            raise WorkerStartupError("parse worker refused to run: module loaded from scan root")
        if keys == {"id", "error"}:
            return FileOutcome(
                task.path,
                OutcomeStatus.CRASHED,
                SkipReason.PARSER_CRASHED,
                "internal error in parse worker",
            )
        if keys != {"id", "module"}:
            return None
        try:
            module = module_from_dict(reply["module"])
        except IRDecodeError:
            return None
        if module.path != task.path or module.language != PYTHON:
            return None
        if module.ok:
            return FileOutcome(task.path, OutcomeStatus.SCANNED, module=module)
        assert module.failure is not None  # noqa: S101 - ModuleIR invariant
        return FileOutcome(
            task.path,
            OutcomeStatus.FAILED,
            SkipReason(module.failure.reason.value),
            module.failure.detail,
            module,
        )


# =============================================================================================
# Public API
# =============================================================================================


def _validate_rel_path(path: str) -> None:
    if not path or "\x00" in path or path.startswith("/") or "\\" in path:
        raise ValueError("file paths must be non-empty, relative, '/'-separated and NUL-free")
    if any(part in ("", ".", "..") for part in path.split("/")):
        raise ValueError("file paths must be normalised (no empty, '.' or '..' components)")


def _fold(ledger: Completeness, outcomes: Sequence[FileOutcome], memory_enforced: bool) -> None:
    truncated_files = 0
    cookie_files = 0
    bidi_files = 0
    for outcome in outcomes:
        if outcome.status is OutcomeStatus.SCANNED:
            ledger.record_scanned()
        else:
            reason = outcome.reason or SkipReason.PARSER_CRASHED
            ledger.record_skip(display_path(outcome.path), reason, outcome.detail)
        module = outcome.module
        if module is not None:
            truncated_files += module.literals_truncated > 0
            cookie_files += "non_utf8_coding_cookie" in module.notes
            bidi_files += "bidi_control" in module.notes
    if truncated_files:
        ledger.add_note(
            f"string literals longer than {limits.MAX_LITERAL_CHARS} characters were truncated "
            f"in {truncated_files} file(s)"
        )
    if cookie_files:
        ledger.add_note(f"{cookie_files} file(s) declare a non-UTF-8 source encoding")
    if bidi_files:
        ledger.add_note(f"{bidi_files} file(s) contain bidirectional control characters")
    if outcomes and not memory_enforced:
        ledger.add_note(
            "worker memory limit is not enforced on this platform; pre-parse limits apply"
        )


def analyse_files(
    root: str,
    files: Sequence[DiscoveredFile | str],
    *,
    options: WorkerOptions | None = None,
    completeness: Completeness | None = None,
    worker_entry: WorkerEntry | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> AnalysisResult:
    """Parse ``files`` (relative to ``root``) in isolated worker processes.

    ``files`` are :class:`DiscoveredFile` records (preferred: their ``(device, inode)`` is
    re-checked at open) or repo-relative ``/``-separated paths. Every input file ends up in
    exactly one :class:`FileOutcome` and in the completeness ledger (``completeness`` is updated
    in place when given): scanned, failed (typed reason), timed out, crashed, or unsupported
    (``parser_unavailable`` for in-scope languages without a parser, ``unsupported_file_type``
    for unknown extensions). Target code is never imported or executed (SR-01).

    ``worker_entry`` replaces the worker's entry point; it exists for fault-injection tests and
    must be a module-level function importable in a fresh interpreter.

    Raises :class:`WorkerStartupError` if a worker's module-origin assertion trips (exit 4).
    """
    opt = options or WorkerOptions()
    ledger = completeness if completeness is not None else Completeness()
    real_root = os.path.realpath(root)
    outcomes: list[FileOutcome | None] = [None] * len(files)
    tasks: list[_Task] = []
    for index, item in enumerate(files):
        language: Language | None
        if isinstance(item, DiscoveredFile):
            path, language = item.path, item.language
            expect: tuple[int, int] | None = (item.device, item.inode)
        else:
            path, language, expect = item, detect_language(item.rsplit("/", 1)[-1]), None
        _validate_rel_path(path)
        if language is None:
            outcomes[index] = FileOutcome(
                path, OutcomeStatus.UNSUPPORTED, SkipReason.UNSUPPORTED_FILE_TYPE
            )
        elif language is not Language.PYTHON:
            outcomes[index] = FileOutcome(
                path,
                OutcomeStatus.UNSUPPORTED,
                SkipReason.PARSER_UNAVAILABLE,
                f"no {language.value} parser in this version",
            )
        else:
            tasks.append(_Task(index=index, path=path, expect=expect))
    pool = _Pool(real_root, opt, worker_entry or worker_main, clock)
    try:
        if tasks:
            for index, outcome in pool.run(tasks).items():
                outcomes[index] = outcome
    finally:
        pool.shutdown()
    final = tuple(o for o in outcomes if o is not None)
    if len(final) != len(files):  # pragma: no cover - every task yields exactly one outcome
        raise RuntimeError("worker pool lost a file outcome")
    memory_enforced = _is_linux()
    _fold(ledger, final, memory_enforced)
    return AnalysisResult(
        outcomes=final, completeness=ledger, memory_limit_enforced=memory_enforced
    )
