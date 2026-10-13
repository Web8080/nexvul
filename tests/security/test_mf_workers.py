"""Worker isolation under hostile conditions (plan sections A and C; SR-01, SR-03, T-02, T-03).

Fault-injecting worker entry points live in ``worker_faults.py``. Every hostile input is
generated inside ``tmp_path`` at test time.
"""

from __future__ import annotations

import json
import multiprocessing
import os
import sys
import time
from pathlib import Path
from typing import Any

import pytest
import worker_faults
from builders import assert_no_canary, canary_source, write_tree

from nexvul.core import workers
from nexvul.core.completeness import SkipReason, Status
from nexvul.core.discovery import discover
from nexvul.core.workers import OutcomeStatus, WorkerOptions, WorkerStartupError, analyse_files

pytestmark = pytest.mark.security


def _assert_no_live_workers() -> None:
    assert multiprocessing.active_children() == []


def _files(root: Path, names: list[str]) -> None:
    write_tree(root, dict.fromkeys(names, "x = 1\n"))


def test_hanging_worker_is_hard_killed_and_file_timed_out(tmp_path: Path) -> None:
    """A worker that never answers is SIGKILLed at the deadline; the file is ``timeout``."""
    _files(tmp_path, ["a.py"])
    start = time.monotonic()
    result = analyse_files(
        str(tmp_path),
        ["a.py"],
        options=WorkerOptions(max_workers=1, timeout_seconds=1.0),
        worker_entry=worker_faults.hang,
    )
    elapsed = time.monotonic() - start
    outcome = result.outcomes[0]
    assert outcome.status is OutcomeStatus.TIMED_OUT and outcome.reason is SkipReason.TIMEOUT
    assert "killed" in outcome.detail
    assert 1.0 <= elapsed < 15
    ledger = result.completeness
    assert ledger.files_timed_out == 1 and ledger.status is Status.PARTIAL
    _assert_no_live_workers()


def test_timeout_does_not_stop_other_files(tmp_path: Path) -> None:
    names = ["a.py", "HANG.py", "b.py", "c.py"]
    _files(tmp_path, names)
    result = analyse_files(
        str(tmp_path),
        names,
        options=WorkerOptions(max_workers=1, timeout_seconds=1.0),
        worker_entry=worker_faults.hang_on_marker,
    )
    statuses = {o.path: o.status for o in result.outcomes}
    assert statuses == {
        "a.py": OutcomeStatus.SCANNED,
        "HANG.py": OutcomeStatus.TIMED_OUT,
        "b.py": OutcomeStatus.SCANNED,  # a fresh worker replaced the killed one
        "c.py": OutcomeStatus.SCANNED,
    }
    _assert_no_live_workers()


def test_mf17_crashing_worker_marks_file_parser_crashed(tmp_path: Path) -> None:
    """Worker death by signal (stand-in for an AST-compiler crash) => ``parser_crashed``."""
    _files(tmp_path, ["a.py"])
    result = analyse_files(
        str(tmp_path),
        ["a.py"],
        options=WorkerOptions(max_workers=1),
        worker_entry=worker_faults.segfault,
    )
    outcome = result.outcomes[0]
    assert outcome.reason is SkipReason.PARSER_CRASHED
    assert "after 2 attempt(s)" in outcome.detail  # retried once, then given up
    assert result.completeness.files_failed == 1
    assert result.completeness.status is Status.PARTIAL
    _assert_no_live_workers()


def test_crash_is_attributed_to_one_file_only(tmp_path: Path) -> None:
    names = ["a.py", "CRASH.py", "b.py"]
    _files(tmp_path, names)
    result = analyse_files(
        str(tmp_path),
        names,
        options=WorkerOptions(max_workers=2, max_crash_attempts=1),
        worker_entry=worker_faults.crash_on_marker,
    )
    by_path = {o.path: o for o in result.outcomes}
    assert by_path["CRASH.py"].reason is SkipReason.PARSER_CRASHED
    assert "exit code 70" in by_path["CRASH.py"].detail
    assert "after 1 attempt(s)" in by_path["CRASH.py"].detail
    assert by_path["a.py"].status is OutcomeStatus.SCANNED
    assert by_path["b.py"].status is OutcomeStatus.SCANNED
    _assert_no_live_workers()


def test_worker_reply_is_never_unpickled(tmp_path: Path, canary_dir: Path) -> None:
    """SR-01: a compromised worker answering with a pickle that would run code on load is
    rejected as a protocol violation; nothing runs in the supervisor."""
    _files(tmp_path, ["a.py", "b.py"])
    for entry in (worker_faults.reply_pickle_canary, worker_faults.reply_pickle):
        result = analyse_files(
            str(tmp_path),
            ["a.py", "b.py"],
            options=WorkerOptions(max_workers=1),
            worker_entry=entry,
        )
        for outcome in result.outcomes:
            assert outcome.reason is SkipReason.PARSER_CRASHED
            assert outcome.detail == "protocol violation by parse worker"
    assert_no_canary(canary_dir)
    _assert_no_live_workers()


def test_real_worker_results_are_json_not_pickle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every byte string the supervisor receives from real workers is plain JSON."""
    write_tree(tmp_path, {"a.py": "import os\nos.getcwd()\n", "b.py": "def (:\n"})
    seen: list[bytes] = []
    real = workers.loads_strict

    def spy(data: bytes) -> Any:
        seen.append(bytes(data))
        return real(data)

    monkeypatch.setattr(workers, "loads_strict", spy)
    result = analyse_files(str(tmp_path), ["a.py", "b.py"], options=WorkerOptions(max_workers=2))
    assert len(seen) == 2
    for raw in seen:
        assert raw[:1] == b"{" and not raw.startswith(b"\x80")
        assert b"pickle" not in raw
        assert isinstance(json.loads(raw), dict)
        raw.decode("ascii")  # ensure_ascii JSON
    assert {o.status for o in result.outcomes} == {OutcomeStatus.SCANNED, OutcomeStatus.FAILED}


@pytest.mark.parametrize(
    "name", ["wrongid.py", "extra.py", "badmodule.py", "list.py", "otherpath.py", "deep.py"]
)
def test_schema_violations_are_protocol_errors(tmp_path: Path, name: str) -> None:
    _files(tmp_path, [name])
    result = analyse_files(
        str(tmp_path),
        [name],
        options=WorkerOptions(max_workers=1),
        worker_entry=worker_faults.reply_garbage,
    )
    assert result.outcomes[0].reason is SkipReason.PARSER_CRASHED
    assert result.outcomes[0].detail == "protocol violation by parse worker"
    _assert_no_live_workers()


def test_oversized_reply_is_rejected(tmp_path: Path) -> None:
    _files(tmp_path, ["a.py"])
    result = analyse_files(
        str(tmp_path),
        ["a.py"],
        options=WorkerOptions(max_workers=1, max_result_bytes=1024 * 1024),
        worker_entry=worker_faults.reply_oversized,
    )
    assert result.outcomes[0].reason is SkipReason.PARSER_CRASHED
    _assert_no_live_workers()


def test_internal_worker_error_is_recorded(tmp_path: Path) -> None:
    _files(tmp_path, ["a.py"])
    result = analyse_files(
        str(tmp_path),
        ["a.py"],
        options=WorkerOptions(max_workers=1),
        worker_entry=worker_faults.reply_internal_error,
    )
    assert result.outcomes[0].detail == "internal error in parse worker"


def test_worker_startup_guard_fails_closed(tmp_path: Path) -> None:
    _files(tmp_path, ["a.py"])
    with pytest.raises(WorkerStartupError):
        analyse_files(
            str(tmp_path),
            ["a.py"],
            options=WorkerOptions(max_workers=1),
            worker_entry=worker_faults.reply_fatal,
        )
    _assert_no_live_workers()


def test_real_worker_startup_guard_on_shadowing_root() -> None:
    """A scan root that contains a module the worker has loaded (here nexvul's own src/) trips
    the module-origin assertion inside the worker (SR-02)."""
    src_root = Path(workers.__file__).resolve().parents[2]
    with pytest.raises(WorkerStartupError):
        analyse_files(str(src_root), ["nexvul/__init__.py"], options=WorkerOptions(max_workers=1))
    _assert_no_live_workers()


def test_rss_cap_kills_worker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Linux RSS polling path, driven with a fake RSS reader (no /proc on macOS)."""
    _files(tmp_path, ["a.py"])
    monkeypatch.setattr(workers, "_rss_bytes", lambda pid: 10 * 1024**3)
    result = analyse_files(
        str(tmp_path),
        ["a.py"],
        options=WorkerOptions(max_workers=1, timeout_seconds=5.0, rss_poll=True),
        worker_entry=worker_faults.hang,
    )
    assert result.outcomes[0].reason is SkipReason.MEMORY_LIMIT
    assert result.completeness.files_failed == 1
    _assert_no_live_workers()


def test_worker_hardening(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The spawned worker sees a reduced environment and the resource limits (T-19, §5.2)."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_fake_test_token")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "fake")
    monkeypatch.setenv("NEXVUL_TEST_MARKER", "1")
    pool = workers._Pool(
        str(tmp_path), WorkerOptions(max_workers=1), worker_faults.probe, time.monotonic
    )
    worker = pool._spawn()
    try:
        assert worker.conn.poll(30)
        report = json.loads(worker.conn.recv_bytes())
    finally:
        pool.shutdown()
    assert "GITHUB_TOKEN" not in report["env"]
    assert "AWS_SECRET_ACCESS_KEY" not in report["env"]
    assert "NEXVUL_TEST_MARKER" in report["env"]
    assert all(workers._env_allowed(k) for k in report["env"])
    assert report["core"] == [0, 0]
    assert report["fsize"] == [0, 0]
    assert report["nofile"][0] <= 64
    if sys.platform.startswith("linux"):  # pragma: no cover - CI on Linux
        assert report["as"][0] == WorkerOptions().memory_limit_bytes
    assert os.environ["GITHUB_TOKEN"] == "ghp_fake_test_token"  # supervisor env restored
    _assert_no_live_workers()


def test_mf01_05_target_code_never_runs_in_workers(tmp_path: Path, canary_dir: Path) -> None:
    """Canary payloads at module level, in decorators, metaclasses, default arguments,
    ``__init__.py``, ``conftest.py`` and ``setup.py`` are parsed but never executed or imported."""
    root = tmp_path / "repo"
    fire = "(pathlib.Path(os.environ['NEXVUL_CANARY_DIR']) / '{}').write_text('x')"
    write_tree(
        root,
        {
            "agent/tools.py": canary_source("MF-01") + "\n@tool\ndef t():\n    return 1\n",
            "setup.py": canary_source("MF-02-setup"),
            "conftest.py": canary_source("MF-02-conftest"),
            "pkg/__init__.py": canary_source("MF-03"),
            "pkg/x.py": "from pkg import y\nfrom . import z\n",
            "deco.py": (
                "import os, pathlib\n"
                "def d(f):\n"
                "    " + fire.format("MF-05-deco") + "\n"
                "    return f\n"
                "@d\n"
                "def g(a=" + fire.format("MF-05-default") + "):\n"
                "    pass\n"
                "class M(type):\n"
                "    def __init_subclass__(cls):\n"
                "        " + fire.format("MF-05-meta") + "\n"
            ),
            "yaml.py": canary_source("MF-06-yaml"),
            "encodings/__init__.py": canary_source("MF-06-encodings"),
            "cookie.py": "# -*- coding: utf-8 -*-\n" + canary_source("MF-122"),
        },
    )
    found = discover(root)
    result = analyse_files(str(root), found.files, options=WorkerOptions(max_workers=2))
    assert result.completeness.status is Status.COMPLETE
    assert result.completeness.files_scanned == len(found.files) == 9
    tools = next(m for m in result.modules if m.path == "agent/tools.py")
    assert tools.functions[0].decorators[0].target.written == "tool"
    assert_no_canary(canary_dir)
    _assert_no_live_workers()
