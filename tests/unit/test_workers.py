"""Worker pool: options, in-process worker logic, folding into completeness (architecture §5.2)."""

from __future__ import annotations

import json
import os
import threading
from multiprocessing import Pipe
from pathlib import Path
from typing import Any

import pytest

from nexvul.core import workers
from nexvul.core.completeness import Completeness, SkipReason, Status
from nexvul.core.discovery import discover
from nexvul.core.workers import (
    FileOutcome,
    OutcomeStatus,
    WorkerOptions,
    analyse_files,
    handle_task,
    read_file,
    serve,
    worker_environment,
)
from nexvul.ir import FailureReason, module_from_json


def _task(root: Path, path: str, **over: Any) -> dict[str, Any]:
    task: dict[str, Any] = {
        "op": "parse",
        "id": 7,
        "root": str(root),
        "path": path,
        "expect": None,
        "timeout": 10.0,
        "max_file_size": 1024 * 1024,
        "max_nesting": 100,
        "max_ast_nodes": 500_000,
        "max_literal_chars": 10_000,
        "max_result_bytes": 64 * 1024 * 1024,
    }
    task.update(over)
    return task


# ---- options -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_workers": 0},
        {"timeout_seconds": 0},
        {"timeout_seconds": 10_000},
        {"max_file_size": 0},
        {"max_file_size": 17 * 1024 * 1024},
        {"max_nesting": 0},
        {"max_crash_attempts": 0},
        {"max_result_bytes": 10},
    ],
)
def test_worker_options_validation(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        WorkerOptions(**kwargs)


def test_default_worker_count_is_bounded() -> None:
    assert 1 <= workers.default_worker_count() <= 8


def test_worker_environment_is_reduced() -> None:
    env = {
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "NEXVUL_X": "1",
        "GITHUB_TOKEN": "secret",
        "AWS_SECRET_ACCESS_KEY": "s",
        "PATH": "/bin",
        "PYTHONPATH": "/evil",
        "HOME": "/home/u",
    }
    assert worker_environment(env) == {"LANG": "C", "LC_ALL": "C", "TZ": "UTC", "NEXVUL_X": "1"}


def test_reduced_environ_restores(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "secret")
    with workers._reduced_environ():
        assert "GITHUB_TOKEN" not in os.environ
    assert os.environ["GITHUB_TOKEN"] == "secret"


def test_rss_reader(tmp_path: Path) -> None:
    (tmp_path / "123").mkdir()
    (tmp_path / "123" / "statm").write_text("1000 50 3 4 5 6 7\n")
    assert workers._rss_bytes(123, str(tmp_path)) == 50 * os.sysconf("SC_PAGE_SIZE")
    assert workers._rss_bytes(999, str(tmp_path)) is None
    (tmp_path / "124").mkdir()
    (tmp_path / "124" / "statm").write_text("x")
    assert workers._rss_bytes(124, str(tmp_path)) is None


# ---- worker side, in-process ----------------------------------------------------------------


def test_read_file_paths_and_failures(tmp_path: Path) -> None:
    (tmp_path / "d").mkdir()
    f = tmp_path / "d" / "a.py"
    f.write_bytes(b"x = 1\n")
    st = f.stat()
    assert read_file(str(tmp_path), "d/a.py", expect=(st.st_dev, st.st_ino), max_file_size=100) == (
        b"x = 1\n"
    )
    assert (
        read_file(str(tmp_path), "d/a.py", expect=(st.st_dev, st.st_ino + 1), max_file_size=100)[0]
        is FailureReason.CHANGED_DURING_SCAN
    )
    assert read_file(str(tmp_path), "d/a.py", expect=None, max_file_size=3)[0] is (
        FailureReason.MAX_FILE_SIZE
    )
    assert read_file(str(tmp_path), "d/missing.py", expect=None, max_file_size=100)[0] is (
        FailureReason.CHANGED_DURING_SCAN
    )
    assert read_file(str(tmp_path / "nope"), "a.py", expect=None, max_file_size=100)[0] is (
        FailureReason.OPEN_FAILED
    )
    (tmp_path / "link.py").symlink_to(f)
    assert read_file(str(tmp_path), "link.py", expect=None, max_file_size=100)[0] is (
        FailureReason.CHANGED_DURING_SCAN
    )
    (tmp_path / "ldir").symlink_to(tmp_path / "d")
    assert read_file(str(tmp_path), "ldir/a.py", expect=None, max_file_size=100)[0] is (
        FailureReason.CHANGED_DURING_SCAN
    )
    os.mkfifo(tmp_path / "fifo.py")
    assert read_file(str(tmp_path), "fifo.py", expect=None, max_file_size=100)[0] is (
        FailureReason.CHANGED_DURING_SCAN
    )


def test_read_file_unreadable(tmp_path: Path) -> None:
    f = tmp_path / "a.py"
    f.write_text("x = 1\n")
    f.chmod(0)
    try:
        if os.access(f, os.R_OK):  # pragma: no cover - running as root
            pytest.skip("running with privileges that bypass file modes")
        reason, detail = read_file(str(tmp_path), "a.py", expect=None, max_file_size=100)  # type: ignore[misc]
        assert reason is FailureReason.OPEN_FAILED and detail == "EACCES"
    finally:
        f.chmod(0o644)


def test_handle_task_success_and_failure(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("import os\nos.getcwd()\n")
    reply = json.loads(handle_task(_task(tmp_path, "ok.py")))
    assert reply["id"] == 7
    module = module_from_json(json.dumps(reply["module"]).encode())
    assert module.ok and module.calls[0].callee.resolved == "os.getcwd"
    gone = json.loads(handle_task(_task(tmp_path, "gone.py")))
    assert gone["module"]["failure"]["reason"] == "changed_during_scan"


def test_handle_task_result_cap(tmp_path: Path) -> None:
    (tmp_path / "big.py").write_text("\n".join(f"f{i}(x)" for i in range(2000)))
    reply = json.loads(handle_task(_task(tmp_path, "big.py", max_result_bytes=4096)))
    assert reply["module"]["failure"]["reason"] == "max_ast_nodes"


def test_handle_task_internal_error_hides_details(tmp_path: Path) -> None:
    (tmp_path / "x.py").write_text("x = 1\n")
    reply = json.loads(handle_task(_task(tmp_path, "x.py", max_nesting="not-an-int")))
    assert reply == {"id": 7, "error": "internal"}


def test_handle_task_module_origin_assertion() -> None:
    src_root = Path(workers.__file__).resolve().parents[2]  # .../src: nexvul is loaded from here
    reply = json.loads(handle_task(_task(src_root, "x.py")))
    assert reply == {"id": 7, "fatal": "module_shadowing"}


def test_serve_loop_in_process(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n")
    parent, child = Pipe(duplex=True)
    thread = threading.Thread(target=serve, args=(child,), daemon=True)
    thread.start()
    parent.send_bytes(json.dumps(_task(tmp_path, "a.py")).encode())
    reply = json.loads(parent.recv_bytes())
    assert reply["module"]["status"] == "ok"
    parent.send_bytes(b'{"op":"stop"}')
    thread.join(5)
    assert not thread.is_alive()
    # EOF also ends the loop.
    parent2, child2 = Pipe(duplex=True)
    t2 = threading.Thread(target=serve, args=(child2,), daemon=True)
    t2.start()
    parent2.close()
    t2.join(5)
    assert not t2.is_alive()


# ---- supervisor ----------------------------------------------------------------------------


def test_analyse_files_end_to_end(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "__init__.py").write_text("from .core import Agent\n")
    (root / "pkg" / "core.py").write_text(
        "from langchain_openai import ChatOpenAI\nm = ChatOpenAI()\nm.invoke('x')\n"
    )
    (root / "bad.py").write_text("def (:\n")
    (root / "latin.py").write_bytes(b"# coding: latin-1\ns = '\xff'\n")
    (root / "big.py").write_text("s = '" + "A" * 20_000 + "'\n")
    (root / "web.ts").write_text("export const x = 1;\n")
    (root / "README.md").write_text("# hi\n")
    found = discover(root)
    result = analyse_files(str(root), found.files, options=WorkerOptions(max_workers=2))
    by_path = {o.path: o for o in result.outcomes}
    assert by_path["pkg/core.py"].status is OutcomeStatus.SCANNED
    core = by_path["pkg/core.py"].module
    assert core is not None
    assert [c.callee.resolved for c in core.calls] == [
        "langchain_openai.ChatOpenAI",
        "langchain_openai.ChatOpenAI.invoke",
    ]
    assert by_path["bad.py"].reason is SkipReason.PARSE_ERROR
    assert by_path["web.ts"].reason is SkipReason.PARSER_UNAVAILABLE
    ledger = result.completeness
    assert ledger.status is Status.PARTIAL
    assert ledger.files_scanned == 4
    assert ledger.count(SkipReason.PARSE_ERROR) == 1
    assert any("non-UTF-8" in n for n in ledger.notes)
    assert any("truncated" in n for n in ledger.notes)
    assert [o.path for o in result.outcomes] == [f.path for f in found.files]
    assert {m.path for m in result.modules} == {
        "pkg/__init__.py",
        "pkg/core.py",
        "latin.py",
        "big.py",
    }


def test_analyse_files_folds_into_existing_ledger(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n")
    ledger = Completeness()
    ledger.record_skip("huge.py", SkipReason.MAX_FILE_SIZE)
    result = analyse_files(
        str(tmp_path),
        ["a.py", "notes.txt"],
        completeness=ledger,
        options=WorkerOptions(max_workers=1),
    )
    assert result.completeness is ledger
    assert ledger.files_scanned == 1
    assert ledger.count(SkipReason.UNSUPPORTED_FILE_TYPE) == 1
    assert ledger.status is Status.PARTIAL  # the discovery-time skip still counts


def test_analyse_files_complete_scan(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n")
    result = analyse_files(str(tmp_path), ["a.py"], options=WorkerOptions(max_workers=1))
    assert result.completeness.status is Status.COMPLETE
    assert result.memory_limit_enforced is workers._is_linux()


def test_analyse_files_no_python_files_spawns_nothing(tmp_path: Path) -> None:
    result = analyse_files(str(tmp_path), ["a.js"])
    assert result.outcomes[0].reason is SkipReason.PARSER_UNAVAILABLE
    assert analyse_files(str(tmp_path), []).outcomes == ()


@pytest.mark.parametrize(
    "bad", ["", "/abs.py", "../x.py", "a//b.py", "./a.py", "a\\b.py", "a\x00.py"]
)
def test_analyse_files_rejects_bad_paths(tmp_path: Path, bad: str) -> None:
    with pytest.raises(ValueError):
        analyse_files(str(tmp_path), [bad])


def test_fold_defaults_missing_reason() -> None:
    ledger = Completeness()
    workers._fold(ledger, [FileOutcome("a.py", OutcomeStatus.CRASHED)], memory_enforced=True)
    assert ledger.count(SkipReason.PARSER_CRASHED) == 1
    assert not any("memory limit" in n for n in ledger.notes)
