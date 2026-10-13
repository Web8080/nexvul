"""Hostile Python inputs through the real parse workers (plan sections B, C, J; SR-03..05, SR-20).

All inputs are generated in ``tmp_path`` at test time; nothing hostile is committed.
"""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from builders import assert_no_canary, canary_source, write_tree

from nexvul.core import limits
from nexvul.core.completeness import SkipReason, Status
from nexvul.core.workers import FileOutcome, OutcomeStatus, WorkerOptions, analyse_files
from nexvul.parser.python import AST_FILENAME, parse_python

pytestmark = pytest.mark.security


def _one(root: Path, name: str, data: bytes, **opts: Any) -> FileOutcome:
    (root / name).write_bytes(data)
    options = WorkerOptions(max_workers=1, **opts)
    result = analyse_files(str(root), [name], options=options)
    outcome = result.outcomes[0]
    if outcome.status is not OutcomeStatus.SCANNED:
        assert result.completeness.status is Status.PARTIAL
        assert result.completeness.files_not_analysed_partial == 1
    return outcome


def test_mf15_deep_parentheses(tmp_path: Path) -> None:
    data = b"x = " + b"(" * 100_000 + b"1" + b")" * 100_000 + b"\n"
    outcome = _one(tmp_path, "parens.py", data)
    assert outcome.reason is SkipReason.MAX_NESTING


def test_mf15_deep_lists(tmp_path: Path) -> None:
    data = b"x = " + b"[" * 100_000 + b"]" * 100_000 + b"\n"
    assert _one(tmp_path, "lists.py", data).reason is SkipReason.MAX_NESTING


@pytest.mark.parametrize(
    ("name", "data"),
    [
        ("binop.py", b"x = " + b"+".join([b"1"] * 200_000) + b"\n"),
        ("unary.py", b"x = " + b"-" * 100_000 + b"1\n"),
        ("attr.py", b"x = a" + b".b" * 100_000 + b"\n"),
        ("calls.py", b"x = a" + b".b()" * 50_000 + b"\n"),
        ("lambdas.py", b"f = " + b"lambda: " * 100_000 + b"1\n"),
    ],
)
def test_mf16_deep_left_recursive_chains(tmp_path: Path, name: str, data: bytes) -> None:
    """No RecursionError escapes; the file is skipped with a typed reason."""
    outcome = _one(tmp_path, name, data)
    assert outcome.reason in (SkipReason.MAX_NESTING, SkipReason.MAX_AST_NODES)


def test_mf16_moderate_binop_chain_is_analysed(tmp_path: Path) -> None:
    data = b"x = f(" + b"+".join([b"a"] * 1_000) + b")\n"
    outcome = _one(tmp_path, "ok.py", data)
    assert outcome.status is OutcomeStatus.SCANNED
    assert outcome.module is not None and outcome.module.calls[0].callee.written == "f"


def test_deep_indentation(tmp_path: Path) -> None:
    lines = [b" " * i + b"if x:\n" for i in range(150)] + [b" " * 150 + b"pass\n"]
    assert _one(tmp_path, "indent.py", b"".join(lines)).reason is SkipReason.MAX_NESTING


def test_mf14b_huge_string_literal_is_truncated_not_skipped(tmp_path: Path) -> None:
    data = b"PROMPT = '" + b"A" * 900_000 + b"'\nllm.invoke(PROMPT)\n"
    outcome = _one(tmp_path, "prompt.py", data)
    assert outcome.status is OutcomeStatus.SCANNED and outcome.module is not None
    s = outcome.module.strings[0]
    assert s.truncated and s.length == 900_000 and len(s.value) == limits.MAX_LITERAL_CHARS
    assert outcome.module.calls[0].callee.written == "llm.invoke"


def test_mf10_file_exactly_at_size_cap_is_parsed_in_time(tmp_path: Path) -> None:
    cap = limits.DEFAULT_MAX_FILE_SIZE
    line = b"result = client.chat.completions.create(model='m', messages=msgs)\n"
    body = line * (cap // len(line))
    data = body + b"#" * (cap - len(body) - 1) + b"\n"
    assert len(data) == cap
    start = time.monotonic()
    outcome = _one(tmp_path, "big.py", data)
    assert outcome.status is OutcomeStatus.SCANNED, outcome.detail
    assert time.monotonic() - start < limits.DEFAULT_PARSE_TIMEOUT_SECONDS
    assert outcome.module is not None and len(outcome.module.calls) == cap // len(line)


def test_mf11_file_one_byte_over_cap(tmp_path: Path) -> None:
    data = b"x = 1\n" + b"#" * (1000 - 6) + b"\n"
    outcome = _one(tmp_path, "over.py", data, max_file_size=len(data) - 1)
    assert outcome.reason is SkipReason.MAX_FILE_SIZE


def test_mf13_huge_int_literal(tmp_path: Path) -> None:
    outcome = _one(tmp_path, "int.py", b"x = 1" + b"0" * 100_000 + b"\n")
    assert outcome.reason is SkipReason.PARSE_ERROR


def test_null_byte_after_binary_sniff_window(tmp_path: Path) -> None:
    """Discovery sniffs the first 8 KiB; a NUL later is still a typed parse failure."""
    data = b"x = 1\n" * 2000 + b"\x00import os\n"
    outcome = _one(tmp_path, "nul.py", data)
    assert outcome.reason is SkipReason.PARSE_ERROR and outcome.detail == "null byte in source"


@pytest.mark.parametrize(
    "data",
    [
        b"x = '\xff\xfe'\n",  # invalid UTF-8, no cookie
        b"# -*- coding: utf-8 -*-\nx = '\xc3\x28'\n",  # invalid UTF-8 with a UTF-8 cookie
        b"# -*- coding: no-such-codec -*-\nx = 1\n",  # unknown codec
        b"\xef\xbb\xbf# coding: latin-1\nx = 1\n",  # BOM contradicts the cookie
    ],
)
def test_invalid_encodings(tmp_path: Path, data: bytes) -> None:
    assert _one(tmp_path, "enc.py", data).reason is SkipReason.NON_UTF8_UNDECODABLE


def test_mf122_utf7_cookie_is_decoded_as_cpython_does(tmp_path: Path) -> None:
    """Code hidden with a UTF-7 cookie is seen by the analyser, and the cookie is reported."""
    data = b"# -*- coding: utf-7 -*-\nx = 1 +AAo-import subprocess\n"
    (tmp_path / "u7.py").write_bytes(data)
    result = analyse_files(str(tmp_path), ["u7.py"], options=WorkerOptions(max_workers=1))
    module = result.modules[0]
    assert [i.resolved for i in module.imports] == ["subprocess"]
    assert "non_utf8_coding_cookie" in module.notes
    assert any("non-UTF-8" in n for n in result.completeness.notes)


def test_mf124_bidi_controls_are_noted(tmp_path: Path) -> None:
    data = "access = 'user\u202e \u2066// admin\u2069'\n".encode()
    (tmp_path / "bidi.py").write_bytes(data)
    result = analyse_files(str(tmp_path), ["bidi.py"], options=WorkerOptions(max_workers=1))
    assert "bidi_control" in result.modules[0].notes
    assert any("bidirectional" in n for n in result.completeness.notes)


def test_mf126_syntax_error(tmp_path: Path) -> None:
    outcome = _one(tmp_path, "err.py", b"def broken(:\n    pass\n")
    assert outcome.reason is SkipReason.PARSE_ERROR and outcome.detail == "syntax error at line 1"


def test_syntax_newer_than_runtime(tmp_path: Path) -> None:
    data = b"name = 'x'\nmsg = t'hello {name}'\n"
    outcome = _one(tmp_path, "new.py", data)
    if sys.version_info >= (3, 14):  # pragma: no cover - depends on the interpreter
        assert outcome.status is OutcomeStatus.SCANNED
    else:
        assert outcome.reason is SkipReason.SYNTAX_UNSUPPORTED_BY_RUNTIME
        assert "requires Python 3.14" in outcome.detail


def test_decorator_bomb(tmp_path: Path) -> None:
    data = b"@d\n" * 50_000 + b"def f():\n    pass\n"
    outcome = _one(tmp_path, "deco.py", data)
    assert outcome.status is OutcomeStatus.SCANNED and outcome.module is not None
    assert len(outcome.module.functions[0].decorators) == 50_000


def test_decorator_bomb_over_node_limit(tmp_path: Path) -> None:
    data = b"@d\n" * 50_000 + b"def f():\n    pass\n"
    outcome = _one(tmp_path, "deco.py", data, max_ast_nodes=10_000)
    assert outcome.reason is SkipReason.MAX_AST_NODES


def test_mf161_failures_do_not_leak_content(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    marker = "LEAKMARKER_sk-test-0000"
    (tmp_path / "leak.py").write_text(f"x = '{marker}'\ndef (:\n")
    result = analyse_files(str(tmp_path), ["leak.py"], options=WorkerOptions(max_workers=1))
    out, err = capfd.readouterr()
    assert marker not in out + err
    assert marker not in repr(result.completeness.to_dict())
    assert str(tmp_path) not in repr(result.completeness.to_dict())


# ---- in-process audit: parsing never imports, executes or opens target files -----------------

_RECORDING: dict[str, Any] = {"armed": False, "events": []}


def _audit(event: str, args: tuple[Any, ...]) -> None:
    if _RECORDING["armed"] and event in ("import", "exec", "compile", "open", "os.system"):
        _RECORDING["events"].append((event, args))


sys.addaudithook(_audit)


@pytest.fixture
def audit() -> Iterator[list[tuple[str, tuple[Any, ...]]]]:
    _RECORDING["events"] = []
    try:
        yield _RECORDING["events"]
    finally:
        _RECORDING["armed"] = False


def test_mf01_parse_is_static_under_audit_hook(
    tmp_path: Path, canary_dir: Path, audit: list[tuple[str, tuple[Any, ...]]]
) -> None:
    root = tmp_path / "repo"
    write_tree(root, {"agent.py": canary_source("MF-01-inproc") + "import yaml\n"})
    data = (root / "agent.py").read_bytes()
    _RECORDING["armed"] = True
    module = parse_python(data, "agent.py")
    _RECORDING["armed"] = False
    assert module.ok
    assert_no_canary(canary_dir)
    compiles = [args for event, args in audit if event == "compile"]
    assert compiles, "the audit hook did not observe ast.parse"
    for event, args in audit:
        assert event != "exec", "target code executed"
        if event == "compile":
            assert args[1] == AST_FILENAME  # ast.parse only, never the target path
        if event == "import":
            assert not str(args[1] or "").startswith(str(root))
        if event == "open":
            assert not str(args[0]).startswith(str(root))
    assert os.listdir(canary_dir) == []
