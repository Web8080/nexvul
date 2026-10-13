"""Output-side malicious-input tests (MF-61..75, MF-110..117; SR-10, SR-11, SR-17, SR-18, SR-19).

Every hostile input is generated in tmp_path. Assertions are on raw output bytes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from nexvul_test_rules import (
    ExplodingRule,
    HostileMessageRule,
    ShellCallRule,
    default_test_registry,
    registry_with,
)

import nexvul.cli.main as cli_main
from nexvul.cli.main import main
from nexvul.reporting.output import OutputRefusedError, prepare_output

pytestmark = pytest.mark.security

HOSTILE_NAMES = [
    "esc\x1b[2Jclear",  # ANSI clear screen
    "osc8\x1b]8;;https:evil.example\x07link\x1b]8;;\x07",  # OSC 8 hyperlink
    "osc52\x1b]52;c;ZWNobyBwd25lZA==\x07",  # clipboard write
    "new\nline Result  0 findings",  # forged line
    "bidi\u202eyp.txt",  # Trojan Source style name
    "[link=https:evil]markup[\\link]",  # Rich-markup lookalike
    "zero\u200bwidth",
    "c1\u009b31m",
]
RAW_FORBIDDEN = ("\x1b", "\u202e", "\u200b", "\u009b", "\x07")


def run(argv: list[str]) -> int:
    with pytest.raises(SystemExit) as exc:
        main(argv)
    return int(exc.value.code or 0)


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("CI", "GITHUB_ACTIONS", "NO_COLOR", "FORCE_COLOR"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("COLUMNS", "100")


def hostile_tree(tmp_path: Path) -> Path:
    root = tmp_path / "proj"
    root.mkdir()
    (root / "ok.py").write_text("import os\nos.system('ls')\n")
    for i, name in enumerate(HOSTILE_NAMES):
        # .ts: in scope, no parser -> listed by path in the partial block. (Was .json until
        # step 4; JSON files are parsed as configuration data now.)
        (root / f"{name}{i}.ts").write_text("export {}\n")
        # .py with a finding -> path appears in findings and flow
        (root / f"{name}{i}.py").write_text("import os\nos.system('x')\n")
    return root


def assert_clean_output(text: str) -> None:
    for ch in RAW_FORBIDDEN:
        assert ch not in text, repr(ch)
    for line in text.splitlines():
        assert not line.startswith("Result  0 findings"), line  # forged line never starts a line


@pytest.mark.parametrize("fmt", ["terminal", "json"])
def test_mf61_75_hostile_filenames_never_reach_output_raw(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    fmt: str,
) -> None:
    monkeypatch.setattr(cli_main, "registry_factory", default_test_registry)
    root = hostile_tree(tmp_path)
    code = run(["scan", str(root), "--format", fmt, "--verbose"])
    captured = capsys.readouterr()
    assert code == 3  # .ts files have no parser: partial
    assert_clean_output(captured.out)
    assert_clean_output(captured.err)
    captured.out.encode("utf-8")  # valid UTF-8, no lone surrogates
    if fmt == "json":
        data = json.loads(captured.out)
        assert_clean_output(json.dumps(data, ensure_ascii=False))
        paths = [f["file"] for f in data["findings"]]
        assert any("\\x1b" in p for p in paths)  # escaped, visible, not dropped
        assert any("\\u{202e}" in p for p in paths)
    else:
        assert (
            "PARTIAL SCAN" in captured.out.splitlines()[-1]
            or "health." in (captured.out.splitlines()[-1])
        )


def test_hostile_finding_messages_are_escaped_in_every_format(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli_main, "registry_factory", lambda: registry_with(HostileMessageRule()))
    root = tmp_path / "p"
    root.mkdir()
    (root / "a.py").write_text("print(1)\n")
    for fmt in ("terminal", "json"):
        assert run(["scan", str(root), "--format", fmt]) == 1
        out = capsys.readouterr().out
        assert_clean_output(out)
        assert "\\x1b[2J" in out
    # colour on: only nexvul's own SGR codes may appear, never the hostile sequences
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert run(["scan", str(root)]) == 1
    out = capsys.readouterr().out
    assert "\x1b[2J" not in out and "\x1b]8" not in out and "\x1b[H" not in out
    stripped = out
    for code in ("1;97;41", "1;31", "33", "34", "2", "36", "1", "35", "1;30;43", "0"):
        stripped = stripped.replace(f"\x1b[{code}m", "")
    assert "\x1b" not in stripped


def test_hostile_suppression_justification_is_rejected_and_named(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """MF-110..117: bare ignore and bidi/control characters in a suppression are rejected."""
    monkeypatch.setattr(cli_main, "registry_factory", lambda: registry_with(ShellCallRule()))
    root = tmp_path / "p"
    root.mkdir()
    (root / "a.py").write_text(
        "import os\n"
        "os.system('a')  # nexvul: ignore[NEX990] -- ok \u202e\u2066 reviewed\u2069\n"
        "os.system('b')  # nexvul: ignore\n"
        "os.system('c')  # nexvul: ignore[NEX990] -- \x1b[2Jfake\n"
        "s = '# nexvul: ignore[NEX990] -- in a string'; os.system('d')\n"
    )
    assert run(["scan", str(root)]) == 1  # nothing suppressed: all four findings active
    captured = capsys.readouterr()
    assert_clean_output(captured.out + captured.err)
    assert "U+202E RIGHT-TO-LEFT OVERRIDE" in captured.err
    assert "U+001B" in captured.err
    assert "no rule ID" in captured.err
    assert "4 findings" in captured.out
    assert "Suppressed (" not in captured.out


def test_ci_requires_justification_and_rejects_loosening(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli_main, "registry_factory", lambda: registry_with(ShellCallRule()))
    root = tmp_path / "p"
    root.mkdir()
    (root / "a.py").write_text("import os\nos.system('a')  # nexvul: ignore[NEX990]\n")
    (root / ".nexvul.yml").write_text(
        "severity:\n  fail_on: critical\nrules:\n  disabled: [NEX990]\nexclude:\n  - 'gen/**'\n"
    )
    assert run(["scan", str(root)]) == 0  # locally: config and suppression honoured
    capsys.readouterr()
    assert run(["scan", str(root), "--ci"]) == 1
    out = capsys.readouterr().out
    assert out.count("NOT APPLIED") >= 4  # fail_on, disabled, exclude, suppression
    assert "NEX990" in out


def test_partial_scan_exits_3_and_never_prints_a_clean_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli_main, "registry_factory", lambda: registry_with(ShellCallRule()))
    root = tmp_path / "p"
    root.mkdir()
    (root / "a.py").write_text("x = 1\n")
    (root / "bomb.py").write_text("x = " + "(" * 200 + ")" * 200 + "\n")  # nesting cap
    assert run(["scan", str(root)]) == 3
    out = capsys.readouterr().out
    assert "No findings from enabled rules" not in out
    assert out.rstrip().splitlines()[-1].startswith(" PARTIAL SCAN") or out.rstrip().endswith(
        "health."
    )


def test_rule_exception_recorded_exit_3(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli_main, "registry_factory", lambda: registry_with(ExplodingRule()))
    root = tmp_path / "p"
    root.mkdir()
    (root / "a.py").write_text("print(1)\n")
    assert run(["scan", str(root), "--format", "json"]) == 3
    data = json.loads(capsys.readouterr().out)
    assert data["completeness"]["rule_failures"] == [
        {"rule_id": "NEX993", "error_type": "RuntimeError"}
    ]
    assert "SECRET-RULE-DETAIL" not in json.dumps(data)


def test_nothing_to_analyse_exits_3(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = tmp_path / "docs"
    root.mkdir()
    (root / "index.md").write_text("# hi\n")
    assert run(["scan", str(root), "--allow-partial"]) == 3
    assert "SCAN FAILED" in capsys.readouterr().out


def test_output_inside_scan_root_refused_unless_explicit(tmp_path: Path) -> None:
    root = tmp_path / "p"
    (root / ".git").mkdir(parents=True)
    with pytest.raises(OutputRefusedError):
        prepare_output(
            str(root / "nexvul.json"), scan_root=str(root), explicit=False, force=False, fmt="json"
        )
    # a committed symlink pointing at a user file is never followed, even with --force
    victim = tmp_path / "victim"
    victim.write_text("keep")
    (root / "nexvul.sarif").symlink_to(victim)
    with pytest.raises(OutputRefusedError):
        prepare_output(
            str(root / "nexvul.sarif"), scan_root=str(root), explicit=True, force=True, fmt="json"
        )
    with pytest.raises(OutputRefusedError):
        prepare_output(
            str(root / ".git" / "config"),
            scan_root=str(root),
            explicit=True,
            force=True,
            fmt="json",
        )
    assert victim.read_text() == "keep"


def test_cli_output_symlink_refused_with_exit_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "p"
    root.mkdir()
    (root / "a.py").write_text("x = 1\n")
    victim = tmp_path / "bashrc"
    victim.write_text("keep")
    (root / "out.json").symlink_to(victim)
    assert run(["scan", str(root), "--output", str(root / "out.json"), "--force"]) == 2
    assert "symbolic link" in capsys.readouterr().err
    assert victim.read_text() == "keep"
