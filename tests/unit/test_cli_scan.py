"""CLI wiring: scan, rules, explain, doctor (exit codes per OD-06, streams per R6)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from nexvul_test_rules import ShellCallRule, default_test_registry, registry_with

import nexvul.cli.main as cli_main
from nexvul.cli.main import main, terminal_style
from nexvul.reporting.utility import Check, doctor_checks, normalise_rule_id, render_doctor
from nexvul.rules.registry import Registry, builtin_registry

SHELL = "import os\nos.system('ls')\n"


def run(argv: list[str]) -> int:
    with pytest.raises(SystemExit) as exc:
        main(argv)
    code = exc.value.code
    return int(code) if code is not None else 0


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("CI", "GITHUB_ACTIONS", "NO_COLOR", "FORCE_COLOR", "NEXVUL_ASCII"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("COLUMNS", "100")
    monkeypatch.setattr(cli_main, "registry_factory", default_test_registry)


def project(tmp_path: Path, files: dict[str, str] | None = None) -> Path:
    root = tmp_path / "proj"
    root.mkdir()
    for rel, text in (files or {"a.py": SHELL}).items():
        (root / rel).write_text(text)
    return root


def test_scan_terminal_exit_1_plain(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(["scan", str(project(tmp_path))]) == 1
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "NEX990" in out and out.rstrip().splitlines()[-1].endswith("Exit code 1.")


def test_scan_json_to_stdout_is_valid(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = project(tmp_path, {"a.py": SHELL + "# nexvul: ignore\n"})
    assert run(["scan", str(root), "--format", "json"]) == 1
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["summary"]["exit_code"] == 1 and data["completeness"]["status"] == "complete"
    assert "warning" in captured.err  # warnings never pollute stdout (R6)


def test_scan_output_file_and_status_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = project(tmp_path)
    out = tmp_path / "r.json"
    assert run(["scan", str(root), "--format", "json", "--output", str(out)]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "wrote" in captured.err and "exit code 1" in captured.err
    assert json.loads(out.read_text())["summary"]["findings"] == 1
    text_out = tmp_path / "r.txt"
    assert run(["scan", str(root), "--output", str(text_out)]) == 1
    assert "\x1b" not in text_out.read_text()


def test_output_refusal_happens_before_scanning(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    root = project(tmp_path)
    readme = tmp_path / "README.md"
    readme.write_text("# keep\n")
    called = []
    monkeypatch.setattr(cli_main, "run_scan", lambda *_a, **_k: called.append(1))
    assert run(["scan", str(root), "--output", str(readme)]) == 2
    err = capsys.readouterr().err
    assert "not a nexvul report" in err and "Nothing was scanned. Exit code 2." in err
    assert called == [] and readme.read_text() == "# keep\n"


def test_fail_on_and_ci_flag(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = project(tmp_path, {"a.py": SHELL, ".nexvul.yml": "severity:\n  fail_on: critical\n"})
    assert run(["scan", str(root)]) == 0
    assert run(["scan", str(root), "--ci"]) == 1  # repo loosening not applied in CI
    assert "NOT APPLIED" in capsys.readouterr().out
    assert run(["scan", str(root), "--fail-on", "critical", "--ci"]) == 0


def test_ci_detected_from_environment(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    assert run(["scan", str(project(tmp_path))]) == 1
    assert "CI (detected from GITHUB_ACTIONS)" in capsys.readouterr().out


def test_partial_and_allow_partial(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = project(tmp_path, {"a.py": SHELL, "b.py": "def (:\n"})
    assert run(["scan", str(root)]) == 3
    out = capsys.readouterr().out
    assert (
        out.rstrip().splitlines()[-1].startswith(" PARTIAL SCAN")
        or "health." in out.rstrip().splitlines()[-1]
    )
    assert "No findings from enabled rules" not in out
    assert run(["scan", str(root), "--allow-partial"]) == 1
    assert "PARTIAL SCAN" in capsys.readouterr().out


def test_nothing_to_analyse_exits_3(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = project(tmp_path, {"README.md": "# docs\n"})
    assert run(["scan", str(root)]) == 3
    out = capsys.readouterr().out
    assert "SCAN FAILED" in out and "No findings" not in out


def test_usage_config_and_internal_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    assert run(["scan", str(tmp_path / "missing")]) == 2
    assert "path not found" in capsys.readouterr().err
    assert run(["scan", str(tmp_path), "--format", "xml"]) == 2
    capsys.readouterr()
    bad = project(tmp_path, {".nexvul.yml": "a: &x 1\nb: *x\n"})
    assert run(["scan", str(bad)]) == 2
    assert "config error in .nexvul.yml" in capsys.readouterr().err

    def boom(*_a: object, **_k: object) -> None:
        raise KeyError("SECRET_SOURCE_LINE")

    monkeypatch.setattr(cli_main, "run_scan", boom)
    assert run(["scan", str(tmp_path)]) == 4
    err = capsys.readouterr().err
    assert "internal error: KeyError" in err and "SECRET_SOURCE_LINE" not in err
    assert "Traceback" not in err

    def interrupt(*_a: object, **_k: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli_main, "run_scan", interrupt)
    assert run(["scan", str(tmp_path)]) == 130
    assert "No result was produced. Exit code 130." in capsys.readouterr().err


def test_discovery_and_startup_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from nexvul.core.discovery import DiscoveryError
    from nexvul.core.startup import ModuleShadowingError, ShadowedModule

    def disc(*_a: object, **_k: object) -> None:
        raise DiscoveryError("scan root could not be opened")

    monkeypatch.setattr(cli_main, "run_scan", disc)
    assert run(["scan", str(tmp_path)]) == 2
    assert "cannot scan" in capsys.readouterr().err

    def shadow(*_a: object, **_k: object) -> None:
        raise ModuleShadowingError((ShadowedModule("yaml", "/x/yaml.py"),))

    monkeypatch.setattr(cli_main, "run_scan", shadow)
    assert run(["scan", str(tmp_path)]) == 4
    assert "Exit code 4" in capsys.readouterr().err


def test_scan_help_lists_exit_codes(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(["scan", "--help"]) == 0
    out = capsys.readouterr().out
    assert "3  scan incomplete" in out and "--allow-partial" in out and "--fail-on" in out


def test_terminal_style_detection() -> None:
    class Tty:
        encoding = "utf-8"

        def isatty(self) -> bool:
            return True

    class Pipe(Tty):
        def isatty(self) -> bool:
            return False

    tty, pipe = Tty(), Pipe()
    style = terminal_style({}, tty, no_color=False, verbose=False, width=80)  # type: ignore[arg-type]
    assert style.color and not style.plain and not style.ascii
    for env, flag in (({"NO_COLOR": ""}, False), ({"TERM": "dumb"}, False), ({}, True)):
        s = terminal_style(env, tty, no_color=flag, verbose=False, width=80)  # type: ignore[arg-type]
        assert not s.color and s.plain and s.ascii
    assert not terminal_style({}, pipe, no_color=False, verbose=False, width=80).color  # type: ignore[arg-type]
    forced = terminal_style({"FORCE_COLOR": "1"}, pipe, no_color=False, verbose=False, width=80)  # type: ignore[arg-type]
    assert forced.color
    asc = terminal_style({"NEXVUL_ASCII": "1"}, tty, no_color=False, verbose=False, width=80)  # type: ignore[arg-type]
    assert asc.color and asc.ascii


def test_force_color_emits_sgr_only_on_request(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    root = project(tmp_path)
    monkeypatch.setenv("FORCE_COLOR", "1")
    run(["scan", str(root)])
    assert "\x1b[" in capsys.readouterr().out
    run(["scan", str(root), "--no-color"])
    assert "\x1b" not in capsys.readouterr().out
    monkeypatch.setenv("NO_COLOR", "1")
    run(["scan", str(root)])
    assert "\x1b" not in capsys.readouterr().out


# --- rules / explain / doctor / version ---------------------------------------------------------


def test_rules_empty_registry_says_so(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli_main, "registry_factory", lambda: Registry(()))
    assert run(["rules"]) == 0
    assert "No detection rules ship in this version" in capsys.readouterr().out
    assert run(["explain", "NEX007"]) == 2
    err = capsys.readouterr().err
    assert "NEX007 is not a nexvul rule" in err and "No detection rules ship" in err


@pytest.mark.parametrize("cols", ["80", "120"])
def test_builtin_rules_and_explain_show_nex007_as_experimental(
    cols: str, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("COLUMNS", cols)
    monkeypatch.setattr(cli_main, "registry_factory", builtin_registry)
    assert run(["rules"]) == 0
    out = capsys.readouterr().out
    assert "NEX007" in out and "experimental" in out
    assert "0 on by default" in out and "1 experimental (off)" in out
    assert all(len(line) <= int(cols) for line in out.splitlines())
    assert run(["explain", "nex7"]) == 0
    text = capsys.readouterr().out
    assert "confidence up to high · experimental" in text
    assert "Experimental thin slice: off by default" in text
    assert "WHAT THIS RULE DOES NOT DETECT" in text and "'claude mcp add'" in text
    assert "JSON has no comments" in text and "rules.disabled" in text
    assert all(len(line) <= 80 for line in text.splitlines() if not line.startswith("  https"))


@pytest.mark.parametrize("cols", ["80", "120"])
def test_rules_table(
    cols: str, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("COLUMNS", cols)
    assert run(["rules"]) == 0
    out = capsys.readouterr().out
    assert "NEX990" in out and "NEX991" in out and "experimental" in out
    assert all(len(line) <= int(cols) for line in out.splitlines())


def test_explain(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    assert run(["explain", "nex990"]) == 0
    out = capsys.readouterr().out
    for heading in ("WHAT IT LOOKS FOR", "HOW TO FIX", "SUPPRESSING THIS FINDING", "REFERENCES"):
        assert heading in out
    assert "# nexvul: ignore[NEX990] --" in out
    assert run(["explain", "NEX991"]) == 0  # no doc: remediation only
    assert "HOW TO FIX" in capsys.readouterr().out
    assert run(["explain", "NEX992"]) == 2
    assert "NEX992 is not a nexvul rule" in capsys.readouterr().err
    assert run(["explain", "\x1b[2Jbad"]) == 2
    assert "\x1b" not in capsys.readouterr().err
    monkeypatch.setattr(cli_main, "registry_factory", lambda: registry_with(ShellCallRule()))
    assert run(["explain", "NEX999"]) == 2
    assert "Did you mean NEX990" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("nex6", "NEX006"),
        (" NEX06 ", "NEX006"),
        ("NEX990", "NEX990"),
        ("ASI06", None),
        ("NEX", None),
        ("NEX1234", None),
        ("NEXab", None),
    ],
)
def test_normalise_rule_id(raw: str, expected: str | None) -> None:
    assert normalise_rule_id(raw) == expected


def test_doctor_checks_and_exit_codes(tmp_path: Path) -> None:
    reg = builtin_registry()
    checks = doctor_checks(
        reg, cwd=str(tmp_path), prefix="/opt/venv", probe=lambda: True, os_name="darwin"
    )
    text, code = render_doctor(checks, width=80)
    assert code == 0 and "All checks ok." in text
    assert "limit not enforced: memory (macOS)" in text
    assert "This checks nexvul's installation, not your code." in text
    linux = doctor_checks(
        reg, cwd=str(tmp_path), prefix="/opt", probe=lambda: True, os_name="linux"
    )
    assert any("Memory limit enforced" in c.text for c in linux)
    bad = doctor_checks(reg, cwd=str(tmp_path), prefix=str(tmp_path / ".venv"), probe=lambda: False)
    text, code = render_doctor(bad, width=80)
    assert code == 1 and "1 warning, 1 failure. Exit code 1." in text
    assert (
        render_doctor([Check("warn", "a"), Check("warn", "b")], width=80)[0].count("  warn  ") == 2
    )


def test_doctor_cli_runs_a_real_worker(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    code = run(["doctor"])
    out = capsys.readouterr().out
    assert "Worker processes start and return results" in out
    assert code in (0, 1)  # 1 only for warnings about this development checkout


def test_doctor_reports_modules_from_cwd(tmp_path: Path) -> None:
    import sys
    import types

    fake = types.ModuleType("shadow_mod")
    fake.__file__ = str(tmp_path / "shadow_mod.py")
    sys.modules["shadow_mod"] = fake
    try:
        checks = doctor_checks(
            builtin_registry(), cwd=str(tmp_path), prefix="/x", probe=lambda: True
        )
    finally:
        del sys.modules["shadow_mod"]
    assert any("Modules loaded from the current directory: shadow_mod" in c.text for c in checks)


def test_version_unchanged(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(["version"]) == 0
    assert capsys.readouterr().out.startswith("nexvul ")
