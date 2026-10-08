"""CLI (version/--help only) and the module-origin startup guard (architecture §2, SR-02)."""

from __future__ import annotations

import os
import subprocess
import sys
import types
from pathlib import Path

import pytest

import nexvul
from nexvul.cli.main import main
from nexvul.core.startup import (
    ModuleShadowingError,
    assert_no_module_from_roots,
    find_modules_under_roots,
)


def run_main(argv: list[str]) -> int:
    with pytest.raises(SystemExit) as exc:
        main(argv)
    code = exc.value.code
    return int(code) if code is not None else 0


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert run_main(["version"]) == 0
    assert capsys.readouterr().out == f"nexvul {nexvul.__version__}\n"


def test_help_mentions_disclaimer(capsys: pytest.CaptureFixture[str]) -> None:
    assert run_main(["--help"]) == 0
    out = capsys.readouterr().out
    assert "version" in out
    assert "never proves" in out


def test_no_scan_command_yet(capsys: pytest.CaptureFixture[str]) -> None:
    assert run_main(["scan", "."]) == 2
    assert "No such command" in capsys.readouterr().err


def test_unknown_option_is_usage_error() -> None:
    assert run_main(["--nope"]) == 2


def test_internal_error_exits_4_without_traceback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import nexvul.cli.main as cli_main

    def boom(*_a: object, **_k: object) -> None:
        raise RuntimeError("SECRET_INTERNAL_DETAIL")

    monkeypatch.setattr(cli_main.click, "echo", boom)
    assert run_main(["version"]) == 4
    err = capsys.readouterr().err
    assert "internal error" in err
    assert "Traceback" not in err and "SECRET_INTERNAL_DETAIL" not in err


def test_keyboard_interrupt_exits_130(monkeypatch: pytest.MonkeyPatch) -> None:
    import nexvul.cli.main as cli_main

    def interrupt(*_a: object, **_k: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli_main.click, "echo", interrupt)
    assert run_main(["version"]) == 130


def test_python_dash_m_reexecs_with_safe_path(tmp_path: Path) -> None:
    """``python -m nexvul`` re-executes itself with -P so CWD is not on sys.path."""
    probe = tmp_path / "probe"
    probe.mkdir()
    proc = subprocess.run(
        [sys.executable, "-m", "nexvul", "version"],
        cwd=probe,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == f"nexvul {nexvul.__version__}"


def test_reexec_loop_is_refused(tmp_path: Path) -> None:
    env = dict(os.environ, NEXVUL_STARTUP_REEXEC="1")
    proc = subprocess.run(
        [sys.executable, "-m", "nexvul", "version"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 4
    assert "refusing to run" in proc.stderr


def test_safe_path_invocation_runs_without_reexec(tmp_path: Path) -> None:
    env = dict(os.environ, NEXVUL_STARTUP_REEXEC="1")  # would fail closed if a re-exec happened
    proc = subprocess.run(
        [sys.executable, "-P", "-m", "nexvul", "version"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr


# ----------------------------------------------------------------------------- startup guard


def test_module_under_root_detected(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    fake = types.ModuleType("yaml")
    fake.__file__ = str(root / "yaml.py")
    pkg = types.ModuleType("click")
    pkg.__path__ = [str(root / "click")]
    clean = types.ModuleType("os_like")
    clean.__file__ = str(tmp_path / "elsewhere.py")
    modules = {"yaml": fake, "click": pkg, "os_like": clean, "none": None}
    hits = find_modules_under_roots([str(root)], modules)
    assert [h.module for h in hits] == ["click", "yaml"]
    with pytest.raises(ModuleShadowingError, match="refusing to scan"):
        assert_no_module_from_roots([str(root)], modules)


def test_sibling_prefix_is_not_inside_root(tmp_path: Path) -> None:
    (tmp_path / "repo").mkdir()
    mod = types.ModuleType("m")
    mod.__file__ = str(tmp_path / "repo-other" / "m.py")
    assert find_modules_under_roots([str(tmp_path / "repo")], {"m": mod}) == ()


def test_real_process_modules_not_under_temp_root(tmp_path: Path) -> None:
    assert_no_module_from_roots([str(tmp_path)])
