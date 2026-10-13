"""Safe report files: refusal rules and atomic writes (SR-07, SR-14, T-09, screen T22)."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from result_factory import t04

import nexvul.reporting.output as output_mod
from nexvul.reporting.json_report import render_json
from nexvul.reporting.output import OutputRefusedError, prepare_output, write_output


def prep(path: Path | str, root: Path, **kw: object):  # type: ignore[no-untyped-def]
    args: dict[str, object] = {"explicit": True, "force": False, "fmt": "json"}
    args.update(kw)
    return prepare_output(str(path), scan_root=str(root), **args)  # type: ignore[arg-type]


@pytest.fixture
def root(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    return r


def test_new_file_outside_root_is_written_atomically(tmp_path: Path, root: Path) -> None:
    target = prep(tmp_path / "out.json", root)
    write_output(target, b"data")
    out = tmp_path / "out.json"
    assert out.read_bytes() == b"data"
    assert stat.S_IMODE(out.stat().st_mode) & 0o777 in (0o644, 0o644 & ~os.umask(0o022))
    assert not [p for p in tmp_path.iterdir() if "nexvul-tmp" in p.name]


def test_inside_scan_root_refused_unless_explicit(root: Path) -> None:
    with pytest.raises(OutputRefusedError, match="inside the scanned directory"):
        prep(root / "report.json", root, explicit=False)
    assert prep(root / "report.json", root, explicit=True).name == "report.json"


def test_git_dir_refused_even_with_force(root: Path) -> None:
    (root / ".git").mkdir()
    with pytest.raises(OutputRefusedError, match=r"inside \.git"):
        prep(root / ".git" / "hooks-pre-commit", root, force=True)


def test_symlink_destination_refused_even_with_force(tmp_path: Path, root: Path) -> None:
    victim = tmp_path / "bashrc"
    victim.write_text("keep")
    link = tmp_path / "report.json"
    link.symlink_to(victim)
    with pytest.raises(OutputRefusedError, match="symbolic link") as exc:
        prep(link, root, force=True)
    assert "--force does not apply" in exc.value.hint
    assert victim.read_text() == "keep"


def test_symlinked_directory_inside_root_refused(tmp_path: Path, root: Path) -> None:
    outside = tmp_path / "home"
    outside.mkdir()
    (root / "reports").symlink_to(outside)
    with pytest.raises(OutputRefusedError, match="symbolic link inside the scanned"):
        prep(root / "reports" / "r.json", root)


def test_existing_non_report_needs_force(tmp_path: Path, root: Path) -> None:
    readme = tmp_path / "README.md"
    readme.write_text("# hello\n")
    with pytest.raises(OutputRefusedError, match="not a nexvul report") as exc:
        prep(readme, root)
    assert "--force" in exc.value.hint
    assert prep(readme, root, force=True).name == "README.md"


def test_existing_nexvul_report_is_overwritten(tmp_path: Path, root: Path) -> None:
    old = tmp_path / "r.json"
    old.write_text(render_json(t04(), pretty=False))
    write_output(prep(old, root), b"{}")
    assert old.read_bytes() == b"{}"
    text = tmp_path / "r.txt"
    text.write_text("nexvul 0.1.0  scan of .\n")
    assert prep(text, root, fmt="terminal").name == "r.txt"


@pytest.mark.parametrize("bad", ["", "a\x00b"])
def test_invalid_paths(root: Path, bad: str) -> None:
    with pytest.raises(OutputRefusedError):
        prep(bad, root)


def test_directory_and_missing_parent_refused(tmp_path: Path, root: Path) -> None:
    with pytest.raises(OutputRefusedError, match="not a regular file"):
        prep(tmp_path, root, force=True)
    with pytest.raises(OutputRefusedError, match="does not exist"):
        prep(tmp_path / "nope" / "r.json", root)
    with pytest.raises(OutputRefusedError, match="names a directory"):
        prep("/", root)


def test_write_failure_removes_temp_file(
    tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = prep(tmp_path / "r.json", root)

    def boom(*_a: object, **_k: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(output_mod.os, "replace", boom)
    with pytest.raises(OSError, match="disk full"):
        write_output(target, b"x")
    assert list(tmp_path.glob(".r.json.nexvul-tmp-*")) == []


def test_destination_turned_symlink_before_rename(tmp_path: Path, root: Path) -> None:
    target = prep(tmp_path / "r.json", root)
    (tmp_path / "r.json").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(OutputRefusedError, match="became a symbolic link"):
        write_output(target, b"x")
    assert not (tmp_path / "elsewhere").exists()
