"""Edge branches of discovery and startup: races, permissions, tracked-file pass, git varints."""

from __future__ import annotations

import hashlib
import os
import struct
from pathlib import Path

import pytest
from builders import (
    MODE_GITLINK,
    MODE_REGULAR,
    MODE_SYMLINK,
    build_git_index,
    make_git_repo,
    write_tree,
)

import nexvul.__main__ as entry
from nexvul.core import discovery as discovery_mod
from nexvul.core.completeness import SkipReason, Status
from nexvul.core.discovery import (
    DiscoveryOptions,
    GitIndexError,
    discover,
    parse_git_index,
    pattern_matches,
)


def test_directory_replaced_by_other_directory_is_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Inode check on directories: a same-named directory swapped in is not trusted."""
    root = tmp_path / "repo"
    write_tree(root, {"sub/a.py": "", "other/b.py": ""})
    real_open = os.open
    done = False

    def swap(path: object, flags: int, *a: object, **k: object) -> int:
        nonlocal done
        if path == "sub" and flags & os.O_DIRECTORY and not done:
            done = True
            os.rename(root / "sub", root / "sub_old")
            os.rename(root / "other", root / "sub")
        return real_open(path, flags, *a, **k)  # type: ignore[arg-type]

    monkeypatch.setattr(discovery_mod.os, "open", swap)
    r = discover(root)
    assert done
    assert "sub/b.py" not in [f.path for f in r.files]
    assert r.completeness.count(SkipReason.CHANGED_DURING_SCAN) >= 1
    assert r.completeness.status is Status.PARTIAL


def test_file_growing_past_limit_after_lstat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    write_tree(root, {"a.py": "x"})
    real_open = os.open

    def grow(path: object, flags: int, *a: object, **k: object) -> int:
        if path == "a.py":
            with (root / "a.py").open("ab") as fh:
                fh.write(b"y" * 4096)
        return real_open(path, flags, *a, **k)  # type: ignore[arg-type]

    monkeypatch.setattr(discovery_mod.os, "open", grow)
    r = discover(root, DiscoveryOptions(max_file_size=100))
    assert r.files == ()
    assert r.completeness.count(SkipReason.MAX_FILE_SIZE) == 1


def test_unreadable_file_is_open_failed(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root ignores file permissions")
    root = tmp_path / "repo"
    write_tree(root, {"a.py": "x = 1\n"})
    (root / "a.py").chmod(0)
    try:
        r = discover(root)
    finally:
        (root / "a.py").chmod(0o644)
    assert r.files == ()
    assert r.completeness.count(SkipReason.OPEN_FAILED) == 1
    assert r.completeness.status is Status.PARTIAL


def test_tracked_pass_branches(tmp_path: Path) -> None:
    """Tracked entries the walk never reached (inside node_modules) are classified one by one."""
    root = tmp_path / "repo"
    nm = root / "node_modules"
    nm.mkdir(parents=True)
    os.symlink("/etc/passwd", nm / "link.js")
    os.mkfifo(nm / "pipe.js")
    (nm / "nowdir.js").mkdir()
    (nm / "ok.js").write_text("")
    deep = "node_modules/" + "/".join(["d"] * 5) + "/x.js"
    make_git_repo(
        root,
        build_git_index(
            [
                (b"node_modules/link.js", MODE_SYMLINK),
                (b"node_modules/pipe.js", MODE_REGULAR),
                (b"node_modules/nowdir.js", MODE_REGULAR),
                (b"node_modules/ok.js", MODE_REGULAR),
                (b"node_modules/gone/x.js", MODE_REGULAR),
                (b"node_modules/sub", MODE_GITLINK),
                (deep.encode(), MODE_REGULAR),
            ]
        ),
    )
    r = discover(root, DiscoveryOptions(max_depth=4))
    c = r.completeness
    assert [(f.path, f.tracked) for f in r.files] == [("node_modules/ok.js", True)]
    assert c.count(SkipReason.SYMLINK_NOT_FOLLOWED) == 1
    assert c.count(SkipReason.SPECIAL_FILE) == 1
    assert c.count(SkipReason.TRACKED_MISSING_ON_DISK) == 2  # now a directory; parent missing
    assert c.count(SkipReason.SUBMODULE_NOT_SCANNED) == 1
    assert c.count(SkipReason.MAX_DEPTH) == 1


def test_gitdir_pointer_to_missing_dir_inside_root(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    write_tree(root, {"a.py": ""})
    (root / ".git").write_text("gitdir: nothere/gitdir\n")
    r = discover(root)
    assert any(n.startswith("gitdir_pointer_unreadable") for n in r.notes)


def test_detached_and_garbage_head(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    make_git_repo(root, build_git_index([]), head=b"a" * 64 + b"\n")
    assert discover(root).git_head == "a" * 64
    make_git_repo(root, build_git_index([]), head=b"zz-not-a-sha\n")
    assert discover(root).git_head is None


def _raw_index(entry_tail: bytes, version: int = 4) -> bytes:
    body = b"DIRC" + struct.pack(">II", version, 1)
    body += b"\x00" * 24 + struct.pack(">I", MODE_REGULAR) + b"\x00" * 12 + b"\x00" * 20
    body += struct.pack(">H", 0) + entry_tail
    return body + hashlib.sha1(body, usedforsecurity=False).digest()


def test_v4_varint_edge_cases() -> None:
    with pytest.raises(GitIndexError):
        parse_git_index(_raw_index(b"\xff\xff\xff\xff\xff\xff" + b"a.py\x00"))  # > 5 bytes
    with pytest.raises(GitIndexError):
        parse_git_index(_raw_index(b"\x00\x00"))  # empty path
    with pytest.raises(GitIndexError):
        parse_git_index(_raw_index(b""))  # truncated before varint


def test_pattern_edge_cases() -> None:
    assert pattern_matches("a**", "abc")
    assert pattern_matches("x/y/", "x/y/z.py")
    assert not pattern_matches("x/y/", "x/y")


# ------------------------------------------------------------------------- __main__ guard


def test_main_reexecs_when_path_unsafe(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, list[str], dict[str, str]]] = []

    def fake_execve(path: str, argv: list[str], env: dict[str, str]) -> None:
        calls.append((path, argv, env))
        raise SystemExit(0)

    monkeypatch.delenv("NEXVUL_STARTUP_REEXEC", raising=False)
    monkeypatch.setattr(entry.os, "execve", fake_execve)
    monkeypatch.setattr(entry, "_needs_reexec", lambda: True)
    monkeypatch.setattr(entry.sys, "argv", ["nexvul", "version"])
    with pytest.raises(SystemExit):
        entry._main()
    _path, argv, env = calls[0]
    assert argv[1:5] == ["-P", "-E", "-m", "nexvul"] and argv[5:] == ["version"]
    assert env["NEXVUL_STARTUP_REEXEC"] == "1"


def test_main_runs_cli_when_safe(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(entry, "_needs_reexec", lambda: False)
    monkeypatch.setattr(entry.sys, "argv", ["nexvul", "version"])
    with pytest.raises(SystemExit) as exc:
        entry._main()
    assert exc.value.code == 0
    assert capsys.readouterr().out.startswith("nexvul ")


def test_reexec_marker_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXVUL_STARTUP_REEXEC", "1")
    monkeypatch.setattr(entry, "_needs_reexec", lambda: True)
    with pytest.raises(SystemExit) as exc:
        entry._main()
    assert exc.value.code == 4


def test_needs_reexec_reflects_interpreter_flags() -> None:
    assert entry._needs_reexec() is not bool(entry.sys.flags.safe_path or entry.sys.flags.isolated)
