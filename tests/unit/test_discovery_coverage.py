"""Remaining discovery branches: hostile index shapes and I/O failures injected at the syscall edge.

Hostile trees are built in ``tmp_path`` at test time. Failures that a real filesystem cannot
produce deterministically (lstat/readlink/scandir errors, races between ``lstat`` and ``open``) are
injected by wrapping the corresponding ``os`` function for the duration of one test.
"""

from __future__ import annotations

import errno
import os
import stat
import struct
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from builders import MODE_REGULAR, build_git_index, make_git_repo, write_tree

from nexvul.core import discovery as discovery_mod
from nexvul.core.completeness import LimitHit, SkipReason, Status
from nexvul.core.discovery import (
    DiscoveryError,
    DiscoveryMode,
    DiscoveryOptions,
    GitIndexError,
    discover,
    parse_git_index,
)


def _raw(version: int, tail: bytes, count: int = 1) -> bytes:
    import hashlib

    body = b"DIRC" + struct.pack(">II", version, count)
    body += b"\x00" * 24 + struct.pack(">I", MODE_REGULAR) + b"\x00" * 12 + b"\x00" * 20
    body += struct.pack(">H", 0) + tail
    return body + hashlib.sha1(body, usedforsecurity=False).digest()


def test_segment_match_trailing_star_after_text_consumed() -> None:
    assert discovery_mod._segment_match("a*", "a")
    assert discovery_mod._segment_match("a***", "a")
    assert not discovery_mod._segment_match("a*b", "a")


def test_index_count_claims_more_entries_than_present() -> None:
    long_name = b"d/" + b"x" * 90 + b".py"
    data = build_git_index([(long_name, MODE_REGULAR)], count_override=2)
    with pytest.raises(GitIndexError, match="truncated"):
        parse_git_index(data)


def test_v4_unterminated_path() -> None:
    with pytest.raises(GitIndexError, match="unterminated"):
        parse_git_index(_raw(4, b"\x00abc"))


def test_v2_padding_runs_past_end_of_index() -> None:
    with pytest.raises(GitIndexError, match="truncated"):
        parse_git_index(_raw(2, b"a.py\x00"))


def test_v4_prefix_compression_cannot_exceed_max_path() -> None:
    data = build_git_index([(b"aaa", MODE_REGULAR), (b"aaabbb", MODE_REGULAR)], version=4)
    with pytest.raises(GitIndexError, match="too long"):
        parse_git_index(data, max_path=4)


@pytest.mark.parametrize(
    ("mode", "kind"),
    [
        (stat.S_IFSOCK, "socket"),
        (stat.S_IFCHR, "character device"),
        (stat.S_IFBLK, "block device"),
        (stat.S_IFDIR, "unknown file type"),
    ],
)
def test_special_kind_names(mode: int, kind: str) -> None:
    assert discovery_mod._special_kind(mode) == kind


def test_note_is_recorded_once() -> None:
    root = os.fspath(Path(__file__).parent)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        w = discovery_mod._Walker(root, fd, DiscoveryOptions(), lambda: 0.0)
        w._note("same")
        w._note("same")
        assert w.notes == ["same"]
    finally:
        os.close(fd)


def test_unopenable_scan_root(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root ignores directory permissions")
    root = tmp_path / "locked"
    root.mkdir()
    root.chmod(0)
    try:
        with pytest.raises(DiscoveryError, match="could not be opened"):
            discover(root)
    finally:
        root.chmod(0o755)


def _wrap(monkeypatch: pytest.MonkeyPatch, name: str, hook: Callable[..., Any | None]) -> None:
    """Replace ``os.<name>``; ``hook`` returns a replacement result, or None to defer to real."""
    real = getattr(os, name)

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        result = hook(real, *args, **kwargs)
        return real(*args, **kwargs) if result is None else result

    monkeypatch.setattr(os, name, wrapper)


def test_git_stat_failure_is_noted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write_tree(tmp_path / "r", {"a.py": "x = 1\n"})

    def hook(_real: Any, path: Any, *a: Any, dir_fd: int | None = None, **k: Any) -> None:
        if path == ".git" and dir_fd is not None:
            raise PermissionError(errno.EACCES, "denied")

    _wrap(monkeypatch, "stat", hook)
    r = discover(tmp_path / "r")
    assert r.mode is DiscoveryMode.DIRECTORY
    assert "git_metadata_unreadable" in r.notes


def test_head_read_failure_is_noted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "r"
    write_tree(root, {"a.py": "x = 1\n"})
    make_git_repo(root, build_git_index([(b"a.py", MODE_REGULAR)]))

    def boom(self: Any, git_fd: int) -> None:
        raise OSError(errno.EIO, "io error")

    monkeypatch.setattr(discovery_mod._Walker, "_read_head", boom)
    r = discover(root)
    assert "git_metadata_unreadable" in r.notes


def test_gitdir_pointer_swapped_for_directory_after_lstat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "r"
    write_tree(root, {"a.py": "x = 1\n", ".git": "gitdir: elsewhere\n"})
    real_open = os.open

    def swapped(path: Any, flags: int, *a: Any, dir_fd: int | None = None, **k: Any) -> int:
        if path == ".git" and dir_fd is not None and flags == discovery_mod._FILE_FLAGS:
            return real_open(os.fspath(root), os.O_RDONLY | os.O_DIRECTORY)
        return real_open(path, flags, *a, dir_fd=dir_fd, **k)

    monkeypatch.setattr(os, "open", swapped)
    r = discover(root)
    assert r.mode is DiscoveryMode.DIRECTORY
    assert [f.path for f in r.files] == ["a.py"]


def test_index_grows_between_fstat_and_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "r"
    write_tree(root, {"a.py": "x = 1\n"})
    data = build_git_index([(b"a.py", MODE_REGULAR)])
    make_git_repo(root, data)
    limit = len(data) - 1

    def understate(real: Any, fd: int) -> Any:
        st = real(fd)
        if stat.S_ISREG(st.st_mode) and st.st_size == len(data):
            fields = list(st)
            fields[stat.ST_SIZE] = 0
            return os.stat_result(fields)
        return None

    _wrap(monkeypatch, "fstat", understate)
    r = discover(root, DiscoveryOptions(max_git_index_bytes=limit))
    assert r.mode is DiscoveryMode.DIRECTORY
    assert LimitHit.GIT_INDEX_UNREADABLE in r.completeness.limits_hit


class _FakeEntry:
    name = "ghost.py"

    def stat(self, *, follow_symlinks: bool = True) -> os.stat_result:
        raise OSError(errno.EIO, "gone")


class _FakeScan:
    def __enter__(self) -> Iterator[Any]:
        return iter([_FakeEntry()])

    def __exit__(self, *exc: object) -> None:
        return None


def test_entry_lstat_failure_is_changed_during_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_tree(tmp_path / "r", {"a.py": "x = 1\n"})
    _wrap(
        monkeypatch,
        "scandir",
        lambda real, arg=None: _FakeScan() if isinstance(arg, int) else None,
    )
    r = discover(tmp_path / "r")
    assert r.completeness.count(SkipReason.CHANGED_DURING_SCAN) == 1
    assert r.completeness.status is Status.PARTIAL


def test_directory_listing_failure_is_unreadable_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_tree(tmp_path / "r", {"a.py": "x = 1\n"})

    def hook(_real: Any, arg: Any = None) -> None:
        if isinstance(arg, int):
            raise PermissionError(errno.EACCES, "denied")

    _wrap(monkeypatch, "scandir", hook)
    r = discover(tmp_path / "r")
    assert r.files == ()
    assert r.completeness.count(SkipReason.UNREADABLE_DIRECTORY) == 1


def test_readlink_failure_while_following(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "r"
    write_tree(root, {"real.py": "x = 1\n"})
    os.symlink("real.py", root / "link.py")

    def hook(_real: Any, *a: Any, **k: Any) -> None:
        raise OSError(errno.EIO, "gone")

    _wrap(monkeypatch, "readlink", hook)
    r = discover(root, DiscoveryOptions(follow_symlinks=True))
    assert r.completeness.count(SkipReason.CHANGED_DURING_SCAN) == 1


def test_file_read_failure_is_open_failed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write_tree(tmp_path / "r", {"a.py": "x = 1\n"})

    def failing(fd: int, limit: int) -> bytes:
        raise OSError(errno.EIO, "read failed")

    monkeypatch.setattr(discovery_mod, "_read_bounded", failing)
    r = discover(tmp_path / "r")
    assert r.files == ()
    assert r.completeness.count(SkipReason.OPEN_FAILED) == 1


def _tracked_root(tmp_path: Path, name: bytes) -> Path:
    root = tmp_path / "r"
    (root / "node_modules" / "sub").mkdir(parents=True)
    make_git_repo(root, build_git_index([(name, MODE_REGULAR)]))
    return root


def test_tracked_parent_unreadable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _tracked_root(tmp_path, b"node_modules/sub/x.js")
    real = discovery_mod._Walker._open_dir_chain

    def denied(self: Any, comps: Any, expect: Any) -> int:
        if "sub" in comps:
            raise PermissionError(errno.EACCES, "denied")
        return real(self, comps, expect)

    monkeypatch.setattr(discovery_mod._Walker, "_open_dir_chain", denied)
    r = discover(root)
    assert r.completeness.count(SkipReason.UNREADABLE_DIRECTORY) == 1


def test_tracked_lstat_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _tracked_root(tmp_path, b"node_modules/boom.js")
    (root / "node_modules" / "boom.js").write_text("")

    def hook(_real: Any, path: Any, *a: Any, dir_fd: int | None = None, **k: Any) -> None:
        if path == "boom.js" and dir_fd is not None:
            raise PermissionError(errno.EACCES, "denied")

    _wrap(monkeypatch, "stat", hook)
    r = discover(root)
    assert r.completeness.count(SkipReason.OPEN_FAILED) == 1
