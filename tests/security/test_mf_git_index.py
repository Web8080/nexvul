"""Forged `.git/index` inputs (SR-06 carve-out, architecture §4.2, R-6).

The index is hostile input. Any malformed index is rejected as a whole; discovery then falls back
to plain-directory mode and marks the scan partial (``git_index_unreadable``). Paths inside the
index are never used to open anything outside the root.
"""

from __future__ import annotations

import struct
import time
from pathlib import Path

import pytest
from builders import MODE_REGULAR, build_git_index, make_git_repo, write_tree

from nexvul.core.completeness import LimitHit, Status
from nexvul.core.discovery import (
    DiscoveryMode,
    DiscoveryOptions,
    GitIndexError,
    discover,
    parse_git_index,
)

pytestmark = pytest.mark.security

SECRET = "NEXVUL_TEST_SECRET_MARKER_91be"


def _reject(data: bytes, match: str | None = None, **kw: int) -> None:
    with pytest.raises(GitIndexError, match=match):
        parse_git_index(data, **kw)


@pytest.mark.parametrize(
    "path",
    [
        b"../outside/secret.py",
        b"a/../../outside/secret.py",
        b"/etc/passwd",
        b"a//b.py",
        b"./a.py",
        b"a/./b.py",
        b".git/hooks/pre-commit",
        b"sub/.GIT/config",
        b"a/",
    ],
)
def test_forged_index_hostile_paths_rejected(path: bytes) -> None:
    _reject(build_git_index([(b"ok.py", MODE_REGULAR), (path, MODE_REGULAR)]))


def test_forged_index_truncated_at_every_offset() -> None:
    full = build_git_index([(b"agent/a.py", MODE_REGULAR), (b"agent/b.py", MODE_REGULAR)])
    for cut in range(len(full) - 1):
        with pytest.raises(GitIndexError):
            parse_git_index(full[:cut])


def test_forged_index_huge_entry_count_rejected_without_allocation() -> None:
    start = time.monotonic()
    _reject(build_git_index([(b"a.py", MODE_REGULAR)], count_override=0xFFFFFFFF), "too many")
    _reject(build_git_index([(b"a.py", MODE_REGULAR)], count_override=900_000), "exceeds")
    assert time.monotonic() - start < 1.0


def test_forged_index_entry_count_larger_than_entries() -> None:
    _reject(build_git_index([(b"a.py", MODE_REGULAR)], count_override=3))


def test_forged_index_bad_signature_version_checksum() -> None:
    good = build_git_index([(b"a.py", MODE_REGULAR)])
    _reject(b"XXXX" + good[4:], "signature")
    _reject(good[:4] + struct.pack(">I", 9) + good[8:], "version")
    _reject(build_git_index([(b"a.py", MODE_REGULAR)], trailer="bad"), "checksum")
    _reject(b"DIRC", "too short")


def test_forged_index_unknown_mode() -> None:
    _reject(build_git_index([(b"a.py", 0o040000)]), "mode")


def test_forged_index_overlong_path_without_nul() -> None:
    _reject(build_git_index([(b"a" * 5000, MODE_REGULAR)]), "overlong|too long")
    _reject(build_git_index([(b"a" * 300, MODE_REGULAR)]), max_path=100)


def test_forged_index_v4_strip_larger_than_previous() -> None:
    data = build_git_index(
        [(b"a.py", MODE_REGULAR), (b"b.py", MODE_REGULAR)], version=4, v4_strip_override=50
    )
    _reject(data, "prefix")


def test_forged_index_v4_strip_cannot_build_traversal() -> None:
    """Prefix compression must not be a way to smuggle '..' past validation."""
    data = build_git_index([(b"x/..", MODE_REGULAR), (b"x/../secret.py", MODE_REGULAR)], version=4)
    _reject(data)


def test_forged_index_extended_flag_in_v2() -> None:
    _reject(build_git_index([(b"a.py", MODE_REGULAR)], skip_worktree=[b"a.py"], version=2))


# ------------------------------------------------------------- discovery integration


def test_forged_index_traversal_falls_back_and_reads_nothing_outside(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text(f"K = '{SECRET}'\n")
    root = tmp_path / "repo"
    write_tree(root, {"agent/a.py": "x = 1\n"})
    make_git_repo(
        root,
        build_git_index([(b"agent/a.py", MODE_REGULAR), (b"../outside/secret.py", MODE_REGULAR)]),
    )
    r = discover(root)
    assert r.mode is DiscoveryMode.DIRECTORY
    assert [f.path for f in r.files] == ["agent/a.py"]
    assert LimitHit.GIT_INDEX_UNREADABLE in r.completeness.limits_hit
    assert r.completeness.status is Status.PARTIAL
    assert SECRET not in repr(r)


def test_truncated_index_falls_back_to_directory_mode(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    write_tree(root, {"a.py": ""})
    make_git_repo(root, build_git_index([(b"a.py", MODE_REGULAR)])[:-7])
    r = discover(root)
    assert r.mode is DiscoveryMode.DIRECTORY
    assert [f.path for f in r.files] == ["a.py"]
    assert r.completeness.status is Status.PARTIAL
    assert any(n.startswith("git_index_unreadable") for n in r.notes)


def test_oversized_index_rejected_before_read(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    write_tree(root, {"a.py": ""})
    make_git_repo(root, build_git_index([(b"a.py", MODE_REGULAR)]))
    with (root / ".git" / "index").open("r+b") as fh:
        fh.truncate(10 * 1024 * 1024)
    r = discover(root, DiscoveryOptions(max_git_index_bytes=1024 * 1024))
    assert r.mode is DiscoveryMode.DIRECTORY
    assert any("larger than limit" in n for n in r.notes)


def test_tracked_path_through_symlinked_parent_not_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text(f"K = '{SECRET}'\n")
    root = tmp_path / "repo"
    root.mkdir()
    (root / "vendor").symlink_to(outside)
    make_git_repo(root, build_git_index([(b"vendor/secret.py", MODE_REGULAR)]))
    r = discover(root)
    assert r.files == ()
    assert SECRET not in repr(r)
