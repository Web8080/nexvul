"""Malicious-input tests for discovery (plan sections B, D, H, J, O; SR-04, SR-06, SR-10, SR-16).

Every hostile tree is built at test time inside ``tmp_path``. Test names carry the MF id.
"""

from __future__ import annotations

import errno
import os
import socket
import stat
from pathlib import Path

import pytest
from builders import (
    MODE_REGULAR,
    build_git_index,
    is_case_sensitive,
    make_git_repo,
    make_non_utf8_name,
    write_tree,
)

from nexvul.core import discovery as discovery_mod
from nexvul.core.completeness import LimitHit, SkipReason, Status
from nexvul.core.discovery import DiscoveryMode, DiscoveryOptions, discover
from nexvul.core.sanitize import is_display_safe

pytestmark = pytest.mark.security

SECRET = "NEXVUL_TEST_SECRET_MARKER_7f3a"


def _all_text(result: object) -> str:
    return repr(result)


def _outside(tmp_path: Path) -> Path:
    out = tmp_path / "outside"
    out.mkdir()
    (out / "secret.py").write_text(f"KEY = '{SECRET}'\n")
    return out


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    return root


# ------------------------------------------------------------------------- B: size / binary


def test_mf10_huge_sparse_file_skipped_before_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    big = root / "big.py"
    with big.open("wb") as fh:
        fh.truncate(3 * 1024**3)  # sparse 3 GB
    opened: list[str] = []
    real_open = os.open

    def spy(path: object, flags: int, *a: object, **k: object) -> int:
        opened.append(str(path))
        return real_open(path, flags, *a, **k)  # type: ignore[arg-type]

    monkeypatch.setattr(discovery_mod.os, "open", spy)
    r = discover(root)
    assert r.files == ()
    assert r.completeness.count(SkipReason.MAX_FILE_SIZE) == 1
    assert r.completeness.status is Status.PARTIAL
    assert "big.py" not in opened  # rejected from lstat size, never opened


def test_mf11_just_over_limit_is_visible_partial(tmp_path: Path) -> None:
    root = _root(tmp_path)
    (root / "agent.py").write_bytes(b"#" * 1025)
    (root / "ok.py").write_bytes(b"#" * 1024)
    r = discover(root, DiscoveryOptions(max_file_size=1024))
    assert [f.path for f in r.files] == ["ok.py"]
    skipped = r.completeness.skipped[0]
    assert skipped.reason is SkipReason.MAX_FILE_SIZE and skipped.path == "agent.py"
    assert r.completeness.status is Status.PARTIAL


@pytest.mark.parametrize(
    "content",
    [
        b"\x7fELF\x02\x01\x01\x00\x00\x00",
        b"import os\n\x00\x00\x00",
        "x = 1\n".encode("utf-16"),  # UTF-16 with BOM: contains NULs
        os.urandom(4096) + b"\x00",
    ],
)
def test_mf14_binary_named_py_is_skipped(tmp_path: Path, content: bytes) -> None:
    root = _root(tmp_path)
    (root / "agent.py").write_bytes(content)
    r = discover(root)
    assert r.files == ()
    assert r.completeness.count(SkipReason.BINARY) == 1
    assert r.completeness.status is Status.PARTIAL


def test_mf14_nul_after_sniff_window_not_read(tmp_path: Path) -> None:
    root = _root(tmp_path)
    (root / "a.py").write_bytes(b"x" * 9000 + b"\x00")
    r = discover(root)
    assert [f.path for f in r.files] == ["a.py"]  # only the first 8 KiB are sniffed


# --------------------------------------------------------------------------- D: FS DoS


def test_mf20_file_count_bomb_stops_at_max_files(tmp_path: Path) -> None:
    """Scaled down (2,000 files, cap 100) to keep the PR suite fast; same code path as 1M."""
    root = _root(tmp_path)
    for i in range(2000):
        (root / f"f{i:05d}.py").write_bytes(b"")
    r = discover(root, DiscoveryOptions(max_files=100))
    assert len(r.files) == 100
    assert LimitHit.MAX_FILES in r.completeness.limits_hit
    assert r.completeness.count(SkipReason.MAX_FILES) == 1
    assert r.completeness.status is Status.PARTIAL
    assert [f.path for f in r.files] == [f"f{i:05d}.py" for i in range(100)]  # deterministic


def test_mf20_entry_bomb_of_non_candidates_is_bounded(tmp_path: Path) -> None:
    root = _root(tmp_path)
    for i in range(3000):
        (root / f"f{i}.bin").write_bytes(b"")
    r = discover(root, DiscoveryOptions(max_dir_entries=1000))
    assert LimitHit.MAX_DIR_ENTRIES in r.completeness.limits_hit
    assert r.entries_examined <= 1001


def test_mf21_dir_depth_bomb_beyond_path_max(tmp_path: Path) -> None:
    root = _root(tmp_path)
    name = "d" * 50
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for _ in range(120):  # 120 * 51 bytes > PATH_MAX on macOS (1024) and Linux (4096)
            os.mkdir(name, dir_fd=fd)
            nfd = os.open(name, os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = nfd
        leaf = os.open("deep.py", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=fd)
        os.close(leaf)
    finally:
        os.close(fd)
    (root / "top.py").write_text("")
    r = discover(root)
    assert [f.path for f in r.files] == ["top.py"]
    assert LimitHit.MAX_DEPTH in r.completeness.limits_hit
    assert r.completeness.count(SkipReason.MAX_DEPTH) == 1
    assert r.completeness.status is Status.PARTIAL


@pytest.mark.timeout(10)
def test_mf22_fifo_named_py_does_not_block(tmp_path: Path) -> None:
    root = _root(tmp_path)
    (root / "agent").mkdir()
    os.mkfifo(root / "agent" / "pipe.py")
    r = discover(root)
    assert r.files == ()
    entry = r.completeness.skipped[0]
    assert entry.reason is SkipReason.SPECIAL_FILE and entry.detail == "fifo"
    assert r.completeness.status is Status.COMPLETE  # policy exclusion, counted


@pytest.mark.timeout(10)
def test_mf22_fifo_swapped_in_after_lstat_does_not_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """O_NONBLOCK + fstat: a FIFO substituted between lstat and open never blocks."""
    root = _root(tmp_path)
    (root / "a.py").write_text("x = 1\n")
    real_open = os.open
    swapped = False

    def swap(path: object, flags: int, *a: object, **k: object) -> int:
        nonlocal swapped
        if path == "a.py" and not swapped:
            swapped = True
            os.unlink(root / "a.py")
            os.mkfifo(root / "a.py")
        return real_open(path, flags, *a, **k)  # type: ignore[arg-type]

    monkeypatch.setattr(discovery_mod.os, "open", swap)
    r = discover(root)
    assert swapped
    assert r.files == ()
    assert r.completeness.count(SkipReason.CHANGED_DURING_SCAN) == 1


@pytest.mark.timeout(10)
@pytest.mark.parametrize("follow", [False, True])
def test_mf23_dev_zero_and_urandom_symlinks(tmp_path: Path, follow: bool) -> None:
    root = _root(tmp_path)
    os.symlink("/dev/zero", root / "x.py")
    os.symlink("/dev/urandom", root / "y.py")
    r = discover(root, DiscoveryOptions(follow_symlinks=follow))
    assert r.files == ()
    reason = SkipReason.SYMLINK_ESCAPES_ROOT if follow else SkipReason.SYMLINK_NOT_FOLLOWED
    assert r.completeness.count(reason) == 2


@pytest.mark.timeout(10)
def test_mf24_unix_socket_is_special(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _root(tmp_path)
    monkeypatch.chdir(root)  # bind by relative name: sun_path is short on macOS
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.bind("s.py")
        r = discover(root)
    finally:
        sock.close()
    assert r.files == ()
    assert r.completeness.skipped[0].detail == "socket"


def test_mf25_case_collision(tmp_path: Path) -> None:
    root = _root(tmp_path)
    if not is_case_sensitive(root):
        pytest.skip("MF-25 requires a case-sensitive filesystem (Linux CI); not run here")
    (root / "Agent.py").write_text("a = 1\n")
    (root / "agent.py").write_text("b = 1\n")
    r = discover(root)
    assert [f.path for f in r.files] == ["Agent.py", "agent.py"]


# ---------------------------------------------------------------- H: symlinks / traversal


@pytest.mark.parametrize("follow", [False, True])
def test_mf50_symlink_to_home_secret_not_read(tmp_path: Path, follow: bool) -> None:
    root = _root(tmp_path)
    home = tmp_path / "home" / ".ssh"
    home.mkdir(parents=True)
    (home / "id_ed25519").write_text(SECRET)
    (root / "agent").mkdir()
    os.symlink(home / "id_ed25519", root / "agent" / "creds.py")
    r = discover(root, DiscoveryOptions(follow_symlinks=follow))
    assert r.files == ()
    assert SECRET not in _all_text(r)
    if follow:
        assert r.completeness.count(SkipReason.SYMLINK_ESCAPES_ROOT) == 1


@pytest.mark.parametrize("follow", [False, True])
def test_mf51_symlink_to_proc_self_environ(
    tmp_path: Path, follow: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEXVUL_ENV_MARKER", SECRET)
    root = _root(tmp_path)
    os.symlink("/proc/self/environ", root / "env.py")
    r = discover(root, DiscoveryOptions(follow_symlinks=follow))
    assert r.files == ()
    assert SECRET not in _all_text(r)


@pytest.mark.parametrize("follow", [False, True])
def test_mf52_directory_symlink_escape(tmp_path: Path, follow: bool) -> None:
    root = _root(tmp_path)
    outside = _outside(tmp_path)
    os.symlink(outside, root / "vendor")
    os.symlink("../outside", root / "rel_vendor")
    r = discover(root, DiscoveryOptions(follow_symlinks=follow))
    assert r.files == ()
    assert SECRET not in _all_text(r)
    reason = SkipReason.SYMLINK_ESCAPES_ROOT if follow else SkipReason.SYMLINK_NOT_FOLLOWED
    assert r.completeness.count(reason) == 2


@pytest.mark.timeout(10)
@pytest.mark.parametrize("follow", [False, True])
def test_mf53_symlink_loops(tmp_path: Path, follow: bool) -> None:
    root = _root(tmp_path)
    os.symlink("b.py", root / "a.py")
    os.symlink("a.py", root / "b.py")
    os.symlink(".", root / "self")
    (root / "sub").mkdir()
    os.symlink("..", root / "sub" / "up")
    (root / "real.py").write_text("")
    r = discover(root, DiscoveryOptions(follow_symlinks=follow))
    assert [f.path for f in r.files] == ["real.py"]
    total_links = r.completeness.count(SkipReason.SYMLINK_NOT_FOLLOWED) + r.completeness.count(
        SkipReason.SYMLINK_ESCAPES_ROOT
    )
    assert total_links == 4


def test_mf54_toctou_file_swapped_for_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    outside = _outside(tmp_path)
    (root / "victim.py").write_text("x = 1\n")
    real_open = os.open

    def swap(path: object, flags: int, *a: object, **k: object) -> int:
        if path == "victim.py":
            os.unlink(root / "victim.py")
            os.symlink(outside / "secret.py", root / "victim.py")
        return real_open(path, flags, *a, **k)  # type: ignore[arg-type]

    monkeypatch.setattr(discovery_mod.os, "open", swap)
    r = discover(root)
    assert r.files == ()
    assert r.completeness.count(SkipReason.CHANGED_DURING_SCAN) == 1
    assert SECRET not in _all_text(r)


def test_mf54_toctou_file_replaced_by_other_inode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    (root / "victim.py").write_text("x = 1\n")
    (root / "zz_other.bin").write_text("y = 2\n")
    real_open = os.open

    def swap(path: object, flags: int, *a: object, **k: object) -> int:
        if path == "victim.py":
            os.replace(root / "zz_other.bin", root / "victim.py")
        return real_open(path, flags, *a, **k)  # type: ignore[arg-type]

    monkeypatch.setattr(discovery_mod.os, "open", swap)
    r = discover(root)
    assert r.files == ()
    assert r.completeness.count(SkipReason.CHANGED_DURING_SCAN) == 1


def test_mf54_toctou_directory_swapped_for_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    outside = _outside(tmp_path)
    (root / "sub").mkdir()
    (root / "sub" / "a.py").write_text("")
    real_open = os.open

    def swap(path: object, flags: int, *a: object, **k: object) -> int:
        if path == "sub" and flags & os.O_DIRECTORY:
            (root / "sub" / "a.py").unlink()
            (root / "sub").rmdir()
            os.symlink(outside, root / "sub")
        return real_open(path, flags, *a, **k)  # type: ignore[arg-type]

    monkeypatch.setattr(discovery_mod.os, "open", swap)
    r = discover(root)
    assert r.files == ()
    assert r.completeness.count(SkipReason.CHANGED_DURING_SCAN) == 1
    assert SECRET not in _all_text(r)
    assert r.completeness.status is Status.PARTIAL


def test_mf56_hardlink_to_outside_is_recorded(tmp_path: Path) -> None:
    root = _root(tmp_path)
    outside = _outside(tmp_path)
    try:
        os.link(outside / "secret.py", root / "inside.py")
    except OSError as exc:  # pragma: no cover - FS without hard links
        pytest.skip(f"filesystem does not support hard links: {errno.errorcode[exc.errno]}")
    r = discover(root)
    # Documented residual: the inode is inside the tree, so it is selected - but it is recorded.
    assert [f.path for f in r.files] == ["inside.py"]
    assert r.hardlinked_files == 1
    assert SECRET not in _all_text(r)  # discovery never keeps content


def test_special_paths_never_resolved_into(tmp_path: Path) -> None:
    root = _root(tmp_path)
    os.symlink("/sys/kernel", root / "k.py")
    os.symlink("/dev", root / "devdir")
    r = discover(root, DiscoveryOptions(follow_symlinks=True))
    assert r.completeness.count(SkipReason.SYMLINK_ESCAPES_ROOT) == 2


def test_symlink_inside_root_counted_not_duplicated(tmp_path: Path) -> None:
    root = _root(tmp_path)
    (root / "real.py").write_text("")
    os.symlink("real.py", root / "alias.py")
    r = discover(root, DiscoveryOptions(follow_symlinks=True))
    assert [f.path for f in r.files] == ["real.py"]
    assert r.completeness.skipped[0].detail == "target inside root; scanned there"


# ------------------------------------------------------------------------ J: filenames


ESC = chr(0x1B)
RLO = chr(0x202E)
DIV_SLASH = chr(0x2215)


@pytest.mark.parametrize(
    "name",
    [
        "agent\n::error file=x::fake.py",  # MF-61
        f"{ESC}[2J{ESC}[Hclear.py",  # MF-62
        f"{ESC}]8;;https:evil.example{ESC}\\link.py",  # MF-62 OSC 8 (no "/" in a name)
        f"evil{RLO}yp.py",  # MF-63
        "[link=https:evil.example]ok[_link].py",  # MF-66
        "[bold red]x[_].py",  # MF-66
        "<img src=x onerror=alert(1)>.py",  # MF-67
        f"src{DIV_SLASH}agent.py",  # MF-68
        "-rf --output=x.py",  # MF-90 flavour
    ],
)
def test_mf61_68_hostile_filenames_are_sanitised(tmp_path: Path, name: str) -> None:
    root = _root(tmp_path)
    (root / name).write_text("x = 1\n")
    r = discover(root)
    assert len(r.files) == 1
    f = r.files[0]
    assert f.path == name  # internal representation is the raw name
    assert "\n" not in f.display_path and ESC not in f.display_path
    assert RLO not in f.display_path and DIV_SLASH not in f.display_path
    f.display_path.encode("utf-8")


def test_mf64_non_utf8_filename(tmp_path: Path) -> None:
    root = _root(tmp_path)
    raw = b"agent_\xff\xfe.py"
    if not make_non_utf8_name(root, raw):
        pytest.skip("MF-64 requires a filesystem accepting non-UTF-8 names (Linux); not run here")
    r = discover(root)
    assert len(r.files) == 1
    f = r.files[0]
    assert f.path_bytes == raw
    assert f.display_path == "agent_\\xff\\xfe.py"
    f.display_path.encode("utf-8")  # no lone surrogates in display text


def test_mf65_long_names(tmp_path: Path) -> None:
    root = _root(tmp_path)
    comp = "n" * 200
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:  # build relative to dir fds: the absolute path exceeds PATH_MAX on macOS
        for _ in range(4):
            os.mkdir(comp, dir_fd=fd)
            nfd = os.open(comp, os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = nfd
        os.close(os.open("f" * 250 + ".py", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=fd))
    finally:
        os.close(fd)
    r = discover(root)
    assert len(r.files) == 1
    f = r.files[0]
    assert len(f.path) > 1000
    assert len(f.display_path) <= 240
    assert is_display_safe(f.display_path.replace(chr(0x2026), ""))


def test_skip_ledger_paths_are_sanitised(tmp_path: Path) -> None:
    root = _root(tmp_path)
    os.mkfifo(root / f"pipe{ESC}[2J\n.py")
    r = discover(root)
    shown = r.completeness.skipped[0].path
    assert ESC not in shown and "\n" not in shown


# --------------------------------------------------------- O: git index vs ignore (SR-16)


def test_mf106_gitignored_tracked_file_is_scanned(tmp_path: Path) -> None:
    root = _root(tmp_path)
    write_tree(root, {".gitignore": "agent/tools/*.py\n", "agent/tools/evil.py": "x = 1\n"})
    make_git_repo(root, build_git_index([(b"agent/tools/evil.py", MODE_REGULAR)]))
    r = discover(root)
    assert [(f.path, f.tracked) for f in r.files] == [("agent/tools/evil.py", True)]


def test_mf107_nested_gitignore_star(tmp_path: Path) -> None:
    root = _root(tmp_path)
    write_tree(root, {"agent/.gitignore": "*\n", "agent/a.py": "", "agent/b.py": ""})
    make_git_repo(root, build_git_index([(b"agent/a.py", MODE_REGULAR)]))
    r = discover(root)
    assert {f.path: f.tracked for f in r.files} == {"agent/a.py": True, "agent/b.py": False}


def test_mf108_non_git_dir_scans_gitignored_files(tmp_path: Path) -> None:
    """Architecture §4.1: ignore files are not honoured in plain directories by default.

    The malicious-input plan expects .gitignore fallback here; architecture rev 2 scans
    everything instead (strictly more coverage). Conflict recorded in the step-1 handoff.
    """
    root = _root(tmp_path)
    write_tree(root, {".gitignore": "agent/\n", "agent/evil.py": ""})
    r = discover(root)
    assert r.mode is DiscoveryMode.DIRECTORY
    assert [f.path for f in r.files] == ["agent/evil.py"]


def test_git_dir_contents_never_walked(tmp_path: Path) -> None:
    root = _root(tmp_path)
    make_git_repo(root, build_git_index([]))
    write_tree(root, {".git/hooks/post-checkout.py": "x", ".git/config.yml": "a: 1"})
    (root / "sub").mkdir()
    (root / "sub" / ".GIT").mkdir()
    (root / "sub" / ".GIT" / "x.py").write_text("")
    r = discover(root)
    assert r.files == ()
    assert r.completeness.count(SkipReason.VCS_METADATA) == 2


def test_git_dir_symlink_not_followed(tmp_path: Path) -> None:
    root = _root(tmp_path)
    elsewhere = tmp_path / "elsewhere_git"
    make_git_repo(elsewhere, build_git_index([(b"x.py", MODE_REGULAR)]))
    os.symlink(elsewhere / ".git", root / ".git")
    (root / "a.py").write_text("")
    r = discover(root)
    assert r.mode is DiscoveryMode.DIRECTORY
    assert any(n.startswith("git_dir_is_symlink") for n in r.notes)


def test_gitdir_pointer_outside_root_refused(tmp_path: Path) -> None:
    root = _root(tmp_path)
    elsewhere = tmp_path / "elsewhere_git"
    make_git_repo(elsewhere, build_git_index([(b"../outside/secret.py", MODE_REGULAR)]))
    (root / ".git").write_text(f"gitdir: {elsewhere / '.git'}\n")
    (root / "a.py").write_text("")
    r = discover(root)
    assert r.mode is DiscoveryMode.DIRECTORY
    assert any(n.startswith("gitdir_outside_root") for n in r.notes)


@pytest.mark.parametrize(
    "content", [b"gitdir: ../..\n", b"gitdir: x\nmore\n", b"not a pointer", b"g" * 5000]
)
def test_gitdir_pointer_malformed(tmp_path: Path, content: bytes) -> None:
    root = _root(tmp_path)
    (root / ".git").write_bytes(content)
    (root / "a.py").write_text("")
    r = discover(root)
    assert r.mode is DiscoveryMode.DIRECTORY
    assert [f.path for f in r.files] == ["a.py"]


def test_index_symlink_not_followed(tmp_path: Path) -> None:
    root = _root(tmp_path)
    (root / ".git").mkdir()
    outside = _outside(tmp_path)
    os.symlink(outside / "secret.py", root / ".git" / "index")
    (root / "a.py").write_text("")
    r = discover(root)
    assert r.mode is DiscoveryMode.DIRECTORY
    assert LimitHit.GIT_INDEX_UNREADABLE in r.completeness.limits_hit
    assert SECRET not in _all_text(r)


@pytest.mark.timeout(10)
def test_index_and_head_fifo_do_not_block(tmp_path: Path) -> None:
    root = _root(tmp_path)
    (root / ".git").mkdir()
    os.mkfifo(root / ".git" / "index")
    os.mkfifo(root / ".git" / "HEAD")
    (root / "a.py").write_text("")
    r = discover(root)
    assert r.mode is DiscoveryMode.DIRECTORY
    assert r.git_head is None
    assert [f.path for f in r.files] == ["a.py"]


def test_forged_head_is_bounded_and_sanitised(tmp_path: Path) -> None:
    root = _root(tmp_path)
    make_git_repo(root, build_git_index([]), head=f"ref: refs/heads/{ESC}[2Jx\n".encode())
    r = discover(root)
    assert r.git_head is not None and ESC not in r.git_head
    make_git_repo(root, build_git_index([]), head=b"ref: " + b"a" * 5000)
    assert discover(root).git_head is None


def test_unreadable_directory_is_partial(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root ignores directory permissions")
    root = _root(tmp_path)
    locked = root / "locked"
    locked.mkdir()
    (locked / "a.py").write_text("")
    locked.chmod(0)
    try:
        r = discover(root)
    finally:
        locked.chmod(stat.S_IRWXU)
    assert r.completeness.count(SkipReason.UNREADABLE_DIRECTORY) == 1
    assert r.completeness.status is Status.PARTIAL
