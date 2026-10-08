"""Builders for hostile test inputs, created at test time inside ``tmp_path`` only.

Nothing built here is committed to the repository (malicious-input plan, Conventions). Canary
payloads only write a marker into ``$NEXVUL_CANARY_DIR``: no network, nothing destructive.
"""

from __future__ import annotations

import hashlib
import os
import struct
from collections.abc import Iterable, Mapping
from pathlib import Path

MODE_REGULAR = 0o100644
MODE_SYMLINK = 0o120000
MODE_GITLINK = 0o160000


def canary_source(mf_id: str) -> str:
    """Python source that creates ``$NEXVUL_CANARY_DIR/<mf_id>`` if it is ever executed."""
    return (
        "import os, pathlib\n"
        "_d = os.environ.get('NEXVUL_CANARY_DIR')\n"
        "if _d:\n"
        f"    (pathlib.Path(_d) / {mf_id!r}).write_text('fired')\n"
    )


def assert_no_canary(canary: Path) -> None:
    fired = sorted(p.name for p in canary.iterdir())
    assert fired == [], f"execution canary fired: {fired}"


def write_tree(root: Path, files: Mapping[str, str | bytes]) -> None:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")


def is_case_sensitive(directory: Path) -> bool:
    probe = directory / "CaseProbe.tmp"
    probe.write_text("x")
    try:
        return not (directory / "caseprobe.tmp").exists()
    finally:
        probe.unlink()


def make_non_utf8_name(directory: Path, name: bytes) -> bool:
    """Try to create a file with a non-UTF-8 byte name. False if the FS refuses (macOS APFS)."""
    try:
        fd = os.open(os.path.join(os.fsencode(directory), name), os.O_WRONLY | os.O_CREAT, 0o644)
    except OSError:
        return False
    os.write(fd, b"x = 1\n")
    os.close(fd)
    return True


def _git_varint(value: int) -> bytes:
    out = [value & 0x7F]
    value >>= 7
    while value:
        value -= 1
        out.append(0x80 | (value & 0x7F))
        value >>= 7
    return bytes(reversed(out))


def build_git_index(
    entries: Iterable[tuple[bytes, int]],
    *,
    version: int = 2,
    hash_len: int = 20,
    skip_worktree: Iterable[bytes] = (),
    count_override: int | None = None,
    trailer: str = "valid",
    v4_strip_override: int | None = None,
) -> bytes:
    """Build a git index (v2/v3/v4, SHA-1 or SHA-256 trailer) from ``(path, mode)`` pairs."""
    items = list(entries)
    skip = set(skip_worktree)
    body = bytearray(b"DIRC")
    body += struct.pack(">II", version, len(items) if count_override is None else count_override)
    prev = b""
    for name, mode in items:
        extended = name in skip
        start = len(body)
        body += b"\x00" * 24  # ctime, mtime, dev, ino
        body += struct.pack(">I", mode)
        body += b"\x00" * 12  # uid, gid, size
        body += (
            hashlib.sha1(name, usedforsecurity=False).digest()[:hash_len].ljust(hash_len, b"\x00")
        )
        flags = min(len(name), 0xFFF) | (0x4000 if extended else 0)
        body += struct.pack(">H", flags)
        if extended:
            body += struct.pack(">H", 0x4000)
        if version == 4:
            common = 0
            while common < min(len(prev), len(name)) and prev[common] == name[common]:
                common += 1
            strip = len(prev) - common if v4_strip_override is None else v4_strip_override
            body += _git_varint(strip) + name[common:] + b"\x00"
        else:
            body += name
            entry_len = len(body) - start
            body += b"\x00" * (8 - entry_len % 8)
        prev = name
    if trailer == "valid":
        algo = "sha1" if hash_len == 20 else "sha256"
        body += hashlib.new(algo, bytes(body), usedforsecurity=False).digest()
    elif trailer == "zero":
        body += b"\x00" * hash_len
    else:
        body += b"\xff" * hash_len
    return bytes(body)


def make_git_repo(root: Path, index: bytes, head: bytes = b"ref: refs/heads/main\n") -> None:
    git = root / ".git"
    git.mkdir(parents=True, exist_ok=True)
    (git / "index").write_bytes(index)
    (git / "HEAD").write_bytes(head)
