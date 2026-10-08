"""Repository discovery with self-protection (architecture §4, SR-04, SR-06, SR-16, T-05, T-08, T-22).

Discovery decides which files later stages may analyse. It treats the scan root as hostile:

* Every file and directory is opened **relative to an already-open directory fd** with
  ``O_NOFOLLOW``; directories are re-checked with ``fstat`` (device/inode) against the ``lstat``
  taken during listing. A path can therefore never resolve outside the resolved root, even if a
  directory is swapped for a symlink mid-scan (TOCTOU, MF-54).
* Symlinks are never followed. With ``follow_symlinks`` the link target is only *resolved as a
  path* to report whether it escapes the root; content is never read through a link.
* Only regular files are opened (``O_NONBLOCK``, so a FIFO swapped in after ``lstat`` cannot
  block). FIFOs, sockets and devices are counted and never opened.
* Size is checked from ``lstat`` before open and again from ``fstat``; only
  ``BINARY_SNIFF_BYTES`` are read (to detect binary content). Discovery never reads whole files.
* ``.git/`` is never walked. The only git metadata read is a bounded, validated parse of
  ``.git/index`` and ``.git/HEAD`` (SR-06 carve-out). ``git`` is never executed.
* In a git work tree, **tracked files are scanned regardless of ignore rules** (SR-16).
* Every discovered entry that is not selected is recorded in the completeness ledger with a
  reason. Global caps (file count, entries, depth, total bytes, wall clock) stop discovery and
  make the scan partial.

Discovery returns a structured :class:`DiscoveryResult` and never prints.
"""

from __future__ import annotations

import errno
import hashlib
import os
import stat
import struct
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

from nexvul.core import limits
from nexvul.core.completeness import Completeness, LimitHit, SkipReason
from nexvul.core.sanitize import display_path, display_text

_CLOEXEC: Final = getattr(os, "O_CLOEXEC", 0)
_FILE_FLAGS: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | _CLOEXEC
_DIR_FLAGS: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | _CLOEXEC

#: Built-in exclusions. Applied only to **untracked** content (architecture §4.1).
DEFAULT_EXCLUDED_DIRS: Final = frozenset(
    {"node_modules", ".venv", "venv", "site-packages", "dist", "build", ".tox"}
)

#: Roots that are never scanned and never resolved into (T-08).
_FORBIDDEN_PREFIXES: Final = ("/proc", "/dev", "/sys")


class DiscoveryError(Exception):
    """The scan root itself is unusable (maps to exit code 2). Message is trusted text."""


class Language(StrEnum):
    PYTHON = "python"
    TYPESCRIPT = "typescript"
    TSX = "tsx"
    JAVASCRIPT = "javascript"
    JSX = "jsx"
    JSON = "json"
    YAML = "yaml"
    TOML = "toml"


_EXTENSIONS: Final[dict[str, Language]] = {
    ".py": Language.PYTHON,
    ".ts": Language.TYPESCRIPT,
    ".mts": Language.TYPESCRIPT,
    ".cts": Language.TYPESCRIPT,
    ".tsx": Language.TSX,
    ".js": Language.JAVASCRIPT,
    ".mjs": Language.JAVASCRIPT,
    ".cjs": Language.JAVASCRIPT,
    ".jsx": Language.JSX,
    ".json": Language.JSON,
    ".yaml": Language.YAML,
    ".yml": Language.YAML,
    ".toml": Language.TOML,
}


def detect_language(name: str) -> Language | None:
    """Language from the file name (case-insensitive extension). Content is checked later."""
    dot = name.rfind(".")
    if dot == -1:
        return None
    return _EXTENSIONS.get(name[dot:].lower())


# ============================================================================================
# Exclude-pattern matching (linear in practice, no regex: SR-09)
# ============================================================================================


def _segment_match(pattern: str, text: str) -> bool:
    """Match one path segment with ``*`` and ``?`` (iterative, no backtracking explosion)."""
    p = t = 0
    star = -1
    mark = 0
    while t < len(text):
        if p < len(pattern) and (pattern[p] == "?" or pattern[p] == text[t]):
            p += 1
            t += 1
        elif p < len(pattern) and pattern[p] == "*":
            star = p
            mark = t
            p += 1
        elif star != -1:
            p = star + 1
            mark += 1
            t = mark
        else:
            return False
    while p < len(pattern) and pattern[p] == "*":
        p += 1
    return p == len(pattern)


def _parts_match(pat: Sequence[str], parts: Sequence[str]) -> bool:
    """Match path segments; a ``**`` segment matches zero or more segments."""
    pi = si = 0
    star = -1
    mark = 0
    while si < len(parts):
        if pi < len(pat) and pat[pi] != "**" and _segment_match(pat[pi], parts[si]):
            pi += 1
            si += 1
        elif pi < len(pat) and pat[pi] == "**":
            star = pi
            mark = si
            pi += 1
        elif star != -1:
            pi = star + 1
            mark += 1
            si = mark
        else:
            return False
    while pi < len(pat) and pat[pi] == "**":
        pi += 1
    return pi == len(pat)


def pattern_matches(pattern: str, rel_path: str, *, is_dir: bool = False) -> bool:
    """Does a normalised exclude pattern match a repo-relative POSIX path?

    Semantics (documented for users in step 2):

    * A pattern without ``/`` matches any single path component (``tests`` excludes every
      ``tests`` directory, ``*.min.js`` excludes such files anywhere).
    * A pattern with ``/`` is anchored at the root and also matches everything below a matching
      directory (``agent/tools`` excludes ``agent/tools/x.py``). ``**`` spans directories.
    * A trailing ``/`` restricts the pattern to directories.
    """
    dir_only = pattern.endswith("/")
    pat = pattern.rstrip("/")
    parts = rel_path.split("/")
    if "/" not in pat:
        upto = len(parts) if (is_dir or not dir_only) else len(parts) - 1
        return any(_segment_match(pat, comp) for comp in parts[:upto])
    pat_parts = pat.split("/")
    for k in range(1, len(parts) + 1):
        if k == len(parts) and dir_only and not is_dir:
            break
        if _parts_match(pat_parts, parts[:k]):
            return True
    return False


# ============================================================================================
# Bounded .git/index reader (SR-06 carve-out; the index is hostile input)
# ============================================================================================


class GitIndexError(Exception):
    """The index is malformed or exceeds limits. Message is trusted text."""


class GitEntryKind(StrEnum):
    REGULAR = "regular"
    SYMLINK = "symlink"
    GITLINK = "gitlink"


@dataclass(frozen=True)
class GitIndexEntry:
    path: bytes
    kind: GitEntryKind
    skip_worktree: bool = False


@dataclass(frozen=True)
class GitIndex:
    version: int
    hash_len: int
    entries: tuple[GitIndexEntry, ...]


def _validate_index_path(name: bytes) -> None:
    if not name:
        raise GitIndexError("empty path in index")
    if name.startswith(b"/"):
        raise GitIndexError("absolute path in index")
    for comp in name.split(b"/"):
        if comp in (b"", b".", b".."):
            raise GitIndexError("invalid path component in index")
        if comp.lower() == b".git":
            raise GitIndexError("'.git' component in index")


def _read_varint(data: bytes, pos: int, end: int) -> tuple[int, int]:
    """Git's offset varint (index v4 prefix compression). Bounded to 5 bytes."""
    if pos >= end:
        raise GitIndexError("truncated varint")
    c = data[pos]
    pos += 1
    value = c & 0x7F
    used = 1
    while c & 0x80:
        if pos >= end or used >= 5:
            raise GitIndexError("bad varint")
        c = data[pos]
        pos += 1
        used += 1
        value = ((value + 1) << 7) | (c & 0x7F)
    return value, pos


def _parse_entries(
    data: bytes, version: int, count: int, hash_len: int, max_path: int
) -> tuple[GitIndexEntry, ...]:
    end = len(data) - hash_len
    pos = 12
    prev = b""
    seen: set[bytes] = set()
    out: list[GitIndexEntry] = []
    fixed = 40 + hash_len + 2
    for _ in range(count):
        if pos + fixed > end:
            raise GitIndexError("index truncated")
        (mode,) = struct.unpack_from(">I", data, pos + 24)
        (flags,) = struct.unpack_from(">H", data, pos + 40 + hash_len)
        p = pos + fixed
        skip_worktree = False
        if flags & 0x4000:
            if version < 3 or p + 2 > end:
                raise GitIndexError("bad extended flags")
            (ext,) = struct.unpack_from(">H", data, p)
            skip_worktree = bool(ext & 0x4000)
            p += 2
        if version == 4:
            strip, p = _read_varint(data, p, end)
            if strip > len(prev):
                raise GitIndexError("bad prefix compression")
            nul = data.find(b"\x00", p, min(end, p + max_path + 1))
            if nul == -1:
                raise GitIndexError("unterminated or overlong path")
            name = prev[: len(prev) - strip] + data[p:nul]
            p = nul + 1
        else:
            nul = data.find(b"\x00", p, min(end, p + max_path + 1))
            if nul == -1:
                raise GitIndexError("unterminated or overlong path")
            name = data[p:nul]
            p = pos + ((nul - pos + 8) & ~7)  # 1..8 NUL padding to a multiple of 8
            if p > end:
                raise GitIndexError("index truncated")
        if len(name) > max_path:
            raise GitIndexError("path too long")
        _validate_index_path(name)
        obj_type = (mode >> 12) & 0xF
        if obj_type == 0b1000:
            kind = GitEntryKind.REGULAR
        elif obj_type == 0b1010:
            kind = GitEntryKind.SYMLINK
        elif obj_type == 0b1110:
            kind = GitEntryKind.GITLINK
        else:
            raise GitIndexError("unknown entry mode")
        if name not in seen:  # merge-conflict stages repeat a path
            seen.add(name)
            out.append(GitIndexEntry(name, kind, skip_worktree))
        prev = name
        pos = p
    return tuple(out)


def parse_git_index(
    data: bytes,
    *,
    max_entries: int = limits.MAX_GIT_INDEX_ENTRIES,
    max_path: int = limits.MAX_GIT_PATH_BYTES,
) -> GitIndex:
    """Parse index versions 2-4 (SHA-1 or SHA-256 object format). Pure; raises GitIndexError.

    The object format is inferred from the trailing checksum, so ``.git/config`` is never read.
    """
    if len(data) < 12 + 20:
        raise GitIndexError("index too short")
    if data[:4] != b"DIRC":
        raise GitIndexError("bad index signature")
    version, count = struct.unpack_from(">II", data, 4)
    if version not in (2, 3, 4):
        raise GitIndexError("unsupported index version")
    if count > max_entries:
        raise GitIndexError("too many index entries")
    candidates: list[int] = []
    for hash_len, algo in ((20, "sha1"), (32, "sha256")):
        if len(data) >= 12 + hash_len:
            digest = hashlib.new(algo, data[:-hash_len], usedforsecurity=False).digest()
            if digest == data[-hash_len:]:
                candidates.append(hash_len)
    if not candidates:
        # index.skipHash=true writes an all-zero trailer
        candidates = [h for h in (20, 32) if data[-h:] == b"\x00" * h]
    if not candidates:
        raise GitIndexError("index checksum mismatch")
    last: GitIndexError | None = None
    for hash_len in candidates:
        if count * (40 + hash_len + 3) > len(data):
            last = GitIndexError("entry count exceeds index size")
            continue
        try:
            return GitIndex(
                version, hash_len, _parse_entries(data, version, count, hash_len, max_path)
            )
        except GitIndexError as exc:
            last = exc
    assert last is not None  # noqa: S101 - candidates was non-empty
    raise last


# ============================================================================================
# Result model
# ============================================================================================


class DiscoveryMode(StrEnum):
    GIT = "git"
    DIRECTORY = "directory"


@dataclass(frozen=True)
class DiscoveredFile:
    """One selected file. ``path`` may contain surrogate escapes (non-UTF-8 names)."""

    path: str
    path_bytes: bytes
    display_path: str
    language: Language
    size: int
    device: int
    inode: int
    tracked: bool | None  # None in directory mode


@dataclass(frozen=True)
class DiscoveryOptions:
    max_files: int = limits.DEFAULT_MAX_FILES
    max_file_size: int = limits.DEFAULT_MAX_FILE_SIZE
    exclude: tuple[str, ...] = ()
    follow_symlinks: bool = False
    use_git_index: bool = True
    max_depth: int = limits.MAX_DIR_DEPTH
    max_dir_entries: int = limits.MAX_DIR_ENTRIES
    max_total_bytes: int = limits.MAX_TOTAL_BYTES
    time_budget_seconds: float = limits.DISCOVERY_TIME_BUDGET_SECONDS
    max_git_index_bytes: int = limits.MAX_GIT_INDEX_BYTES
    max_git_index_entries: int = limits.MAX_GIT_INDEX_ENTRIES


@dataclass
class DiscoveryResult:
    root: str
    mode: DiscoveryMode
    files: tuple[DiscoveredFile, ...]
    completeness: Completeness
    git_head: str | None = None
    hardlinked_files: int = 0
    entries_examined: int = 0
    notes: list[str] = field(default_factory=list)  # trusted strings


# ============================================================================================
# Walker
# ============================================================================================


class _Stop(Exception):
    """Internal: a global cap was hit."""


def _is_forbidden(path: str) -> bool:
    return any(path == p or path.startswith(p + "/") for p in _FORBIDDEN_PREFIXES)


def _inside(root: str, path: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def _read_bounded(fd: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = limit
    while remaining > 0:
        chunk = os.read(fd, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class _Walker:
    def __init__(
        self, root: str, root_fd: int, options: DiscoveryOptions, clock: Callable[[], float]
    ) -> None:
        self.root = root
        self.root_fd = root_fd
        self.opt = options
        self.clock = clock
        self.deadline = clock() + options.time_budget_seconds
        self.ledger = Completeness()
        self.selected: dict[bytes, DiscoveredFile] = {}
        self.visited: set[bytes] = set()
        self.tracked: dict[bytes, GitIndexEntry] = {}
        self.gitlinks: set[bytes] = set()
        self.mode = DiscoveryMode.DIRECTORY
        self.git_head: str | None = None
        self.total_bytes = 0
        self.entries = 0
        self.hardlinks = 0
        self.notes: list[str] = []

    # -- helpers -----------------------------------------------------------------------------

    def _note(self, text: str) -> None:
        if text not in self.notes:
            self.notes.append(text)
        self.ledger.add_note(text)

    def _skip(self, rel: str, reason: SkipReason, detail: str = "") -> None:
        self.ledger.record_skip(display_path(rel), reason, detail)

    def _limit(self, limit: LimitHit) -> None:
        self.ledger.record_limit(limit)
        raise _Stop

    def _tick(self) -> None:
        self.entries += 1
        if self.entries > self.opt.max_dir_entries:
            self._limit(LimitHit.MAX_DIR_ENTRIES)
        if self.entries % 256 == 0 and self.clock() > self.deadline:
            self._limit(LimitHit.DISCOVERY_TIME_BUDGET)

    def _excluded(self, rel: str, *, is_dir: bool) -> bool:
        return any(pattern_matches(p, rel, is_dir=is_dir) for p in self.opt.exclude)

    def _open_dir_chain(self, comps: Sequence[str], expect: tuple[int, int] | None) -> int:
        """Open ``root/comps...`` one component at a time with O_NOFOLLOW. Caller closes."""
        fd = os.dup(self.root_fd)
        try:
            for comp in comps:
                nfd = os.open(comp, _DIR_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = nfd
            if expect is not None:
                st = os.fstat(fd)
                if (st.st_dev, st.st_ino) != expect:
                    raise OSError(errno.ESTALE, "directory changed during scan")
        except BaseException:
            os.close(fd)
            raise
        return fd

    # -- git metadata ------------------------------------------------------------------------

    def load_git(self) -> None:
        if not self.opt.use_git_index:
            return
        try:
            st = os.stat(".git", dir_fd=self.root_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError:
            self._note("git_metadata_unreadable")
            return
        git_fd: int | None = None
        try:
            if stat.S_ISDIR(st.st_mode):
                git_fd = os.open(".git", _DIR_FLAGS, dir_fd=self.root_fd)
            elif stat.S_ISREG(st.st_mode):
                git_fd = self._open_gitdir_pointer()
            else:
                self._note("git_dir_is_symlink_or_special: scanned as plain directory")
                return
            if git_fd is None:
                return
            self._read_index(git_fd)
            self._read_head(git_fd)
        except OSError:
            self._note("git_metadata_unreadable")
        finally:
            if git_fd is not None:
                os.close(git_fd)

    def _open_gitdir_pointer(self) -> int | None:
        fd = os.open(".git", _FILE_FLAGS, dir_fd=self.root_fd)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None
            data = _read_bounded(fd, limits.MAX_GIT_SMALL_FILE_BYTES + 1)
        finally:
            os.close(fd)
        text = data.decode("utf-8", "replace").strip() if len(data) <= 1024 else ""
        if not text.startswith("gitdir:") or "\n" in text or "\x00" in text:
            self._note("gitdir_pointer_invalid: scanned as plain directory")
            return None
        target = text[len("gitdir:") :].strip()
        resolved = os.path.realpath(os.path.join(self.root, target))
        if not _inside(self.root, resolved) or resolved == self.root:
            self._note("gitdir_outside_root: scanned as plain directory")
            return None
        rel = os.path.relpath(resolved, self.root)
        try:
            return self._open_dir_chain(rel.split(os.sep), None)
        except OSError:
            self._note("gitdir_pointer_unreadable: scanned as plain directory")
            return None

    def _read_index(self, git_fd: int) -> None:
        try:
            fd = os.open("index", _FILE_FLAGS, dir_fd=git_fd)
        except FileNotFoundError:
            self.mode = DiscoveryMode.GIT
            self._note("git_index_absent: no tracked files")
            return
        except OSError:
            self._index_failed("index could not be opened")
            return
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                self._index_failed("index is not a regular file")
                return
            if st.st_size > self.opt.max_git_index_bytes:
                self._index_failed("index larger than limit")
                return
            data = _read_bounded(fd, self.opt.max_git_index_bytes + 1)
        finally:
            os.close(fd)
        if len(data) > self.opt.max_git_index_bytes:
            self._index_failed("index larger than limit")
            return
        try:
            index = parse_git_index(data, max_entries=self.opt.max_git_index_entries)
        except GitIndexError as exc:
            self._index_failed(str(exc))
            return
        self.mode = DiscoveryMode.GIT
        for entry in index.entries:
            if entry.kind is GitEntryKind.GITLINK:
                self.gitlinks.add(entry.path)
            else:
                self.tracked[entry.path] = entry

    def _index_failed(self, why: str) -> None:
        # Architecture §4.2: fall back to directory mode and mark the scan partial.
        self.ledger.record_limit(LimitHit.GIT_INDEX_UNREADABLE)
        self._note(f"git_index_unreadable: {why}; scanned as plain directory")

    def _read_head(self, git_fd: int) -> None:
        try:
            fd = os.open("HEAD", _FILE_FLAGS, dir_fd=git_fd)
        except OSError:
            return
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return
            data = _read_bounded(fd, limits.MAX_GIT_SMALL_FILE_BYTES + 1)
        finally:
            os.close(fd)
        if len(data) > limits.MAX_GIT_SMALL_FILE_BYTES:
            return
        text = data.decode("utf-8", "replace").strip()
        if text.startswith("ref: "):
            self.git_head = display_text(text[5:], max_chars=200)
        elif len(text) in (40, 64) and all(c in "0123456789abcdef" for c in text):
            self.git_head = text

    # -- walk --------------------------------------------------------------------------------

    def walk(self) -> None:
        stack: list[tuple[tuple[str, ...], tuple[int, int] | None]] = [((), None)]
        while stack:
            comps, expect = stack.pop()
            rel_dir = "/".join(comps)
            try:
                dir_fd = self._open_dir_chain(comps, expect)
            except OSError as exc:
                reason = (
                    SkipReason.CHANGED_DURING_SCAN
                    if exc.errno in (errno.ELOOP, errno.ENOTDIR, errno.ESTALE, errno.ENOENT)
                    else SkipReason.UNREADABLE_DIRECTORY
                )
                self._skip(rel_dir or ".", reason, "directory")
                continue
            try:
                children = self._list_dir(dir_fd, rel_dir)
                subdirs: list[tuple[tuple[str, ...], tuple[int, int]]] = []
                for name, st in children:
                    sub = self._entry(dir_fd, comps, name, st)
                    if sub is not None:
                        subdirs.append(sub)
                stack.extend(reversed(subdirs))
            finally:
                os.close(dir_fd)

    def _list_dir(self, dir_fd: int, rel_dir: str) -> list[tuple[str, os.stat_result]]:
        out: list[tuple[str, os.stat_result]] = []
        try:
            with os.scandir(dir_fd) as it:
                for entry in it:
                    self._tick()
                    try:
                        out.append((entry.name, entry.stat(follow_symlinks=False)))
                    except OSError:
                        rel = f"{rel_dir}/{entry.name}" if rel_dir else entry.name
                        self._skip(rel, SkipReason.CHANGED_DURING_SCAN, "lstat failed")
        except OSError:
            self._skip(rel_dir or ".", SkipReason.UNREADABLE_DIRECTORY, "directory listing")
        out.sort(key=lambda item: os.fsencode(item[0]))
        return out

    def _entry(
        self, dir_fd: int, comps: tuple[str, ...], name: str, st: os.stat_result
    ) -> tuple[tuple[str, ...], tuple[int, int]] | None:
        rel = "/".join((*comps, name))
        rel_b = os.fsencode(rel)
        mode = st.st_mode
        if name.lower() == ".git":  # case-insensitive filesystems treat .GIT as .git
            self._skip(rel, SkipReason.VCS_METADATA)
            return None
        if stat.S_ISDIR(mode):
            if rel_b in self.gitlinks:
                self.visited.add(rel_b)
                self._skip(rel, SkipReason.SUBMODULE_NOT_SCANNED, "submodules are not traversed")
                return None
            if len(comps) + 1 > self.opt.max_depth:
                self._skip(rel, SkipReason.MAX_DEPTH, f"deeper than {self.opt.max_depth}")
                self.ledger.record_limit(LimitHit.MAX_DEPTH)
                return None
            if self._excluded(rel, is_dir=True):
                self._skip(rel, SkipReason.EXCLUDED_BY_CONFIG, "directory")
                return None
            if name in DEFAULT_EXCLUDED_DIRS:
                self._skip(rel, SkipReason.DEFAULT_EXCLUDED_DIR, "untracked content not scanned")
                return None
            if not comps and name == ".nexvul":
                self._note("nexvul_dir_present: scanned as ordinary content, never as config")
            return ((*comps, name), (st.st_dev, st.st_ino))
        self.visited.add(rel_b)
        if stat.S_ISLNK(mode):
            self._symlink(dir_fd, comps, name, rel)
        elif stat.S_ISREG(mode):
            self._consider_file(dir_fd, comps, name, st, tracked=rel_b in self.tracked)
        else:
            self._skip(rel, SkipReason.SPECIAL_FILE, _special_kind(mode))
        return None

    def _symlink(self, dir_fd: int, comps: tuple[str, ...], name: str, rel: str) -> None:
        if not self.opt.follow_symlinks:
            self._skip(rel, SkipReason.SYMLINK_NOT_FOLLOWED)
            return
        # Resolve the link as a *path* only; never open through it.
        try:
            target = os.readlink(name, dir_fd=dir_fd)
        except OSError:
            self._skip(rel, SkipReason.CHANGED_DURING_SCAN, "readlink failed")
            return
        resolved = os.path.realpath(os.path.join(self.root, *comps, target))
        if _is_forbidden(resolved) or not _inside(self.root, resolved):
            self._skip(rel, SkipReason.SYMLINK_ESCAPES_ROOT, "target outside scan root")
        else:
            self._skip(rel, SkipReason.SYMLINK_NOT_FOLLOWED, "target inside root; scanned there")

    def _consider_file(
        self,
        dir_fd: int,
        comps: tuple[str, ...],
        name: str,
        st: os.stat_result,
        *,
        tracked: bool,
    ) -> None:
        rel = "/".join((*comps, name))
        language = detect_language(name)
        if language is None:
            self._skip(rel, SkipReason.UNSUPPORTED_FILE_TYPE)
            return
        if self._excluded(rel, is_dir=False):
            self._skip(rel, SkipReason.EXCLUDED_BY_CONFIG)
            return
        if st.st_size > self.opt.max_file_size:
            self._skip(rel, SkipReason.MAX_FILE_SIZE, f"{st.st_size} > {self.opt.max_file_size}")
            return
        if len(self.selected) >= self.opt.max_files:
            self._skip(rel, SkipReason.MAX_FILES, f"limit {self.opt.max_files}")
            self._limit(LimitHit.MAX_FILES)
        if self.total_bytes + st.st_size > self.opt.max_total_bytes:
            self._skip(rel, SkipReason.MAX_TOTAL_BYTES, f"limit {self.opt.max_total_bytes}")
            self._limit(LimitHit.MAX_TOTAL_BYTES)
        try:
            fd = os.open(name, _FILE_FLAGS, dir_fd=dir_fd)
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.ENOENT, errno.EMLINK, errno.ENXIO):
                self._skip(rel, SkipReason.CHANGED_DURING_SCAN, "changed before open")
            else:
                self._skip(rel, SkipReason.OPEN_FAILED, errno.errorcode.get(exc.errno or 0, ""))
            return
        try:
            fst = os.fstat(fd)
            if not stat.S_ISREG(fst.st_mode) or (fst.st_dev, fst.st_ino) != (
                st.st_dev,
                st.st_ino,
            ):
                self._skip(rel, SkipReason.CHANGED_DURING_SCAN, "changed after lstat")
                return
            if fst.st_size > self.opt.max_file_size:
                self._skip(
                    rel, SkipReason.MAX_FILE_SIZE, f"{fst.st_size} > {self.opt.max_file_size}"
                )
                return
            head = _read_bounded(fd, min(limits.BINARY_SNIFF_BYTES, fst.st_size))
        except OSError:
            self._skip(rel, SkipReason.OPEN_FAILED, "read failed")
            return
        finally:
            os.close(fd)
        if b"\x00" in head:
            self._skip(rel, SkipReason.BINARY, "NUL byte in leading content")
            return
        if fst.st_nlink > 1:
            self.hardlinks += 1
        rel_b = os.fsencode(rel)
        self.total_bytes += fst.st_size
        self.selected[rel_b] = DiscoveredFile(
            path=rel,
            path_bytes=rel_b,
            display_path=display_path(rel),
            language=language,
            size=fst.st_size,
            device=fst.st_dev,
            inode=fst.st_ino,
            tracked=tracked if self.mode is DiscoveryMode.GIT else None,
        )

    # -- tracked files not reached by the walk (SR-16) ---------------------------------------

    def tracked_pass(self) -> None:
        pending: Iterable[bytes] = sorted(set(self.tracked) | self.gitlinks)
        for path_b in pending:
            if path_b in self.visited or path_b in self.selected:
                continue
            self._tick()
            rel = os.fsdecode(path_b)
            if path_b in self.gitlinks:
                self._skip(rel, SkipReason.SUBMODULE_NOT_SCANNED, "submodules are not traversed")
                continue
            comps = rel.split("/")
            if len(comps) - 1 > self.opt.max_depth:
                self._skip(rel, SkipReason.MAX_DEPTH, f"deeper than {self.opt.max_depth}")
                self.ledger.record_limit(LimitHit.MAX_DEPTH)
                continue
            if self._excluded(rel, is_dir=False):
                self._skip(rel, SkipReason.EXCLUDED_BY_CONFIG)
                continue
            try:
                dir_fd = self._open_dir_chain(comps[:-1], None)
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    self._skip(rel, SkipReason.SYMLINK_NOT_FOLLOWED, "parent is not a directory")
                elif exc.errno == errno.ENOENT:
                    self._skip(rel, SkipReason.TRACKED_MISSING_ON_DISK)
                else:
                    self._skip(rel, SkipReason.UNREADABLE_DIRECTORY, "parent directory")
                continue
            try:
                try:
                    st = os.stat(comps[-1], dir_fd=dir_fd, follow_symlinks=False)
                except FileNotFoundError:
                    self._skip(rel, SkipReason.TRACKED_MISSING_ON_DISK)
                    continue
                except OSError:
                    self._skip(rel, SkipReason.OPEN_FAILED, "lstat failed")
                    continue
                self.visited.add(path_b)
                if stat.S_ISLNK(st.st_mode):
                    self._symlink(dir_fd, tuple(comps[:-1]), comps[-1], rel)
                elif stat.S_ISREG(st.st_mode):
                    self._consider_file(dir_fd, tuple(comps[:-1]), comps[-1], st, tracked=True)
                elif stat.S_ISDIR(st.st_mode):
                    self._skip(rel, SkipReason.TRACKED_MISSING_ON_DISK, "is now a directory")
                else:
                    self._skip(rel, SkipReason.SPECIAL_FILE, _special_kind(st.st_mode))
            finally:
                os.close(dir_fd)


def _special_kind(mode: int) -> str:
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISCHR(mode):
        return "character device"
    if stat.S_ISBLK(mode):
        return "block device"
    return "unknown file type"


def discover(
    root: str | os.PathLike[str],
    options: DiscoveryOptions | None = None,
    *,
    clock: Callable[[], float] = time.monotonic,
) -> DiscoveryResult:
    """Discover analysable files under ``root``. Never prints, never executes anything.

    Raises :class:`DiscoveryError` only when the root itself cannot be scanned.
    """
    opt = options or DiscoveryOptions()
    real = os.path.realpath(os.fspath(root))
    if _is_forbidden(real):
        raise DiscoveryError("refusing to scan a system pseudo-filesystem")
    try:
        root_fd = os.open(real, os.O_RDONLY | os.O_DIRECTORY | _CLOEXEC)
    except FileNotFoundError:
        raise DiscoveryError("scan root does not exist") from None
    except NotADirectoryError:
        raise DiscoveryError("scan root is not a directory") from None
    except OSError:
        raise DiscoveryError("scan root could not be opened") from None
    try:
        walker = _Walker(real, root_fd, opt, clock)
        try:
            walker.load_git()
            walker.walk()
            if walker.mode is DiscoveryMode.GIT:
                walker.tracked_pass()
        except _Stop:
            pass
        files = tuple(walker.selected[k] for k in sorted(walker.selected))
        return DiscoveryResult(
            root=real,
            mode=walker.mode,
            files=files,
            completeness=walker.ledger,
            git_head=walker.git_head,
            hardlinked_files=walker.hardlinks,
            entries_examined=walker.entries,
            notes=walker.notes,
        )
    finally:
        os.close(root_fd)
