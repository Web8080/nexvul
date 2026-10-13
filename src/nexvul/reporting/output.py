"""Safe report files (architecture §2.3, SR-07, SR-14, T-09, T-14; screen T22).

Output paths come only from the trusted CLI (``--output``); repository config can never set one
(architecture §3.2). Even so, the path is checked before anything is scanned:

* never inside a ``.git`` directory, never through a symbolic link that lives inside the scan
  root, never onto a symbolic link (``--force`` does not change these);
* a path inside the scan root is refused unless the trusted CLI gave it explicitly;
* an existing file is overwritten only when it is a nexvul report of the same format, or with
  ``--force``;
* the write is atomic: a new temporary file is created next to the target with
  ``O_CREAT | O_EXCL | O_NOFOLLOW`` relative to an open directory descriptor, written, synced and
  renamed over the target. An interrupted scan leaves any previous file untouched (T20).
"""

from __future__ import annotations

import contextlib
import os
import secrets
import stat
from dataclasses import dataclass

from nexvul.core.sanitize import display_path
from nexvul.reporting.json_report import is_nexvul_report

_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | _CLOEXEC
_CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | _CLOEXEC
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | _CLOEXEC
_HEAD_BYTES = 256


class OutputRefusedError(Exception):
    """The output path is not acceptable (exit 2, nothing scanned). Message is display-safe.

    ``hint`` is an optional second line (for example how to use ``--force``).
    """

    def __init__(self, message: str, hint: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint


@dataclass(frozen=True)
class OutputTarget:
    directory: str  # real path of the containing directory
    name: str
    shown: str  # display-safe form of the path as given


def _inside(root: str, path: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def _is_nexvul_file(head: bytes, fmt: str) -> bool:
    if fmt == "json":
        return is_nexvul_report(head)
    return head.startswith(b"nexvul ")


def prepare_output(
    path: str, *, scan_root: str, explicit: bool, force: bool, fmt: str
) -> OutputTarget:
    """Validate an output path before the scan starts. Raises :class:`OutputRefusedError`."""
    shown = display_path(path)
    if not path or "\x00" in path:
        raise OutputRefusedError(
            "refusing to write the report: the output path is empty or invalid."
        )
    absolute = os.path.abspath(path)
    parent, name = os.path.split(absolute)
    if name in ("", ".", ".."):
        raise OutputRefusedError(f"refusing to write {shown}: it names a directory.")
    real_parent = os.path.realpath(parent)
    if not os.path.isdir(real_parent):
        raise OutputRefusedError(f"refusing to write {shown}: its directory does not exist.")
    real_root = os.path.realpath(scan_root)
    target = os.path.join(real_parent, name)

    # Any symbolic link on the way that itself lives inside the scan root was put there by the
    # scanned repository: refuse (T-09). Links outside the root (e.g. macOS /var) are the user's.
    probe = parent
    while True:
        if os.path.islink(probe) and _inside(real_root, os.path.realpath(os.path.dirname(probe))):
            raise OutputRefusedError(
                f"refusing to write {shown}: the path goes through a symbolic link inside the "
                "scanned directory.",
                "Choose an output path outside the scanned tree. --force does not apply.",
            )
        up = os.path.dirname(probe)
        if up == probe:
            break
        probe = up

    if _inside(real_root, target):
        rel = os.path.relpath(target, real_root)
        if any(part.lower() == ".git" for part in rel.split(os.sep)):
            raise OutputRefusedError(
                f"refusing to write {shown}: it is inside .git/.", "--force does not apply."
            )
        if not explicit:
            raise OutputRefusedError(
                f"refusing to write {shown}: it is inside the scanned directory.",
                "Pass the path with --output to write it there.",
            )

    try:
        st = os.lstat(target)
    except FileNotFoundError:
        return OutputTarget(real_parent, name, shown)
    if stat.S_ISLNK(st.st_mode):
        raise OutputRefusedError(
            f"refusing to write {shown}: it is a symbolic link.",
            "Choose an output path that is a regular file. --force does not apply.",
        )
    if not stat.S_ISREG(st.st_mode):
        raise OutputRefusedError(
            f"refusing to write {shown}: it is not a regular file.", "--force does not apply."
        )
    if not force:
        head = b""
        with contextlib.suppress(OSError):
            fd = os.open(target, _READ_FLAGS)
            try:
                head = os.read(fd, _HEAD_BYTES)
            finally:
                os.close(fd)
        if not _is_nexvul_file(head, fmt):
            raise OutputRefusedError(
                f"refusing to overwrite {shown}: it is not a nexvul report.",
                "Use --force to overwrite it.",
            )
    return OutputTarget(real_parent, name, shown)


def write_output(target: OutputTarget, data: bytes) -> None:
    """Atomically replace ``target`` with ``data`` (mode 0644, no symlink followed)."""
    dir_fd = os.open(target.directory, _DIR_FLAGS)
    tmp = f".{target.name}.nexvul-tmp-{secrets.token_hex(6)}"
    try:
        fd = os.open(tmp, _CREATE_FLAGS, 0o644, dir_fd=dir_fd)
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            st = os.lstat(target.name, dir_fd=dir_fd)
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISLNK(st.st_mode):
                raise OutputRefusedError(
                    f"refusing to write {target.shown}: it became a symbolic link."
                )
        os.replace(tmp, target.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp, dir_fd=dir_fd)
        raise
    finally:
        os.close(dir_fd)
