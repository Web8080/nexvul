"""Completeness ledger and exit codes (threat model §7, architecture §12.3-12.4, SR-18/19).

The ledger is trusted accounting kept by the supervisor. It is never derived from rule output.
A partial scan must never be presentable as clean (DEC-0004 §3).

Exit codes (OD-06, DEC-0007; public contract once released)::

    0   complete, no unsuppressed finding at/above fail_on
    1   complete, >= 1 unsuppressed finding at/above fail_on
    2   usage or configuration error (nothing scanned)
    3   partial scan (regardless of findings)
    4   internal error / scan failed / startup guard tripped
    130 interrupted (SIGINT), 143 terminated (SIGTERM)

Precedence when several apply: 2 > 4 > 3 > 1 > 0.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from enum import Enum, IntEnum, StrEnum
from typing import Any

from nexvul.core.limits import MAX_SKIPPED_PATHS_LISTED


class ExitCode(IntEnum):
    OK = 0
    FINDINGS = 1
    USAGE_ERROR = 2
    PARTIAL = 3
    INTERNAL_ERROR = 4
    INTERRUPTED = 130
    TERMINATED = 143


class Status(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class Impact(Enum):
    """What a skip reason does to completeness status."""

    PARTIAL = "partial"  # in-scope content was not analysed: scan is partial
    COUNTED = "counted"  # deliberate, policy-driven exclusion: counted, not partial
    INFO = "info"  # out of scope by design (not a source file, VCS metadata): counted only


class SkipReason(StrEnum):
    """Reason codes for every discovered entry that is not analysed (architecture §12.3)."""

    # --- per-file limits / content (partial) ---
    MAX_FILE_SIZE = "max_file_size"
    BINARY = "binary"
    CHANGED_DURING_SCAN = "changed_during_scan"  # TOCTOU: lstat/fstat mismatch, O_NOFOLLOW hit
    OPEN_FAILED = "open_failed"
    TRACKED_MISSING_ON_DISK = "tracked_missing_on_disk"
    # --- global limits (partial) ---
    MAX_DEPTH = "max_depth"
    MAX_FILES = "max_files"
    MAX_TOTAL_BYTES = "max_total_bytes"
    UNREADABLE_DIRECTORY = "unreadable_directory"
    # --- parse/analysis stage (partial; recorded by later phases) ---
    PARSE_ERROR = "parse_error"
    PARSER_CRASHED = "parser_crashed"
    TIMEOUT = "timeout"
    MEMORY_LIMIT = "memory_limit"
    MAX_NESTING = "max_nesting"
    MAX_AST_NODES = "max_ast_nodes"
    NON_UTF8_UNDECODABLE = "non_utf8_undecodable"
    SYNTAX_UNSUPPORTED_BY_RUNTIME = "syntax_unsupported_by_runtime"
    SUBMODULE_NOT_SCANNED = "submodule_not_scanned"
    # --- policy (counted, not partial) ---
    SYMLINK_NOT_FOLLOWED = "symlink_not_followed"
    SYMLINK_ESCAPES_ROOT = "symlink_escapes_root"
    SPECIAL_FILE = "special_file"
    EXCLUDED_BY_CONFIG = "excluded_by_config"
    DEFAULT_EXCLUDED_DIR = "default_excluded_dir"
    # --- out of scope (info) ---
    UNSUPPORTED_FILE_TYPE = "unsupported_file_type"
    VCS_METADATA = "vcs_metadata"


_IMPACT: dict[SkipReason, Impact] = {
    SkipReason.MAX_FILE_SIZE: Impact.PARTIAL,
    SkipReason.BINARY: Impact.PARTIAL,
    SkipReason.CHANGED_DURING_SCAN: Impact.PARTIAL,
    SkipReason.OPEN_FAILED: Impact.PARTIAL,
    SkipReason.TRACKED_MISSING_ON_DISK: Impact.PARTIAL,
    SkipReason.MAX_DEPTH: Impact.PARTIAL,
    SkipReason.MAX_FILES: Impact.PARTIAL,
    SkipReason.MAX_TOTAL_BYTES: Impact.PARTIAL,
    SkipReason.UNREADABLE_DIRECTORY: Impact.PARTIAL,
    SkipReason.PARSE_ERROR: Impact.PARTIAL,
    SkipReason.PARSER_CRASHED: Impact.PARTIAL,
    SkipReason.TIMEOUT: Impact.PARTIAL,
    SkipReason.MEMORY_LIMIT: Impact.PARTIAL,
    SkipReason.MAX_NESTING: Impact.PARTIAL,
    SkipReason.MAX_AST_NODES: Impact.PARTIAL,
    SkipReason.NON_UTF8_UNDECODABLE: Impact.PARTIAL,
    SkipReason.SYNTAX_UNSUPPORTED_BY_RUNTIME: Impact.PARTIAL,
    SkipReason.SUBMODULE_NOT_SCANNED: Impact.PARTIAL,
    SkipReason.SYMLINK_NOT_FOLLOWED: Impact.COUNTED,
    SkipReason.SYMLINK_ESCAPES_ROOT: Impact.COUNTED,
    SkipReason.SPECIAL_FILE: Impact.COUNTED,
    SkipReason.EXCLUDED_BY_CONFIG: Impact.COUNTED,
    SkipReason.DEFAULT_EXCLUDED_DIR: Impact.COUNTED,
    SkipReason.UNSUPPORTED_FILE_TYPE: Impact.INFO,
    SkipReason.VCS_METADATA: Impact.INFO,
}

#: Reasons that are failures of the parse stage (counted as "failed", not "skipped").
FAILED_REASONS = frozenset(
    {
        SkipReason.PARSE_ERROR,
        SkipReason.PARSER_CRASHED,
        SkipReason.MEMORY_LIMIT,
        SkipReason.NON_UTF8_UNDECODABLE,
        SkipReason.SYNTAX_UNSUPPORTED_BY_RUNTIME,
    }
)


def impact_of(reason: SkipReason) -> Impact:
    return _IMPACT[reason]


class LimitHit(StrEnum):
    """Global caps that stop discovery or analysis early (always partial)."""

    MAX_FILES = "max_files"
    MAX_DIR_ENTRIES = "max_dir_entries"
    MAX_TOTAL_BYTES = "max_total_bytes"
    MAX_DEPTH = "max_depth"
    DISCOVERY_TIME_BUDGET = "discovery_time_budget"
    GIT_INDEX_UNREADABLE = "git_index_unreadable"


@dataclass(frozen=True)
class SkippedEntry:
    path: str  # sanitised display form only; never raw untrusted text
    reason: SkipReason
    detail: str = ""  # trusted text composed by nexvul (sizes, limit names), never file content


@dataclass
class Completeness:
    """Mutable ledger owned by the supervisor. Not thread-safe; one per scan."""

    files_scanned: int = 0
    files_failed: int = 0
    files_timed_out: int = 0
    skipped_by_reason: Counter[SkipReason] = field(default_factory=Counter)
    skipped: list[SkippedEntry] = field(default_factory=list)
    skipped_list_truncated: int = 0
    limits_hit: list[LimitHit] = field(default_factory=list)
    internal_error: bool = False
    notes: list[str] = field(default_factory=list)  # trusted strings only

    # -- recording ---------------------------------------------------------------------------

    def record_scanned(self) -> None:
        self.files_scanned += 1

    def record_skip(self, path: str, reason: SkipReason, detail: str = "") -> None:
        """Record one entry that was discovered but not analysed. ``path`` must be sanitised."""
        self.skipped_by_reason[reason] += 1
        if reason is SkipReason.TIMEOUT:
            self.files_timed_out += 1
        elif reason in FAILED_REASONS:
            self.files_failed += 1
        if len(self.skipped) < MAX_SKIPPED_PATHS_LISTED:
            self.skipped.append(SkippedEntry(path=path, reason=reason, detail=detail))
        else:
            self.skipped_list_truncated += 1

    def record_limit(self, limit: LimitHit) -> None:
        if limit not in self.limits_hit:
            self.limits_hit.append(limit)

    def record_internal_error(self) -> None:
        self.internal_error = True

    def add_note(self, note: str) -> None:
        if note not in self.notes:
            self.notes.append(note)

    # -- derived -----------------------------------------------------------------------------

    def count(self, reason: SkipReason) -> int:
        return self.skipped_by_reason.get(reason, 0)

    @property
    def files_not_analysed_partial(self) -> int:
        """Entries whose omission makes the scan partial (N in 'N of M files not analysed')."""
        return sum(n for r, n in self.skipped_by_reason.items() if _IMPACT[r] is Impact.PARTIAL)

    @property
    def files_skipped(self) -> int:
        """Skipped entries that are neither parse failures nor timeouts (any impact)."""
        return sum(
            n
            for r, n in self.skipped_by_reason.items()
            if r not in FAILED_REASONS and r is not SkipReason.TIMEOUT
        )

    @property
    def status(self) -> Status:
        if self.internal_error:
            return Status.FAILED
        if self.limits_hit or self.files_not_analysed_partial > 0:
            return Status.PARTIAL
        return Status.COMPLETE

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready view. Keys are stable; values contain only sanitised or trusted text."""
        return {
            "status": self.status.value,
            "files_scanned": self.files_scanned,
            "files_failed": self.files_failed,
            "files_timed_out": self.files_timed_out,
            "files_skipped": self.files_skipped,
            "skipped_by_reason": {r.value: n for r, n in sorted(self.skipped_by_reason.items())},
            "skipped": [
                {"path": s.path, "reason": s.reason.value, "detail": s.detail} for s in self.skipped
            ],
            "skipped_list_truncated": self.skipped_list_truncated,
            "limits_hit": [lim.value for lim in self.limits_hit],
            "notes": list(self.notes),
        }


def resolve_exit_code(
    *,
    usage_error: bool = False,
    internal_error: bool = False,
    partial: bool = False,
    findings_over_threshold: bool = False,
    partial_is_warning: bool = False,
) -> ExitCode:
    """Apply the OD-06 precedence 2 > 4 > 3 > 1 > 0.

    ``partial_is_warning`` is the trusted ``--partial=warn`` downgrade (architecture §12.4): it may
    only be set from CLI flags or user config, never from repository config. The caller must
    record that the downgrade was used.
    """
    if usage_error:
        return ExitCode.USAGE_ERROR
    if internal_error:
        return ExitCode.INTERNAL_ERROR
    if partial and not partial_is_warning:
        return ExitCode.PARTIAL
    if findings_over_threshold:
        return ExitCode.FINDINGS
    return ExitCode.OK


def exit_code_for(
    ledger: Completeness,
    *,
    findings_over_threshold: bool,
    partial_is_warning: bool = False,
) -> ExitCode:
    """Exit code for a scan that ran (usage errors are resolved before a ledger exists)."""
    status = ledger.status
    return resolve_exit_code(
        internal_error=status is Status.FAILED,
        partial=status is Status.PARTIAL,
        findings_over_threshold=findings_over_threshold,
        partial_is_warning=partial_is_warning,
    )
