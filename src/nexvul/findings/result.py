"""Scan result: findings + completeness + config provenance + versions (architecture §12, SR-27).

A :class:`ScanResult` is a frozen, fully display-safe snapshot. Reporters render it; they never
recompute status or exit codes. Every string field is either trusted text composed by nexvul or
was sanitised when the result was assembled (``core/scan.py``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from nexvul.core.completeness import RuleFailure, SkippedEntry, SkipReason
from nexvul.core.config import ConfigChange, ConfigProvenance
from nexvul.findings.model import Finding, Severity
from nexvul.rules.suppressions import SuppressionIssue


class ScanStatus(StrEnum):
    """Scan status vocabulary (screen-inventory §0). Never paraphrased."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class FailedCause(StrEnum):
    NOTHING_TO_ANALYSE = "nothing_to_analyse"  # no in-scope file at all (T18, OD-05)
    NONE_ANALYSED = "none_analysed"  # in-scope files exist but none could be analysed (T07)


@dataclass(frozen=True)
class ToolInfo:
    name: str
    version: str
    rule_pack_version: str
    rule_pack_sha256: str
    python: str
    platform: str
    parsers: tuple[str, ...]


@dataclass(frozen=True)
class RuleSummary:
    id: str
    title: str
    asi: tuple[str, ...]


@dataclass(frozen=True)
class EffectiveSetting:
    key: str
    value: str  # display-safe rendering
    sources: tuple[str, ...]


@dataclass(frozen=True)
class LimitedNote:
    """An analysis-limited construct (dynamic import, exec, computed getattr). Display-safe."""

    path: str
    line: int
    reason: str


@dataclass(frozen=True)
class CompletenessReport:
    """Frozen view of the ledger plus derived counts (threat-model §7)."""

    status: ScanStatus
    failed_cause: FailedCause | None
    files_discovered: int
    files_analysed: int
    files_not_analysed: int
    files_failed: int
    files_timed_out: int
    skipped_by_reason: tuple[tuple[SkipReason, int], ...]
    skipped: tuple[SkippedEntry, ...]
    skipped_list_truncated: int
    limits_hit: tuple[str, ...]
    rule_failures: tuple[RuleFailure, ...]
    findings_truncated: int
    notes: tuple[str, ...]
    dynamic_constructs_not_analysed: int
    suppressed_inline: int
    allow_partial: bool
    scope: str = "repository"

    def count(self, reason: SkipReason) -> int:
        return dict(self.skipped_by_reason).get(reason, 0)


@dataclass(frozen=True)
class ScanResult:
    tool: ToolInfo
    target: str  # display form of the root as the user gave it (terminal only)
    target_name: str  # basename of the root (machine outputs carry no absolute paths, SR-24)
    discovery_mode: str
    commit: str | None
    started_at: str
    ended_at: str
    ci: bool
    ci_reason: str
    fail_on: Severity
    rules_available: int
    rules_enabled: tuple[RuleSummary, ...]
    rules_failed: tuple[str, ...]
    effective_config: tuple[EffectiveSetting, ...]
    config_changes: tuple[ConfigChange, ...]
    config_sources: tuple[ConfigProvenance, ...]
    completeness: CompletenessReport
    findings: tuple[Finding, ...]  # active findings (including NOT APPLIED suppressions)
    suppressed: tuple[Finding, ...]  # suppressed findings, kept and marked (SR-17)
    suppression_issues: tuple[SuppressionIssue, ...]
    languages_analysed: tuple[tuple[str, int], ...]
    limited: tuple[LimitedNote, ...]
    exit_code: int
    timings: tuple[tuple[str, float], ...] = ()
    frameworks: tuple[str, ...] = field(default_factory=tuple)

    @property
    def status(self) -> ScanStatus:
        return self.completeness.status

    @property
    def at_or_above(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.severity.at_or_above(self.fail_on))

    def counts(self) -> dict[Severity, int]:
        out = dict.fromkeys(Severity, 0)
        for f in self.findings:
            out[f.severity] += 1
        return out
