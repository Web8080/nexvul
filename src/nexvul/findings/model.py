"""Finding model (architecture §12.1, threat-model §7, SR-10, SR-17, SR-24).

Invariants (rule IDs and ASI labels are checked in ``__post_init__``; the rest is guaranteed by
``nexvul.rules.engine``, the only place findings are built):

* Every ``str`` field of a finding is **display-safe**: built by
  :func:`nexvul.core.sanitize.display_text` (or composed only from trusted text), so it contains
  no control, format or bidi character and is valid UTF-8. Reporters may print it; they still
  pass it through :func:`~nexvul.core.sanitize.ensure_display_safe` as defence in depth.
* Severity and confidence are words from fixed enums, never numbers (tokens.json).
* ASI labels are an ordered tuple; the first label is the primary category (DEC-0005, OD-02).
* The fingerprint is computed from **raw** values before sanitising (path bytes, rule ID, flow
  shape, sink context) and contains no line numbers, so it is stable under edits above the
  finding and distinct for distinct flows (architecture §12.1, test-strategy §5.3).

Columns: IR columns are 0-based UTF-8 byte offsets. Findings store **1-based** lines and columns
(``column_unit = "utf8_bytes"``) because that is what people type into editors; the unit is declared
in every JSON report (SR-29).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

#: Semantic version of the JSON report and finding shape (architecture §12.1).
REPORT_SCHEMA_VERSION: Final = "1.0.0"

COLUMN_UNIT: Final = "utf8_bytes"

_RULE_ID: Final = re.compile(r"NEX[0-9]{3}")
_ASI_ID: Final = re.compile(r"ASI(0[1-9]|10)")


def is_rule_id(value: str) -> bool:
    return _RULE_ID.fullmatch(value) is not None


def is_asi_id(value: str) -> bool:
    return _ASI_ID.fullmatch(value) is not None


class Severity(StrEnum):
    """Severity words (tokens.json -> severity). Order: info < low < medium < high < critical."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self)

    def at_or_above(self, threshold: Severity) -> bool:
        return self.rank >= threshold.rank


_SEVERITY_ORDER: Final = (
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)

#: Highest first, the order findings and counts are shown in.
SEVERITIES_DESCENDING: Final = tuple(reversed(_SEVERITY_ORDER))


class Confidence(StrEnum):
    """Confidence words (detection-taxonomy §3.2). Never shown as a number."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return (Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH).index(self)


class FlowRole(StrEnum):
    """Role word of one flow step. ``source`` and ``sink`` are printed as words (design §3)."""

    SOURCE = "source"
    STEP = "step"
    CALL = "call"
    SINK = "sink"


class SuppressionStatus(StrEnum):
    """How an inline suppression affected a finding (SR-17, DEC-0004 §2)."""

    NONE = "none"
    SUPPRESSED = "suppressed"  # applied: the finding is listed as suppressed, never dropped
    NOT_APPLIED = "not_applied"  # matched but not honoured (CI without justification)


@dataclass(frozen=True)
class FindingLocation:
    """Display-safe repo-relative path plus 1-based positions (0 = unknown)."""

    path: str
    line: int
    column: int
    end_line: int
    end_column: int
    #: base64 of the raw path bytes when the name is not valid UTF-8 (T-10); otherwise ``None``.
    raw_path_b64: str | None = None


@dataclass(frozen=True)
class FlowStep:
    index: int
    role: FlowRole
    location: FindingLocation
    text: str  # display-safe code rendering, capped


@dataclass(frozen=True)
class Evidence:
    kind: str  # trusted code chosen by the rule, e.g. "no_sanitiser"
    description: str  # display-safe
    snippet: str | None = None  # display-safe, capped and secret-redacted (SR-24)


@dataclass(frozen=True)
class Suppression:
    """The suppression state of one finding. ``justification`` is display-safe or ``None``."""

    status: SuppressionStatus = SuppressionStatus.NONE
    kind: str = "inline"
    line: int = 0
    justification: str | None = None
    reason: str = ""  # trusted text, e.g. "CI requires a justification"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    asi: tuple[str, ...]
    location: FindingLocation
    message: str
    remediation: str
    references: tuple[str, ...]
    fingerprint: str
    flow: tuple[FlowStep, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    cwe: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    suppression: Suppression = field(default_factory=Suppression)

    def __post_init__(self) -> None:
        if not is_rule_id(self.rule_id):
            raise ValueError("invalid rule id")
        if not self.asi or not all(is_asi_id(a) for a in self.asi):
            raise ValueError("findings need at least one valid ASI label")
        if len(set(self.asi)) != len(self.asi):
            raise ValueError("duplicate ASI label")
        if not self.fingerprint.startswith("sha256:"):
            raise ValueError("fingerprint must be sha256:<hex>")

    @property
    def suppressed(self) -> bool:
        return self.suppression.status is SuppressionStatus.SUPPRESSED

    @property
    def active(self) -> bool:
        """Counts towards the exit code (not suppressed; NOT_APPLIED stays active)."""
        return not self.suppressed

    def sort_key(self) -> tuple[int, str, int, int, str]:
        loc = self.location
        return (-self.severity.rank, loc.path, loc.line, loc.column, self.rule_id)


def fingerprint(
    *,
    rule_id: str,
    path: bytes,
    flow_shape: tuple[tuple[str, str], ...],
    context: str,
) -> str:
    """``sha256:`` over rule ID, normalised path, flow signature and sink context.

    ``flow_shape`` is ``(role, normalised code)`` per step; ``context`` is the rule's sink
    context (normally the code at the sink). Whitespace inside code is collapsed, and no line or
    column number is included, so moving code or editing comments above a finding keeps its
    fingerprint (architecture §12.1).
    """
    h = hashlib.sha256()
    for part in (
        b"nexvul-fp-v1",
        rule_id.encode("ascii"),
        _normalise_path(path),
        "\x1f".join(f"{role}:{_squash(code)}" for role, code in flow_shape).encode(
            "utf-8", "surrogatepass"
        ),
        _squash(context).encode("utf-8", "surrogatepass"),
    ):
        h.update(len(part).to_bytes(8, "big"))
        h.update(part)
    return f"sha256:{h.hexdigest()}"


def disambiguate(base: str, occurrence: int) -> str:
    """Make repeated identical fingerprints in one file distinct, in source order."""
    if occurrence == 0:
        return base
    digest = hashlib.sha256(f"{base}#{occurrence}".encode("ascii")).hexdigest()
    return f"sha256:{digest}"


def _normalise_path(path: bytes) -> bytes:
    parts = [p for p in path.replace(b"\\", b"/").split(b"/") if p not in (b"", b".")]
    return b"/".join(parts)


def _squash(text: str) -> str:
    return " ".join(text.split())
