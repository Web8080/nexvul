"""Rule plugin API: declarative metadata plus a ``check`` over per-file IR (architecture §11).

A rule is trusted, built-in code (DEC-0004 §4: no plugins before 1.0). It receives decoded IR
only, never file bytes, and returns :class:`Match` objects. The engine (``rules.engine``) turns a
match into a :class:`~nexvul.findings.model.Finding`: it fills title, ASI labels, remediation and
references from the rule's metadata (a rule cannot forge them per finding), sanitises every
string derived from the scanned repository, redacts snippets and computes the fingerprint.

Writing messages: follow design-system §8.2. Name the API and the missing control; never use the
banned words (secure, safe, vulnerable, ...). Identifiers taken from the scanned code may be
embedded; :func:`code` caps them at ``MAX_IDENTIFIER_CHARS`` and the engine sanitises the whole
message.
"""

from __future__ import annotations

import abc
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import ClassVar

from nexvul.core import limits
from nexvul.findings.model import Confidence, FlowRole, Severity, is_asi_id, is_rule_id
from nexvul.ir.model import Location, ModuleIR


class Readiness(StrEnum):
    """Status column of ``nexvul rules`` (U01)."""

    DEFAULT = "default"  # on by default
    EXPERIMENTAL = "experimental"  # off unless enabled by ID or ASI selector


@dataclass(frozen=True)
class RuleDoc:
    """Built-in rule documentation for ``nexvul explain`` (U03). Never from scanned content."""

    looks_for: str
    why_it_matters: str
    how_to_fix: str
    not_detected: str
    example_flagged: str = ""
    example_not_flagged: str = ""
    asi_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class RuleMeta:
    """Declarative rule metadata. ``confidence`` is the ceiling for every finding of the rule."""

    id: str
    name: str
    asi: tuple[str, ...]
    severity: Severity
    confidence: Confidence
    readiness: Readiness
    remediation: str
    references: tuple[str, ...] = ()
    cwe: tuple[str, ...] = ()
    languages: tuple[str, ...] = ("python",)
    doc: RuleDoc | None = None

    def __post_init__(self) -> None:
        if not is_rule_id(self.id):
            raise ValueError(f"rule id must look like NEX001, got {self.id!r}")
        if not self.name.strip() or not self.remediation.strip():
            raise ValueError("rule name and remediation are required")
        if not self.asi or not all(is_asi_id(a) for a in self.asi):
            raise ValueError("rules need an ordered, non-empty list of ASI labels")
        if len(set(self.asi)) != len(self.asi):
            raise ValueError("duplicate ASI label")

    def to_dict(self) -> dict[str, object]:
        """Canonical metadata (used for the rule-pack hash and ``rules --json``)."""
        return {
            "id": self.id,
            "name": self.name,
            "asi": list(self.asi),
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "readiness": self.readiness.value,
            "remediation": self.remediation,
            "references": list(self.references),
            "cwe": list(self.cwe),
            "languages": list(self.languages),
        }


@dataclass(frozen=True)
class FlowStepDraft:
    """One step of a data flow as a rule reports it. ``path`` is ``ModuleIR.path`` (raw)."""

    role: FlowRole
    path: str
    location: Location
    text: str


@dataclass(frozen=True)
class EvidenceDraft:
    kind: str
    description: str
    snippet: str | None = None


@dataclass(frozen=True)
class Match:
    """What a rule returns for one finding.

    ``path``/``location`` are the primary (sink) location. ``context`` distinguishes findings for
    the fingerprint (normally the code at the sink); it defaults to the message. ``severity`` and
    ``confidence`` may refine the rule defaults; confidence is capped at the rule's ceiling.
    """

    path: str
    location: Location
    message: str
    flow: tuple[FlowStepDraft, ...] = ()
    evidence: tuple[EvidenceDraft, ...] = ()
    severity: Severity | None = None
    confidence: Confidence | None = None
    context: str = ""
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class RuleContext:
    """Everything a rule may look at: successfully parsed modules, in discovery order."""

    modules: tuple[ModuleIR, ...]
    ci: bool = False
    extra: dict[str, str] = field(default_factory=dict)


class Rule(abc.ABC):
    """Base class for built-in rules. Subclasses set ``meta`` and implement :meth:`check`."""

    meta: ClassVar[RuleMeta]

    @abc.abstractmethod
    def check(self, ctx: RuleContext) -> Iterable[Match]:
        """Yield matches. Must not read files, import target code or touch the network."""


def code(text: str, max_chars: int = limits.MAX_IDENTIFIER_CHARS) -> str:
    """Cap an identifier or code fragment taken from the scanned repo before embedding it."""
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 1] + "…"
