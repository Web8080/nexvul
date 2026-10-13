"""Rule runner: IR in, findings out (architecture §11, §12; SR-10, SR-18, SR-24).

* Rules run in ID order over the modules that parsed successfully.
* A rule that raises is **never swallowed**: the failure (rule ID and exception class name only,
  SR-24) is recorded in the completeness ledger, which makes the scan partial. Matches the rule
  yielded before it raised are kept.
* A rule that returns something other than a :class:`~nexvul.rules.base.Match`, or a match for a
  file it was not given, is treated as a failing rule.
* Finding caps (architecture §15): at most ``MAX_FINDINGS_PER_FILE`` per file and
  ``MAX_FINDINGS_TOTAL`` overall; dropped findings are counted and make the scan partial.
* Every repository-derived string is sanitised here, once, when the finding is built.

Phase 1 deviation (recorded in the handoff): rules run in the supervisor process. They see only
decoded IR (never file bytes) and are trusted built-in code; the analysis worker with its own
budgets and kill (architecture §5.2) arrives with the taint engine.
"""

from __future__ import annotations

import base64
import os
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, replace

from nexvul.core import limits
from nexvul.core.completeness import Completeness
from nexvul.core.sanitize import display_path, display_text
from nexvul.findings.model import (
    Evidence,
    Finding,
    FindingLocation,
    FlowStep,
    disambiguate,
    fingerprint,
)
from nexvul.findings.redact import redact_secrets
from nexvul.ir.model import Location, ModuleIR
from nexvul.rules.base import Match, Rule, RuleContext


class RuleContractError(TypeError):
    """A rule returned something that is not a valid match."""


@dataclass(frozen=True)
class RuleRun:
    findings: tuple[Finding, ...]
    rules_run: tuple[str, ...]
    rules_failed: tuple[str, ...]


def _location(path: str, loc: Location) -> FindingLocation:
    raw_b64: str | None = None
    try:
        path.encode("utf-8")
    except UnicodeEncodeError:
        raw_b64 = base64.b64encode(os.fsencode(path)).decode("ascii")
    return FindingLocation(
        path=display_path(path),
        line=max(loc.line, 0),
        column=loc.col + 1 if loc.line > 0 else 0,
        end_line=max(loc.end_line, 0),
        end_column=loc.end_col + 1 if loc.end_line > 0 else 0,
        raw_path_b64=raw_b64,
    )


def _snippet(text: str | None) -> str | None:
    if text is None:
        return None
    capped = text[: limits.MAX_SNIPPET_CHARS * 2]
    return display_text(redact_secrets(capped), max_chars=limits.MAX_SNIPPET_CHARS)


def build_finding(rule: Rule, match: Match, known_paths: frozenset[str]) -> tuple[Finding, str]:
    """Build one finding (fingerprint not yet disambiguated). Returns ``(finding, raw_path)``."""
    if not isinstance(match, Match):
        raise RuleContractError("rule returned a non-Match value")
    if match.path not in known_paths or any(s.path not in known_paths for s in match.flow):
        raise RuleContractError("rule reported a file it was not given")
    meta = rule.meta
    confidence = meta.confidence
    if match.confidence is not None and match.confidence.rank < confidence.rank:
        confidence = match.confidence
    flow = tuple(
        FlowStep(
            index=i + 1,
            role=step.role,
            location=_location(step.path, step.location),
            text=_snippet(step.text) or "",
        )
        for i, step in enumerate(match.flow[: limits.MAX_FLOW_STEPS])
    )
    evidence = tuple(
        Evidence(
            kind=display_text(e.kind, max_chars=64),
            description=display_text(e.description, max_chars=limits.MAX_MESSAGE_CHARS),
            snippet=_snippet(e.snippet),
        )
        for e in match.evidence[: limits.MAX_EVIDENCE_ITEMS]
    )
    shape = tuple((s.role.value, s.text) for s in match.flow)
    fp = fingerprint(
        rule_id=meta.id,
        path=os.fsencode(match.path),
        flow_shape=shape,
        context=match.context or match.message,
    )
    finding = Finding(
        rule_id=meta.id,
        title=meta.name,
        severity=match.severity or meta.severity,
        confidence=confidence,
        asi=meta.asi,
        location=_location(match.path, match.location),
        message=display_text(match.message, max_chars=limits.MAX_MESSAGE_CHARS),
        remediation=meta.remediation,
        references=meta.references,
        fingerprint=fp,
        flow=flow,
        evidence=evidence,
        cwe=meta.cwe,
        limitations=tuple(display_text(x, max_chars=200) for x in match.limitations),
    )
    return finding, match.path


def run_rules(
    rules: Sequence[Rule],
    modules: Sequence[ModuleIR],
    ledger: Completeness,
    *,
    ci: bool = False,
    max_per_file: int = limits.MAX_FINDINGS_PER_FILE,
    max_total: int = limits.MAX_FINDINGS_TOTAL,
) -> RuleRun:
    """Run ``rules`` over the successfully parsed ``modules``; record failures in ``ledger``."""
    ok_modules = tuple(m for m in modules if m.ok)
    known = frozenset(m.path for m in ok_modules)
    ctx = RuleContext(modules=ok_modules, ci=ci)
    built: list[tuple[Finding, str]] = []
    ran: list[str] = []
    failed: list[str] = []
    for rule in sorted(rules, key=lambda r: r.meta.id):
        ran.append(rule.meta.id)
        try:
            for match in rule.check(ctx):
                built.append(build_finding(rule, match, known))
        except Exception as exc:  # recorded, never swallowed (see module doc)
            ledger.record_rule_failure(rule.meta.id, type(exc).__name__)
            failed.append(rule.meta.id)

    built.sort(key=lambda item: item[0].sort_key())
    per_file: Counter[str] = Counter()
    kept: list[tuple[Finding, str]] = []
    dropped = 0
    for finding, raw_path in built:
        if per_file[raw_path] >= max_per_file or len(kept) >= max_total:
            dropped += 1
            continue
        per_file[raw_path] += 1
        kept.append((finding, raw_path))
    if dropped:
        ledger.record_findings_truncated(dropped)

    seen: Counter[str] = Counter()
    final: list[Finding] = []
    for found, _raw in sorted(
        kept, key=lambda item: (item[1], item[0].location.line, item[0].location.column)
    ):
        n = seen[found.fingerprint]
        seen[found.fingerprint] += 1
        final.append(replace(found, fingerprint=disambiguate(found.fingerprint, n)) if n else found)
    final.sort(key=Finding.sort_key)
    return RuleRun(findings=tuple(final), rules_run=tuple(ran), rules_failed=tuple(failed))
