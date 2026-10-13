"""Inline suppressions (architecture §11.5, DEC-0004 §2, DEC-0007 OD-03/OD-04, SR-17, T-17).

Syntax (OD-04, public)::

    # nexvul: ignore[NEX006] -- auth enforced by the API gateway
    # nexvul: ignore[NEX016,NEX017] -- tool runs only in the sandbox account

* The comment comes from a real COMMENT token (extracted in the parse worker). A ``# nexvul:``
  inside a string literal is therefore never a suppression.
* It applies to its own line when trailing code, else to the next line holding code (C03).
* **Rejected** (never applied, finding stays active, one warning each, in every mode): no rule
  ID (a bare ``ignore``), a malformed or unknown rule ID, any directive other than ``ignore``
  (no blanket or file-level suppressions), hidden characters (bidi overrides, zero-width and
  other format or control characters, Trojan Source), non-ASCII characters in the directive part
  (homoglyphs), text after ``]`` that is not `` -- <justification>``, over-long comments.
* **Justification**: optional locally (the suppression applies and is listed as
  ``(no justification)``); required in CI mode (at least ``MIN_CI_JUSTIFICATION_CHARS``
  characters), otherwise the suppression is **not applied** and listed as such.
* Suppressed findings are never dropped: they keep their place in the JSON report, marked
  ``suppressed``, and are counted in completeness.
"""

from __future__ import annotations

import difflib
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum

from nexvul.core import limits
from nexvul.core.sanitize import describe_char, display_path, display_text, first_hidden_char
from nexvul.findings.model import Finding, Suppression, SuppressionStatus, is_rule_id
from nexvul.ir.model import ModuleIR, SuppressionComment

_PREFIX = "nexvul:"
_DIRECTIVE = "ignore"
_SEPARATOR = "--"


class Problem(StrEnum):
    NO_RULE_ID = "no_rule_id"
    INVALID_RULE_ID = "invalid_rule_id"
    UNKNOWN_RULE_ID = "unknown_rule_id"
    HIDDEN_CHARACTER = "hidden_character"
    NON_ASCII = "non_ascii_directive"
    UNSUPPORTED_DIRECTIVE = "unsupported_directive"
    MALFORMED = "malformed"
    TOO_LONG = "too_long"


class IssueKind(StrEnum):
    REJECTED = "rejected"  # never applied
    NOT_APPLIED = "not_applied"  # valid, matched, but not honoured (CI without justification)
    NO_JUSTIFICATION = "no_justification"  # applied locally without a justification
    UNMATCHED = "unmatched"  # valid but no finding on its target line


@dataclass(frozen=True)
class InlineSuppression:
    path: str  # display-safe
    line: int
    target_line: int
    rule_ids: tuple[str, ...]
    justification: str | None  # display-safe, capped for display
    justification_chars: int


@dataclass(frozen=True)
class SuppressionIssue:
    """One line of the suppression report. All text is display-safe."""

    kind: IssueKind
    path: str
    line: int
    message: str
    problem: Problem | None = None
    rule_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "path": self.path,
            "line": self.line,
            "problem": self.problem.value if self.problem else None,
            "rule_ids": list(self.rule_ids),
            "message": self.message,
        }


class _RejectedError(Exception):
    def __init__(self, problem: Problem, message: str) -> None:
        super().__init__(message)
        self.problem = problem
        self.message = message


def parse_comment(
    comment: SuppressionComment, path: str, known_ids: frozenset[str]
) -> InlineSuppression:
    """Interpret one ``# nexvul:`` comment. Raises ``_RejectedError`` (see :func:`collect`)."""
    if comment.truncated:
        raise _RejectedError(
            Problem.TOO_LONG,
            f"suppression ignored: comment longer than "
            f"{limits.MAX_SUPPRESSION_COMMENT_CHARS} characters.",
        )
    text = comment.text.replace("\t", " ")
    hidden = first_hidden_char(text)
    if hidden is not None:
        raise _RejectedError(
            Problem.HIDDEN_CHARACTER,
            f"suppression ignored: it contains a hidden character ({describe_char(hidden)}).",
        )
    body = text.strip()
    sep = body.find(f" {_SEPARATOR}")
    directive = body if sep == -1 else body[:sep]
    if not directive.isascii():
        raise _RejectedError(
            Problem.NON_ASCII,
            "suppression ignored: the directive contains a non-ASCII character "
            "(possible look-alike). Write it in plain ASCII.",
        )
    if not body.startswith(_PREFIX):
        raise _RejectedError(
            Problem.MALFORMED,
            "suppression ignored: write it as nexvul: ignore[NEX0nn] -- <reason>.",
        )
    rest = body[len(_PREFIX) :].lstrip(" ")
    if not rest.startswith(_DIRECTIVE):
        raise _RejectedError(
            Problem.UNSUPPORTED_DIRECTIVE,
            "suppression ignored: only ignore[NEX0nn] is supported; blanket and file-level "
            "suppressions are not.",
        )
    rest = rest[len(_DIRECTIVE) :]
    if not rest.startswith("["):
        raise _RejectedError(
            Problem.NO_RULE_ID, "suppression ignored: no rule ID. Write ignore[NEX0nn] -- <reason>."
        )
    close = rest.find("]")
    if close == -1:
        raise _RejectedError(
            Problem.MALFORMED, "suppression ignored: missing ']' after the rule IDs."
        )
    ids = tuple(part.strip() for part in rest[1:close].split(","))
    if not any(ids):
        raise _RejectedError(
            Problem.NO_RULE_ID, "suppression ignored: no rule ID. Write ignore[NEX0nn] -- <reason>."
        )
    if len(ids) > limits.MAX_SUPPRESSION_RULE_IDS:
        raise _RejectedError(
            Problem.MALFORMED,
            f"suppression ignored: more than {limits.MAX_SUPPRESSION_RULE_IDS} rule IDs.",
        )
    for rule_id in ids:
        if not is_rule_id(rule_id):
            shown = display_text(rule_id, max_chars=24)
            raise _RejectedError(
                Problem.INVALID_RULE_ID,
                f"suppression ignored: '{shown}' is not a rule ID. Write ignore[NEX0nn].",
            )
        if rule_id not in known_ids:
            hint = difflib.get_close_matches(rule_id, sorted(known_ids), n=1, cutoff=0.6)
            more = f" Did you mean {hint[0]}?" if hint else ""
            raise _RejectedError(
                Problem.UNKNOWN_RULE_ID, f"ignore[{rule_id}] names no rule in this version.{more}"
            )
    tail = rest[close + 1 :].strip(" ")
    justification_raw: str | None = None
    if tail:
        if not tail.startswith(_SEPARATOR):
            raise _RejectedError(
                Problem.MALFORMED,
                "suppression ignored: write the justification after ' -- '.",
            )
        justification_raw = tail[len(_SEPARATOR) :].strip(" ") or None
    return InlineSuppression(
        path=path,
        line=comment.location.line,
        target_line=comment.target_line,
        rule_ids=ids,
        justification=(
            display_text(justification_raw, max_chars=limits.MAX_JUSTIFICATION_DISPLAY_CHARS)
            if justification_raw
            else None
        ),
        justification_chars=len(justification_raw or ""),
    )


@dataclass(frozen=True)
class SuppressionOutcome:
    findings: tuple[Finding, ...]
    issues: tuple[SuppressionIssue, ...]
    inline_applied: int


def collect(
    modules: Iterable[ModuleIR], known_ids: frozenset[str]
) -> tuple[list[InlineSuppression], list[SuppressionIssue]]:
    """Parse every suppression comment of every parsed module."""
    valid: list[InlineSuppression] = []
    issues: list[SuppressionIssue] = []
    for module in modules:
        if not module.ok:
            continue
        path = display_path(module.path)
        for comment in module.suppressions:
            try:
                valid.append(parse_comment(comment, path, known_ids))
            except _RejectedError as exc:
                issues.append(
                    SuppressionIssue(
                        IssueKind.REJECTED, path, comment.location.line, exc.message, exc.problem
                    )
                )
    return valid, issues


def apply_suppressions(
    findings: Sequence[Finding],
    modules: Iterable[ModuleIR],
    known_ids: frozenset[str],
    *,
    ci: bool,
) -> SuppressionOutcome:
    """Mark matched findings; return every issue (rejected, not applied, unmatched)."""
    valid, issues = collect(modules, known_ids)
    index: dict[tuple[str, int], list[InlineSuppression]] = defaultdict(list)
    for sup in valid:
        if sup.target_line > 0:
            index[(sup.path, sup.target_line)].append(sup)
    used: set[tuple[int, str]] = set()  # (id(sup), rule_id)
    reported_missing: set[int] = set()
    out: list[Finding] = []
    applied = 0
    for finding in findings:
        candidates = index.get((finding.location.path, finding.location.line), [])
        match = next((s for s in candidates if finding.rule_id in s.rule_ids), None)
        if match is None:
            out.append(finding)
            continue
        used.add((id(match), finding.rule_id))
        short = match.justification_chars < limits.MIN_CI_JUSTIFICATION_CHARS
        if ci and short:
            reason = (
                f"CI requires a justification of at least {limits.MIN_CI_JUSTIFICATION_CHARS} "
                "characters after ' -- '"
            )
            out.append(
                replace(
                    finding,
                    suppression=Suppression(
                        status=SuppressionStatus.NOT_APPLIED,
                        line=match.line,
                        justification=match.justification,
                        reason=reason,
                    ),
                )
            )
            issues.append(
                SuppressionIssue(
                    IssueKind.NOT_APPLIED,
                    match.path,
                    match.line,
                    f"ignore[{finding.rule_id}] not applied: {reason}.",
                    rule_ids=(finding.rule_id,),
                )
            )
            continue
        applied += 1
        out.append(
            replace(
                finding,
                suppression=Suppression(
                    status=SuppressionStatus.SUPPRESSED,
                    line=match.line,
                    justification=match.justification,
                ),
            )
        )
        if match.justification is None and id(match) not in reported_missing:
            reported_missing.add(id(match))
            issues.append(
                SuppressionIssue(
                    IssueKind.NO_JUSTIFICATION,
                    match.path,
                    match.line,
                    f"ignore[{finding.rule_id}] has no justification. It applies locally; in CI "
                    "it would not be applied.",
                    rule_ids=(finding.rule_id,),
                )
            )
    for sup in valid:
        unused = tuple(r for r in sup.rule_ids if (id(sup), r) not in used)
        if unused:
            issues.append(
                SuppressionIssue(
                    IssueKind.UNMATCHED,
                    sup.path,
                    sup.line,
                    f"ignore[{','.join(unused)}] matched no finding.",
                    rule_ids=unused,
                )
            )
    issues.sort(key=lambda i: (i.path, i.line, i.kind.value))
    return SuppressionOutcome(findings=tuple(out), issues=tuple(issues), inline_applied=applied)
