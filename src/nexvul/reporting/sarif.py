"""SARIF 2.1.0 reporter (architecture §12.3, §13; github-and-action.md §2-§4; SR-10/12, T-12/20).

What goes where, and why:

* ``tool.driver.rules`` lists **every built-in rule** (experimental ones too, with
  ``defaultConfiguration.enabled = false``), so a SARIF consumer can tell "rule did not run" from
  "rule found nothing". Rule text (``shortDescription``, ``fullDescription``, ``help``) comes only
  from built-in :class:`~nexvul.rules.base.RuleMeta` / ``RuleDoc`` - never from scanned content
  (SR-12). ``help.markdown`` escapes Markdown in that trusted text and links only to allowlisted
  hosts (§4 rule-help lint).
* ``security-severity`` is the rule **default** (GitHub reads it per rule). Each result's
  ``message.text`` starts with nexvul's **effective** severity, and states the rule default when
  it differs (OD-07, CA-1); ``properties.nexvul.severity`` carries it for tools.
* Results use ``message.text`` only, never ``message.markdown``. Repo-derived text in the message
  is display-safe (sanitised when the finding was built, re-checked here), URL literals are
  replaced by ``<url literal, N chars>`` because GitHub auto-links plain-text URLs (§2.1), and the
  text is capped at 400 characters.
* Locations are repo-relative, percent-encoded URIs with ``uriBaseId: %SRCROOT%``; no scheme, no
  leading ``/``, no ``..`` (T-12). Lines are 1-based. nexvul's columns are 1-based **UTF-8 byte**
  offsets (SR-29); SARIF has no byte column kind, so the run declares ``utf16CodeUnits`` (the
  kind GitHub assumes) and ``properties.nexvul.position_encoding`` records that the columns are
  exact only where the line prefix is ASCII. See the step-5a handoff.
* ``partialFingerprints.primaryLocationLineHash`` is derived from ``Finding.fingerprint``, which
  contains no line numbers, so an alert survives code moving up or down (CA-7).
* Inline-suppressed findings are emitted with ``suppressions[{kind: inSource}]``; NOT APPLIED
  suppressions stay unsuppressed results and say so in the message.
* Completeness travels in ``invocations[0]``: ``executionSuccessful`` is true only for a complete,
  untruncated scan, and every completeness gap (each partial skip reason with up to 10 example
  paths, each rule failure, limit hit, engine truncation and SARIF truncation) is a
  ``toolExecutionNotifications`` entry. The full completeness block and scan provenance are in
  ``runs[0].properties.nexvul``.
* GitHub's limits (25,000 results per run, 10 MB gzip-compressed) are enforced by the writer:
  results are sorted by severity, the lowest are dropped first, and the drop is recorded as an
  error notification and in ``properties.nexvul.sarif`` - never silently.
* ``info`` findings are not uploaded (§3, OD-13); they are counted in the run properties.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import quote

from nexvul.core.completeness import Impact, impact_of
from nexvul.core.config import ChangeStatus
from nexvul.core.sanitize import ensure_display_safe
from nexvul.findings.model import (
    COLUMN_UNIT,
    Finding,
    FindingLocation,
    FlowRole,
    Severity,
    SuppressionStatus,
)
from nexvul.findings.result import FailedCause, ScanResult, ScanStatus
from nexvul.reporting import tokens as tk
from nexvul.reporting.json_report import UNTRUSTED_FIELDS, report_dict
from nexvul.reporting.terminal import REASON_LABELS
from nexvul.rules.base import Readiness, Rule, RuleMeta
from nexvul.rules.registry import Registry

SARIF_VERSION: Final = "2.1.0"
#: The schema id (OASIS errata01). Never fetched (SR-23); tests use a vendored copy.
SARIF_SCHEMA_URI: Final = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
SRCROOT: Final = "%SRCROOT%"
AUTOMATION_ID: Final = "nexvul/"

#: Fixed, trusted URLs. The canonical repository is github.com/Web8080/nexvul (OD-11, decided
#: 2026-10-16). Never derive a link from scanned content.
REPO_URL: Final = "https://github.com/Web8080/nexvul"
RULE_DOCS_URL: Final = REPO_URL + "/blob/main/docs/rules/{rule_id}.md"
FP_REPORT_URL: Final = REPO_URL + "/issues/new?template=false-positive.yml"

#: Hosts a rule-help Markdown link may point to (github-and-action.md §4).
LINK_HOSTS: Final = frozenset(
    {
        "owasp.org",
        "genai.owasp.org",
        "cwe.mitre.org",
        "modelcontextprotocol.io",
        "github.com",
    }
)

#: GitHub code scanning limits (docs/research/tooling/sarif.md).
MAX_RESULTS: Final = 25_000
MAX_GZIP_BYTES: Final = 10 * 1024 * 1024
MAX_FLOW_LOCATIONS: Final = 1_000  # GitHub shows 1,000 of up to 10,000
MAX_TAGS: Final = 20
MAX_MESSAGE_CHARS: Final = 400
MAX_SNIPPET_CHARS: Final = 300
MAX_PROPERTY_TEXT_CHARS: Final = 500
MAX_NOTIFICATION_LOCATIONS: Final = 10

#: github-and-action.md §3.
SECURITY_SEVERITY: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
}
LEVEL: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_URL_LITERAL: Final = re.compile(
    r"(?i)(?:\b[a-z][a-z0-9+.\-]{0,31}://|\bwww\.)[^\s'\"<>]*[^\s'\"<>.,;:!?)\]]",
    flags=re.ASCII,
)
_MD_SPECIAL: Final = frozenset("\\`*_{}[]()#+-.!|<>~&=")
_ESCAPE_TOKEN: Final = re.compile(r"\\\\|\\x([0-9a-f]{2})|\\u\{([0-9a-f]{4,6})\}")


# --------------------------------------------------------------------------------------------
# Text helpers
# --------------------------------------------------------------------------------------------


def _cap(text: str, limit: int) -> str:
    """Cap display text with an ellipsis and a short hash suffix (same shape as display_text)."""
    safe = ensure_display_safe(text)
    if len(safe) <= limit:
        return safe
    digest = hashlib.sha256(safe.encode("utf-8", "surrogatepass")).hexdigest()[:10]
    return f"{safe[: max(limit - 12, 1)]}{tk.ELLIPSIS}~{digest}"


def defang_urls(text: str) -> str:
    """Replace URL literals so GitHub cannot auto-link repo-derived URLs (§2.1, T-12)."""
    return _URL_LITERAL.sub(lambda m: f"<url literal, {len(m.group(0))} chars>", text)


def md_escape(text: str) -> str:
    """Backslash-escape CommonMark punctuation in trusted rule text (newlines kept)."""
    return "".join("\\" + ch if ch in _MD_SPECIAL else ch for ch in text)


def _fence(code: str) -> str:
    longest = max((len(m) for m in re.findall(r"`+", code)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}text\n{code}\n{fence}"


def _undisplay(path: str) -> str:
    """Invert :func:`display_text` escapes so the URI names the real file (still inert)."""

    def repl(m: re.Match[str]) -> str:
        if m.group(0) == "\\\\":
            return "\\"
        if m.group(1) is not None:
            return chr(int(m.group(1), 16))
        return chr(int(m.group(2), 16))

    return _ESCAPE_TOKEN.sub(repl, path)


def artifact_uri(loc: FindingLocation) -> str:
    """Repo-relative, normalised, percent-encoded URI: no scheme, no leading ``/``, no ``..``."""
    if loc.raw_path_b64 is not None:
        raw = base64.b64decode(loc.raw_path_b64)
    else:
        raw = _undisplay(loc.path).encode("utf-8", "surrogatepass")
    parts = [p for p in raw.replace(b"\\", b"/").split(b"/") if p not in (b"", b".", b"..")]
    uri = "/".join(quote(p, safe="") for p in parts)
    return uri or "unknown"


# --------------------------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------------------------


def _link(ref: str) -> tuple[str, str | None]:
    """(label, url-or-None). Relative doc paths become fixed docs URLs; others need an allowlisted
    host."""
    m = re.fullmatch(r"docs/rules/(NEX[0-9]{3})\.md", ref)
    if m:
        return f"nexvul rule {m.group(1)}", RULE_DOCS_URL.format(rule_id=m.group(1))
    host = re.match(r"https://([^/:?#]+)(?:[/?#]|$)", ref)
    if host and host.group(1).lower() in LINK_HOSTS:
        return ref, ref
    return ref, None


def _lines(text: str) -> list[str]:
    return [ln.strip() for ln in text.split("\n") if ln.strip()]


def _help(meta: RuleMeta) -> tuple[str, str]:
    """(help.text, help.markdown) in the §4 section order. Trusted text only."""
    doc = meta.doc
    asi = ", ".join(meta.asi)
    md: list[str] = [
        f"**{md_escape(meta.name)}** · {md_escape(asi)}",
        "",
        md_escape(tk.FINDING_MEANING),
    ]
    tx: list[str] = [f"{meta.name} - {asi}", "", tk.FINDING_MEANING]
    if doc is not None and doc.status_note:
        md += ["", f"*{md_escape(doc.status_note)}*"]
        tx += ["", doc.status_note]

    def section(title: str, body_md: list[str], body_tx: list[str]) -> None:
        md.extend(["", f"#### {title}", *body_md])
        tx.extend(["", title.upper(), *body_tx])

    if doc is not None:
        section(
            "What nexvul looked for",
            [md_escape(p) + "\n" for p in _lines(doc.looks_for)],
            _lines(doc.looks_for),
        )
        section("Why it matters", [md_escape(doc.why_it_matters)], [doc.why_it_matters])
        fix_md = [md_escape(doc.how_to_fix)]
        fix_tx = [doc.how_to_fix]
        if doc.example_flagged:
            fix_md += ["", "Flagged:", "", _fence(doc.example_flagged)]
            fix_tx += ["", "Flagged:", doc.example_flagged]
        if doc.example_not_flagged:
            fix_md += ["", "Not flagged:", "", _fence(doc.example_not_flagged)]
            fix_tx += ["", "Not flagged:", doc.example_not_flagged]
        section("How to fix", fix_md, fix_tx)
        section(
            "What this rule does not detect",
            [f"- {md_escape(p)}" for p in _lines(doc.not_detected)],
            [f"- {p}" for p in _lines(doc.not_detected)],
        )
    else:
        section("How to fix", [md_escape(meta.remediation)], [meta.remediation])
    sev = (
        f"Default severity {meta.severity.value}. Highest confidence {meta.confidence.value}. "
        "The alert message states this result's own severity and confidence."
    )
    section("Severity and confidence", [md_escape(sev)], [sev])
    triage = [
        "Snippets and identifiers in this alert come from the scanned repository. Treat them as "
        "untrusted text.",
    ]
    reproduce = f"nexvul explain {meta.id}"
    section(
        "Triage",
        [
            f"- {md_escape(triage[0])}",
            f"- Reproduce locally: `{reproduce}` and `nexvul scan --verbose <path>`",
            f"- False positive? Report it: {FP_REPORT_URL}",
        ],
        [
            f"- {triage[0]}",
            f"- Reproduce locally: {reproduce} and nexvul scan --verbose <path>",
            f"- False positive? Report it: {FP_REPORT_URL}",
        ],
    )
    if doc is not None and doc.suppression_note:
        sup_md, sup_tx = [md_escape(doc.suppression_note)], [doc.suppression_note]
    else:
        syntax = f"# nexvul: ignore[{meta.id}] -- <reason>"
        lead = (
            "Add a comment on the flagged line or the line above, naming the rule and the reason:"
        )
        tail = "Suppressed findings stay visible as suppressed. In CI the reason is required."
        sup_md = [md_escape(lead), f"`{syntax}`", md_escape(tail)]
        sup_tx = [lead, syntax, tail]
    section("Suppressing this finding", sup_md, sup_tx)
    refs_md: list[str] = []
    refs_tx: list[str] = []
    for ref in (*meta.references, f"docs/rules/{meta.id}.md"):
        label, url = _link(ref)
        line_tx = f"- {label}: {url}" if url and url != label else f"- {label}"
        if line_tx in refs_tx:
            continue
        refs_tx.append(line_tx)
        refs_md.append(f"- [{md_escape(label)}]({url})" if url else f"- {md_escape(label)}")
    section("References", refs_md, refs_tx)
    return "\n".join(tx), "\n".join(md)


def _tags(meta: RuleMeta) -> list[str]:
    tags = ["security", *(f"external/owasp/{a.lower()}" for a in meta.asi)]
    tags += [f"external/cwe/{c.lower()}" for c in meta.cwe]
    if meta.readiness is Readiness.EXPERIMENTAL:
        tags.append("experimental")
    return tags[:MAX_TAGS]


def rule_descriptor(rule: Rule) -> dict[str, Any]:
    meta = rule.meta
    text, markdown = _help(meta)
    summary = _lines(meta.doc.looks_for)[0] if meta.doc else meta.remediation
    props: dict[str, Any] = {"tags": _tags(meta), "precision": meta.confidence.value}
    if meta.severity in SECURITY_SEVERITY:
        props["security-severity"] = SECURITY_SEVERITY[meta.severity]
    props["nexvul"] = {
        "readiness": meta.readiness.value,
        "asi": list(meta.asi),
        "cwe": list(meta.cwe),
        "default_severity": meta.severity.value,
        "confidence_ceiling": meta.confidence.value,
        "languages": list(meta.languages),
    }
    return {
        "id": meta.id,
        "name": type(rule).__name__,
        "shortDescription": {"text": meta.name},
        "fullDescription": {"text": summary},
        "help": {"text": text, "markdown": markdown},
        "helpUri": RULE_DOCS_URL.format(rule_id=meta.id),
        "defaultConfiguration": {
            "enabled": meta.readiness is Readiness.DEFAULT,
            "level": LEVEL[meta.severity],
        },
        "properties": props,
    }


def _fallback_descriptor(f: Finding) -> dict[str, Any]:
    """Descriptor for a finding whose rule is not in the registry passed in (test registries)."""
    tags = ["security", *(f"external/owasp/{a.lower()}" for a in f.asi)]
    return {
        "id": f.rule_id,
        "shortDescription": {"text": f.title},
        "fullDescription": {"text": f.title},
        "help": {"text": f.remediation, "markdown": md_escape(f.remediation)},
        "helpUri": RULE_DOCS_URL.format(rule_id=f.rule_id),
        "properties": {"tags": tags[:MAX_TAGS]},
    }


# --------------------------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------------------------


def _region(loc: FindingLocation, snippet: str | None = None) -> dict[str, Any] | None:
    if loc.line <= 0:
        return None
    region: dict[str, Any] = {"startLine": loc.line}
    if loc.column > 0:
        region["startColumn"] = loc.column
    if loc.end_line >= loc.line:
        region["endLine"] = loc.end_line
        if loc.end_column > 0 and (loc.end_line > loc.line or loc.end_column >= loc.column):
            region["endColumn"] = loc.end_column
    if snippet:
        region["snippet"] = {"text": _cap(snippet, MAX_SNIPPET_CHARS)}
    return region


def _location(
    loc: FindingLocation, *, snippet: str | None = None, message: str | None = None
) -> dict[str, Any]:
    physical: dict[str, Any] = {
        "artifactLocation": {"uri": artifact_uri(loc), "uriBaseId": SRCROOT}
    }
    region = _region(loc, snippet)
    if region is not None:
        physical["region"] = region
    out: dict[str, Any] = {"physicalLocation": physical}
    if message is not None:
        out["message"] = {"text": message}
    return out


def message_text(f: Finding, default: Severity | None) -> str:
    """§2.1 template: effective severity first, then the finding's sentence, confidence, steps."""
    head = tk.SEVERITY_LABEL[f.severity]
    if default is not None and default is not f.severity:
        head += f" (rule default {tk.SEVERITY_LABEL[default]})"
    tail = f" Confidence: {f.confidence.value}."
    if f.flow:
        tail += f" Steps: {len(f.flow)} (Show paths)."
    if f.suppression.status is SuppressionStatus.NOT_APPLIED:
        tail += " Suppression NOT APPLIED."
    body = defang_urls(ensure_display_safe(f.message)).strip()
    if body and body[-1] not in ".!?":
        body += "."
    room = MAX_MESSAGE_CHARS - len(head) - len(" · ") - len(tail)
    if len(body) > room:
        body = body[: max(room - 1, 0)].rstrip() + tk.ELLIPSIS
    return f"{head} · {body}{tail}"


def primary_location_line_hash(fp: str) -> str:
    """GitHub-style ``<16 hex>:<n>`` from the line-independent fingerprint (CA-7)."""
    return f"{fp.removeprefix('sha256:')[:16]}:1"


def _code_flow(f: Finding) -> dict[str, Any]:
    steps = f.flow[:MAX_FLOW_LOCATIONS]
    locations = []
    for step in steps:
        role = "sanitiser not recognised" if step.role is FlowRole.CALL else step.role.value
        locations.append(
            {
                "location": _location(step.location, snippet=step.text, message=role),
                "executionOrder": step.index,
                "properties": {"nexvul": {"role": step.role.value}},
            }
        )
    flow: dict[str, Any] = {"threadFlows": [{"locations": locations}]}
    if len(f.flow) > len(steps):
        flow["message"] = {"text": f"Flow truncated: {len(steps)} of {len(f.flow)} steps shown."}
    return flow


def result_object(f: Finding, *, rule_index: int, default: Severity | None) -> dict[str, Any]:
    sink_text = f.flow[-1].text if f.flow and f.flow[-1].role is FlowRole.SINK else None
    out: dict[str, Any] = {
        "ruleId": f.rule_id,
        "ruleIndex": rule_index,
        "level": LEVEL[f.severity],
        "message": {"text": message_text(f, default)},
        "locations": [_location(f.location, snippet=sink_text)],
        "partialFingerprints": {
            "primaryLocationLineHash": primary_location_line_hash(f.fingerprint),
            "nexvulFingerprint/v1": f.fingerprint,
        },
    }
    if f.flow:
        out["codeFlows"] = [_code_flow(f)]
    if f.suppressed:
        sup: dict[str, Any] = {"kind": "inSource", "status": "accepted"}
        if f.suppression.justification:
            sup["justification"] = _cap(f.suppression.justification, MAX_PROPERTY_TEXT_CHARS)
        if f.suppression.line > 0:
            sup["location"] = _location(
                FindingLocation(
                    f.location.path,
                    f.suppression.line,
                    0,
                    f.suppression.line,
                    0,
                    f.location.raw_path_b64,
                )
            )
        out["suppressions"] = [sup]
    nexvul: dict[str, Any] = {
        "severity": f.severity.value,
        "confidence": f.confidence.value,
        "rule_default_severity": default.value if default else None,
        "title": f.title,
        "asi": list(f.asi),
        "cwe": list(f.cwe),
        "fingerprint": f.fingerprint,
        "message": _cap(f.message, MAX_PROPERTY_TEXT_CHARS * 2),
        "evidence": [
            {
                "type": _cap(e.kind, 60),
                "description": _cap(e.description, MAX_PROPERTY_TEXT_CHARS),
                "snippet": _cap(e.snippet, MAX_SNIPPET_CHARS) if e.snippet else None,
            }
            for e in f.evidence
        ],
        "limitations": [_cap(x, MAX_PROPERTY_TEXT_CHARS) for x in f.limitations],
        "suppression": {
            "status": f.suppression.status.value,
            "reason": f.suppression.reason,
        },
        "column_unit": COLUMN_UNIT,
    }
    if f.location.raw_path_b64 is not None:
        nexvul["raw_path_b64"] = f.location.raw_path_b64
    out["properties"] = {"nexvul": nexvul}
    return out


# --------------------------------------------------------------------------------------------
# Invocation / notifications
# --------------------------------------------------------------------------------------------


def _note(
    ident: str,
    level: str,
    text: str,
    *,
    rule: tuple[str, int] | None = None,
    locations: Sequence[dict[str, Any]] = (),
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "descriptor": {"id": ident},
        "level": level,
        "message": {"text": text},
    }
    if rule is not None:
        out["associatedRule"] = {"id": rule[0], "index": rule[1]}
    if locations:
        out["locations"] = list(locations)
    return out


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def _utc(stamp: str) -> str:
    return stamp[:-6] + "Z" if stamp.endswith("+00:00") else stamp


def execution_notifications(result: ScanResult, rule_index: dict[str, int]) -> list[dict[str, Any]]:
    """One notification per completeness gap, most important first."""
    c = result.completeness
    out: list[dict[str, Any]] = []
    if c.status is ScanStatus.PARTIAL:
        out.append(
            _note(
                "nexvul.completeness.partial",
                "error",
                tk.PARTIAL_BANNER.format(
                    not_analysed=c.files_not_analysed, discovered=c.files_discovered
                )
                + (" --allow-partial was set." if c.allow_partial else ""),
            )
        )
    elif c.status is ScanStatus.FAILED:
        if c.failed_cause is FailedCause.NOTHING_TO_ANALYSE:
            cause = "nothing to analyse in the scan root."
        else:
            cause = f"none of the {c.files_discovered} files in scope could be analysed."
        out.append(
            _note("nexvul.completeness.failed", "error", tk.FAILED_BANNER.format(cause=cause))
        )
    for reason, count in c.skipped_by_reason:
        impact = impact_of(reason)
        if impact is Impact.INFO:
            continue
        label = REASON_LABELS.get(reason, reason.value)
        examples = [
            _location(FindingLocation(e.path, 0, 0, 0, 0)) for e in c.skipped if e.reason is reason
        ][:MAX_NOTIFICATION_LOCATIONS]
        if impact is Impact.PARTIAL:
            text = f"{_plural(count, 'file')} not analysed: {label}."
            level = "error"
        else:
            text = (
                f"{_plural(count, 'file')} not analysed by policy: {label} (counted, not partial)."
            )
            level = "note"
        out.append(_note(f"nexvul.skip.{reason.value}", level, text, locations=examples))
    if c.skipped_list_truncated:
        out.append(
            _note(
                "nexvul.skip.list_truncated",
                "note",
                f"{c.skipped_list_truncated} more skipped paths are counted but not listed.",
            )
        )
    for limit in c.limits_hit:
        out.append(
            _note(
                "nexvul.limit_hit",
                "error",
                f"Limit hit: {ensure_display_safe(limit)}. Analysis stopped early.",
            )
        )
    for failure in c.rule_failures:
        out.append(
            _note(
                "nexvul.rule_failure",
                "error",
                f"Rule {failure.rule_id} stopped with {_cap(failure.error_type, 60)}; its results "
                "are incomplete.",
                rule=(failure.rule_id, rule_index[failure.rule_id])
                if failure.rule_id in rule_index
                else None,
            )
        )
    if c.findings_truncated:
        out.append(
            _note(
                "nexvul.findings_truncated",
                "error",
                f"{_plural(c.findings_truncated, 'finding')} dropped by the per-file or total "
                "finding cap.",
            )
        )
    return out


def configuration_notifications(result: ScanResult) -> list[dict[str, Any]]:
    out = []
    for ch in result.config_changes:
        level = "warning" if ch.status is ChangeStatus.APPLIED else "note"
        out.append(_note(f"nexvul.config.{ch.status.value}", level, _cap(ch.display(), 400)))
    return out


def _rule_overrides(
    registry: Registry, result: ScanResult, rule_index: dict[str, int]
) -> list[dict[str, Any]]:
    """Rules whose state in this run differs from ``defaultConfiguration.enabled``."""
    enabled = {r.id for r in result.rules_enabled}
    out = []
    for rule in registry:
        on = rule.meta.id in enabled
        default_on = rule.meta.readiness is Readiness.DEFAULT
        if on != default_on:
            out.append(
                {
                    "descriptor": {"id": rule.meta.id, "index": rule_index[rule.meta.id]},
                    "configuration": {"enabled": on},
                }
            )
    return out


# --------------------------------------------------------------------------------------------
# Assembly
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class SarifLimits:
    max_results: int = MAX_RESULTS
    max_gzip_bytes: int = MAX_GZIP_BYTES


def _dump(data: dict[str, Any], *, pretty: bool) -> str:
    if pretty:
        text = json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False)
    else:
        text = json.dumps(data, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return text + "\n"


def _gzip_size(text: str) -> int:
    return len(gzip.compress(text.encode("utf-8"), compresslevel=6, mtime=0))


def _build(
    result: ScanResult,
    registry: Registry,
    *,
    keep: int | None,
) -> tuple[dict[str, Any], int]:
    """The SARIF log keeping the first ``keep`` results (``None`` = all). Returns (log, total)."""
    rules: list[dict[str, Any]] = [rule_descriptor(r) for r in registry]
    rule_index = {r["id"]: i for i, r in enumerate(rules)}
    defaults = {r.meta.id: r.meta.severity for r in registry}

    uploadable = [
        f for f in (*result.findings, *result.suppressed) if f.severity is not Severity.INFO
    ]
    info_count = sum(
        1 for f in (*result.findings, *result.suppressed) if f.severity is Severity.INFO
    )
    # Severity first (truncation drops the lowest), then active before suppressed.
    uploadable.sort(key=lambda f: (f.sort_key()[0], f.suppressed, f.sort_key()))
    for f in uploadable:
        if f.rule_id not in rule_index:
            rule_index[f.rule_id] = len(rules)
            rules.append(_fallback_descriptor(f))
    total = len(uploadable)
    kept = uploadable if keep is None else uploadable[:keep]
    results = [
        result_object(f, rule_index=rule_index[f.rule_id], default=defaults.get(f.rule_id))
        for f in kept
    ]
    dropped = total - len(kept)

    exec_notes = execution_notifications(result, rule_index)
    if dropped:
        lowest = kept[-1].severity.value if kept else "none"
        exec_notes.insert(
            0,
            _note(
                "nexvul.sarif.truncated",
                "error",
                f"SARIF truncated to GitHub limits: {len(kept)} of {total} results kept "
                f"(highest severity first; lowest kept: {lowest}). {dropped} results are in the "
                "JSON report only (nexvul scan --format json).",
            ),
        )
    invocation: dict[str, Any] = {
        "executionSuccessful": result.status is ScanStatus.COMPLETE and not dropped,
        "exitCode": result.exit_code,
        "startTimeUtc": _utc(result.started_at),
        "endTimeUtc": _utc(result.ended_at),
        "toolExecutionNotifications": exec_notes,
        "toolConfigurationNotifications": configuration_notifications(result),
    }
    overrides = _rule_overrides(registry, result, rule_index)
    if overrides:
        invocation["ruleConfigurationOverrides"] = overrides

    report = report_dict(result)
    run_props = {
        "nexvul": {
            "status": result.status.value,
            "exit_code": result.exit_code,
            "fail_on": result.fail_on.value,
            "completeness": report["completeness"],
            "scan": report["scan"],
            "tool": report["nexvul"],
            "config": report["config"],
            "summary": report["summary"],
            "frameworks": [ensure_display_safe(x) for x in result.frameworks],
            "rules_enabled": [r.id for r in result.rules_enabled],
            "suppression_issues": [
                {
                    k: (ensure_display_safe(v) if isinstance(v, str) else v)
                    for k, v in i.to_dict().items()
                }
                for i in result.suppression_issues
            ],
            "position_encoding": {
                "line_base": 1,
                "column_base": 1,
                "column_unit": COLUMN_UNIT,
                "sarif_column_kind": "utf16CodeUnits",
                "note": (
                    "Columns are 1-based UTF-8 byte offsets. They equal UTF-16 code units when "
                    "the text before the column on that line is ASCII; otherwise they can be "
                    "larger."
                ),
            },
            "sarif": {
                "results_total": total,
                "results_emitted": len(kept),
                "results_dropped": dropped,
                "info_findings_not_uploaded": info_count,
                "limits": {"max_results": MAX_RESULTS, "max_gzip_bytes": MAX_GZIP_BYTES},
            },
            "disclaimer": tk.DISCLAIMER,
            "untrusted_fields": list(UNTRUSTED_FIELDS),
        }
    }
    driver: dict[str, Any] = {
        "name": result.tool.name,
        "version": result.tool.version,
        "semanticVersion": result.tool.version,
        "informationUri": REPO_URL,
        "rules": rules,
        "properties": {
            "nexvul": {
                "rule_pack_version": result.tool.rule_pack_version,
                "rule_pack_sha256": result.tool.rule_pack_sha256,
            }
        },
    }
    log: dict[str, Any] = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {"driver": driver},
                "automationDetails": {"id": AUTOMATION_ID},
                "originalUriBaseIds": {
                    SRCROOT: {
                        "description": {
                            "text": "The scan root. Every artifact URI is relative to it."
                        }
                    }
                },
                "columnKind": "utf16CodeUnits",
                "invocations": [invocation],
                "results": results,
                "properties": run_props,
            }
        ],
    }
    return log, total


def sarif_log(
    result: ScanResult, registry: Registry, *, limits: SarifLimits | None = None
) -> dict[str, Any]:
    """The SARIF log as plain data, within ``limits`` (default: GitHub's)."""
    return _fit(result, registry, limits or SarifLimits(), pretty=False)[0]


def _fit(
    result: ScanResult, registry: Registry, limits: SarifLimits, *, pretty: bool
) -> tuple[dict[str, Any], str]:
    log, total = _build(result, registry, keep=None)
    text = _dump(log, pretty=pretty)
    if total <= limits.max_results and _gzip_size(text) <= limits.max_gzip_bytes:
        return log, text
    # Largest prefix (results sorted by severity) that fits both limits. Binary search.
    lo, hi = 0, min(total, limits.max_results)
    best: tuple[dict[str, Any], str] | None = None
    while lo <= hi:
        mid = (lo + hi) // 2
        cand, _ = _build(result, registry, keep=mid)
        cand_text = _dump(cand, pretty=pretty)
        if _gzip_size(cand_text) <= limits.max_gzip_bytes:
            best = (cand, cand_text)
            lo = mid + 1
        else:
            hi = mid - 1
    if best is None:
        # Even with no results the log is over the limit: emit it anyway (the rule table and
        # notices are needed to explain the run); GitHub's rejection is then visible (A07).
        cand, _ = _build(result, registry, keep=0)
        best = (cand, _dump(cand, pretty=pretty))
    return best


def render_sarif(
    result: ScanResult,
    registry: Registry,
    *,
    pretty: bool = True,
    limits: SarifLimits | None = None,
) -> str:
    """Serialise the SARIF log. Valid UTF-8, newline-terminated, deterministic for one input."""
    return _fit(result, registry, limits or SarifLimits(), pretty=pretty)[1]


_HEAD_PREFIX: Final = (
    '{"$schema":"' + SARIF_SCHEMA_URI + '","version":"2.1.0","runs":[{"tool":{"driver":'
    '{"name":"nexvul"'
).encode("ascii")


def is_nexvul_sarif(head: bytes) -> bool:
    """True when ``head`` (first bytes of an existing file) starts a nexvul SARIF log."""
    compact = b"".join(head.split())
    return compact.startswith(_HEAD_PREFIX)
