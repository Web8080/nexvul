"""JSON reporter (architecture §12; screen J01; threat-model §7; SR-10, SR-18, SR-24, SR-27).

* Versioned shape: ``nexvul.schema_version`` (semver). The JSON Schema ships in the package at
  ``nexvul/schemas/report-1.0.0.json``; nexvul never fetches a ``$schema`` URL (SR-23).
* ``completeness`` is a required top-level object, computed from trusted accounting.
* Effective config is reported per key with its source(s), plus every config file (path, source,
  SHA-256) and every weakening change with ``applied`` / ``not_applied`` (SR-15, SR-27).
* No absolute paths: the scan target is its basename; every file path is repo-relative (SR-24).
* Every repository-derived string was sanitised when the result was built (no control, bidi or
  surrogate characters) and is passed through ``ensure_display_safe`` again here, so the file is
  valid UTF-8. Fields holding repository-derived text are listed in ``untrusted_fields`` so that
  downstream consumers (including LLM agents) can segregate it (T-23).
* Suppressed findings are kept (``suppressed[]``, each ``suppressed: true``) - never dropped.
"""

from __future__ import annotations

import json
from typing import Any

from nexvul.core.completeness import Impact, impact_of
from nexvul.core.sanitize import ensure_display_safe
from nexvul.findings.model import (
    COLUMN_UNIT,
    REPORT_SCHEMA_VERSION,
    SEVERITIES_DESCENDING,
    Finding,
    FindingLocation,
)
from nexvul.findings.result import ScanResult
from nexvul.reporting import tokens as tk

REPORT_FORMAT = "nexvul-json"

#: JSON paths whose values come from the scanned repository (T-23).
UNTRUSTED_FIELDS: tuple[str, ...] = (
    "scan.target",
    "scan.commit",
    "config.effective[].value",
    "config.sources[].path",
    "config.changes[].detail",
    "completeness.files_skipped[].path",
    "completeness.protections_weakened_by_repo_config[]",
    "findings[].file",
    "findings[].message",
    "findings[].dataflow[].file",
    "findings[].dataflow[].code",
    "findings[].evidence[].description",
    "findings[].evidence[].snippet",
    "findings[].limitations[]",
    "findings[].suppression.justification",
    "suppressed[].file",
    "suppressed[].message",
    "suppressed[].dataflow[].file",
    "suppressed[].dataflow[].code",
    "suppressed[].evidence[].description",
    "suppressed[].evidence[].snippet",
    "suppressed[].limitations[]",
    "suppressed[].suppression.justification",
    "suppressions[].path",
    "suppressions[].message",
    "analysis_limited[].path",
)

_FINDING_UNTRUSTED: tuple[str, ...] = (
    "file",
    "message",
    "dataflow[].file",
    "dataflow[].code",
    "evidence[].description",
    "evidence[].snippet",
    "limitations[]",
    "suppression.justification",
)


def _s(value: str) -> str:
    return ensure_display_safe(value)


def _opt(value: str | None) -> str | None:
    return None if value is None else ensure_display_safe(value)


def _position(loc: FindingLocation) -> dict[str, Any]:
    return {
        "file": _s(loc.path),
        "line": loc.line,
        "column": loc.column,
        "end_line": loc.end_line,
        "end_column": loc.end_column,
        "raw_path_b64": loc.raw_path_b64,
    }


def finding_to_dict(f: Finding) -> dict[str, Any]:
    out: dict[str, Any] = {
        "rule_id": f.rule_id,
        "title": f.title,
        "severity": f.severity.value,
        "confidence": f.confidence.value,
        "owasp": list(f.asi),
        "cwe": list(f.cwe),
    }
    out.update(_position(f.location))
    out.update(
        {
            "message": _s(f.message),
            "fingerprint": f.fingerprint,
            "dataflow": [
                {
                    "step": step.index,
                    "role": step.role.value,
                    "file": _s(step.location.path),
                    "line": step.location.line,
                    "column": step.location.column,
                    "code": _s(step.text),
                }
                for step in f.flow
            ],
            "evidence": [
                {"type": _s(e.kind), "description": _s(e.description), "snippet": _opt(e.snippet)}
                for e in f.evidence
            ],
            "limitations": [_s(x) for x in f.limitations],
            "remediation": f.remediation,
            "references": list(f.references),
            "suppressed": f.suppressed,
            "suppression": {
                "status": f.suppression.status.value,
                "kind": f.suppression.kind,
                "line": f.suppression.line,
                "justification": _opt(f.suppression.justification),
                "reason": f.suppression.reason,
            },
            "untrusted_fields": list(_FINDING_UNTRUSTED),
        }
    )
    return out


def report_dict(result: ScanResult) -> dict[str, Any]:
    """The report as plain JSON-ready data, keys in J01 order."""
    c = result.completeness
    counts = result.counts()
    weakened = [_s(change.display()) for change in result.config_changes]
    sources = [
        {
            "source": p.source.value,
            "path": _s(p.display_path),
            "sha256": p.sha256 or None,
            "ref": _opt(p.ref),
        }
        for p in result.config_sources
    ]
    return {
        "nexvul": {
            "report_format": REPORT_FORMAT,
            "schema_version": REPORT_SCHEMA_VERSION,
            "version": result.tool.version,
            "rule_pack": {
                "version": result.tool.rule_pack_version,
                "sha256": result.tool.rule_pack_sha256,
                "rules": result.rules_available,
            },
            "python": result.tool.python,
            "platform": result.tool.platform,
            "parsers": list(result.tool.parsers),
            "plugins_loaded": [],
        },
        "scan": {
            "target": _s(result.target_name),
            "mode": result.discovery_mode,
            "commit": _opt(result.commit),
            "started_at": result.started_at,
            "ended_at": result.ended_at,
            "ci": result.ci,
            "ci_reason": _s(result.ci_reason),
            "scope": c.scope,
            "position_encoding": {"line_base": 1, "column_base": 1, "column_unit": COLUMN_UNIT},
        },
        "config": {
            "effective": [
                {"key": e.key, "value": _s(e.value), "sources": list(e.sources)}
                for e in result.effective_config
            ],
            "sources": sources,
            "changes": [
                {
                    "key": ch.key,
                    "detail": _s(ch.detail),
                    "source": ch.source.value,
                    "status": ch.status.value,
                    "reason": ch.reason,
                }
                for ch in result.config_changes
            ],
        },
        "completeness": {
            "status": c.status.value,
            "failed_cause": c.failed_cause.value if c.failed_cause else None,
            "files_discovered": c.files_discovered,
            "files_analysed": c.files_analysed,
            "files_not_analysed": c.files_not_analysed,
            "files_failed": c.files_failed,
            "files_timed_out": c.files_timed_out,
            "files_skipped": [
                {
                    "path": _s(e.path),
                    "reason": e.reason.value,
                    "detail": _s(e.detail),
                    "makes_partial": impact_of(e.reason) is Impact.PARTIAL,
                }
                for e in c.skipped
            ],
            "files_skipped_truncated": c.skipped_list_truncated,
            "skipped_by_reason": {r.value: n for r, n in c.skipped_by_reason},
            "limits_hit": list(c.limits_hit),
            "analysis_budgets_exhausted": [],
            "rule_failures": [
                {"rule_id": f.rule_id, "error_type": _s(f.error_type)} for f in c.rule_failures
            ],
            "findings_truncated": c.findings_truncated,
            "suppressed": {"inline": c.suppressed_inline, "baseline": 0},
            "protections_weakened_by_repo_config": weakened,
            "config_sources": sources,
            "plugins_loaded": [],
            "dynamic_constructs_not_analysed": c.dynamic_constructs_not_analysed,
            "allow_partial": c.allow_partial,
            "notes": [_s(n) for n in c.notes],
        },
        "summary": {
            "status": c.status.value,
            "exit_code": result.exit_code,
            "fail_on": result.fail_on.value,
            "findings": len(result.findings),
            "by_severity": {s.value: counts[s] for s in SEVERITIES_DESCENDING},
            "at_or_above_fail_on": len(result.at_or_above),
            "suppressed": len(result.suppressed),
            "rules": {
                "available": result.rules_available,
                "enabled": [r.id for r in result.rules_enabled],
                "failed": list(result.rules_failed),
            },
            "disclaimer": tk.DISCLAIMER,
        },
        "findings": [finding_to_dict(f) for f in result.findings],
        "suppressed": [finding_to_dict(f) for f in result.suppressed],
        "suppressions": [i.to_dict() for i in result.suppression_issues],
        "analysis_limited": [
            {"path": _s(n.path), "line": n.line, "reason": n.reason} for n in result.limited
        ],
        "untrusted_fields": list(UNTRUSTED_FIELDS),
    }


def render_json(result: ScanResult, *, pretty: bool) -> str:
    """Serialise the report. Valid UTF-8, no NaN, newline-terminated."""
    data = report_dict(result)
    if pretty:
        text = json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False)
    else:
        text = json.dumps(data, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return text + "\n"


def is_nexvul_report(head: bytes) -> bool:
    """True when ``head`` (the first bytes of an existing file) starts a nexvul JSON report."""
    compact = b"".join(head.split())
    return compact.startswith(b'{"nexvul":{"report_format":"' + REPORT_FORMAT.encode() + b'"')
