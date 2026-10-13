"""Utility screens: ``nexvul rules`` (U01), ``explain`` (U03/U04) and ``doctor`` (U05/U06).

``rules`` and ``explain`` read only the built-in registry metadata (never scanned content,
SR-12). With no rule shipped yet they say so plainly. ``doctor`` checks nexvul's installation,
not the user's code; it reports which resource limits are actually enforced on this platform
(DEC-0013 §2).
"""

from __future__ import annotations

import contextlib
import difflib
import os
import platform
import shutil
import sys
import tempfile
import textwrap
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from nexvul import __version__
from nexvul.core import limits
from nexvul.core.sanitize import display_text
from nexvul.core.startup import find_modules_under_roots
from nexvul.core.workers import OutcomeStatus, WorkerOptions, analyse_files, platform_label
from nexvul.reporting import tokens as tk
from nexvul.rules.base import Readiness, Rule
from nexvul.rules.registry import Registry

# =============================================================================================
# rules / explain
# =============================================================================================

NO_RULES_TEXT = (
    "No detection rules ship in this version of nexvul.\n"
    "nexvul scan discovers and parses files and reports scan completeness;\n"
    "it does not yet look for risky patterns. Rules arrive in a later release.\n"
)


def normalise_rule_id(raw: str) -> str | None:
    """``nex6`` / ``NEX06`` / `` nex006 `` -> ``NEX006``; ``None`` if it is not ID-shaped."""
    text = raw.strip().upper()
    if not text.startswith("NEX"):
        return None
    digits = text[3:]
    if not digits or len(digits) > 3 or not digits.isascii() or not digits.isdigit():
        return None
    return f"NEX{int(digits):03d}"


def render_rules(registry: Registry, *, width: int) -> str:
    if len(registry) == 0:
        return NO_RULES_TEXT
    lines: list[str] = []
    rules = registry.rules
    on = sum(1 for r in rules if r.meta.readiness is Readiness.DEFAULT)
    off = len(rules) - on
    if width >= tk.WIDE_BREAKPOINT:
        lines.append(f"{'ID':<8}{'Title':<62}{'ASI':<16}{'Severity':<10}{'Confidence':<12}Status")
        for r in rules:
            m = r.meta
            title = m.name if len(m.name) <= 60 else m.name[:59] + "…"
            lines.append(
                f"{m.id:<8}{title:<62}{' '.join(m.asi):<16}{m.severity.value:<10}"
                f"{m.confidence.value:<12}{m.readiness.value}"
            )
        lines.append("")
        lines.append(
            f"{len(rules)} rules · {on} on by default · {off} experimental (off) "
            "· nexvul explain <ID> for details"
        )
    else:
        for r in rules:
            m = r.meta
            lines.append(f"{m.id}  {m.name}")
            lines.append(
                f"        {' '.join(m.asi)} · {m.severity.value} · "
                f"confidence {m.confidence.value} · {m.readiness.value}"
            )
        lines.append(f"{len(rules)} rules · {on} on by default · {off} experimental (off)")
        lines.append("nexvul explain <ID> for details")
    return "\n".join(lines) + "\n"


def _section(lines: list[str], heading: str, body: str, width: int) -> None:
    if not body.strip():
        return
    lines.append("")
    lines.append(heading)
    for para in body.split("\n"):
        if not para.strip():
            continue
        if para.startswith("    "):  # code example: keep as written
            lines.append("  " + para[4:])
            continue
        lines.extend(textwrap.wrap(para, width=width, initial_indent="  ", subsequent_indent="  "))


def render_explain(rule: Rule, *, width: int) -> str:
    m = rule.meta
    wrap = min(max(width, tk.MIN_WRAPPED_WIDTH), 80) - 2
    doc = m.doc
    asi_names = doc.asi_names if doc and doc.asi_names else m.asi
    lines = [
        f"{m.id}  {m.name}",
        f"        {' '.join(asi_names)} · default severity {m.severity.value}",
        f"        confidence up to {m.confidence.value} · {m.readiness.value}",
    ]
    if doc is not None:
        _section(lines, "WHAT IT LOOKS FOR", doc.looks_for, wrap)
        _section(lines, "WHY IT MATTERS", doc.why_it_matters, wrap)
        _section(lines, "EXAMPLE (flagged)", doc.example_flagged, wrap)
        _section(lines, "EXAMPLE (not flagged)", doc.example_not_flagged, wrap)
        _section(lines, "HOW TO FIX", doc.how_to_fix, wrap)
        _section(lines, "WHAT THIS RULE DOES NOT DETECT", doc.not_detected, wrap)
    else:
        _section(lines, "HOW TO FIX", m.remediation, wrap)
    lines.append("")
    lines.append("SUPPRESSING THIS FINDING")
    lines.append(f"  # nexvul: ignore[{m.id}] -- <why this is acceptable>")
    lines.append("  In CI the justification after -- is required.")
    if m.references:
        lines.append("")
        lines.append("REFERENCES")
        lines.extend(f"  {ref}" for ref in m.references)
    return "\n".join(lines) + "\n"


def unknown_rule_message(raw: str, registry: Registry) -> str:
    shown = display_text(raw, max_chars=40)
    lines = [f"nexvul: {shown} is not a nexvul rule."]
    if len(registry) == 0:
        lines.append("  No detection rules ship in this version yet.")
    else:
        wanted = normalise_rule_id(raw) or raw.strip().upper()
        hint = difflib.get_close_matches(wanted, sorted(registry.ids()), n=1, cutoff=0.6)
        if hint:
            rule = registry.get(hint[0])
            title = f" ({rule.meta.name})" if rule is not None else ""
            lines.append(f"  Did you mean {hint[0]}{title}?")
    lines.append("  List all rules: nexvul rules")
    return "\n".join(lines) + "\n"


# =============================================================================================
# doctor
# =============================================================================================


@dataclass(frozen=True)
class Check:
    level: str  # ok | info | warn | fail
    text: str
    fix: str = ""


def _home(path: str) -> str:
    home = os.path.expanduser("~")
    if home and home != "~" and (path == home or path.startswith(home + os.sep)):
        return "~" + path[len(home) :]
    return path


def worker_probe() -> bool:
    """Start one real worker and parse a one-line file outside the current directory."""
    tmp = tempfile.mkdtemp(prefix="nexvul-doctor-")
    try:
        fd = os.open(os.path.join(tmp, "probe.py"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, b"x = 1\n")
        finally:
            os.close(fd)
        result = analyse_files(
            tmp, ["probe.py"], options=WorkerOptions(max_workers=1, timeout_seconds=30)
        )
        return bool(result.outcomes) and result.outcomes[0].status is OutcomeStatus.SCANNED
    except Exception:  # any failure to start or talk to a worker is reported, not raised
        return False
    finally:
        with contextlib.suppress(OSError):
            shutil.rmtree(tmp)


def doctor_checks(
    registry: Registry,
    *,
    cwd: str,
    prefix: str,
    probe: Callable[[], bool] = worker_probe,
    os_name: str | None = None,
    package_dir: str | None = None,
) -> list[Check]:
    checks: list[Check] = []
    pkg = package_dir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    checks.append(Check("ok", f'nexvul {__version__} (distribution "nexvul") at {_home(pkg)}'))
    checks.append(Check("ok", f"Python {platform.python_version()} ({sys.implementation.name})"))
    flags = sys.flags
    checks.append(
        Check(
            "info",
            "Interpreter import path: "
            + (
                "isolated (-P or -I)"
                if flags.safe_path or flags.isolated
                else "console script (sys.path[0] is the script directory)"
            ),
        )
    )
    checks.append(
        Check(
            "ok",
            f"Python parser: stdlib ast (CPython {sys.version_info[0]}.{sys.version_info[1]} "
            "grammar)",
        )
    )
    checks.append(
        Check(
            "info",
            "JavaScript/TypeScript, JSON, YAML and TOML parsers are not in this version.",
            "Such files are recorded as not analysed and make scans PARTIAL.",
        )
    )
    if probe():
        checks.append(Check("ok", "Worker processes start and return results (JSON only)"))
    else:
        checks.append(
            Check(
                "fail",
                "Worker processes could not start; every scan would fail.",
                "Reinstall nexvul in its own environment: pipx reinstall nexvul",
            )
        )
    checks.append(
        Check(
            "ok",
            f"Limits enforced per file: wall clock {limits.DEFAULT_PARSE_TIMEOUT_SECONDS:g} s "
            "(process killed), CPU time, no file writes, open files, no core dumps; file size "
            f"{limits.DEFAULT_MAX_FILE_SIZE // limits.MIB} MiB, nesting {limits.MAX_NESTING}, "
            f"{limits.MAX_AST_NODES} syntax nodes",
        )
    )
    name = platform_label(os_name)
    if name == "Linux":
        checks.append(
            Check(
                "ok",
                f"Memory limit enforced: {limits.WORKER_MEMORY_LIMIT_BYTES // limits.GIB} GiB "
                "per worker (RLIMIT_AS and RSS polling)",
            )
        )
    else:
        checks.append(
            Check(
                "info",
                f"limit not enforced: memory ({name}). The operating system does not apply "
                "RLIMIT_AS reliably.",
                "File-size, nesting and node-count caps still bound each file.",
            )
        )
    count = len(registry)
    rules_text = f"{count}" if count else "0 (none ship in this version)"
    checks.append(
        Check(
            "ok",
            f"Built-in rules: {rules_text}; rule pack {registry.pack_version} "
            f"{registry.sha256[:19]}…",
        )
    )
    checks.append(Check("ok", "Plugins: none loaded (rule plugins are not supported before 1.0)"))
    real_cwd = os.path.realpath(cwd)
    real_prefix = os.path.realpath(prefix)
    if real_prefix == real_cwd or real_prefix.startswith(real_cwd.rstrip("/") + "/"):
        checks.append(
            Check(
                "warn",
                f"nexvul is installed inside the current directory ({_home(real_prefix)}). A "
                "malicious dependency of the project could load code into nexvul.",
                "Install nexvul in its own environment: pipx install nexvul",
            )
        )
    shadow = find_modules_under_roots([cwd])
    if shadow:
        names = ", ".join(h.module for h in shadow[:5])
        more = f" and {len(shadow) - 5} more" if len(shadow) > 5 else ""
        checks.append(
            Check(
                "warn",
                f"Modules loaded from the current directory: {names}{more}.",
                "nexvul refuses to scan a directory its own code was loaded from.",
            )
        )
    checks.append(
        Check("info", "Network: nexvul makes no network connections and sends no telemetry")
    )
    return checks


def render_doctor(checks: Sequence[Check], *, width: int) -> tuple[str, int]:
    wrap = max(min(width, 100), tk.MIN_WRAPPED_WIDTH)
    lines = ["nexvul doctor", ""]
    for check in checks:
        first = f"  {check.level:<6}"
        lines.extend(
            textwrap.wrap(check.text, width=wrap, initial_indent=first, subsequent_indent=" " * 8)
        )
        if check.fix:
            lines.extend(
                textwrap.wrap(
                    check.fix, width=wrap, initial_indent=" " * 8, subsequent_indent=" " * 8
                )
            )
    warns = sum(1 for c in checks if c.level == "warn")
    fails = sum(1 for c in checks if c.level == "fail")
    lines.append("")
    if warns or fails:
        lines.append(
            f"{warns} warning{'s' if warns != 1 else ''}, {fails} failure"
            f"{'s' if fails != 1 else ''}. Exit code 1. {tk.DOCTOR_SCOPE}"
        )
        return "\n".join(lines) + "\n", 1
    lines.append(f"All checks ok. {tk.DOCTOR_SCOPE}")
    return "\n".join(lines) + "\n", 0
