"""Terminal reporter (terminal-mockups T02-T19; design-system §3-5; SR-10, SR-11, SR-18).

Rules this module enforces:

* **Untrusted text is never styled and never interpreted.** Every string that comes from the
  scanned repository (paths, messages, flow code, justifications) was sanitised when the result
  was built and passes through :func:`ensure_display_safe` again here. There is no markup
  language: SGR codes are added only around trusted text (labels, rule IDs, titles, status
  words), so a filename such as ``[link=https://x]a.py`` is printed literally.
* With colour off (``NO_COLOR``, ``--no-color``, ``TERM=dumb``, not a TTY) the output contains
  **zero** ESC bytes and uses the plain layout (T15): ASCII meter and rules, no blank lines inside
  a finding.
* Order: header, findings, suppressions, completeness, then the **result line last**. For a
  partial scan the fixed ``PARTIAL SCAN`` banner follows the result line and is the final line
  (threat model §7 rule 2; T05). The completeness block is always present.
* "No findings from enabled rules" is printed only for a complete scan with no active finding,
  and always with its disclaimer. A partial scan never prints it (T06).
* Widths: >= 120 wide layout; 80-119 standard; 40-79 stacked (T16); < 40 standard layout without
  wrapping. Body text wraps at ``min(width - 2, 100)``.

Known limitation: widths count code points; East Asian wide characters may overflow a line.
"""

from __future__ import annotations

import textwrap
from dataclasses import dataclass

from nexvul.core.completeness import FAILED_REASONS, Impact, SkipReason, impact_of
from nexvul.core.config import ChangeStatus, ConfigChange, ConfigSource
from nexvul.core.sanitize import ensure_display_safe
from nexvul.findings.model import (
    SEVERITIES_DESCENDING,
    Finding,
    FlowRole,
    Severity,
    SuppressionStatus,
)
from nexvul.findings.result import FailedCause, ScanResult, ScanStatus
from nexvul.reporting import tokens as tk
from nexvul.rules.suppressions import IssueKind

_NOWRAP = 10**6

REASON_LABELS: dict[SkipReason, str] = {
    SkipReason.PARSE_ERROR: "parse error",
    SkipReason.PARSER_CRASHED: "parser crashed",
    SkipReason.TIMEOUT: "parser timeout",
    SkipReason.MEMORY_LIMIT: "memory limit",
    SkipReason.MAX_NESTING: "nesting too deep",
    SkipReason.MAX_AST_NODES: "too many nodes",
    SkipReason.NON_UTF8_UNDECODABLE: "undecodable text",
    SkipReason.SYNTAX_UNSUPPORTED_BY_RUNTIME: "newer syntax",
    SkipReason.PARSER_UNAVAILABLE: "no parser yet",
    SkipReason.MAX_FILE_SIZE: "over size limit",
    SkipReason.BINARY: "binary content",
    SkipReason.CHANGED_DURING_SCAN: "changed in scan",
    SkipReason.OPEN_FAILED: "could not open",
    SkipReason.TRACKED_MISSING_ON_DISK: "missing on disk",
    SkipReason.MAX_DEPTH: "too deep in tree",
    SkipReason.MAX_FILES: "over max_files",
    SkipReason.MAX_TOTAL_BYTES: "over total size",
    SkipReason.UNREADABLE_DIRECTORY: "unreadable dir",
    SkipReason.SUBMODULE_NOT_SCANNED: "git submodule",
    SkipReason.SYMLINK_NOT_FOLLOWED: "symlinks not followed",
    SkipReason.SYMLINK_ESCAPES_ROOT: "symlinks outside root",
    SkipReason.SPECIAL_FILE: "special files",
    SkipReason.EXCLUDED_BY_CONFIG: "excluded by config",
    SkipReason.DEFAULT_EXCLUDED_DIR: "default-excluded dirs",
    SkipReason.UNSUPPORTED_FILE_TYPE: "unsupported file type",
    SkipReason.VCS_METADATA: "version-control metadata",
    SkipReason.NEXVUL_CONFIG: "nexvul config file",
}

LANGUAGE_NAMES = {
    "python": "Python",
    "typescript": "TypeScript",
    "javascript": "JavaScript",
    "json": "JSON",
}


@dataclass(frozen=True)
class TerminalStyle:
    width: int = tk.DEFAULT_WIDTH_UNKNOWN
    color: bool = False
    plain: bool = True  # T15 layout: compact spacing
    ascii: bool = True  # ASCII meter, rules and separators
    verbose: bool = False

    @property
    def layout(self) -> str:
        if self.width >= tk.WIDE_BREAKPOINT:
            return "wide"
        if self.width >= tk.NARROW_BREAKPOINT:
            return "standard"
        if self.width >= tk.MIN_WRAPPED_WIDTH:
            return "narrow"
        return "nowrap"


class _Writer:
    def __init__(self, style: TerminalStyle) -> None:
        self.s = style
        self.lines: list[str] = []
        layout = style.layout
        self.width = _NOWRAP if layout == "nowrap" else style.width
        self.rule_width = 80 if layout == "nowrap" else style.width
        self.body = _NOWRAP if layout == "nowrap" else min(style.width - 2, tk.BODY_WRAP_MAX)
        self.narrow = layout == "narrow"
        self.wide = layout == "wide"
        self.lead = "" if self.narrow else " "
        self.dot = tk.SEPARATOR_DOT_ASCII if style.ascii else tk.SEPARATOR_DOT
        self.ell = tk.ELLIPSIS_ASCII if style.ascii else tk.ELLIPSIS

    # -- primitives ------------------------------------------------------------------------

    def sgr(self, text: str, code: str) -> str:
        if not self.s.color or not code or not text:
            return text
        return f"\x1b[{code}m{text}\x1b[0m"

    def add(self, line: str = "") -> None:
        self.lines.append(line.rstrip(" "))

    def blank(self) -> None:
        if self.lines and self.lines[-1] != "":
            self.lines.append("")

    def gap(self) -> None:
        """A blank line that the plain (CI) layout omits."""
        if not self.s.plain:
            self.blank()

    def sep(self) -> None:
        char = tk.RULE_CHAR_ASCII if self.s.ascii else tk.RULE_CHAR
        self.add(self.sgr(char * self.rule_width, tk.DIM_SGR))

    def wrap(self, text: str, first: str, rest: str, width: int | None = None) -> list[str]:
        limit = self.body if width is None else width
        if limit >= _NOWRAP:
            return [first + text]
        wrapper = textwrap.TextWrapper(
            width=max(limit, len(first) + 10),
            initial_indent=first,
            subsequent_indent=rest,
            break_long_words=True,
            break_on_hyphens=False,
            replace_whitespace=False,
            drop_whitespace=True,
        )
        return wrapper.wrap(text) or [first.rstrip()]

    def para(self, text: str, first: str, rest: str, width: int | None = None) -> None:
        for line in self.wrap(text, first, rest, width):
            self.add(line)

    def kv(self, label: str, value: str, *, indent: int = 2, col: int = 12) -> None:
        first = " " * indent + label.ljust(max(col, len(label) + 2))
        self.para(value, first, " " * len(first), self.width if not self.narrow else self.body)


def _safe(text: str) -> str:
    return ensure_display_safe(text)


def _plural(n: int, word: str, plural: str | None = None) -> str:
    return f"{n} {word if n == 1 else (plural or word + 's')}"


# =============================================================================================
# Header
# =============================================================================================


def _languages(result: ScanResult) -> str:
    if not result.languages_analysed:
        return ""
    parts = [f"{LANGUAGE_NAMES.get(lang, lang)} {n}" for lang, n in result.languages_analysed]
    return " (" + ", ".join(parts) + ")"


def _rules_text(result: ScanResult) -> str:
    if result.rules_available == 0:
        return "none ship in this version"
    return f"{len(result.rules_enabled)} of {result.rules_available} enabled"


def _config_text(result: ScanResult, *, with_hash: bool, ell: str) -> str:
    parts: list[str] = []
    for prov in result.config_sources:
        if prov.source is ConfigSource.REPO:
            where = "repository, tighten-only in CI" if result.ci else "local"
            if with_hash and prov.sha256:
                where += f", sha256 {prov.sha256[:4]}{ell}"
            parts.append(f"{_safe(prov.display_path)} ({where})")
        elif prov.source is ConfigSource.CLI:
            parts.append("command line")
        else:
            parts.append(f"{_safe(prov.display_path)} ({prov.source.value})")
    return " + ".join(parts) if parts else "defaults"


def _frameworks_text(result: ScanResult) -> str:
    if result.frameworks:
        return ", ".join(_safe(f) for f in result.frameworks)
    return "none recognised (MCP client configs only in this version)"


def _header(w: _Writer, result: ScanResult) -> None:
    title = f"nexvul {result.tool.version}"
    target = _safe(result.target)
    if w.narrow:
        w.add(f"{w.sgr(title, tk.BOLD_SGR)}  {target}")
        c = result.completeness
        w.para(
            f"{c.files_analysed} of {c.files_discovered} files {w.dot} rules: {_rules_text(result)}"
            f" {w.dot} fail-on {result.fail_on.value}",
            "  ",
            "  ",
        )
        w.para(_frameworks_text(result), "  ", "  ")
        if result.ci:
            w.para(f"CI mode ({_safe(result.ci_reason)})", "  ", "  ")
        w.sep()
        return
    w.add(f"{w.sgr(title, tk.BOLD_SGR)}  scan of {target}")
    c = result.completeness
    files = f"{c.files_analysed} of {c.files_discovered} analysed{_languages(result)}"
    rules = f"{_rules_text(result)} {w.dot} fail-on {result.fail_on.value}"
    config = _config_text(result, with_hash=w.wide, ell=w.ell)
    frameworks = _frameworks_text(result)
    left_col = 75
    if (
        w.wide
        and len("  Files       " + files) <= left_col
        and len("  Rules       " + rules) <= left_col
        and left_col + 2 + 12 + max(len(frameworks), len(config)) <= w.width
    ):
        w.add(("  Files       " + files).ljust(left_col) + "  Frameworks  " + frameworks)
        w.add(("  Rules       " + rules).ljust(left_col) + "  Config      " + config)
    else:
        w.kv("Files", files)
        w.kv("Frameworks", frameworks)
        w.kv("Rules", f"{rules} {w.dot} config {config}")
    if result.ci:
        w.kv(
            "Mode",
            f"CI ({_safe(result.ci_reason)}) {w.dot} inline suppressions need a justification "
            f"{w.dot} repository config may only tighten the scan",
        )
    if w.s.verbose:
        _verbose(w, result)
    w.sep()


def _verbose(w: _Writer, result: ScanResult) -> None:
    w.add("  Effective config")
    for setting in result.effective_config:
        w.add(f"    {setting.key:<24}{_safe(setting.value):<16}{', '.join(setting.sources)}")
    for change in result.config_changes:
        w.para(_safe(change.display()), "    change  ", "            ")
    w.kv("Plugins", "none loaded (rule plugins are not supported before 1.0)", col=26)
    w.kv(
        "Rule pack",
        f"{result.tool.rule_pack_version} {result.tool.rule_pack_sha256}",
        col=26,
    )
    w.kv("Parsers", "; ".join(result.tool.parsers), col=26)
    if result.timings:
        timing = f" {w.dot} ".join(f"{name} {secs:.2f} s" for name, secs in result.timings)
        w.kv("Timings", timing, col=26)
    if result.limited:
        first = True
        for note in result.limited:
            w.kv(
                "Analysis-limited" if first else "",
                f"{_safe(note.path)}:{note.line}  {note.reason}",
                col=26,
            )
            first = False
    c = result.completeness
    shown = 0
    for entry in c.skipped:
        if shown >= tk.VERBOSE_SKIP_PATHS_MAX:
            break
        detail = f" ({_safe(entry.detail)})" if entry.detail else ""
        w.kv(
            "Not analysed" if shown == 0 else "",
            f"{_safe(entry.path)}  {REASON_LABELS.get(entry.reason, entry.reason.value)}{detail}",
            col=26,
        )
        shown += 1
    hidden = len(c.skipped) - shown + c.skipped_list_truncated
    if hidden > 0:
        w.kv("", f"and {hidden} more", col=26)


# =============================================================================================
# Findings
# =============================================================================================


def _meter(w: _Writer, sev: Severity) -> str:
    return (tk.SEVERITY_METER_ASCII if w.s.ascii else tk.SEVERITY_METER)[sev]


def _location(f: Finding) -> str:
    loc = f.location
    text = _safe(loc.path)
    if loc.line:
        text += f":{loc.line}"
        if loc.column:
            text += f":{loc.column}"
    return text


def _tags(w: _Writer, f: Finding) -> str:
    if w.s.plain:
        return f"{', '.join(f.asi)} {w.dot} confidence {f.confidence.value}"
    return f" {w.dot} ".join((*f.asi, f"confidence {f.confidence.value}"))


def _finding(w: _Writer, f: Finding) -> None:
    label = tk.SEVERITY_LABEL[f.severity]
    sev_code = tk.SEVERITY_SGR[f.severity]
    meter = _meter(w, f.severity)
    location = _location(f)
    w.blank()
    if w.narrow:
        w.add(
            f"{w.sgr(label, sev_code)} {w.sgr(meter, sev_code)}  {w.sgr(f.rule_id, tk.ACCENT_SGR)}"
        )
        for line in w.wrap(f.title, "", "", w.width):
            w.add(w.sgr(line, tk.BOLD_SGR))
        w.para(_tags(w, f), "", "", w.width)
        w.para(location, "", "", w.width)
        indent = "  "
    else:
        head_plain = f" {label:<8} {meter}  {f.rule_id}  "
        hang = " " * len(head_plain)
        styled_head = (
            f" {w.sgr(label, sev_code)}{' ' * (8 - len(label))} {w.sgr(meter, sev_code)}  "
            f"{w.sgr(f.rule_id, tk.ACCENT_SGR)}  "
        )
        title_lines = w.wrap(f.title, "", "", w.width - len(head_plain))
        right = ""
        if (
            w.wide
            and len(title_lines) == 1
            and len(head_plain) + len(title_lines[0]) + 2 + len(location) <= w.width
        ):
            pad = w.width - len(head_plain) - len(title_lines[0]) - len(location)
            right = " " * pad + location
        w.add(styled_head + w.sgr(title_lines[0], tk.BOLD_SGR) + right)
        for line in title_lines[1:]:
            w.add(hang + w.sgr(line, tk.BOLD_SGR))
        tag_hang = " " * len(f" {label:<8} {meter}  ")
        w.para(_tags(w, f), tag_hang, tag_hang, w.width)
        if not right:
            w.para(location, tag_hang, tag_hang, w.width)
        indent = "    "
    w.gap()
    w.para(_safe(f.message), indent, indent)
    if f.suppression.status is SuppressionStatus.NOT_APPLIED:
        w.para(
            f"Suppression on line {f.suppression.line} NOT APPLIED: {_safe(f.suppression.reason)}.",
            indent,
            indent,
        )
    if f.flow:
        w.gap()
        _flow(w, f, indent)
    w.gap()
    fix_label = "Fix   " if w.wide else "Fix  "
    w.para(_safe(f.remediation), indent + fix_label, indent + " " * len(fix_label))


def _role_word(w: _Writer, role: FlowRole) -> tuple[str, str]:
    if role is FlowRole.SOURCE:
        return "source", w.sgr("source", tk.SOURCE_WORD_SGR)
    if role is FlowRole.SINK:
        return "sink", w.sgr("sink", tk.SINK_WORD_SGR)
    if role is FlowRole.CALL:
        return "call", "call"
    return "", ""


def _truncate(w: _Writer, text: str, room: int) -> str:
    if w.s.verbose or room >= _NOWRAP or len(text) <= room:
        return text
    keep = max(room - len(w.ell), 1)
    return text[:keep] + w.ell


def _flow(w: _Writer, f: Finding, indent: str) -> None:
    locs = [
        f"{_safe(s.location.path)}:{s.location.line}" if s.location.line else _safe(s.location.path)
        for s in f.flow
    ]
    loc_w = max(len(x) for x in locs)
    if w.narrow:
        w.add(indent + "Flow")
        for step, loc in zip(f.flow, locs, strict=True):
            plain_role, role = _role_word(w, step.role)
            num = f"{step.index}"
            w.add(f"{indent}{num} {role}{' ' * (6 - len(plain_role))} {loc}")
            hang = indent + " " * (len(num) + 8)
            w.add(hang + _truncate(w, _safe(step.text), w.width - len(hang)))
        return
    if w.wide:
        first_prefix, rest_prefix = indent + "Flow  ", indent + "      "
    else:
        w.add(indent + "Flow")
        first_prefix = rest_prefix = indent + "  "
    for i, (step, loc) in enumerate(zip(f.flow, locs, strict=True)):
        plain_role, role = _role_word(w, step.role)
        prefix = first_prefix if i == 0 else rest_prefix
        lead = f"{prefix}{step.index} "
        cell = f"{role}{' ' * (6 - len(plain_role))}  {loc.ljust(loc_w)}  "
        visible = len(lead) + 6 + 2 + loc_w + 2
        w.add(lead + cell + _truncate(w, _safe(step.text), w.body - visible))


def _findings(w: _Writer, result: ScanResult) -> None:
    for f in result.findings:
        _finding(w, f)
    if result.findings:
        w.blank()
        top = result.findings[0].rule_id
        w.add(f"{w.lead}Learn a rule: nexvul explain {top}")


# =============================================================================================
# Suppressions
# =============================================================================================


def _suppressions(w: _Writer, result: ScanResult) -> None:
    not_applied = [
        f for f in result.findings if f.suppression.status is SuppressionStatus.NOT_APPLIED
    ]
    rejected = [i for i in result.suppression_issues if i.kind is IssueKind.REJECTED]
    unmatched = [i for i in result.suppression_issues if i.kind is IssueKind.UNMATCHED]
    if not (result.suppressed or not_applied or rejected or unmatched):
        return
    lead = w.lead
    sub = lead + "  "
    if result.suppressed or not_applied or unmatched:
        w.blank()
        w.add(f"{lead}{w.sgr('Suppressed', tk.BOLD_SGR)} ({len(result.suppressed)})")
        for f in (*result.suppressed, *not_applied):
            where = f"{_safe(f.location.path)}:{f.suppression.line}"
            just = (
                f'"{_safe(f.suppression.justification)}"'
                if f.suppression.justification
                else "(no justification)"
            )
            if f.suppression.status is SuppressionStatus.NOT_APPLIED:
                just += f" {w.dot} NOT APPLIED: {_safe(f.suppression.reason)}"
            first = f"{sub}{f.rule_id}  {where}  inline  "
            w.para(just, first, " " * len(first), w.width)
        for issue in unmatched:
            w.para(
                f"{_safe(issue.path)}:{issue.line}  {_safe(issue.message)}",
                sub + "unmatched  ",
                sub + "           ",
                w.width,
            )
    if rejected:
        w.blank()
        w.add(f"{lead}{w.sgr('Rejected suppressions', tk.BOLD_SGR)} ({len(rejected)})")
        for issue in rejected:
            first = f"{sub}{_safe(issue.path)}:{issue.line}  "
            w.para(_safe(issue.message), first, sub + "  ", w.width)


# =============================================================================================
# Completeness
# =============================================================================================


def _change_text(change: ConfigChange) -> str:
    if change.status is ChangeStatus.NOT_APPLIED:
        why = (
            "repository config; CI mode"
            if change.source is ConfigSource.REPO
            else change.source.value
        )
        return f"{change.key}: {_safe(change.detail)} NOT APPLIED ({why})"
    where = {
        ConfigSource.REPO: "local config",
        ConfigSource.CLI: "command line",
        ConfigSource.DEFAULT: "enabled wins",
    }.get(change.source, change.source.value)
    return f"{change.key}: {_safe(change.detail)} (applied; {where})"


def _skip_rows(w: _Writer, result: ScanResult) -> list[tuple[str, int, str]]:
    c = result.completeness
    rows: list[tuple[str, int, str]] = []
    for reason, count in c.skipped_by_reason:
        if impact_of(reason) is not Impact.PARTIAL:
            continue
        paths = [e for e in c.skipped if e.reason is reason]
        shown = paths[: tk.INLINE_SKIP_PATHS_MAX]
        text = ", ".join(_safe(e.path) for e in shown)
        if len(shown) == 1 and shown[0].detail:
            text += f" ({_safe(shown[0].detail)})"
        more = count - len(shown)
        if more > 0:
            text += f"{', ' if text else ''}and {more} more"
        rows.append((REASON_LABELS.get(reason, reason.value), count, text))
    return rows


def _completeness(w: _Writer, result: ScanResult) -> None:
    c = result.completeness
    status_word = {
        ScanStatus.COMPLETE: "COMPLETE",
        ScanStatus.PARTIAL: "PARTIAL",
        ScanStatus.FAILED: "FAILED",
    }[c.status]
    status_code = {
        ScanStatus.COMPLETE: tk.STATUS_COMPLETE_SGR,
        ScanStatus.PARTIAL: tk.STATUS_PARTIAL_SGR,
        ScanStatus.FAILED: tk.STATUS_FAILED_SGR,
    }[c.status]
    lead = w.lead
    col = 18 if w.wide else 14
    row_indent = len(lead) + 2

    def row(label: str, value: str) -> None:
        w.kv(label, value, indent=row_indent, col=col)

    counts = (
        f"{_plural(_skipped_count(result), 'skipped', 'skipped')} {w.dot} "
        f"{_plural(_parse_errors(result), 'parse error')} {w.dot} "
        f"{_plural(c.files_timed_out, 'timeout')}"
    )
    w.blank()
    heading = w.sgr("Scan completeness", tk.BOLD_SGR)
    if w.wide:
        summary = (
            f"{w.sgr(status_word, status_code)} {w.dot} "
            f"{c.files_analysed} of {c.files_discovered} files analysed"
        )
        if c.status is ScanStatus.COMPLETE:
            summary += f" {w.dot} {counts}"
        w.add(f"{lead}{heading}   {summary}")
    else:
        w.add(f"{lead}{heading}")
        row("Status", w.sgr(status_word, status_code))
        analysed = f"{c.files_analysed} of {c.files_discovered} files"
        if c.status is ScanStatus.COMPLETE:
            analysed += f" {w.dot} {counts}"
        row("Analysed", analysed)
    skip_rows = _skip_rows(w, result)
    if skip_rows:
        if not w.wide:
            row("Not analysed", _plural(c.files_not_analysed, "file"))
        label_w = max(len(r[0]) for r in skip_rows)
        base = " " * (row_indent + col)
        for i, (label, count, text) in enumerate(skip_rows):
            if w.wide:
                start = " " * row_indent + ("Not analysed" if i == 0 else "").ljust(col)
            else:
                start = base + "  "
            first = f"{start}{label.ljust(label_w)}  {count:>3}   "
            w.para(text or "-", first, " " * len(first), w.width)
    if c.status is not ScanStatus.COMPLETE:
        row("Limits hit", ", ".join(c.limits_hit) if c.limits_hit else "none")
    other = [
        f"{REASON_LABELS.get(r, r.value)}: {n}"
        for r, n in c.skipped_by_reason
        if impact_of(r) is not Impact.PARTIAL
    ]
    if other:
        row("Not in scope", f" {w.dot} ".join(other))
    row("Rules run", _rules_run_text(result))
    for failure in c.rule_failures:
        row(
            "Rule error",
            f"{_safe(failure.rule_id)} raised {_safe(failure.error_type)}; its results are "
            "incomplete",
        )
    if c.findings_truncated:
        row("Findings cap", f"{c.findings_truncated} findings not reported (cap reached)")
    if result.suppressed or c.suppressed_inline:
        row("Suppressed", f"{c.suppressed_inline} inline")
    for change in result.config_changes:
        row("Weakened", _change_text(change))
    if c.allow_partial and c.status is not ScanStatus.COMPLETE:
        row("Allow partial", "--allow-partial: a partial scan does not exit 3")
    if c.dynamic_constructs_not_analysed:
        row(
            "Not followed",
            f"{_plural(c.dynamic_constructs_not_analysed, 'dynamic construct')} "
            "(analysis-limited; see --verbose)",
        )
    for note in c.notes:
        row("Note", _safe(note))
    if c.status is not ScanStatus.COMPLETE and c.files_not_analysed:
        w.gap()
        w.para(
            "Code in these files was not checked. Run with --verbose for details.",
            " " * row_indent,
            " " * row_indent,
        )


def _skipped_count(result: ScanResult) -> int:
    c = result.completeness
    return sum(
        n
        for r, n in c.skipped_by_reason
        if r not in FAILED_REASONS
        and r is not SkipReason.TIMEOUT
        and impact_of(r) is Impact.PARTIAL
    )


def _parse_errors(result: ScanResult) -> int:
    return result.completeness.files_failed


def _rules_run_text(result: ScanResult) -> str:
    if result.rules_available == 0:
        return "0 (no detection rules ship in this version)"
    if result.completeness.status is ScanStatus.FAILED:
        return "none (nothing was analysed)"
    done = len(result.rules_enabled) - len(result.rules_failed)
    return f"{done} of {len(result.rules_enabled)} enabled rules finished"


# =============================================================================================
# Result line and banners
# =============================================================================================


def _counts(result: ScanResult) -> str:
    counts = result.counts()
    total = len(result.findings)
    if total == 0:
        return "0 findings"
    parts = [f"{counts[s]} {s.value}" for s in SEVERITIES_DESCENDING if counts[s]]
    return f"{_plural(total, 'finding')}: {', '.join(parts)}"


def _partial_what(result: ScanResult) -> str:
    c = result.completeness
    if c.files_not_analysed:
        return f"{c.files_not_analysed} of {c.files_discovered} files not analysed"
    if c.rule_failures:
        return f"{_plural(len(c.rule_failures), 'rule')} did not finish"
    if c.findings_truncated:
        return f"{c.findings_truncated} findings not reported (cap reached)"
    return "limit reached: " + ", ".join(c.limits_hit)


def _banner(w: _Writer, text: str, code: str) -> None:
    lines = w.wrap(text, w.lead, w.lead, w.width)
    for line in lines:
        if w.s.color:
            w.add(w.sgr(line.ljust(w.width), code))
        else:
            w.add(line)


def _result_lines(w: _Writer, result: ScanResult) -> None:
    c = result.completeness
    code = result.exit_code
    sup = f" {w.dot} {len(result.suppressed)} suppressed" if result.suppressed else ""
    over = len(result.at_or_above)
    fail_on = result.fail_on.value
    parts: list[str]
    joiner = " "
    if c.status is ScanStatus.FAILED:
        parts = [f"No result. Exit code {code} (scan incomplete)."]
    elif c.status is ScanStatus.PARTIAL:
        suffix = " (scan incomplete)" if code == 3 else " (partial scan allowed by --allow-partial)"
        if result.findings:
            parts = [
                f"{_counts(result)}{sup}",
                f"{over} at or above fail-on ({fail_on}). Exit code {code}{suffix}.",
            ]
            joiner = f" {w.dot} "
        else:
            parts = [f"0 findings in analysed files{sup}.", f"Exit code {code}{suffix}."]
    elif result.findings and over:
        parts = [
            f"{_counts(result)}{sup}",
            f"{over} at or above fail-on ({fail_on}). Exit code {code}.",
        ]
        joiner = f" {w.dot} "
    elif result.findings:
        parts = [
            f"{_counts(result)}{sup} {w.dot} 0 at or above fail-on ({fail_on}).",
            f"Exit code {code}. Lower-severity findings are listed above.",
        ]
    else:
        parts = [f"0 findings {w.dot} scan complete{sup}. Exit code {code}."]
    first = w.lead + "Result  "
    rest = " " * len(first)
    joined = joiner.join(parts)
    if len(first) + len(joined) <= w.width:
        lines = [first + joined]
    else:
        lines = []
        for i, part in enumerate(parts):
            lines.extend(w.wrap(part, first if i == 0 else rest, rest, w.width))
    lines[0] = lines[0].replace("Result", w.sgr("Result", tk.BOLD_SGR), 1)
    for line in lines:
        w.add(line)
    if c.status is ScanStatus.PARTIAL:
        _banner(
            w,
            f"PARTIAL SCAN — {_partial_what(result)}. This result is not a clean bill of health.",
            tk.STATUS_PARTIAL_SGR,
        )


# =============================================================================================
# Screens
# =============================================================================================


def _no_findings_block(w: _Writer, result: ScanResult) -> None:
    c = result.completeness
    lead = w.lead
    sub = lead + "  "
    w.blank()
    if c.status is ScanStatus.COMPLETE:
        w.para(tk.NO_FINDINGS_COMPLETE, lead, lead, w.width)
        w.blank()
        w.add(f"{lead}{w.sgr('What was checked', tk.BOLD_SGR)}")
        if result.rules_available == 0:
            w.para(
                "No detection rules ship in this version, so no risky patterns were looked for.",
                sub,
                sub,
            )
        else:
            labels = sorted({a for r in result.rules_enabled for a in r.asi})
            w.para(f"{_plural(len(result.rules_enabled), 'rule')} ({', '.join(labels)})", sub, sub)
        w.para(
            f"{_plural(c.files_analysed, 'file')}: every discovered source file was parsed",
            sub,
            sub,
        )
        if c.dynamic_constructs_not_analysed:
            w.para(
                f"{_plural(c.dynamic_constructs_not_analysed, 'dynamic construct')} could not be "
                "followed",
                sub,
                sub,
            )
        w.blank()
        w.add(f"{lead}{w.sgr('What was not checked', tk.BOLD_SGR)}")
        w.para(
            "Runtime behaviour, deployed configuration, model behaviour, MCP servers configured "
            "outside this repository, and risks no enabled rule targets.",
            sub,
            sub,
        )
        w.para("List of rules: nexvul rules", sub, sub)
    else:
        if c.files_not_analysed:
            # tokens.copy.no_findings_partial, with singular forms for counts of one.
            text = (
                f"No findings in the {_plural(c.files_analysed, 'file')} that "
                f"{'was' if c.files_analysed == 1 else 'were'} analysed. "
                f"{_plural(c.files_not_analysed, 'file')} "
                f"{'was' if c.files_not_analysed == 1 else 'were'} not analysed."
            )
        else:
            text = (
                f"No findings in the {c.files_analysed} files that were analysed. Not every "
                "check finished; see Scan completeness."
            )
        w.para(text, lead, lead, w.width)


def _failed_block(w: _Writer, result: ScanResult) -> None:
    c = result.completeness
    lead = w.lead
    sub = lead + "  "
    w.blank()
    if c.failed_cause is FailedCause.NOTHING_TO_ANALYSE:
        cause = f"nothing to analyse in {_safe(result.target)}."
    else:
        cause = f"none of the {c.files_discovered} files in scope could be analysed."
    _banner(w, tk.FAILED_BANNER.format(cause=cause), tk.STATUS_FAILED_SGR)
    w.blank()
    if c.failed_cause is FailedCause.NOTHING_TO_ANALYSE:
        other = sum(n for r, n in c.skipped_by_reason if impact_of(r) is not Impact.PARTIAL)
        exts = _extension_summary(result)
        if other:
            w.para(
                f"Found {_plural(other, 'file')}{exts}; none is a source file nexvul reads.",
                sub,
                sub,
            )
        else:
            w.para("Found no files.", sub, sub)
        w.para("This version of nexvul analyses Python source files (.py).", sub, sub)
        w.blank()
        w.para("Did you mean to scan the project root? Try: nexvul scan .", sub, sub)
    else:
        w.para(
            "Every file in scope was skipped or failed to parse. The reasons are listed under "
            "Scan completeness; run with --verbose to see every file.",
            sub,
            sub,
        )


def _extension_summary(result: ScanResult) -> str:
    counts: dict[str, int] = {}
    for entry in result.completeness.skipped:
        if entry.reason is not SkipReason.UNSUPPORTED_FILE_TYPE:
            continue
        name = entry.path.rsplit("/", 1)[-1]
        dot = name.rfind(".")
        ext = name[dot:][:12] if dot > 0 else "(no extension)"
        counts[ext] = counts.get(ext, 0) + 1
    if not counts:
        return ""
    top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:5]
    return ": " + ", ".join(f"{n} {_safe(ext)}" for ext, n in top)


def render_scan(result: ScanResult, style: TerminalStyle) -> str:
    """Render a scan result for the terminal (stdout). Ends with a newline."""
    w = _Writer(style)
    _header(w, result)
    c = result.completeness
    if c.status is ScanStatus.FAILED:
        _failed_block(w, result)
    elif result.findings:
        _findings(w, result)
    else:
        _no_findings_block(w, result)
    if c.status is not ScanStatus.FAILED and (result.findings or result.suppressed):
        w.sep()
    _suppressions(w, result)
    _completeness(w, result)
    w.blank()
    _result_lines(w, result)
    return "\n".join(w.lines) + "\n"


def status_line(result: ScanResult) -> str:
    """One-line stderr status after a machine format is written (T21). Trusted text only."""
    c = result.completeness
    if c.status is ScanStatus.FAILED:
        return f"nexvul: SCAN FAILED — no result {_dot_ascii()} exit code {result.exit_code}"
    if c.status is ScanStatus.PARTIAL:
        return (
            f"nexvul: PARTIAL SCAN — {_partial_what(result)} {_dot_ascii()} exit code "
            f"{result.exit_code}"
        )
    over = len(result.at_or_above)
    return (
        f"nexvul: scan complete {_dot_ascii()} {over} at or above fail-on "
        f"({result.fail_on.value}) {_dot_ascii()} exit code {result.exit_code}"
    )


def _dot_ascii() -> str:
    return tk.SEPARATOR_DOT_ASCII


def suppression_warnings(result: ScanResult) -> list[str]:
    """C02/C05 warning lines for stderr (printed before the report)."""
    out: list[str] = []
    for issue in result.suppression_issues:
        if issue.kind in (IssueKind.REJECTED, IssueKind.NOT_APPLIED, IssueKind.NO_JUSTIFICATION):
            out.append(f"nexvul: warning: {_safe(issue.path)}:{issue.line}: {_safe(issue.message)}")
    return out
