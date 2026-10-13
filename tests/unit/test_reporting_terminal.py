"""Terminal reporter: golden files at 80/120/60 columns and plain mode (terminal-mockups T02-T19).

Regenerate goldens after an intended layout change with ``NEXVUL_UPDATE_GOLDEN=1 pytest ...`` and
review the diff against docs/design/terminal-mockups.md.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import replace
from pathlib import Path

import pytest
from result_factory import SCENARIOS, t04, t05, t06, t18

from nexvul.core.completeness import SkippedEntry, SkipReason
from nexvul.findings.model import Severity
from nexvul.findings.result import ScanStatus
from nexvul.reporting import tokens as tk
from nexvul.reporting.terminal import (
    TerminalStyle,
    render_scan,
    status_line,
    suppression_warnings,
)

GOLDEN = Path(__file__).resolve().parents[1] / "golden" / "terminal"
REPO = Path(__file__).resolve().parents[2]
UPDATE = os.environ.get("NEXVUL_UPDATE_GOLDEN") == "1"

STYLES = {
    "80": TerminalStyle(width=80, color=False, plain=False, ascii=False),
    "120": TerminalStyle(width=120, color=False, plain=False, ascii=False),
    "60": TerminalStyle(width=60, color=False, plain=False, ascii=False),
    "plain-80": TerminalStyle(width=80),
}
SGR = re.compile(r"\x1b\[[0-9;]*m")


def check_golden(name: str, text: str) -> None:
    path = GOLDEN / f"{name}.txt"
    if UPDATE:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    assert path.exists(), f"missing golden {path}; run with NEXVUL_UPDATE_GOLDEN=1"
    assert text == path.read_text(encoding="utf-8")


@pytest.mark.parametrize("style_name", list(STYLES))
@pytest.mark.parametrize("scenario", list(SCENARIOS))
def test_golden(scenario: str, style_name: str) -> None:
    style = STYLES[style_name]
    text = render_scan(SCENARIOS[scenario](), style)
    check_golden(f"{scenario}-{style_name}", text)
    assert "\x1b" not in text
    for line in text.splitlines():
        assert len(line) <= style.width, (scenario, style_name, line)


@pytest.mark.parametrize("scenario", ["T04", "T05", "T18"])
def test_golden_colour(scenario: str) -> None:
    style = TerminalStyle(width=80, color=True, plain=False, ascii=False)
    text = render_scan(SCENARIOS[scenario](), style)
    check_golden(f"{scenario}-color-80", text)
    plain = SGR.sub("", text)
    assert "\x1b" not in plain  # only SGR sequences, nothing else
    for line in plain.splitlines():
        assert len(line) <= 80


def test_plain_mode_has_zero_esc_and_ascii_glyphs() -> None:
    text = render_scan(t04(), TerminalStyle(width=80))
    assert "\x1b" not in text
    assert "[####]" in text and "█" not in text and "─" not in text


def test_nowrap_below_40_columns() -> None:
    text = render_scan(t04(), TerminalStyle(width=30, plain=False, ascii=False))
    assert any(len(line) > 30 for line in text.splitlines())
    assert "-" * 10 in text or "─" * 80 in text


def test_result_line_last_and_partial_banner_final() -> None:
    lines = render_scan(t05(), TerminalStyle(width=120)).rstrip("\n").splitlines()
    assert lines[-1].startswith(" PARTIAL SCAN — 4 of 312 files not analysed.")
    assert lines[-2].startswith(" Result  ")
    complete = render_scan(t04(), TerminalStyle(width=120)).rstrip("\n").splitlines()
    assert complete[-1].startswith(" Result  ")
    assert "Exit code 1" in complete[-1]


@pytest.mark.parametrize("scenario", list(SCENARIOS))
def test_completeness_block_always_present(scenario: str) -> None:
    for style in STYLES.values():
        assert "Scan completeness" in render_scan(SCENARIOS[scenario](), style)


@pytest.mark.parametrize("scenario", [n for n in SCENARIOS if n not in ("T02",)])
def test_no_findings_sentence_only_for_complete_scans(scenario: str) -> None:
    result = SCENARIOS[scenario]()
    text = render_scan(result, TerminalStyle(width=80))
    if result.status is not ScanStatus.COMPLETE or result.findings:
        assert "No findings from enabled rules" not in text


def test_t06_partial_no_findings_never_says_no_findings() -> None:
    text = render_scan(t06(), TerminalStyle(width=80))
    assert "No findings from enabled rules" not in text
    assert "No findings in the 308 files that were analysed. 4 files were not analysed." in text
    assert "PARTIAL SCAN" in text


def test_t02_has_disclaimer_and_scope() -> None:
    text = render_scan(SCENARIOS["T02"](), TerminalStyle(width=80))
    assert tk.NO_FINDINGS_COMPLETE in text
    assert "What was not checked" in text


def test_zero_rules_is_said_plainly() -> None:
    result = replace(SCENARIOS["T02"](), rules_available=0, rules_enabled=())
    text = render_scan(result, TerminalStyle(width=80))
    assert "No detection rules ship in this version" in text
    assert "none ship in this version" in text


def test_allow_partial_is_shown_and_banner_kept() -> None:
    base = t05()
    result = replace(base, completeness=replace(base.completeness, allow_partial=True), exit_code=1)
    text = render_scan(result, TerminalStyle(width=100))
    assert "--allow-partial" in text and "PARTIAL SCAN" in text
    assert "Exit code 1 (partial scan allowed by --allow-partial)" in text


def test_partial_reasons_other_than_files() -> None:
    base = t05()
    for overrides, expected in (
        ({"findings_truncated": 7}, "7 findings not reported"),
        ({"limits_hit": ("max_files",)}, "limit reached: max_files"),
    ):
        comp = replace(
            base.completeness,
            files_not_analysed=0,
            skipped_by_reason=(),
            skipped=(),
            **overrides,  # type: ignore[arg-type]
        )
        text = render_scan(replace(base, completeness=comp), TerminalStyle(width=100))
        assert expected in text


def test_inline_skip_paths_capped_with_more() -> None:
    base = t05()
    skipped = tuple(SkippedEntry(f"f{i}.py", SkipReason.PARSE_ERROR) for i in range(9))
    comp = replace(
        base.completeness,
        skipped=skipped,
        skipped_by_reason=((SkipReason.PARSE_ERROR, 40),),
        files_not_analysed=40,
    )
    text = render_scan(replace(base, completeness=comp), TerminalStyle(width=120))
    assert "f4.py, and 35 more" in text and "f5.py" not in text


def test_verbose_lists_config_skips_and_limited_notes() -> None:
    base = t05()
    comp = replace(base.completeness, skipped_list_truncated=3)
    text = render_scan(replace(base, completeness=comp), TerminalStyle(width=100, verbose=True))
    for needle in (
        "Effective config",
        "rules.disabled",
        "Plugins",
        "Timings",
        "Analysis-limited",
        "agent/plugins.py:12",
        "agent/legacy.py",
        "and 3 more",
    ):
        assert needle in text


def test_verbose_flow_text_is_not_truncated() -> None:
    text = render_scan(t04(), TerminalStyle(width=80, verbose=True))
    assert "currency=order.currency)" in text


def test_ci_header_and_failed_screen() -> None:
    text = render_scan(SCENARIOS["T17-ci"](), TerminalStyle(width=120))
    assert "CI (--ci)" in text and "NOT APPLIED" in text
    failed = render_scan(t18(), TerminalStyle(width=80))
    assert "SCAN FAILED — nothing to analyse in ./docs." in failed
    assert "2 .md, 1 .png" in failed and "Exit code 3" in failed


def test_status_line_and_warnings() -> None:
    assert "exit code 1" in status_line(t04()) and "scan complete" in status_line(t04())
    assert status_line(t05()).startswith("nexvul: PARTIAL SCAN")
    assert "SCAN FAILED" in status_line(t18())
    warnings = suppression_warnings(SCENARIOS["T17-ci"]())
    assert warnings == [
        "nexvul: warning: agent/admin.py:30: suppression ignored: no rule ID. "
        "Write ignore[NEX0nn] -- <reason>."
    ]


def test_severity_never_colour_only() -> None:
    text = render_scan(t04(), TerminalStyle(width=80, color=True, plain=False, ascii=False))
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        assert tk.SEVERITY_LABEL[sev] in text and tk.SEVERITY_METER[sev] in text


BANNED = re.compile(
    r"\b(secure|safe|clean|all clear|looks good|passed|vulnerable|vulnerabilit(y|ies)|"
    r"protected|hardened|guaranteed|verified|dangerous)\b",
    re.IGNORECASE,
)
ALLOWED = (tk.NO_FINDINGS_COMPLETE, "This result is not a clean bill of health.", tk.DISCLAIMER)


@pytest.mark.parametrize("scenario", list(SCENARIOS))
def test_copy_lint_banned_words(scenario: str) -> None:
    """design-system §8.1: banned words never appear except in the fixed sentences."""
    for style in STYLES.values():
        text = " ".join(render_scan(SCENARIOS[scenario](), style).split())
        for allowed in ALLOWED:
            text = text.replace(allowed, "")
        text = text.replace("This result is not a clean bill of health.", "")
        text = text.replace("clean(html)", "")  # sample repository code, not nexvul copy
        assert not BANNED.search(text.replace("not a clean bill of health", "")), scenario


def test_tokens_mirror_design_tokens_json() -> None:
    data = json.loads((REPO / "docs/design/tokens.json").read_text(encoding="utf-8"))
    for sev in Severity:
        entry = data["severity"][sev.value]
        assert tk.SEVERITY_LABEL[sev] == entry["label"]
        assert tk.SEVERITY_METER[sev] == entry["meter"]
        assert tk.SEVERITY_METER_ASCII[sev] == entry["meter_ascii"]
        assert tk.SEVERITY_SGR[sev] == entry["terminal_sgr"]
    term = data["terminal"]
    assert term["accent_sgr"] == tk.ACCENT_SGR
    assert term["dim_sgr"] == tk.DIM_SGR and term["bold_sgr"] == tk.BOLD_SGR
    assert term["source_word_sgr"] == tk.SOURCE_WORD_SGR
    assert term["sink_word_sgr"] == tk.SINK_WORD_SGR
    assert term["rule_char"] == tk.RULE_CHAR and term["rule_char_ascii"] == tk.RULE_CHAR_ASCII
    assert term["separator_dot"] == tk.SEPARATOR_DOT
    assert term["separator_dot_ascii"] == tk.SEPARATOR_DOT_ASCII
    assert term["body_wrap_max"] == tk.BODY_WRAP_MAX
    assert term["default_width_unknown"] == tk.DEFAULT_WIDTH_UNKNOWN
    assert term["min_wrapped_width"] == tk.MIN_WRAPPED_WIDTH
    assert term["narrow_breakpoint"] == tk.NARROW_BREAKPOINT
    status = data["status"]
    assert status["partial"]["terminal_sgr"] == tk.STATUS_PARTIAL_SGR
    assert status["failed"]["terminal_sgr"] == tk.STATUS_FAILED_SGR
    assert status["complete"]["terminal_sgr"] == tk.STATUS_COMPLETE_SGR
    copy = data["copy"]
    assert copy["disclaimer"] == tk.DISCLAIMER
    assert copy["no_findings_complete"] == tk.NO_FINDINGS_COMPLETE
    assert copy["no_findings_partial"] == tk.NO_FINDINGS_PARTIAL
    assert copy["partial_banner"] == tk.PARTIAL_BANNER
    assert copy["failed_banner"] == tk.FAILED_BANNER
    assert copy["doctor_scope"] == tk.DOCTOR_SCOPE
    assert copy["finding_meaning"] == tk.FINDING_MEANING
    assert data["truncation"]["ellipsis"] == tk.ELLIPSIS
    assert data["truncation"]["ellipsis_ascii"] == tk.ELLIPSIS_ASCII
    assert data["layout"]["inline_skip_paths_max"] == tk.INLINE_SKIP_PATHS_MAX
    assert data["layout"]["verbose_skip_paths_max"] == tk.VERBOSE_SKIP_PATHS_MAX
    assert "green" not in json.dumps(data["severity"]).lower()
