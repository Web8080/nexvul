"""Design tokens used by the terminal reporter (docs/design/tokens.json, design-system §2-5).

The package cannot read ``docs/`` at run time, so the values the terminal needs are mirrored
here. ``tests/unit/test_reporting_terminal.py`` asserts that every value equals the one in
``docs/design/tokens.json``; change the JSON first, then this module.

No green anywhere (design-system §2). Severity is always a word plus a meter; colour is the third
cue only (R4).
"""

from __future__ import annotations

from typing import Final

from nexvul.findings.model import Severity

SEVERITY_LABEL: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}
SEVERITY_METER: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "████",
    Severity.HIGH: "███░",
    Severity.MEDIUM: "██░░",
    Severity.LOW: "█░░░",
    Severity.INFO: "░░░░",
}
SEVERITY_METER_ASCII: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "[####]",
    Severity.HIGH: "[###.]",
    Severity.MEDIUM: "[##..]",
    Severity.LOW: "[#...]",
    Severity.INFO: "[....]",
}
SEVERITY_SGR: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "1;97;41",
    Severity.HIGH: "1;31",
    Severity.MEDIUM: "33",
    Severity.LOW: "34",
    Severity.INFO: "2",
}

STATUS_COMPLETE_SGR: Final = "1"
STATUS_PARTIAL_SGR: Final = "1;30;43"
STATUS_FAILED_SGR: Final = "1;97;41"

ACCENT_SGR: Final = "36"
BOLD_SGR: Final = "1"
DIM_SGR: Final = "2"
SOURCE_WORD_SGR: Final = "35"
SINK_WORD_SGR: Final = "33"

RULE_CHAR: Final = "─"
RULE_CHAR_ASCII: Final = "-"
SEPARATOR_DOT: Final = "·"
SEPARATOR_DOT_ASCII: Final = "-"
ELLIPSIS: Final = "…"
ELLIPSIS_ASCII: Final = "..."

BODY_WRAP_MAX: Final = 100
DEFAULT_WIDTH_UNKNOWN: Final = 100
MIN_WRAPPED_WIDTH: Final = 40
NARROW_BREAKPOINT: Final = 80
WIDE_BREAKPOINT: Final = 120
INLINE_SKIP_PATHS_MAX: Final = 5
VERBOSE_SKIP_PATHS_MAX: Final = 200

# Fixed sentences (tokens.json -> copy). The only places the words "secure" and "clean bill of
# health" may appear, negated (design-system §8.1).
DISCLAIMER: Final = "A clean nexvul result does not prove that an application is secure."
NO_FINDINGS_COMPLETE: Final = (
    "No findings from enabled rules. This does not prove the application is secure."
)
NO_FINDINGS_PARTIAL: Final = (
    "No findings in the {analysed} files that were analysed. "
    "{not_analysed} files were not analysed."
)
PARTIAL_BANNER: Final = (
    "PARTIAL SCAN — {not_analysed} of {discovered} files not analysed. "
    "This result is not a clean bill of health."
)
FAILED_BANNER: Final = "SCAN FAILED — {cause}"
DOCTOR_SCOPE: Final = "This checks nexvul's installation, not your code."
FINDING_MEANING: Final = (
    "A finding means nexvul identified a risky pattern. It does not prove the code is exploitable."
)
