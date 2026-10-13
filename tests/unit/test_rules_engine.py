"""Rule runner: findings from IR, failures recorded, caps, sanitising (architecture §11-12)."""

from __future__ import annotations

from nexvul_test_rules import (
    HOSTILE_TEXT,
    ContractBreakingRule,
    ExplodingRule,
    ForeignPathRule,
    HostileMessageRule,
    PrintRule,
    ShellCallRule,
)

from nexvul.core.completeness import Completeness, Status
from nexvul.core.sanitize import first_hidden_char
from nexvul.findings.model import Confidence, FlowRole, Severity
from nexvul.parser.python import parse_python
from nexvul.rules.engine import run_rules

SRC = b"""import os
import subprocess

def run(cmd):
    os.system(cmd)
    os.system(cmd)
    subprocess.run("echo sk-ant-api03-abcdefghijklmnopqrstuvwxyz")
    print("hi")
"""


def modules():  # type: ignore[no-untyped-def]
    return (parse_python(SRC, "agent/tools.py"),)


def test_findings_are_built_from_metadata_and_sorted() -> None:
    ledger = Completeness()
    run = run_rules([ShellCallRule()], modules(), ledger)
    assert run.rules_run == ("NEX990",) and run.rules_failed == ()
    assert len(run.findings) == 3
    f = run.findings[0]
    assert f.rule_id == "NEX990"
    assert f.title == ShellCallRule.meta.name
    assert f.asi == ("ASI05", "ASI02")
    assert f.severity is Severity.HIGH
    assert f.location.path == "agent/tools.py"
    assert f.location.line == 5 and f.location.column == 5  # 1-based column
    assert [s.role for s in f.flow] == [FlowRole.SOURCE, FlowRole.SINK]
    assert f.flow[0].index == 1
    assert ledger.status is Status.COMPLETE


def test_identical_calls_get_distinct_stable_fingerprints() -> None:
    run1 = run_rules([ShellCallRule()], modules(), Completeness())
    run2 = run_rules([ShellCallRule()], modules(), Completeness())
    fps = [f.fingerprint for f in run1.findings]
    assert len(set(fps)) == 3
    assert fps == [f.fingerprint for f in run2.findings]
    # moving code down (blank lines above) keeps fingerprints
    shifted = (parse_python(b"\n\n\n" + SRC, "agent/tools.py"),)
    assert sorted(fps) == sorted(
        f.fingerprint for f in run_rules([ShellCallRule()], shifted, Completeness()).findings
    )


def test_secrets_in_snippets_and_flow_are_redacted() -> None:
    run = run_rules([ShellCallRule()], modules(), Completeness())
    texts = [
        t
        for f in run.findings
        for t in (*(s.text for s in f.flow), *(e.snippet or "" for e in f.evidence))
    ]
    assert texts
    assert not any("abcdefghijklmnopqrstuvwxyz" in t for t in texts)


def test_confidence_capped_at_rule_ceiling() -> None:
    run = run_rules([PrintRule()], modules(), Completeness())
    assert run.findings[0].confidence is Confidence.LOW
    assert run.findings[0].severity is Severity.LOW


def test_raising_rule_is_recorded_not_swallowed_and_partial() -> None:
    ledger = Completeness()
    ledger.record_scanned()
    run = run_rules([ExplodingRule(), ShellCallRule()], modules(), ledger)
    assert run.rules_failed == ("NEX993",)
    assert [(f.rule_id, f.error_type) for f in ledger.rule_failures] == [("NEX993", "RuntimeError")]
    assert ledger.status is Status.PARTIAL
    # the match yielded before the exception is kept; other rules still ran
    assert {f.rule_id for f in run.findings} == {"NEX990", "NEX993"}
    assert "SECRET-RULE-DETAIL" not in str(ledger.to_dict())


def test_contract_violations_are_rule_failures() -> None:
    ledger = Completeness()
    run = run_rules([ContractBreakingRule(), ForeignPathRule()], modules(), ledger)
    assert run.findings == ()
    assert {(f.rule_id, f.error_type) for f in ledger.rule_failures} == {
        ("NEX994", "RuleContractError"),
        ("NEX995", "RuleContractError"),
    }


def test_failed_modules_are_not_given_to_rules() -> None:
    bad = parse_python(b"def (:\n", "bad.py")
    run = run_rules([ShellCallRule()], (bad,), Completeness())
    assert run.findings == ()


def test_finding_caps_are_counted_and_make_the_scan_partial() -> None:
    ledger = Completeness()
    run = run_rules([ShellCallRule()], modules(), ledger, max_per_file=2)
    assert len(run.findings) == 2
    assert ledger.findings_truncated == 1
    assert ledger.status is Status.PARTIAL
    ledger2 = Completeness()
    run2 = run_rules([ShellCallRule()], modules(), ledger2, max_total=1)
    assert len(run2.findings) == 1 and ledger2.findings_truncated == 2


def test_hostile_rule_text_is_sanitised_everywhere() -> None:
    run = run_rules([HostileMessageRule()], modules(), Completeness())
    f = run.findings[0]
    for text in (
        f.message,
        f.flow[0].text,
        f.evidence[0].description,
        f.evidence[0].snippet or "",
        f.evidence[0].kind,
        *f.limitations,
    ):
        assert first_hidden_char(text) is None, text
        assert "\x1b" not in text and "\n" not in text and "\u202e" not in text
    assert "\\x1b" in f.message  # visible escape, not dropped silently
    assert len(f.message) <= 400 + 12
    assert HOSTILE_TEXT not in f.message


def test_non_utf8_paths_get_raw_b64() -> None:
    mod = parse_python(b"import os\nos.system('x')\n", "caf\udce9.py")
    f = run_rules([ShellCallRule()], (mod,), Completeness()).findings[0]
    assert f.location.raw_path_b64 == "Y2Fm6S5weQ=="
    assert f.location.path == "caf\\xe9.py"
