"""Generic rule-fixture runner (test-strategy §4.1): every case under ``tests/rules/<rule>/`` is
scanned as data through the real pipeline and the findings are compared to ``expect.txt``.

All cases of a rule are scanned in **one** virtual tree (``<category>/<case>/<virtual path>``),
so the worker pool starts once. Client recognition depends only on a file's name and parent
directory, which the case prefix does not change. The scan runs lazily inside the first test so
the network guard of ``tests/conftest.py`` is active while it runs.
"""

from __future__ import annotations

import pytest
from rule_fixtures import Case, load_cases, scan_virtual

from nexvul.findings.model import Finding
from nexvul.findings.result import ScanResult

RULE_DIRS = ("nex007",)
CASES: list[Case] = [case for rule in RULE_DIRS for case in load_cases(rule)]
_SCANS: dict[str, ScanResult] = {}


def _scan(rule: str, tmp_path_factory: pytest.TempPathFactory) -> ScanResult:
    if rule not in _SCANS:
        files: dict[str, bytes] = {}
        for case in CASES:
            if case.rule == rule:
                for rel, data in case.files.items():
                    files[f"{case.id}/{rel}"] = data
        root = tmp_path_factory.mktemp(f"fixtures-{rule.lower()}") / "tree"
        _SCANS[rule] = scan_virtual(files, root, enable=(rule,))
    return _SCANS[rule]


def _findings_for(result: ScanResult, case: Case) -> list[Finding]:
    prefix = case.id + "/"
    return [
        f
        for f in (*result.findings, *result.suppressed)
        if f.rule_id == case.rule and f.location.path.startswith(prefix)
    ]


def test_fixture_cases_exist_with_minimum_counts() -> None:
    # test-strategy §4.2 minimums per rule
    minimum = {"positive": 5, "negative": 8, "edge_cases": 3, "adversarial": 6}
    for rule in RULE_DIRS:
        counts = dict.fromkeys(minimum, 0)
        for case in CASES:
            if case.rule == rule.upper():
                counts[case.category] = counts.get(case.category, 0) + 1
        for cat, low in minimum.items():
            assert counts[cat] >= low, (rule, cat, counts[cat])


@pytest.mark.parametrize("case", CASES, ids=[f"{c.rule}:{c.id}" for c in CASES])
def test_fixture_case(case: Case, tmp_path_factory: pytest.TempPathFactory) -> None:
    result = _scan(case.rule, tmp_path_factory)
    prefix = case.id + "/"
    actual = sorted(
        (f.location.path[len(prefix) :], f.location.line, f.severity.value, f.confidence.value)
        for f in _findings_for(result, case)
    )
    expected = sorted((e.file, e.line, e.severity, e.confidence) for e in case.expect)
    assert actual == expected
    for item in case.expect_not:
        assert all(row[0] != item.file for row in actual), item.reason
    for miss in case.known_miss:
        # Known misses stay in the corpus; if one starts being detected, update the docs.
        assert all((row[0], row[1]) != (miss.file, miss.line) for row in actual), miss.ref
    if case.category == "positive" or case.expect:
        for f in _findings_for(result, case):
            assert f.asi == ("ASI07", "ASI04")
            assert f.remediation and f.message and f.evidence
            assert "secure" not in f.message.lower()


def test_whole_fixture_scan_status_is_explained(tmp_path_factory: pytest.TempPathFactory) -> None:
    result = _scan("NEX007", tmp_path_factory)
    # The only file that is not analysed is the deliberately invalid JSON edge case.
    skipped = [(s.path, s.reason.value) for s in result.completeness.skipped]
    partial = [p for p, r in skipped if r == "parse_error"]
    assert partial == ["edge_cases/case_007_invalid_json_not_analysed/.mcp.json"]
    assert any("JSONC" in n for n in result.completeness.notes)
    assert any("repeat a key" in n for n in result.completeness.notes)
    assert result.frameworks and result.frameworks[0].startswith("MCP client config (")
