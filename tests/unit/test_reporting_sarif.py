"""SARIF 2.1.0 reporter: official-schema validation, GitHub expectations, completeness, limits,
hostile input, goldens and CLI wiring (SR-12, T-12, T-20; github-and-action.md §2-§4)."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import unicodedata
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from nexvul_test_rules import default_test_registry
from result_factory import (
    NEX007,
    NEX014,
    NEX015,
    SCENARIOS,
    loc,
    t04,
    t05,
    t05_rule_failure,
    t17_ci,
    t18,
)
from rule_fixtures import scan_virtual
from schema_draft04 import Draft04

import nexvul.cli.main as cli_main
from nexvul.cli.main import main
from nexvul.core.completeness import SkipReason
from nexvul.findings.model import (
    Confidence,
    Evidence,
    FindingLocation,
    FlowRole,
    FlowStep,
    Severity,
)
from nexvul.findings.result import ScanResult
from nexvul.reporting.sarif import (
    MAX_MESSAGE_CHARS,
    SECURITY_SEVERITY,
    SarifLimits,
    artifact_uri,
    defang_urls,
    is_nexvul_sarif,
    md_escape,
    primary_location_line_hash,
    render_sarif,
    sarif_log,
)
from nexvul.rules.base import Readiness
from nexvul.rules.registry import Registry, builtin_registry

REPO = Path(__file__).resolve().parents[2]
SCHEMA_FILE = REPO / "tests" / "schemas" / "sarif-schema-2.1.0.json"
SCHEMA_SHA256 = "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e"
SCHEMA = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
VALIDATOR = Draft04(SCHEMA)
GOLDEN = REPO / "tests" / "golden" / "sarif"
UPDATE = os.environ.get("NEXVUL_UPDATE_GOLDEN") == "1"
REG = builtin_registry()


def log_of(result: ScanResult, registry: Registry = REG, **kw: Any) -> dict[str, Any]:
    return dict(json.loads(render_sarif(result, registry, **kw)))


def run0(log: dict[str, Any]) -> dict[str, Any]:
    return dict(log["runs"][0])


def walk(node: Any, key: str = "") -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    if isinstance(node, dict):
        for k, v in node.items():
            out += walk(v, k)
    elif isinstance(node, list):
        for v in node:
            out += walk(v, key)
    else:
        out.append((key, node))
    return out


def all_locations(log: dict[str, Any]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []

    def visit(node: Any) -> None:
        if isinstance(node, dict):
            if "artifactLocation" in node:
                found.append(node)
            for v in node.values():
                visit(v)
        elif isinstance(node, list):
            for v in node:
                visit(v)

    visit(log)
    return found


# --- vendored schema and validator ------------------------------------------------------------


def test_vendored_schema_is_the_pinned_official_file() -> None:
    assert hashlib.sha256(SCHEMA_FILE.read_bytes()).hexdigest() == SCHEMA_SHA256
    readme = (SCHEMA_FILE.parent / "README.md").read_text(encoding="utf-8")
    assert SCHEMA_SHA256 in readme and "oasis-tcs/sarif-spec" in readme
    assert SCHEMA["id"].endswith("sarif-schema-2.1.0.json")


def test_validator_catches_errors() -> None:
    bad = log_of(t04())
    bad["version"] = "2.0.0"
    run = bad["runs"][0]
    run["results"][0]["level"] = "fatal"
    del run["results"][0]["message"]
    run["invocations"][0]["startTimeUtc"] = "yesterday"
    run["tool"]["driver"]["informationUri"] = "not a uri"
    run["results"][1]["locations"][0]["physicalLocation"]["region"]["startLine"] = 0
    errors = VALIDATOR.errors(bad)
    joined = "\n".join(errors)
    assert "'2.0.0' not in enum" in joined
    assert "'fatal' not in enum" in joined
    assert "missing message" in joined
    assert "not a valid date-time" in joined
    assert "not a valid uri" in joined
    assert "below minimum 1" in joined
    with pytest.raises(ValueError, match="unsupported"):
        VALIDATOR.errors({}, {"if": {}})


@pytest.mark.parametrize("scenario", list(SCENARIOS))
@pytest.mark.parametrize("pretty", [True, False])
def test_every_scenario_validates_against_official_schema(scenario: str, pretty: bool) -> None:
    data = json.loads(render_sarif(SCENARIOS[scenario](), REG, pretty=pretty))
    assert VALIDATOR.errors(data) == []


# --- GitHub expectations ----------------------------------------------------------------------


def test_github_required_fields_and_rule_table() -> None:
    log = log_of(t04())
    assert log["version"] == "2.1.0" and log["$schema"].endswith("sarif-schema-2.1.0.json")
    run = run0(log)
    driver = run["tool"]["driver"]
    assert driver["name"] == "nexvul" and driver["rules"]
    builtin = {r.meta.id: r for r in REG}
    ids = [r["id"] for r in driver["rules"]]
    assert set(builtin) <= set(ids)
    for rule in driver["rules"]:
        for field in ("shortDescription", "fullDescription", "help"):
            assert rule[field]["text"].strip()
        assert rule["help"]["markdown"].strip()
        assert rule["helpUri"].startswith("https://github.com/")
        tags = rule["properties"]["tags"]
        assert "security" in tags and len(tags) <= 20
        if rule["id"] in builtin:
            meta = builtin[rule["id"]].meta
            assert rule["defaultConfiguration"]["enabled"] is (meta.readiness is Readiness.DEFAULT)
            assert rule["properties"]["security-severity"] == SECURITY_SEVERITY[meta.severity]
            assert float(rule["properties"]["security-severity"]) <= 10.0
            assert {f"external/owasp/{a.lower()}" for a in meta.asi} <= set(tags)
    nex007 = driver["rules"][ids.index("NEX007")]
    assert nex007["defaultConfiguration"] == {"enabled": False, "level": "error"}
    assert "experimental" in nex007["properties"]["tags"]
    assert "Experimental thin slice" in nex007["help"]["text"]
    assert "external/cwe/cwe-319" in nex007["properties"]["tags"]
    assert run["automationDetails"]["id"] == "nexvul/"
    assert run["columnKind"] == "utf16CodeUnits"
    pe = run["properties"]["nexvul"]["position_encoding"]
    assert pe["column_unit"] == "utf8_bytes"
    for result in run["results"]:
        assert result["ruleId"] and result["message"]["text"].strip()
        assert "markdown" not in result["message"]
        assert len(result["message"]["text"]) <= MAX_MESSAGE_CHARS
        assert run["tool"]["driver"]["rules"][result["ruleIndex"]]["id"] == result["ruleId"]
        assert re.fullmatch(
            r"[0-9a-f]{16}:1", result["partialFingerprints"]["primaryLocationLineHash"]
        )
        assert result["locations"]


def test_uris_are_repo_relative_and_regions_valid() -> None:
    for scenario in SCENARIOS.values():
        log = log_of(scenario())
        for location in all_locations(log):
            art = location["artifactLocation"]
            uri = art["uri"]
            assert art["uriBaseId"] == "%SRCROOT%"
            assert not uri.startswith("/") and ":" not in uri
            assert ".." not in uri.split("/") and "\\" not in uri
            region = location.get("region")
            if region:
                assert region["startLine"] >= 1
                assert region.get("startColumn", 1) >= 1
                assert region.get("endLine", region["startLine"]) >= region["startLine"]


def test_levels_and_effective_severity_first() -> None:
    medium = replace(NEX007, severity=Severity.MEDIUM, confidence=Confidence.MEDIUM)
    log = log_of(replace(t04(), findings=(NEX007, medium, NEX015), suppressed=()))
    results = run0(log)["results"]
    by_level = [(r["level"], r["message"]["text"]) for r in results]
    assert by_level[0][0] == "error" and by_level[0][1].startswith("HIGH · ")
    assert by_level[1][0] == "warning"
    assert by_level[1][1].startswith("MEDIUM (rule default HIGH) · ")
    assert "Confidence: medium." in by_level[1][1]
    assert by_level[2][0] == "note" and by_level[2][1].startswith("LOW · ")
    assert results[1]["properties"]["nexvul"]["severity"] == "medium"
    assert results[1]["properties"]["nexvul"]["rule_default_severity"] == "high"


def test_code_flows_carry_role_words_and_snippets() -> None:
    results = run0(log_of(t04()))["results"]
    nex018 = next(r for r in results if r["ruleId"] == "NEX018")
    steps = nex018["codeFlows"][0]["threadFlows"][0]["locations"]
    assert [s["location"]["message"]["text"] for s in steps] == ["source", "step", "sink"]
    assert [s["executionOrder"] for s in steps] == [1, 2, 3]
    assert "Steps: 3 (Show paths)." in nex018["message"]["text"]
    sink = nex018["locations"][0]["physicalLocation"]["region"]["snippet"]["text"]
    assert sink.startswith("stripe.Refund.create(")
    nex007 = next(r for r in results if r["ruleId"] == "NEX007")
    assert "codeFlows" not in nex007


def test_info_findings_are_not_uploaded() -> None:
    info = replace(NEX014, severity=Severity.INFO)
    log = log_of(replace(t04(), findings=(NEX007, info)))
    run = run0(log)
    assert [r["ruleId"] for r in run["results"]] == ["NEX007", "NEX006"]  # active first
    assert run["properties"]["nexvul"]["sarif"]["info_findings_not_uploaded"] == 1


def test_rule_configuration_overrides_record_run_state() -> None:
    log = log_of(t04())  # rules_enabled includes NEX007 (experimental -> on)
    overrides = run0(log)["invocations"][0]["ruleConfigurationOverrides"]
    assert overrides == [
        {"descriptor": {"id": "NEX007", "index": 0}, "configuration": {"enabled": True}}
    ]
    off = log_of(replace(t04(), rules_enabled=()))
    assert "ruleConfigurationOverrides" not in run0(off)["invocations"][0]


def test_unknown_rule_gets_a_fallback_descriptor() -> None:
    run = run0(log_of(t04(), Registry(())))
    ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert sorted(ids) == ["NEX002", "NEX006", "NEX007", "NEX014", "NEX015", "NEX018"]
    assert all(VALIDATOR.errors(log_of(t04(), Registry(()))) == [] for _ in (0,))


# --- suppressions -----------------------------------------------------------------------------


def test_suppressed_and_not_applied() -> None:
    results = run0(log_of(t17_ci()))["results"]
    suppressed = next(r for r in results if r["ruleId"] == "NEX006")
    [sup] = suppressed["suppressions"]
    assert sup["kind"] == "inSource" and sup["status"] == "accepted"
    assert sup["justification"].startswith("auth enforced by the API gateway")
    assert sup["location"]["physicalLocation"]["region"]["startLine"] == 40
    not_applied = next(r for r in results if r["ruleId"] == "NEX015")
    assert "suppressions" not in not_applied
    assert "Suppression NOT APPLIED." in not_applied["message"]["text"]
    props = not_applied["properties"]["nexvul"]["suppression"]
    assert props["status"] == "not_applied" and "CI requires" in props["reason"]


# --- completeness -----------------------------------------------------------------------------


def _notes(log: dict[str, Any]) -> list[dict[str, Any]]:
    return list(run0(log)["invocations"][0]["toolExecutionNotifications"])


def test_complete_scan_is_successful_with_no_error_notifications() -> None:
    log = log_of(t04())
    inv = run0(log)["invocations"][0]
    assert inv["executionSuccessful"] is True and inv["exitCode"] == 1
    assert inv["startTimeUtc"] == "2026-10-13T00:00:00Z"
    assert not [n for n in _notes(log) if n["level"] == "error"]
    assert run0(log)["properties"]["nexvul"]["completeness"]["status"] == "complete"


def test_partial_scan_is_visible_in_sarif() -> None:
    log = log_of(t05())
    inv = run0(log)["invocations"][0]
    assert inv["executionSuccessful"] is False and inv["exitCode"] == 3
    notes = _notes(log)
    assert notes[0]["descriptor"]["id"] == "nexvul.completeness.partial"
    assert notes[0]["level"] == "error"
    assert notes[0]["message"]["text"].startswith("PARTIAL SCAN — 4 of 312 files not analysed.")
    ids = {n["descriptor"]["id"]: n for n in notes}
    for reason in ("parse_error", "max_file_size", "timeout"):
        assert ids[f"nexvul.skip.{reason}"]["level"] == "error"
    parse = ids["nexvul.skip.parse_error"]
    assert parse["message"]["text"] == "2 files not analysed: parse error."
    uris = [loc["physicalLocation"]["artifactLocation"]["uri"] for loc in parse["locations"]]
    assert uris == ["agent/legacy.py", "tools/gen_api.py"]
    assert "nexvul.skip.unsupported_file_type" not in ids  # info, not a gap
    cfg = run0(log)["invocations"][0]["toolConfigurationNotifications"]
    assert cfg[0]["level"] == "warning" and "rules.disabled" in cfg[0]["message"]["text"]
    props = run0(log)["properties"]["nexvul"]
    assert props["completeness"]["status"] == "partial" and props["status"] == "partial"
    assert props["completeness"]["files_not_analysed"] == 4


def test_failed_scan_rule_failure_limits_and_counted_skips() -> None:
    failed = _notes(log_of(t18()))
    assert failed[0]["descriptor"]["id"] == "nexvul.completeness.failed"
    assert failed[0]["message"]["text"].startswith("SCAN FAILED — nothing to analyse")
    assert run0(log_of(t18()))["invocations"][0]["executionSuccessful"] is False
    none = _notes(log_of(SCENARIOS["T07"]()))
    assert "none of the 2 files in scope" in none[0]["message"]["text"]

    rf = _notes(log_of(t05_rule_failure()))
    failure = next(n for n in rf if n["descriptor"]["id"] == "nexvul.rule_failure")
    assert failure["message"]["text"].startswith("Rule NEX014 stopped with RuntimeError")
    # NEX014 is not built in; it has a fallback descriptor because a finding of it exists.
    rules = run0(log_of(t05_rule_failure()))["tool"]["driver"]["rules"]
    assert rules[failure["associatedRule"]["index"]]["id"] == "NEX014"
    alone = replace(t05_rule_failure(), findings=())
    lone = next(n for n in _notes(log_of(alone)) if n["descriptor"]["id"] == "nexvul.rule_failure")
    assert "associatedRule" not in lone

    base = t05()
    c = replace(
        base.completeness,
        status=base.completeness.status,
        limits_hit=("max_files",),
        findings_truncated=3,
        skipped_list_truncated=7,
        allow_partial=True,
        skipped_by_reason=(
            *base.completeness.skipped_by_reason,
            (SkipReason.EXCLUDED_BY_CONFIG, 2),
        ),
        rule_failures=(
            *base.completeness.rule_failures,
            type(t05_rule_failure().completeness.rule_failures[0])("NEX007", "KeyError"),
        ),
    )
    notes = _notes(log_of(replace(base, completeness=c)))
    texts = {n["descriptor"]["id"]: n for n in notes}
    assert "--allow-partial was set." in notes[0]["message"]["text"]
    assert texts["nexvul.limit_hit"]["level"] == "error"
    assert texts["nexvul.findings_truncated"]["message"]["text"].startswith("3 findings dropped")
    assert texts["nexvul.skip.list_truncated"]["level"] == "note"
    assert texts["nexvul.skip.excluded_by_config"]["level"] == "note"
    assert "counted, not partial" in texts["nexvul.skip.excluded_by_config"]["message"]["text"]
    rule_notes = [n for n in notes if n["descriptor"]["id"] == "nexvul.rule_failure"]
    assert any(n.get("associatedRule") == {"id": "NEX007", "index": 0} for n in rule_notes)
    assert VALIDATOR.errors(log_of(replace(base, completeness=c))) == []


def test_not_applied_config_change_is_a_note() -> None:
    cfg = run0(log_of(t17_ci()))["invocations"][0]["toolConfigurationNotifications"]
    assert cfg[0]["level"] == "note" and "[NOT APPLIED]" in cfg[0]["message"]["text"]


# --- limits and truncation --------------------------------------------------------------------


def test_result_count_limit_truncates_lowest_severity_with_notice() -> None:
    log = json.loads(render_sarif(t04(), REG, limits=SarifLimits(max_results=2)))
    run = run0(log)
    assert [r["ruleId"] for r in run["results"]] == ["NEX018", "NEX002"]
    inv = run["invocations"][0]
    assert inv["executionSuccessful"] is False
    notice = inv["toolExecutionNotifications"][0]
    assert notice["descriptor"]["id"] == "nexvul.sarif.truncated" and notice["level"] == "error"
    assert "2 of 6 results kept" in notice["message"]["text"]
    stats = run["properties"]["nexvul"]["sarif"]
    assert stats == {**stats, "results_total": 6, "results_emitted": 2, "results_dropped": 4}
    assert VALIDATOR.errors(log) == []


def test_size_limit_truncates_and_never_silently() -> None:
    full = render_sarif(t04(), REG, pretty=False)
    import gzip

    size = len(gzip.compress(full.encode(), mtime=0))
    log = json.loads(
        render_sarif(t04(), REG, pretty=False, limits=SarifLimits(max_gzip_bytes=size - 1))
    )
    run = run0(log)
    assert 0 < len(run["results"]) < 6
    assert run["invocations"][0]["toolExecutionNotifications"][0]["descriptor"]["id"] == (
        "nexvul.sarif.truncated"
    )
    # A limit nothing can meet still produces a valid, explained log with zero results.
    tiny = json.loads(render_sarif(t04(), REG, limits=SarifLimits(max_gzip_bytes=10)))
    assert run0(tiny)["results"] == []
    assert "0 of 6 results kept" in _notes(tiny)[0]["message"]["text"]
    assert VALIDATOR.errors(tiny) == []


def test_long_flows_are_capped() -> None:
    steps = tuple(FlowStep(i + 1, FlowRole.STEP, loc("a.py", i + 1), "x") for i in range(1_005))
    f = replace(NEX014, flow=steps)
    [result] = run0(log_of(replace(t04(), findings=(f,), suppressed=())))["results"]
    flow = result["codeFlows"][0]
    assert len(flow["threadFlows"][0]["locations"]) == 1_000
    assert flow["message"]["text"] == "Flow truncated: 1000 of 1005 steps shown."


# --- hostile input (T-12, SR-10, SR-12) ---------------------------------------------------------

HOSTILE_PATH = "\u202eevil/<img src=x onerror=alert(1)>/\x1b[31m.py"
HOSTILE_MESSAGE = (
    "Tool </script><script>alert(1)</script> [click me](javascript:alert(1)) "
    "![pixel](https://evil.example/p.png) visit https://evil.example/phish?t=1 or www.evil.example "
    "\x1b]8;;https://evil.example\x07link\x1b]8;;\x07 \u202egnp.exe **bold** # heading "
    + "A"
    * 4000
)


def _hostile_result() -> ScanResult:
    where = FindingLocation(HOSTILE_PATH, 3, 2, 3, 9)
    f = replace(
        NEX014,
        location=where,
        message=HOSTILE_MESSAGE,
        evidence=(Evidence("kind", HOSTILE_MESSAGE, "</script>" * 200),),
        limitations=(HOSTILE_MESSAGE,),
        flow=(
            FlowStep(1, FlowRole.SOURCE, where, "<svg onload=alert(1)>" + "B" * 2000),
            FlowStep(2, FlowRole.SINK, FindingLocation("../../etc/passwd", 1, 1, 1, 2), "x"),
        ),
    )
    abs_path = replace(NEX015, location=FindingLocation("/abs/C:/x.py", 1, 1, 1, 1), message="m")
    return replace(t04(), findings=(f, abs_path), suppressed=())


def test_hostile_strings_are_inert_in_sarif() -> None:
    text = render_sarif(_hostile_result(), REG)
    log = json.loads(text)
    assert VALIDATOR.errors(log) == []
    # No control, ESC or bidi character in any decoded string (they are escaped as visible text).
    for _key, value in walk(log):
        if isinstance(value, str):
            hidden = [c for c in value if c != "\n" and unicodedata.category(c) in ("Cc", "Cf")]
            assert not hidden, value[:80]
    assert "\\u001b" not in text  # json.dumps would write a raw ESC this way
    # Repo-derived text never reaches any markdown property.
    for key, value in walk(log):
        if key == "markdown":
            for needle in ("evil", "onerror", "<script", "javascript:", "AAAA", "onload"):
                assert needle not in value
    result = run0(log)["results"][0]
    msg = result["message"]["text"]
    assert len(msg) <= MAX_MESSAGE_CHARS and "Confidence: high. Steps: 2" in msg
    assert "evil.example/phish" not in msg and "https://" not in msg and "www." not in msg
    assert "<url literal," in msg
    assert "markdown" not in result["message"]
    for location in all_locations(log):
        uri = location["artifactLocation"]["uri"]
        assert "<" not in uri and ">" not in uri and " " not in uri
        assert ".." not in uri.split("/") and not uri.startswith("/") and ":" not in uri
    sink = result["codeFlows"][0]["threadFlows"][0]["locations"][1]
    assert sink["location"]["physicalLocation"]["artifactLocation"]["uri"] == "etc/passwd"
    props = result["properties"]["nexvul"]
    assert len(props["evidence"][0]["snippet"]) <= 300
    assert len(props["message"]) <= 1000


def test_artifact_uri_encoding() -> None:
    assert artifact_uri(FindingLocation("dir/a b%.py", 1, 1, 1, 1)) == "dir/a%20b%25.py"
    assert artifact_uri(FindingLocation("./x/../y.py", 1, 1, 1, 1)) == "x/y.py"
    assert artifact_uri(FindingLocation("c:\\\\w\\\\a.py", 1, 1, 1, 1)) == "c%3A/w/a.py"
    assert artifact_uri(FindingLocation("/", 1, 1, 1, 1)) == "unknown"
    # display escapes are inverted so the URI names the real file
    assert artifact_uri(FindingLocation("a\\u{202e}b.py", 1, 1, 1, 1)) == "a%E2%80%AEb.py"
    assert artifact_uri(FindingLocation("a\\x1b.py", 1, 1, 1, 1)) == "a%1B.py"
    raw = base64.b64encode(b"bad\xffname.py").decode()
    assert artifact_uri(FindingLocation("bad\\xffname.py", 1, 1, 1, 1, raw)) == "bad%FFname.py"


def test_text_helpers() -> None:
    assert defang_urls("at http://x.example/a, over http:// to") == (
        "at <url literal, 18 chars>, over http:// to"
    )
    assert defang_urls("see www.a.b/c") == "see <url literal, 9 chars>"
    assert md_escape("a*b_[c](d) <e> #1.") == "a\\*b\\_\\[c\\]\\(d\\) \\<e\\> \\#1\\."
    assert primary_location_line_hash("sha256:" + "0123456789abcdef" * 4) == "0123456789abcdef:1"


def test_rule_help_links_only_allowlisted_hosts() -> None:
    log = log_of(t04())
    for rule in run0(log)["tool"]["driver"]["rules"]:
        for url in re.findall(r"\]\(([^)]*)\)", rule["help"]["markdown"]):
            assert re.match(
                r"https://(github\.com|modelcontextprotocol\.io|owasp\.org|genai\.owasp\.org|"
                r"cwe\.mitre\.org)/",
                url,
            )


def test_rule_help_links_reject_other_hosts() -> None:
    from nexvul.reporting.sarif import _link

    assert _link("https://evil.example/x") == ("https://evil.example/x", None)
    assert _link("https://github.com.evil.example/x")[1] is None
    assert _link("docs/rules/NEX007.md")[1] is not None
    assert _link("tests/support/x.py") == ("tests/support/x.py", None)


def test_test_rule_without_doc_and_suppression_note() -> None:
    """Rules without a RuleDoc (and without suppression notes) still get full help."""
    log = json.loads(render_sarif(t04(), default_test_registry()))
    assert VALIDATOR.errors(log) == []
    rules = {r["id"]: r for r in run0(log)["tool"]["driver"]["rules"]}
    for rule in default_test_registry():
        assert "#### Suppressing this finding" in rules[rule.meta.id]["help"]["markdown"]
    # Findings of rules outside the registry get a minimal, trusted descriptor.
    assert rules["NEX018"]["help"]["text"].startswith("Require human approval")


# --- fingerprints, determinism, goldens ----------------------------------------------------------


def test_fingerprint_stable_across_line_moves(tmp_path: Path) -> None:
    body = {"mcpServers": {"search": {"type": "http", "url": "http://mcp.example.com/mcp"}}}
    one = scan_virtual({".cursor/mcp.json": json.dumps(body).encode()}, tmp_path / "a")
    moved = "\n\n\n\n" + json.dumps(body, indent=4)
    two = scan_virtual({".cursor/mcp.json": moved.encode()}, tmp_path / "b")
    [r1] = run0(log_of(one))["results"]
    [r2] = run0(log_of(two))["results"]
    line = lambda r: r["locations"][0]["physicalLocation"]["region"]["startLine"]  # noqa: E731
    assert line(r1) != line(r2)
    assert r1["partialFingerprints"] == r2["partialFingerprints"]


def test_render_is_deterministic() -> None:
    assert render_sarif(t05(), REG) == render_sarif(t05(), REG)
    assert sarif_log(t05(), REG) == json.loads(render_sarif(t05(), REG, pretty=False))
    assert render_sarif(t05(), REG, pretty=False).count("\n") == 1


def test_is_nexvul_sarif() -> None:
    for pretty in (True, False):
        assert is_nexvul_sarif(render_sarif(t04(), REG, pretty=pretty).encode()[:256])
    assert not is_nexvul_sarif(b'{"$schema": "x", "version": "2.1.0"}')
    assert not is_nexvul_sarif(b"# README\n")


def _normalise(result: ScanResult) -> ScanResult:
    tool = replace(result.tool, python="3.x", platform="test-platform", version="0.0.0-test")
    return replace(
        result,
        tool=tool,
        target="./mcp-demo",
        target_name="mcp-demo",
        started_at="2026-10-13T00:00:00+00:00",
        ended_at="2026-10-13T00:00:01+00:00",
        timings=(),
        completeness=replace(
            result.completeness,
            notes=tuple(n for n in result.completeness.notes if "memory" not in n),
        ),
    )


def _check(path: Path, text: str) -> None:
    if UPDATE:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    assert path.exists(), f"missing golden {path}; run with NEXVUL_UPDATE_GOLDEN=1"
    assert text == path.read_text(encoding="utf-8")


def test_golden_real_nex007_scan(tmp_path: Path) -> None:
    doc = (
        '{\n  "mcpServers": {\n    "search": {\n      "type": "http",\n'
        '      "url": "http://mcp.example.com/mcp"\n    },\n    "docs": {\n'
        '      "type": "http",\n      "url": "https://docs.example.com/mcp"\n    }\n  }\n}\n'
    )
    result = _normalise(scan_virtual({".cursor/mcp.json": doc.encode()}, tmp_path / "mcp-demo"))
    text = render_sarif(result, REG)
    log = json.loads(text)
    assert VALIDATOR.errors(log) == []
    results = run0(log)["results"]
    assert [r["level"] for r in results] == ["error", "warning"]
    assert results[1]["message"]["text"].startswith("MEDIUM (rule default HIGH) · ")
    assert results[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 5
    _check(GOLDEN / "NEX007-scan.sarif", text)


@pytest.mark.parametrize("scenario", ["T04", "T05", "T17-ci"])
def test_golden_synthetic_scenarios(scenario: str) -> None:
    _check(GOLDEN / f"{scenario}.sarif", render_sarif(SCENARIOS[scenario](), REG))


# --- CLI --------------------------------------------------------------------------------------


def _run(argv: list[str]) -> int:
    with pytest.raises(SystemExit) as exc:
        main(argv)
    return int(exc.value.code or 0)


def _mcp_project(tmp_path: Path) -> Path:
    root = tmp_path / "proj"
    (root / ".cursor").mkdir(parents=True)
    (root / ".cursor" / "mcp.json").write_text(
        '{"mcpServers": {"s": {"type": "http", "url": "http://mcp.example.com/mcp"}}}'
    )
    (root / ".nexvul.yml").write_text("rules:\n  enabled: [NEX007]\n")
    return root


@pytest.fixture
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("CI", "GITHUB_ACTIONS", "NO_COLOR", "FORCE_COLOR"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(cli_main, "registry_factory", builtin_registry)


@pytest.mark.usefixtures("_clean_env")
def test_cli_sarif_stdout_and_exit_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _mcp_project(tmp_path)
    assert _run(["scan", str(root), "--format", "sarif"]) == 1
    log = json.loads(capsys.readouterr().out)
    assert VALIDATOR.errors(log) == []
    [result] = run0(log)["results"]
    assert result["ruleId"] == "NEX007"
    assert (
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == ".cursor/mcp.json"
    )
    assert str(tmp_path) not in json.dumps(log)  # no absolute paths (SR-24)


@pytest.mark.usefixtures("_clean_env")
def test_cli_sarif_output_rules(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _mcp_project(tmp_path)
    out = tmp_path / "nexvul.sarif"
    assert _run(["scan", str(root), "--format", "sarif", "--output", str(out)]) == 1
    assert "(SARIF, 1 findings)" in capsys.readouterr().err
    assert VALIDATOR.errors(json.loads(out.read_text())) == []
    # Overwriting our own SARIF is allowed; a foreign file needs --force (exit 2, no scan).
    assert _run(["scan", str(root), "--format", "sarif", "--output", str(out)]) == 1
    other = tmp_path / "notes.sarif"
    other.write_text("my notes\n")
    assert _run(["scan", str(root), "--format", "sarif", "--output", str(other)]) == 2
    assert other.read_text() == "my notes\n"
    assert _run(["scan", str(root), "--format", "sarif", "--output", str(other), "--force"]) == 1
    # A JSON report is not a SARIF log.
    js = tmp_path / "r.json"
    assert _run(["scan", str(root), "--format", "json", "--output", str(js)]) == 1
    assert _run(["scan", str(root), "--format", "sarif", "--output", str(js)]) == 2


@pytest.mark.usefixtures("_clean_env")
def test_cli_sarif_partial_exit_3(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _mcp_project(tmp_path)
    (root / "app.ts").write_text("export const x = 1;\n")
    assert _run(["scan", str(root), "--format", "sarif"]) == 3
    log = json.loads(capsys.readouterr().out)
    inv = run0(log)["invocations"][0]
    assert inv["executionSuccessful"] is False and inv["exitCode"] == 3
    assert inv["toolExecutionNotifications"][0]["message"]["text"].startswith("PARTIAL SCAN")
