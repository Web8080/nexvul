"""Deterministic synthetic ScanResults for golden-file tests of the reporters.

Content mirrors the illustrative data of docs/design/terminal-mockups.md (T02-T06, T18, T07) so
reviewers can compare the golden files with the mock-ups. Nothing here is scanned.
"""

from __future__ import annotations

from dataclasses import replace

from nexvul.core.completeness import RuleFailure, SkippedEntry, SkipReason
from nexvul.core.config import ChangeStatus, ConfigChange, ConfigProvenance, ConfigSource
from nexvul.findings.model import (
    Confidence,
    Finding,
    FindingLocation,
    FlowRole,
    FlowStep,
    Severity,
    Suppression,
    SuppressionStatus,
)
from nexvul.findings.result import (
    CompletenessReport,
    EffectiveSetting,
    FailedCause,
    LimitedNote,
    RuleSummary,
    ScanResult,
    ScanStatus,
    ToolInfo,
)
from nexvul.rules.suppressions import IssueKind, Problem, SuppressionIssue

FP = "sha256:" + "ab" * 32


def loc(path: str, line: int, col: int = 1) -> FindingLocation:
    return FindingLocation(path, line, col, line, col + 10)


def finding(  # noqa: PLR0917 - mirrors the mock-up columns
    rule_id: str,
    title: str,
    severity: Severity,
    asi: tuple[str, ...],
    where: FindingLocation,
    message: str,
    remediation: str,
    *,
    confidence: Confidence = Confidence.HIGH,
    flow: tuple[tuple[FlowRole, FindingLocation, str], ...] = (),
    suppression: Suppression | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        confidence=confidence,
        asi=asi,
        location=where,
        message=message,
        remediation=remediation,
        references=(f"docs/rules/{rule_id}.md",),
        fingerprint=FP,
        flow=tuple(FlowStep(i + 1, r, l_, t) for i, (r, l_, t) in enumerate(flow)),
        suppression=suppression or Suppression(),
    )


NEX018 = finding(
    "NEX018",
    "Financial action without human oversight",
    Severity.CRITICAL,
    ("ASI02", "ASI09"),
    loc("agent/billing.py", 58, 9),
    "Tool refund_order calls stripe.Refund.create() with an amount chosen by the model. No "
    "approval step was found on the path to the call in the scanned code.",
    "Require human approval before the call (needs_approval=True on the tool), or cap the "
    "amount in code.",
    confidence=Confidence.MEDIUM,
    flow=(
        (FlowRole.SOURCE, loc("agent/billing.py", 31), "@function_tool def refund_order(amount)"),
        (FlowRole.STEP, loc("agent/billing.py", 44), "amt = int(amount * 100)"),
        (
            FlowRole.SINK,
            loc("agent/billing.py", 58),
            "stripe.Refund.create(amount=amt, currency=order.currency)",
        ),
    ),
)
NEX002 = finding(
    "NEX002",
    "External content indexed into a vector store",
    Severity.HIGH,
    ("ASI06",),
    loc("agent/ingest.py", 42, 5),
    "Content returned by requests.get() reaches vector_store.add_documents() without an "
    "identified validation or trust-boundary check.",
    "Record provenance on stored documents and validate or allowlist sources before indexing.",
    flow=(
        (FlowRole.SOURCE, loc("agent/ingest.py", 30), "html = requests.get(url).text"),
        (FlowRole.STEP, loc("agent/ingest.py", 35), "text = clean(html)"),
        (FlowRole.STEP, loc("agent/ingest.py", 38), "docs = [Document(page_content=text)]"),
        (FlowRole.SINK, loc("agent/ingest.py", 42), "vector_store.add_documents(docs)"),
    ),
)
NEX007 = finding(
    "NEX007",
    "MCP connection without authentication or over cleartext",
    Severity.HIGH,
    ("ASI07", "ASI04"),
    loc("mcp.json", 12, 7),
    'Server "search" is reached over http:// at a non-loopback host with no auth headers or '
    "OAuth configuration.",
    "Use https:// and configure authentication for remote MCP servers.",
)
NEX014 = finding(
    "NEX014",
    "Agent iteration limit disabled or unbounded",
    Severity.MEDIUM,
    ("ASI08",),
    loc("agent/graph.py", 91, 12),
    "graph.compile() is invoked with recursion_limit=None.",
    "Set a finite recursion_limit sized to the longest legitimate run.",
)
NEX015 = finding(
    "NEX015",
    "Missing timeout around agent or tool execution",
    Severity.LOW,
    ("ASI08",),
    loc("agent/tools.py", 45, 16),
    "httpx.get() inside tool search_web has no timeout argument.",
    "Pass timeout= to the client or wrap the tool in asyncio.wait_for().",
    confidence=Confidence.MEDIUM,
)
SUPPRESSED_NEX006 = finding(
    "NEX006",
    "A2A / agent HTTP endpoint without authentication",
    Severity.HIGH,
    ("ASI07",),
    loc("agent/server.py", 41, 1),
    "POST /agents/run has no authentication dependency.",
    "Add an authentication dependency.",
    suppression=Suppression(
        SuppressionStatus.SUPPRESSED,
        line=40,
        justification="auth enforced by the API gateway (infra/gateway.tf, route /agents/*)",
    ),
)


def tool() -> ToolInfo:
    return ToolInfo(
        name="nexvul",
        version="0.1.0",
        rule_pack_version="0.0.0",
        rule_pack_sha256="sha256:" + "9c1e" * 16,
        python="3.13.0",
        platform="Test-arch",
        parsers=("python: stdlib ast (CPython 3.13)",),
    )


def completeness(**overrides: object) -> CompletenessReport:
    base = CompletenessReport(
        status=ScanStatus.COMPLETE,
        failed_cause=None,
        files_discovered=312,
        files_analysed=312,
        files_not_analysed=0,
        files_failed=0,
        files_timed_out=0,
        skipped_by_reason=(),
        skipped=(),
        skipped_list_truncated=0,
        limits_hit=(),
        rule_failures=(),
        findings_truncated=0,
        notes=(),
        dynamic_constructs_not_analysed=3,
        suppressed_inline=0,
        allow_partial=False,
    )
    return replace(base, **overrides)  # type: ignore[arg-type]


RULES = tuple(
    RuleSummary(i, t, a)
    for i, t, a in (
        ("NEX002", "External content indexed into a vector store", ("ASI06",)),
        ("NEX007", "MCP connection without authentication or over cleartext", ("ASI07", "ASI04")),
        ("NEX014", "Agent iteration limit disabled or unbounded", ("ASI08",)),
    )
)


def result(**overrides: object) -> ScanResult:
    base = ScanResult(
        tool=tool(),
        target="./my-agent-project",
        target_name="my-agent-project",
        discovery_mode="git",
        commit="9e41d0c",
        started_at="2026-10-13T00:00:00+00:00",
        ended_at="2026-10-13T00:00:05+00:00",
        ci=False,
        ci_reason="",
        fail_on=Severity.HIGH,
        rules_available=3,
        rules_enabled=RULES,
        rules_failed=(),
        effective_config=(
            EffectiveSetting("severity.fail_on", "high", ("default",)),
            EffectiveSetting("rules.disabled", "[NEX004]", ("default", "repo")),
        ),
        config_changes=(),
        config_sources=(
            ConfigProvenance(ConfigSource.REPO, ".nexvul.yml", "4be1" + "0" * 60, None),
        ),
        completeness=completeness(),
        findings=(),
        suppressed=(),
        suppression_issues=(),
        languages_analysed=(("python", 241),),
        limited=(LimitedNote("agent/plugins.py", 12, "dynamic_import"),),
        exit_code=0,
        timings=(("discover", 0.08), ("parse", 1.21), ("analyse", 0.94)),
    )
    return replace(base, **overrides)  # type: ignore[arg-type]


PARTIAL_SKIPS = (
    SkippedEntry("agent/legacy.py", SkipReason.PARSE_ERROR, "syntax error at line 3"),
    SkippedEntry("tools/gen_api.py", SkipReason.PARSE_ERROR, "syntax error at line 9"),
    SkippedEntry("data/fixtures.py", SkipReason.MAX_FILE_SIZE, "3145728 > 1048576"),
    SkippedEntry("agent/huge_graph.py", SkipReason.TIMEOUT, "10 s limit"),
    SkippedEntry("README.md", SkipReason.UNSUPPORTED_FILE_TYPE, ""),
)
PARTIAL_COUNTS = (
    (SkipReason.MAX_FILE_SIZE, 1),
    (SkipReason.PARSE_ERROR, 2),
    (SkipReason.TIMEOUT, 1),
    (SkipReason.UNSUPPORTED_FILE_TYPE, 1),
)
WEAKENED = ConfigChange(
    "rules.disabled",
    "add NEX004",
    ConfigSource.REPO,
    ChangeStatus.APPLIED,
    "loosening honoured (outside CI mode or from a trusted source)",
)


def t04() -> ScanResult:
    return result(
        findings=(NEX018, NEX002, NEX007, NEX014, NEX015),
        suppressed=(SUPPRESSED_NEX006,),
        completeness=completeness(suppressed_inline=1),
        exit_code=1,
    )


def t02() -> ScanResult:
    return result()


def t03() -> ScanResult:
    return result(findings=(NEX014, NEX015), exit_code=0)


def t05() -> ScanResult:
    return result(
        findings=(NEX018, NEX002, NEX007, NEX014),
        config_changes=(WEAKENED,),
        completeness=completeness(
            status=ScanStatus.PARTIAL,
            files_analysed=308,
            files_not_analysed=4,
            files_failed=2,
            files_timed_out=1,
            skipped_by_reason=PARTIAL_COUNTS,
            skipped=PARTIAL_SKIPS,
        ),
        exit_code=3,
    )


def t06() -> ScanResult:
    return replace(t05(), findings=(), config_changes=())


def t05_rule_failure() -> ScanResult:
    return result(
        findings=(NEX014,),
        completeness=completeness(
            status=ScanStatus.PARTIAL, rule_failures=(RuleFailure("NEX014", "RuntimeError"),)
        ),
        rules_failed=("NEX014",),
        exit_code=3,
    )


def t18() -> ScanResult:
    return result(
        target="./docs",
        completeness=completeness(
            status=ScanStatus.FAILED,
            failed_cause=FailedCause.NOTHING_TO_ANALYSE,
            files_discovered=0,
            files_analysed=0,
            dynamic_constructs_not_analysed=0,
            skipped_by_reason=((SkipReason.UNSUPPORTED_FILE_TYPE, 3),),
            skipped=(
                SkippedEntry("a.md", SkipReason.UNSUPPORTED_FILE_TYPE),
                SkippedEntry("b.md", SkipReason.UNSUPPORTED_FILE_TYPE),
                SkippedEntry("logo.png", SkipReason.UNSUPPORTED_FILE_TYPE),
            ),
        ),
        languages_analysed=(),
        limited=(),
        exit_code=3,
    )


def t07() -> ScanResult:
    return result(
        completeness=completeness(
            status=ScanStatus.FAILED,
            failed_cause=FailedCause.NONE_ANALYSED,
            files_discovered=2,
            files_analysed=0,
            files_not_analysed=2,
            files_failed=2,
            dynamic_constructs_not_analysed=0,
            skipped_by_reason=((SkipReason.PARSE_ERROR, 2),),
            skipped=PARTIAL_SKIPS[:2],
        ),
        languages_analysed=(),
        exit_code=3,
    )


def t17_ci() -> ScanResult:
    not_applied = replace(
        NEX015,
        suppression=Suppression(
            SuppressionStatus.NOT_APPLIED,
            line=87,
            justification=None,
            reason="CI requires a justification of at least 10 characters after ' -- '",
        ),
    )
    return result(
        ci=True,
        ci_reason="--ci",
        findings=(NEX018, not_applied),
        suppressed=(SUPPRESSED_NEX006,),
        suppression_issues=(
            SuppressionIssue(
                IssueKind.REJECTED,
                "agent/admin.py",
                30,
                "suppression ignored: no rule ID. Write ignore[NEX0nn] -- <reason>.",
                Problem.NO_RULE_ID,
            ),
            SuppressionIssue(
                IssueKind.UNMATCHED,
                "agent/old.py",
                12,
                "ignore[NEX014] matched no finding.",
                rule_ids=("NEX014",),
            ),
        ),
        config_changes=(
            ConfigChange(
                "severity.fail_on",
                "high -> critical",
                ConfigSource.REPO,
                ChangeStatus.NOT_APPLIED,
                "loosening from untrusted repository config in CI mode",
            ),
        ),
        completeness=completeness(suppressed_inline=1),
        exit_code=1,
    )


SCENARIOS = {
    "T02": t02,
    "T03": t03,
    "T04": t04,
    "T05": t05,
    "T05-rule-failure": t05_rule_failure,
    "T06": t06,
    "T07": t07,
    "T17-ci": t17_ci,
    "T18": t18,
}
