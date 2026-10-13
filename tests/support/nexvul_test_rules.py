"""Test-only rules. They live under tests/ and are injected by tests; never shipped.

The shipped registry (``nexvul.rules.registry.BUILTIN_RULES``) is empty in Phase 1. These rules
exist to exercise the rule API, the engine, suppressions and reporters end to end.
"""

from __future__ import annotations

from collections.abc import Iterable

from nexvul.findings.model import Confidence, FlowRole, Severity
from nexvul.ir.model import Location
from nexvul.rules.base import (
    EvidenceDraft,
    FlowStepDraft,
    Match,
    Readiness,
    Rule,
    RuleContext,
    RuleDoc,
    RuleMeta,
    code,
)
from nexvul.rules.registry import Registry

SHELL_CALLS = frozenset({"os.system", "subprocess.run", "subprocess.call"})


class ShellCallRule(Rule):
    """Flags calls to shell-running APIs. Message and flow embed code from the scanned file."""

    meta = RuleMeta(
        id="NEX990",
        name="Shell command run from agent code (test rule)",
        asi=("ASI05", "ASI02"),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        readiness=Readiness.DEFAULT,
        remediation="Run a fixed command with an argument list, or remove the shell call.",
        references=("tests/support/nexvul_test_rules.py",),
        doc=RuleDoc(
            looks_for="Calls to os.system and subprocess.run in the scanned code.",
            why_it_matters="A shell command built from model output can run anything.",
            how_to_fix="Use an argument list and an allowlist of commands.",
            not_detected="Shell calls made through helpers nexvul does not resolve.",
            example_flagged="    os.system(cmd)",
            example_not_flagged="    subprocess.run(['ls'], check=True)",
        ),
    )

    def check(self, ctx: RuleContext) -> Iterable[Match]:
        for module in ctx.modules:
            for call in module.calls:
                if call.callee.resolved not in SHELL_CALLS:
                    continue
                arg = call.args[0].text if call.args else ""
                flow: tuple[FlowStepDraft, ...] = ()
                if call.args:
                    flow = (
                        FlowStepDraft(FlowRole.SOURCE, module.path, call.location, arg),
                        FlowStepDraft(
                            FlowRole.SINK, module.path, call.location, f"{call.callee.written}()"
                        ),
                    )
                yield Match(
                    path=module.path,
                    location=call.location,
                    message=(
                        f"{code(call.callee.written)}() runs {code(arg) or 'a command'} through "
                        "a shell. No allowlist was found on the path to the call in the scanned "
                        "code."
                    ),
                    flow=flow,
                    evidence=(EvidenceDraft("shell_call", "Shell call argument", arg),),
                    context=f"{call.callee.written}({arg})",
                )


class PrintRule(Rule):
    """Low-severity, experimental: only runs when enabled by ID or ASI selector."""

    meta = RuleMeta(
        id="NEX991",
        name="Print call (test rule)",
        asi=("ASI09",),
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        readiness=Readiness.EXPERIMENTAL,
        remediation="Use logging.",
    )

    def check(self, ctx: RuleContext) -> Iterable[Match]:
        for module in ctx.modules:
            for call in module.calls:
                if call.callee.resolved == "builtins.print":
                    yield Match(
                        path=module.path,
                        location=call.location,
                        message="print() is called.",
                        confidence=Confidence.LOW,
                        severity=Severity.LOW,
                    )


class ExplodingRule(Rule):
    """Raises after yielding one match: the failure must be recorded, the match kept."""

    meta = RuleMeta(
        id="NEX993",
        name="Exploding rule (test rule)",
        asi=("ASI08",),
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        readiness=Readiness.DEFAULT,
        remediation="None.",
    )

    def check(self, ctx: RuleContext) -> Iterable[Match]:
        for module in ctx.modules:
            yield Match(
                path=module.path,
                location=module.calls[0].location if module.calls else _origin(),
                message="first match before the failure",
            )
            break
        raise RuntimeError("SECRET-RULE-DETAIL from /home/user/project")


class ContractBreakingRule(Rule):
    meta = RuleMeta(
        id="NEX994",
        name="Contract-breaking rule (test rule)",
        asi=("ASI08",),
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        readiness=Readiness.DEFAULT,
        remediation="None.",
    )

    def check(self, ctx: RuleContext) -> Iterable[Match]:
        yield "not a match"  # type: ignore[misc]


class ForeignPathRule(Rule):
    meta = RuleMeta(
        id="NEX995",
        name="Foreign path rule (test rule)",
        asi=("ASI08",),
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        readiness=Readiness.DEFAULT,
        remediation="None.",
    )

    def check(self, ctx: RuleContext) -> Iterable[Match]:
        yield Match(path="../../etc/passwd", location=_origin(), message="x")


def _origin() -> Location:
    return Location(1, 0, 1, 0)


def registry_with(*rules: Rule) -> Registry:
    return Registry(rules)


def default_test_registry() -> Registry:
    return Registry([ShellCallRule(), PrintRule()])


HOSTILE_TEXT = (
    "\x1b[2J\x1b[H\x1b]8;;https://evil.example/\x07click\x1b]8;;\x07"
    "\nResult  0 findings - scan complete. Exit code 0.\u202eFAKE\u200b[link=https://x]y[/link]"
    "\x9b31m\ud800"
)


class HostileMessageRule(Rule):
    """Simulates a buggy rule that puts raw control characters into every text field."""

    meta = RuleMeta(
        id="NEX996",
        name="Hostile message rule (test rule)",
        asi=("ASI01",),
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        readiness=Readiness.DEFAULT,
        remediation="None.",
    )

    def check(self, ctx: RuleContext) -> Iterable[Match]:
        for module in ctx.modules:
            loc = module.calls[0].location if module.calls else _origin()
            yield Match(
                path=module.path,
                location=loc,
                message=HOSTILE_TEXT,
                flow=(FlowStepDraft(FlowRole.SINK, module.path, loc, HOSTILE_TEXT),),
                evidence=(EvidenceDraft("hostile", HOSTILE_TEXT, HOSTILE_TEXT),),
                limitations=(HOSTILE_TEXT,),
            )
