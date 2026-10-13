"""End-to-end scan pipeline (architecture §1, §3, §12; DEC-0004, DEC-0007, DEC-0012, DEC-0013).

Order (architecture §1.2):

1. validate the root (usage error, exit 2);
2. startup guard: no loaded module may come from the scan root (SR-02, exit 4);
3. effective config: repo ``.nexvul.yml`` (untrusted) + CLI flags (trusted, rank above repo
   config); in CI mode repo config may only tighten (DEC-0004 §1, exit 2 on a config error);
4. discovery (fd-based, no symlinks, every exclusion counted);
5. parse in isolated workers into the **same** completeness ledger;
6. rules over the IR (failures recorded, never swallowed);
7. inline suppressions (DEC-0004 §2, OD-03/OD-04);
8. completeness, status and exit code (precedence 2 > 4 > 3 > 1 > 0, OD-06; nothing to analyse
   exits 3, OD-05).

Nothing here prints. Nothing here imports or executes scanned code.
"""

from __future__ import annotations

import os
import platform
import sys
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime

from nexvul import __version__
from nexvul.core import limits
from nexvul.core.completeness import (
    Completeness,
    ExitCode,
    SkipReason,
    Status,
    exit_code_for,
    resolve_exit_code,
)
from nexvul.core.config import (
    ALL_KEYS,
    CONFIG_FILENAME,
    ConfigSource,
    ConfigValues,
    EffectiveConfig,
    LoadedConfig,
    load_repo_config,
    resolve_config,
)
from nexvul.core.discovery import DiscoveryOptions, discover
from nexvul.core.sanitize import display_path, display_text
from nexvul.core.startup import assert_no_module_from_roots
from nexvul.core.workers import WorkerOptions, analyse_files
from nexvul.findings.model import Finding, Severity
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
from nexvul.ir.model import ModuleIR
from nexvul.rules.engine import run_rules
from nexvul.rules.registry import Registry, builtin_registry
from nexvul.rules.suppressions import apply_suppressions


class ScanUsageError(Exception):
    """The scan cannot start because of how it was invoked (exit 2). Message is display-safe."""


@dataclass(frozen=True)
class ScanOptions:
    """Trusted inputs (CLI flags, environment). Repository content never sets these."""

    root: str
    ci: bool = False
    ci_reason: str = ""
    fail_on: str | None = None
    allow_partial: bool = False
    worker_options: WorkerOptions | None = None
    registry: Registry | None = None


def _cli_layer(fail_on: str | None) -> tuple[LoadedConfig, ...]:
    if fail_on is None:
        return ()
    values = ConfigValues(fail_on=fail_on)
    return (
        LoadedConfig(
            values=values, source=ConfigSource.CLI, display_path="command line", sha256="", size=0
        ),
    )


def _setting_value(effective: EffectiveConfig, key: str) -> str:
    attr = {
        "severity.fail_on": "fail_on",
        "rules.enabled": "rules_enabled",
        "rules.disabled": "rules_disabled",
        "exclude": "exclude",
        "frameworks.auto_detect": "auto_detect",
        "analysis.cross_file": "cross_file",
        "analysis.max_files": "max_files",
        "analysis.max_file_size": "max_file_size",
    }[key]
    value = getattr(effective, attr)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, frozenset | tuple):
        items = sorted(value) if isinstance(value, frozenset) else list(value)
        return display_text("[" + ", ".join(items) + "]", max_chars=160)
    return display_text(str(value), max_chars=80)


def _limited_notes(modules: tuple[ModuleIR, ...]) -> tuple[int, tuple[LimitedNote, ...]]:
    total = 0
    notes: list[LimitedNote] = []
    for module in modules:
        for item in module.limited:
            total += 1
            if len(notes) < limits.MAX_LIMITED_NOTES:
                notes.append(
                    LimitedNote(display_path(module.path), item.location.line, item.reason.value)
                )
    return total, tuple(notes)


def tool_info(registry: Registry) -> ToolInfo:
    return ToolInfo(
        name="nexvul",
        version=__version__,
        rule_pack_version=registry.pack_version,
        rule_pack_sha256=registry.sha256,
        python=platform.python_version(),
        platform=f"{platform.system()}-{platform.machine()}",
        parsers=(f"python: stdlib ast (CPython {sys.version_info[0]}.{sys.version_info[1]})",),
    )


def scan_status(ledger: Completeness) -> tuple[ScanStatus, FailedCause | None]:
    """Status from trusted accounting only. Zero analysed files is FAILED (input cause)."""
    if ledger.status is Status.FAILED:
        return ScanStatus.FAILED, None
    if ledger.files_scanned == 0:
        if ledger.files_not_analysed_partial == 0:
            return ScanStatus.FAILED, FailedCause.NOTHING_TO_ANALYSE
        return ScanStatus.FAILED, FailedCause.NONE_ANALYSED
    if ledger.status is Status.PARTIAL:
        return ScanStatus.PARTIAL, None
    return ScanStatus.COMPLETE, None


def scan_exit_code(
    ledger: Completeness,
    status: ScanStatus,
    cause: FailedCause | None,
    findings: tuple[Finding, ...],
    fail_on: Severity,
    *,
    allow_partial: bool,
) -> ExitCode:
    """OD-06 precedence. Nothing analysed is an input failure: exit 3, never downgraded."""
    over = any(f.active and f.severity.at_or_above(fail_on) for f in findings)
    if status is ScanStatus.FAILED and cause is not None:
        return resolve_exit_code(partial=True, findings_over_threshold=over)
    return exit_code_for(ledger, findings_over_threshold=over, partial_is_warning=allow_partial)


def run_scan(
    opts: ScanOptions,
    *,
    clock: Callable[[], float] = time.monotonic,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> ScanResult:
    """Run one scan. Raises ``ScanUsageError``/``ConfigError``/``DiscoveryError`` (exit 2),
    ``ModuleShadowingError``/``WorkerStartupError`` (exit 4)."""
    started = now()
    root = opts.root
    shown_root = display_path(root)
    if not os.path.exists(root):
        raise ScanUsageError(f"path not found: {shown_root}")
    if not os.path.isdir(root):
        raise ScanUsageError(f"not a directory: {shown_root}")
    assert_no_module_from_roots([root])

    registry = opts.registry if opts.registry is not None else builtin_registry()
    repo_layer = load_repo_config(root)
    resolved = resolve_config(repo=repo_layer, ci=opts.ci, overrides=_cli_layer(opts.fail_on))
    eff = resolved.effective

    t0 = clock()
    found = discover(
        root,
        DiscoveryOptions(
            max_files=eff.max_files, max_file_size=eff.max_file_size, exclude=eff.exclude
        ),
    )
    t1 = clock()
    files = tuple(f for f in found.files if f.path != CONFIG_FILENAME)
    if len(files) != len(found.files):
        found.completeness.record_skip(
            CONFIG_FILENAME, SkipReason.NEXVUL_CONFIG, "read as nexvul configuration"
        )
    worker_opts = replace(opts.worker_options or WorkerOptions(), max_file_size=eff.max_file_size)
    analysis = analyse_files(
        found.root, files, options=worker_opts, completeness=found.completeness
    )
    t2 = clock()
    ledger = analysis.completeness
    modules = analysis.modules

    selection = registry.select(eff.rules_enabled, eff.rules_disabled)
    run = run_rules(selection.enabled, modules, ledger, ci=opts.ci)
    outcome = apply_suppressions(run.findings, modules, registry.ids(), ci=opts.ci)
    t3 = clock()

    fail_on = Severity(eff.fail_on)
    status, cause = scan_status(ledger)
    code = scan_exit_code(
        ledger, status, cause, outcome.findings, fail_on, allow_partial=opts.allow_partial
    )
    dynamic_total, limited = _limited_notes(modules)
    report = CompletenessReport(
        status=status,
        failed_cause=cause,
        files_discovered=ledger.files_scanned + ledger.files_not_analysed_partial,
        files_analysed=ledger.files_scanned,
        files_not_analysed=ledger.files_not_analysed_partial,
        files_failed=ledger.files_failed,
        files_timed_out=ledger.files_timed_out,
        skipped_by_reason=tuple(sorted(ledger.skipped_by_reason.items())),
        skipped=tuple(ledger.skipped),
        skipped_list_truncated=ledger.skipped_list_truncated,
        limits_hit=tuple(lim.value for lim in ledger.limits_hit),
        rule_failures=tuple(ledger.rule_failures),
        findings_truncated=ledger.findings_truncated,
        notes=tuple(ledger.notes),
        dynamic_constructs_not_analysed=dynamic_total,
        suppressed_inline=outcome.inline_applied,
        allow_partial=opts.allow_partial,
    )
    languages = Counter(m.language for m in modules)
    by_id = {r.meta.id: r for r in selection.enabled}
    return ScanResult(
        tool=tool_info(registry),
        target=shown_root,
        target_name=display_text(os.path.basename(os.path.realpath(root)) or "/", max_chars=80),
        discovery_mode=found.mode.value,
        commit=display_text(found.git_head, max_chars=64) if found.git_head else None,
        started_at=started.isoformat(timespec="seconds"),
        ended_at=now().isoformat(timespec="seconds"),
        ci=opts.ci,
        ci_reason=opts.ci_reason,
        fail_on=fail_on,
        rules_available=len(registry),
        rules_enabled=tuple(
            RuleSummary(i, by_id[i].meta.name, by_id[i].meta.asi) for i in sorted(by_id)
        ),
        rules_failed=run.rules_failed,
        effective_config=tuple(
            EffectiveSetting(
                key,
                _setting_value(eff, key),
                tuple(s.value for s in eff.sources.get(key, (ConfigSource.DEFAULT,))),
            )
            for key in ALL_KEYS
        ),
        config_changes=resolved.changes,
        config_sources=resolved.config_sources,
        completeness=report,
        findings=tuple(f for f in outcome.findings if not f.suppressed),
        suppressed=tuple(f for f in outcome.findings if f.suppressed),
        suppression_issues=outcome.issues,
        languages_analysed=tuple(sorted(languages.items())),
        limited=limited,
        exit_code=int(code),
        timings=(("discover", t1 - t0), ("parse", t2 - t1), ("analyse", t3 - t2)),
    )
