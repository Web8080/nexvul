"""End-to-end pipeline (core/scan.py): config, discovery, workers, rules, suppressions, exit codes.

These tests spawn real parse workers (one each, to keep them fast).
"""

from __future__ import annotations

import itertools
import types
from pathlib import Path

import pytest
from nexvul_test_rules import ExplodingRule, PrintRule, ShellCallRule, registry_with

from nexvul.core.completeness import Completeness, ExitCode, resolve_exit_code
from nexvul.core.config import ChangeStatus, ConfigError
from nexvul.core.discovery import DiscoveryError
from nexvul.core.scan import ScanOptions, ScanUsageError, run_scan, scan_exit_code, scan_status
from nexvul.core.startup import ModuleShadowingError
from nexvul.core.workers import WorkerOptions
from nexvul.findings.model import Severity
from nexvul.findings.result import FailedCause, ScanStatus

WORKERS = WorkerOptions(max_workers=1)
SHELL = "import os\nos.system('ls')\nprint('x')\n"


def scan(root: Path, **kw: object):  # type: ignore[no-untyped-def]
    kw.setdefault("registry", registry_with(ShellCallRule(), PrintRule()))
    return run_scan(ScanOptions(root=str(root), worker_options=WORKERS, **kw))  # type: ignore[arg-type]


def tree(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return tmp_path


# --- exit-code precedence (OD-06): 2 > 4 > 3 > 1 > 0 --------------------------------------------


def expected_code(usage: bool, internal: bool, partial: bool, over: bool, allow: bool) -> int:
    if usage:
        return 2
    if internal:
        return 4
    if partial and not allow:
        return 3
    return 1 if over else 0


@pytest.mark.parametrize("flags", list(itertools.product([False, True], repeat=5)))
def test_exit_code_precedence_table(flags: tuple[bool, ...]) -> None:
    usage, internal, partial, over, allow = flags
    got = resolve_exit_code(
        usage_error=usage,
        internal_error=internal,
        partial=partial,
        findings_over_threshold=over,
        partial_is_warning=allow,
    )
    assert int(got) == expected_code(usage, internal, partial, over, allow)


def test_nothing_analysed_is_failed_and_exits_3_even_with_allow_partial() -> None:
    ledger = Completeness()
    status, cause = scan_status(ledger)
    assert (status, cause) == (ScanStatus.FAILED, FailedCause.NOTHING_TO_ANALYSE)
    code = scan_exit_code(ledger, status, cause, (), Severity.HIGH, allow_partial=True)
    assert code is ExitCode.PARTIAL
    ledger.record_internal_error()
    assert scan_status(ledger) == (ScanStatus.FAILED, None)


# --- full scans ---------------------------------------------------------------------------------


def test_complete_scan_with_findings_exits_1(tmp_path: Path) -> None:
    r = scan(tree(tmp_path, {"agent/a.py": SHELL}))
    assert r.status is ScanStatus.COMPLETE and r.exit_code == 1
    assert [f.rule_id for f in r.findings] == ["NEX990"]  # NEX991 experimental: off
    assert r.languages_analysed == (("python", 1),)
    assert r.completeness.files_discovered == 1 and r.rules_available == 2


def test_fail_on_from_cli_and_repo_config(tmp_path: Path) -> None:
    root = tree(tmp_path, {"a.py": SHELL, ".nexvul.yml": "severity:\n  fail_on: critical\n"})
    local = scan(root)
    assert local.exit_code == 0 and local.fail_on is Severity.CRITICAL
    assert any(c.status is ChangeStatus.APPLIED for c in local.config_changes)
    # CLI outranks repository config (architecture §3.1)
    assert scan(root, fail_on="high").exit_code == 1


def test_ci_mode_rejects_loosening_from_repo_config(tmp_path: Path) -> None:
    root = tree(
        tmp_path,
        {
            "a.py": SHELL,
            ".nexvul.yml": "severity:\n  fail_on: critical\nrules:\n  disabled: [NEX990]\n",
        },
    )
    assert scan(root).exit_code == 0  # locally the developer's config applies
    r = scan(root, ci=True, ci_reason="--ci")
    assert r.exit_code == 1 and r.fail_on is Severity.HIGH
    assert [f.rule_id for f in r.findings] == ["NEX990"]
    not_applied = {c.key for c in r.config_changes if c.status is ChangeStatus.NOT_APPLIED}
    assert not_applied == {"severity.fail_on", "rules.disabled"}


def test_repo_config_can_tighten_in_ci(tmp_path: Path) -> None:
    root = tree(tmp_path, {"a.py": "print('x')\n", ".nexvul.yml": "rules:\n  enabled: [NEX991]\n"})
    r = scan(root, ci=True, fail_on="low")
    assert [f.rule_id for f in r.findings] == ["NEX991"] and r.exit_code == 1


def test_partial_scan_exits_3_and_allow_partial_downgrades(tmp_path: Path) -> None:
    # c.ts: in scope, no parser (c.json until step 4; JSON is parsed as configuration data now)
    root = tree(tmp_path, {"a.py": SHELL, "b.py": "def (:\n", "c.ts": "let x = 1\n"})
    r = scan(root)
    assert r.status is ScanStatus.PARTIAL and r.exit_code == 3
    assert r.completeness.files_not_analysed == 2 and r.findings
    allowed = scan(root, allow_partial=True)
    assert allowed.exit_code == 1 and allowed.completeness.allow_partial
    assert allowed.status is ScanStatus.PARTIAL


def test_nothing_to_analyse_exits_3(tmp_path: Path) -> None:
    files = {"README.md": "# x\n", "logo.png": "x", ".nexvul.yml": "severity:\n  fail_on: low\n"}
    r = scan(tree(tmp_path, files), allow_partial=True)
    assert r.status is ScanStatus.FAILED and r.exit_code == 3
    assert r.completeness.failed_cause is FailedCause.NOTHING_TO_ANALYSE


def test_nothing_analysable_exits_3(tmp_path: Path) -> None:
    r = scan(tree(tmp_path, {"a.py": "def (:\n", "b.ts": "let x"}))
    assert r.completeness.failed_cause is FailedCause.NONE_ANALYSED and r.exit_code == 3


def test_rule_exception_is_recorded_and_makes_scan_partial(tmp_path: Path) -> None:
    r = scan(tree(tmp_path, {"a.py": SHELL}), registry=registry_with(ExplodingRule()))
    assert r.status is ScanStatus.PARTIAL and r.exit_code == 3
    assert r.rules_failed == ("NEX993",)
    assert r.completeness.rule_failures[0].error_type == "RuntimeError"


def test_suppressions_and_warnings_flow_through(tmp_path: Path) -> None:
    src = (
        "import os\n"
        "os.system('a')  # nexvul: ignore[NEX990] -- fixed command only\n"
        "# nexvul: ignore\n"
    )
    r = scan(tree(tmp_path, {"a.py": src}))
    assert r.exit_code == 0 and len(r.suppressed) == 1 and r.findings == ()
    assert r.completeness.suppressed_inline == 1
    assert any(i.problem and i.problem.value == "no_rule_id" for i in r.suppression_issues)


def test_effective_config_and_metadata(tmp_path: Path) -> None:
    r = scan(tree(tmp_path, {"a.py": "x = 1\n"}), fail_on="medium")
    keys = {e.key: e for e in r.effective_config}
    assert keys["severity.fail_on"].value == "medium"
    assert "cli" in keys["severity.fail_on"].sources
    assert r.tool.rule_pack_sha256.startswith("sha256:")
    assert r.target_name == tmp_path.name and r.discovery_mode == "directory"
    assert dict(r.timings).keys() == {"discover", "parse", "analyse"}


def test_usage_and_config_errors(tmp_path: Path) -> None:
    with pytest.raises(ScanUsageError, match="path not found"):
        scan(tmp_path / "missing")
    f = tmp_path / "file.py"
    f.write_text("x")
    with pytest.raises(ScanUsageError, match="not a directory"):
        scan(f)
    (tmp_path / ".nexvul.yml").write_text("rules:\n  disable: [NEX1]\n")
    with pytest.raises(ConfigError):
        scan(tmp_path)


def test_discovery_error_on_pseudo_filesystem(monkeypatch: pytest.MonkeyPatch) -> None:
    import nexvul.core.scan as scan_mod

    def refuse(*_a: object, **_k: object) -> None:
        raise DiscoveryError("refusing to scan a system pseudo-filesystem")

    monkeypatch.setattr(scan_mod, "discover", refuse)
    monkeypatch.setattr(scan_mod, "assert_no_module_from_roots", lambda _roots: None)
    with pytest.raises(DiscoveryError):
        run_scan(ScanOptions(root="/"))


def test_shadowed_module_aborts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = types.ModuleType("yaml_shadow")
    fake.__file__ = str(tmp_path / "yaml.py")
    (tmp_path / "yaml.py").write_text("")
    monkeypatch.setitem(__import__("sys").modules, "yaml_shadow", fake)
    with pytest.raises(ModuleShadowingError):
        scan(tmp_path)
