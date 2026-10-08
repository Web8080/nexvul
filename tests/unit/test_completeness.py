"""Completeness ledger and exit codes (architecture §12.3-12.4, OD-06, SR-18, SR-19)."""

from __future__ import annotations

import itertools

import pytest

from nexvul.core import limits
from nexvul.core.completeness import (
    Completeness,
    ExitCode,
    Impact,
    LimitHit,
    SkipReason,
    Status,
    exit_code_for,
    impact_of,
    resolve_exit_code,
)


def test_every_reason_has_an_impact() -> None:
    for reason in SkipReason:
        assert isinstance(impact_of(reason), Impact)


def test_empty_ledger_is_complete() -> None:
    ledger = Completeness()
    assert ledger.status is Status.COMPLETE
    assert ledger.files_not_analysed_partial == 0


@pytest.mark.parametrize("reason", [r for r in SkipReason if impact_of(r) is Impact.PARTIAL])
def test_partial_reasons_make_scan_partial(reason: SkipReason) -> None:
    ledger = Completeness()
    ledger.record_skip("a.py", reason)
    assert ledger.status is Status.PARTIAL


@pytest.mark.parametrize("reason", [r for r in SkipReason if impact_of(r) is not Impact.PARTIAL])
def test_policy_and_info_reasons_do_not_make_scan_partial(reason: SkipReason) -> None:
    ledger = Completeness()
    ledger.record_skip("a.py", reason)
    assert ledger.status is Status.COMPLETE
    assert ledger.count(reason) == 1


def test_counts_failed_timed_out_and_skipped_separately() -> None:
    ledger = Completeness()
    ledger.record_scanned()
    ledger.record_scanned()
    ledger.record_skip("a.py", SkipReason.PARSE_ERROR)
    ledger.record_skip("b.py", SkipReason.PARSER_CRASHED)
    ledger.record_skip("c.py", SkipReason.TIMEOUT)
    ledger.record_skip("d.py", SkipReason.MAX_FILE_SIZE)
    ledger.record_skip("e.png", SkipReason.UNSUPPORTED_FILE_TYPE)
    assert ledger.files_scanned == 2
    assert ledger.files_failed == 2
    assert ledger.files_timed_out == 1
    assert ledger.files_skipped == 2
    assert ledger.files_not_analysed_partial == 4
    d = ledger.to_dict()
    assert d["status"] == "partial"
    assert d["skipped_by_reason"]["max_file_size"] == 1
    assert d["files_timed_out"] == 1


def test_limit_hit_is_partial_and_deduplicated() -> None:
    ledger = Completeness()
    ledger.record_limit(LimitHit.MAX_FILES)
    ledger.record_limit(LimitHit.MAX_FILES)
    assert ledger.limits_hit == [LimitHit.MAX_FILES]
    assert ledger.status is Status.PARTIAL


def test_internal_error_is_failed() -> None:
    ledger = Completeness()
    ledger.record_internal_error()
    assert ledger.status is Status.FAILED
    assert exit_code_for(ledger, findings_over_threshold=False) is ExitCode.INTERNAL_ERROR


def test_skipped_path_list_is_capped_but_counts_stay_exact() -> None:
    ledger = Completeness()
    n = limits.MAX_SKIPPED_PATHS_LISTED + 25
    for i in range(n):
        ledger.record_skip(f"f{i}.py", SkipReason.MAX_FILE_SIZE)
    assert len(ledger.skipped) == limits.MAX_SKIPPED_PATHS_LISTED
    assert ledger.skipped_list_truncated == 25
    assert ledger.count(SkipReason.MAX_FILE_SIZE) == n


def test_notes_deduplicated() -> None:
    ledger = Completeness()
    ledger.add_note("x")
    ledger.add_note("x")
    assert ledger.notes == ["x"]


def test_exit_code_precedence_matrix() -> None:
    """MF-133 (unit level): 2 > 4 > 3 > 1 > 0 for every combination."""
    for usage, internal, partial, findings in itertools.product([False, True], repeat=4):
        code = resolve_exit_code(
            usage_error=usage,
            internal_error=internal,
            partial=partial,
            findings_over_threshold=findings,
        )
        if usage:
            expected = ExitCode.USAGE_ERROR
        elif internal:
            expected = ExitCode.INTERNAL_ERROR
        elif partial:
            expected = ExitCode.PARTIAL
        elif findings:
            expected = ExitCode.FINDINGS
        else:
            expected = ExitCode.OK
        assert code is expected


def test_partial_scan_is_never_exit_zero() -> None:
    ledger = Completeness()
    ledger.record_skip("big.py", SkipReason.MAX_FILE_SIZE)
    assert exit_code_for(ledger, findings_over_threshold=False) is ExitCode.PARTIAL
    assert exit_code_for(ledger, findings_over_threshold=True) is ExitCode.PARTIAL


def test_partial_warning_downgrade_maps_to_findings_code() -> None:
    ledger = Completeness()
    ledger.record_skip("big.py", SkipReason.MAX_FILE_SIZE)
    assert (
        exit_code_for(ledger, findings_over_threshold=False, partial_is_warning=True) is ExitCode.OK
    )
    assert (
        exit_code_for(ledger, findings_over_threshold=True, partial_is_warning=True)
        is ExitCode.FINDINGS
    )


def test_exit_code_values_are_the_public_contract() -> None:
    assert [int(c) for c in ExitCode] == [0, 1, 2, 3, 4, 130, 143]
