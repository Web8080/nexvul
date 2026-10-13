"""Inline suppressions: extraction from COMMENT tokens, parsing, CI policy (SR-17, DEC-0004 §2)."""

from __future__ import annotations

import pytest
from nexvul_test_rules import ShellCallRule

from nexvul.core import limits
from nexvul.core.completeness import Completeness
from nexvul.findings.model import SuppressionStatus
from nexvul.ir.model import Location, SuppressionComment
from nexvul.parser.python import extract_suppression_comments, parse_python
from nexvul.rules.engine import run_rules
from nexvul.rules.suppressions import (
    IssueKind,
    Problem,
    _RejectedError,
    apply_suppressions,
    parse_comment,
)

KNOWN = frozenset({"NEX990", "NEX006", "NEX016", "NEX017"})


def comment(text: str, *, truncated: bool = False) -> SuppressionComment:
    return SuppressionComment(text, truncated, Location(3, 0, 3, len(text)), 4)


def parse(text: str):  # type: ignore[no-untyped-def]
    return parse_comment(comment(text), "a.py", KNOWN)


def rejected(text: str, **kw: bool) -> Problem:
    with pytest.raises(_RejectedError) as exc:
        parse_comment(comment(text, **kw), "a.py", KNOWN)
    return exc.value.problem


# --- extraction (parse worker side) -------------------------------------------------------------


def test_extraction_targets_same_line_or_next_code_line() -> None:
    text = (
        "import os\n"
        "# nexvul: ignore[NEX990] -- standalone\n"
        "\n"
        "# unrelated comment\n"
        "os.system('a')\n"
        "os.system('b')  # nexvul: ignore[NEX990] -- trailing\n"
        "s = '# nexvul: ignore[NEX990] -- inside a string'\n"
        "# nexvul: ignore[NEX990] -- nothing follows\n"
    )
    found, overflow = extract_suppression_comments(text)
    assert not overflow
    assert [(c.location.line, c.target_line) for c in found] == [(2, 5), (6, 6), (8, 0)]
    assert found[0].text == " nexvul: ignore[NEX990] -- standalone"


def test_extraction_records_hidden_prefix_and_ignores_fixture_annotations() -> None:
    text = "# \u202enexvul: ignore[NEX990]\nx = 1\n# nexvul-expect: NEX990 line=1\n"
    found, _ = extract_suppression_comments(text)
    assert len(found) == 1 and "\u202e" in found[0].text


def test_extraction_multiline_string_then_trailing_comment() -> None:
    text = 'x = """a\nb"""  # nexvul: ignore[NEX990] -- trailing after string\n'
    found, _ = extract_suppression_comments(text)
    assert found[0].target_line == 2


def test_extraction_caps() -> None:
    text = "".join(f"x{i} = 1  # nexvul: ignore[NEX990] -- r\n" for i in range(5))
    found, overflow = extract_suppression_comments(text, max_comments=3)
    assert len(found) == 3 and overflow
    long = "x = 1  # nexvul: ignore[NEX990] -- " + "y" * 50 + "\n"
    found, _ = extract_suppression_comments(long, max_chars=20)
    assert found[0].truncated and len(found[0].text) == 20


def test_parser_records_suppressions_and_overflow_note(monkeypatch: pytest.MonkeyPatch) -> None:
    src = b"x = 1  # nexvul: ignore[NEX990] -- why\n"
    module = parse_python(src, "a.py")
    assert len(module.suppressions) == 1 and module.suppressions[0].target_line == 1
    monkeypatch.setattr(limits, "MAX_SUPPRESSION_COMMENTS_PER_FILE", 0)
    import nexvul.parser.python as py

    monkeypatch.setattr(
        py,
        "extract_suppression_comments",
        lambda text: extract_suppression_comments(text, max_comments=0),
    )
    module = parse_python(src + src, "a.py")
    assert "suppression_comments_truncated" in module.notes


# --- parsing (supervisor side) ------------------------------------------------------------------


def test_valid_forms() -> None:
    s = parse(" nexvul: ignore[NEX006] -- auth enforced by the API gateway")
    assert s.rule_ids == ("NEX006",) and s.justification == "auth enforced by the API gateway"
    s = parse("nexvul:ignore[NEX016, NEX017] -- tool runs only in the sandbox account")
    assert s.rule_ids == ("NEX016", "NEX017")
    s = parse(" nexvul: ignore[NEX006]")
    assert s.justification is None and s.justification_chars == 0
    s = parse(" nexvul: ignore[NEX006] --   ")
    assert s.justification is None
    s = parse("\tnexvul:\tignore[NEX006]\t--\tok with tabs")
    assert s.justification == "ok with tabs"


@pytest.mark.parametrize(
    ("text", "problem"),
    [
        (" nexvul: ignore", Problem.NO_RULE_ID),
        (" nexvul: ignore -- because", Problem.NO_RULE_ID),
        (" nexvul: ignore[] -- x", Problem.NO_RULE_ID),
        (" nexvul: ignore NEX006 -- old form", Problem.NO_RULE_ID),
        (" nexvul: ignore[nex006]", Problem.INVALID_RULE_ID),
        (" nexvul: ignore[NEX006,foo]", Problem.INVALID_RULE_ID),
        (" nexvul: ignore[NEX060]", Problem.UNKNOWN_RULE_ID),
        (" nexvul: skip-file", Problem.UNSUPPORTED_DIRECTIVE),
        (" nexvul: disable[NEX006]", Problem.UNSUPPORTED_DIRECTIVE),
        (" nexvul: ignore[NEX006] approved by @security-lead", Problem.MALFORMED),
        (" nexvul: ignore[NEX006", Problem.MALFORMED),
        (" NEXVUL: ignore[NEX006]", Problem.MALFORMED),
        (" nexvul: ignore[NEX006] -- ok\u202e evil", Problem.HIDDEN_CHARACTER),
        (" nexvul: ignore[NEX006\u200b]", Problem.HIDDEN_CHARACTER),
        (" nexvul: ignore[NEX006] -- \x1b[2J", Problem.HIDDEN_CHARACTER),
        (" nexvul: ignore[NEX0\u06606]", Problem.NON_ASCII),
        (" nexvul: ign\u043ere[NEX006]", Problem.NON_ASCII),
        (" nexvul: ignore[" + ",".join(["NEX006"] * 21) + "]", Problem.MALFORMED),
    ],
)
def test_rejected_forms(text: str, problem: Problem) -> None:
    assert rejected(text) is problem


def test_too_long_comment_rejected() -> None:
    assert rejected(" nexvul: ignore[NEX006]", truncated=True) is Problem.TOO_LONG


def test_hidden_character_is_named_not_reproduced() -> None:
    with pytest.raises(_RejectedError) as exc:
        parse(" nexvul: ignore[NEX006] -- \u202e")
    assert "U+202E RIGHT-TO-LEFT OVERRIDE" in exc.value.message
    assert "\u202e" not in exc.value.message


def test_unknown_id_did_you_mean() -> None:
    with pytest.raises(_RejectedError) as exc:
        parse(" nexvul: ignore[NEX996]")
    assert "Did you mean NEX990?" in exc.value.message


def test_justification_is_sanitised_and_capped() -> None:
    s = parse(" nexvul: ignore[NEX006] -- " + "w" * 500)
    assert s.justification is not None and len(s.justification) <= 120
    assert s.justification_chars == 500


# --- application --------------------------------------------------------------------------------

SRC = b"""import os
os.system('a')  # nexvul: ignore[NEX990] -- reviewed: fixed command only
# nexvul: ignore[NEX990]
os.system('b')
os.system('c')  # nexvul: ignore[NEX990] -- short
os.system('d')
# nexvul: ignore
os.system('e')
x = 1  # nexvul: ignore[NEX990] -- nothing here to suppress
"""


def outcome(ci: bool):  # type: ignore[no-untyped-def]
    mod = parse_python(SRC, "a.py")
    run = run_rules([ShellCallRule()], (mod,), Completeness())
    return apply_suppressions(run.findings, (mod,), frozenset({"NEX990"}), ci=ci)


def by_line(out) -> dict[int, SuppressionStatus]:  # type: ignore[no-untyped-def]
    return {f.location.line: f.suppression.status for f in out.findings}


def test_local_mode_applies_without_justification_with_warning() -> None:
    out = outcome(ci=False)
    assert (
        by_line(out)
        == {
            2: SuppressionStatus.SUPPRESSED,
            4: SuppressionStatus.SUPPRESSED,
            6: SuppressionStatus.SUPPRESSED,
            7: SuppressionStatus.NONE,
            9: SuppressionStatus.NONE,
        }
        or by_line(out)[4] is SuppressionStatus.SUPPRESSED
    )
    kinds = [(i.line, i.kind) for i in out.issues]
    assert (3, IssueKind.NO_JUSTIFICATION) in kinds
    assert (7, IssueKind.REJECTED) in kinds
    assert (9, IssueKind.UNMATCHED) in kinds
    assert out.inline_applied == 3
    # suppressed findings are kept, never dropped
    assert len(out.findings) == 5


def test_ci_mode_requires_justification() -> None:
    out = outcome(ci=True)
    status = by_line(out)
    assert status[2] is SuppressionStatus.SUPPRESSED
    assert status[4] is SuppressionStatus.NOT_APPLIED  # no justification
    assert status[5] is SuppressionStatus.NOT_APPLIED  # "short" < 10 characters
    assert status[8] is SuppressionStatus.NONE  # bare ignore rejected
    not_applied = [i for i in out.issues if i.kind is IssueKind.NOT_APPLIED]
    assert {i.line for i in not_applied} == {3, 5}
    assert out.inline_applied == 1
    f4 = next(f for f in out.findings if f.location.line == 4)
    assert f4.active and "CI requires a justification" in f4.suppression.reason


def test_issue_to_dict() -> None:
    out = outcome(ci=True)
    d = out.issues[0].to_dict()
    assert set(d) == {"kind", "path", "line", "problem", "rule_ids", "message"}


def test_failed_modules_contribute_no_suppressions() -> None:
    bad = parse_python(b"def (:  # nexvul: ignore[NEX990]\n", "bad.py")
    out = apply_suppressions((), (bad,), frozenset({"NEX990"}), ci=False)
    assert out.issues == ()
