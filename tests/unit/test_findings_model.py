"""Finding model, fingerprints and secret redaction (architecture §12.1, SR-24)."""

from __future__ import annotations

import time

import pytest

from nexvul.findings.model import (
    Confidence,
    Finding,
    FindingLocation,
    Severity,
    disambiguate,
    fingerprint,
    is_asi_id,
    is_rule_id,
)
from nexvul.findings.redact import redact_secrets

LOC = FindingLocation("a.py", 1, 1, 1, 2)
FP = "sha256:" + "0" * 64


def make(**kw: object) -> Finding:
    base: dict[str, object] = {
        "rule_id": "NEX001",
        "title": "t",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "asi": ("ASI06",),
        "location": LOC,
        "message": "m",
        "remediation": "r",
        "references": (),
        "fingerprint": FP,
    }
    base.update(kw)
    return Finding(**base)  # type: ignore[arg-type]


def test_severity_order_and_threshold() -> None:
    assert [s.rank for s in Severity] == [0, 1, 2, 3, 4]
    assert Severity.CRITICAL.at_or_above(Severity.HIGH)
    assert Severity.HIGH.at_or_above(Severity.HIGH)
    assert not Severity.MEDIUM.at_or_above(Severity.HIGH)
    assert Confidence.LOW.rank < Confidence.MEDIUM.rank < Confidence.HIGH.rank


@pytest.mark.parametrize("value", ["NEX001", "NEX999"])
def test_rule_id_shape(value: str) -> None:
    assert is_rule_id(value)


@pytest.mark.parametrize("value", ["NEX1", "nex001", "NEX0001", "NEX00A", "\uff2eEX001", ""])
def test_rule_id_rejects(value: str) -> None:
    assert not is_rule_id(value)


def test_asi_shape() -> None:
    assert is_asi_id("ASI01") and is_asi_id("ASI10")
    assert not is_asi_id("ASI11") and not is_asi_id("ASI00") and not is_asi_id("asi01")


@pytest.mark.parametrize(
    "kw",
    [
        {"rule_id": "BAD"},
        {"asi": ()},
        {"asi": ("ASI99",)},
        {"asi": ("ASI06", "ASI06")},
        {"fingerprint": "md5:x"},
    ],
)
def test_finding_validation(kw: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        make(**kw)


def test_finding_properties() -> None:
    f = make()
    assert f.active and not f.suppressed
    assert f.sort_key()[0] == -Severity.HIGH.rank


def test_fingerprint_is_stable_under_whitespace_and_line_moves() -> None:
    a = fingerprint(
        rule_id="NEX001", path=b"./a//b.py", flow_shape=(("sink", "f( x )"),), context="f(x)"
    )
    b = fingerprint(
        rule_id="NEX001", path=b"a/b.py", flow_shape=(("sink", "f(  x )"),), context=" f(x) "
    )
    assert a == b
    assert a.startswith("sha256:") and len(a) == 7 + 64


def test_fingerprint_distinguishes_flows_rules_and_paths() -> None:
    base = {"rule_id": "NEX001", "path": b"a.py", "flow_shape": (("sink", "f(x)"),), "context": "c"}
    fp = fingerprint(**base)  # type: ignore[arg-type]
    assert fp != fingerprint(**{**base, "rule_id": "NEX002"})  # type: ignore[arg-type]
    assert fp != fingerprint(**{**base, "path": b"b.py"})  # type: ignore[arg-type]
    assert fp != fingerprint(**{**base, "flow_shape": (("sink", "g(x)"),)})  # type: ignore[arg-type]
    assert fp != fingerprint(**{**base, "context": "d"})  # type: ignore[arg-type]
    # length-prefixing: moving a separator between fields changes the hash
    assert fingerprint(rule_id="NEX001", path=b"ab", flow_shape=(), context="c") != fingerprint(
        rule_id="NEX001", path=b"a", flow_shape=(), context="bc"
    )


def test_disambiguate() -> None:
    assert disambiguate(FP, 0) == FP
    one, two = disambiguate(FP, 1), disambiguate(FP, 2)
    assert len({FP, one, two}) == 3
    assert one.startswith("sha256:")


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("key = 'sk-ant-api03-abcdefghijklmnopqrstuvwx'", "abcdefghijklmnopqrstuvwx"),
        ("token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123"),
        ("AKIAABCDEFGHIJKLMNOP", "ABCDEFGHIJKLMNOP"),
        ('password = "hunter2hunter2"', "hunter2hunter2"),
        ("API_KEY='zzzzzzzzzzzz'", "zzzzzzzzzzzz"),
        ("headers={'Authorization': 'Bearer abcdef0123456789xyz'}", "abcdef0123456789xyz"),
    ],
)
def test_redaction(text: str, secret: str) -> None:
    out = redact_secrets(text)
    assert secret not in out
    assert "[redacted " in out and "sha256:" in out


def test_redaction_keeps_ordinary_code() -> None:
    code = "client = OpenAI(api_key=os.environ['KEY'])"
    assert redact_secrets(code) == code
    assert redact_secrets("skeleton = 1") == "skeleton = 1"


def test_redaction_is_capped_and_fast_on_adversarial_input() -> None:
    hostile = "password='" + "a" * 100_000
    start = time.perf_counter()
    out = redact_secrets(hostile)
    assert time.perf_counter() - start < 1.0
    assert len(out) <= 500
