"""benchmarks/run.py: corpus validation and scoring with hand-computed expectations."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[2]


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("nexvul_bench_run", REPO / "benchmarks/run.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["nexvul_bench_run"] = module
    spec.loader.exec_module(module)
    return module


bench = _load()
SCHEMA = json.loads((REPO / "benchmarks/schema/example.schema.json").read_text(encoding="utf-8"))


def test_committed_corpus_is_valid() -> None:
    cases, errors = bench.load_corpus()
    assert errors == []
    assert len(cases) >= 12
    assert {c.meta["category"] for c in cases} >= {"vulnerable", "safe", "adversarial"}


def _good_case() -> dict[str, object]:
    cases, _ = bench.load_corpus()
    return json.loads(json.dumps(cases[0].meta))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda m: m.pop("license"),
        lambda m: m.update(id="NEX007-1"),
        lambda m: m.update(split="heldout-x"),
        lambda m: m.update(extra=1),
        lambda m: m["labels"].update(labelled_by=["one"]),
        lambda m: m.update(
            expected_findings=[
                {
                    "rule": "NEX007",
                    "file": "../x",
                    "line": 1,
                    "severity": "high",
                    "confidence": "high",
                }
            ]
        ),
        lambda m: m.update(
            expected_findings=[
                {"rule": "NEX007", "file": "a", "severity": "high", "confidence": "high"}
            ]
        ),
        lambda m: m.update(source={"kind": "derived"}),
        lambda m: m.update(owasp=["ASI07", "ASI07"]),
    ],
)
def test_validator_rejects_bad_metadata(mutate: object) -> None:
    meta = _good_case()
    mutate(meta)  # type: ignore[operator]
    with pytest.raises(bench.SchemaError):
        bench.validate(meta, SCHEMA, SCHEMA)


def test_case_file_rejects_duplicates_and_nan(tmp_path: Path) -> None:
    p = tmp_path / "case.yaml"
    p.write_text('# c\n{"a": 1, "a": 2}\n')
    with pytest.raises(ValueError, match="duplicate"):
        bench.load_case_file(p)
    p.write_text('{"a": NaN}')
    with pytest.raises(ValueError):
        bench.load_case_file(p)


def test_virtual_path() -> None:
    assert bench.virtual_path("dot-cursor/mcp.json.fixture") == ".cursor/mcp.json"
    with pytest.raises(bench.SchemaError):
        bench.virtual_path("agent.py")


def test_wilson() -> None:
    assert bench.wilson(0, 0) is None
    low, high = bench.wilson(8, 8)
    assert 0.67 < low < 0.69 and high == 1.0


def _finding(path: str, line: int, sev: str = "high", conf: str = "high") -> SimpleNamespace:
    return SimpleNamespace(
        rule_id="NEX007",
        location=SimpleNamespace(path=path, line=line),
        severity=SimpleNamespace(value=sev),
        confidence=SimpleNamespace(value=conf),
    )


def test_scoring_matches_section_8_1() -> None:
    def case(cid: str, expected: list[dict[str, object]], non: list[dict[str, object]]) -> object:
        return bench.Case(
            path=Path(cid),
            meta={"id": cid, "expected_findings": expected, "expected_non_findings": non},
        )

    exp = {"rule": "NEX007", "file": "a.json", "severity": "high", "confidence": "high"}
    cases = [
        case("C1", [{**exp, "line": 3}], []),  # TP
        case("C2", [{**exp, "line": 3}], []),  # FN (finding on another line) + FP
        case("C3", [], [{"rule": "NEX007", "file": "a.json", "line": 5, "reason": "x" * 10}]),
        case("C4", [{**exp, "line_range": [2, 4], "known_miss": True}], []),  # known miss FN
        case("C5", [{**exp, "line": 1}], []),  # TP with a label mismatch + duplicate FP
    ]
    result = SimpleNamespace(
        findings=[
            _finding("C1/a.json", 3),
            _finding("C2/a.json", 9),
            _finding("C3/a.json", 5),
            _finding("C5/a.json", 1, "medium"),
            _finding("C5/a.json", 1),
        ],
        suppressed=[],
    )
    s = bench.score(cases, result)["NEX007"]
    assert (s.tp, s.fp, s.fn, s.known_miss) == (2, 3, 2, 1)
    assert s.fn_cases == ["C2", "C4 (known miss)"]
    assert any("labelled non-finding" in c for c in s.fp_cases)
    assert len(s.label_mismatches) == 1 and len(s.labelled_cases) == 5
