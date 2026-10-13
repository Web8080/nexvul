"""Benchmark harness v0 for nexvul (docs/benchmark-strategy.md §3, §8.1; DEC-0002).

Usage (from the repository root, with nexvul installed in the active environment)::

    python benchmarks/run.py [--json]

What it does:

1. Loads every ``case.yaml`` under ``benchmarks/{vulnerable,safe,adversarial,frameworks}/``.
   Case files are written as JSON (a subset of YAML 1.2), so this script needs only the
   standard library to read them; duplicate keys and non-finite numbers are rejected.
2. Validates each case against ``benchmarks/schema/example.schema.json`` with a small built-in
   validator (the keywords that schema uses). An invalid corpus is refused (exit 2).
3. Builds one virtual tree from the cases' ``files/`` directories (``.fixture`` suffix removed,
   ``dot-x`` path components restored to ``.x``), writes it to a temporary directory **outside**
   the repository, and scans it with the real nexvul pipeline (``run_scan``) with the rules
   named in the cases enabled. Nothing in the corpus is executed or imported (§6).
4. Scores per rule with the §8.1 matching: TP / FP / FN with raw counts, precision and recall
   with a Wilson 95% interval, "insufficient data" below 10 observations, every FP and FN listed
   by case ID. Severity/confidence disagreements are listed separately.

DEC-0002: a precision threshold is enforced for a rule only once at least 20 labelled cases
exist for it. Below that this harness reports counts only and makes **no pass/fail claim**.

Exit codes: 0 scored (whatever the numbers), 2 invalid corpus, 4 the scan itself failed.
"""

from __future__ import annotations

import json
import math
import re
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

BENCH = Path(__file__).resolve().parent
REPO = BENCH.parent
SCHEMA_PATH = BENCH / "schema" / "example.schema.json"
CATEGORIES = ("vulnerable", "safe", "adversarial", "frameworks")
MIN_CASES_FOR_THRESHOLD = 20  # DEC-0002 amendment 1
MIN_OBSERVATIONS = 10  # benchmark-strategy §8.1 "insufficient data"


# ---------------------------------------------------------------------------------------------
# Loading and validation
# ---------------------------------------------------------------------------------------------


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name}")


def load_case_file(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    body = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    return json.loads(body, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)


class SchemaError(Exception):
    pass


def _type_ok(value: Any, expected: str | list[str]) -> bool:
    names = [expected] if isinstance(expected, str) else expected
    checks = {
        "object": lambda v: isinstance(v, dict),
        "array": lambda v: isinstance(v, list),
        "string": lambda v: isinstance(v, str),
        "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
        "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
        "boolean": lambda v: isinstance(v, bool),
        "null": lambda v: v is None,
    }
    return any(checks[n](value) for n in names)


def validate(value: Any, schema: Any, root: dict[str, Any], where: str = "$") -> None:
    """Validate ``value`` against the JSON Schema keywords used by example.schema.json."""
    if schema is True:
        return
    if "$ref" in schema:
        target: Any = root
        for part in schema["$ref"].removeprefix("#/").split("/"):
            target = target[part]
        validate(value, target, root, where)
    for sub in schema.get("allOf", []):
        validate(value, sub, root, where)
    if "oneOf" in schema:
        passed = 0
        for sub in schema["oneOf"]:
            try:
                validate(value, sub, root, where)
                passed += 1
            except SchemaError:
                pass
        if passed != 1:
            raise SchemaError(f"{where}: must match exactly one alternative")
    if "not" in schema:
        try:
            validate(value, schema["not"], root, where)
        except SchemaError:
            pass
        else:
            raise SchemaError(f"{where}: matches a forbidden pattern")
    if "if" in schema:
        try:
            validate(value, schema["if"], root, where)
            matched = True
        except SchemaError:
            matched = False
        if matched and "then" in schema:
            validate(value, schema["then"], root, where)
    if "type" in schema and not _type_ok(value, schema["type"]):
        raise SchemaError(f"{where}: expected {schema['type']}")
    if "const" in schema and value != schema["const"]:
        raise SchemaError(f"{where}: must equal {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        raise SchemaError(f"{where}: {value!r} not in {schema['enum']}")
    if isinstance(value, str):
        if "pattern" in schema and not re.search(schema["pattern"], value):
            raise SchemaError(f"{where}: does not match {schema['pattern']}")
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", 1 << 30):
            raise SchemaError(f"{where}: length out of range")
    if (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and "minimum" in schema
        and value < schema["minimum"]
    ):
        raise SchemaError(f"{where}: below minimum")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", 1 << 30):
            raise SchemaError(f"{where}: item count out of range")
        if schema.get("uniqueItems") and len({json.dumps(v, sort_keys=True) for v in value}) != len(
            value
        ):
            raise SchemaError(f"{where}: items must be unique")
        prefix = schema.get("prefixItems", [])
        for i, item in enumerate(value):
            if i < len(prefix):
                validate(item, prefix[i], root, f"{where}[{i}]")
            elif "items" in schema:
                validate(item, schema["items"], root, f"{where}[{i}]")
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                raise SchemaError(f"{where}: missing {key!r}")
        props = schema.get("properties", {})
        for key, item in value.items():
            if key in props:
                validate(item, props[key], root, f"{where}.{key}")
            elif schema.get("additionalProperties") is False:
                raise SchemaError(f"{where}: unexpected key {key!r}")


@dataclass
class Case:
    path: Path
    meta: dict[str, Any]
    files: dict[str, bytes] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return str(self.meta["id"])


def virtual_path(rel: str) -> str:
    if not rel.endswith(".fixture"):
        raise SchemaError(f"corpus file without .fixture suffix: {rel}")
    parts = rel[: -len(".fixture")].split("/")
    return "/".join("." + p[4:] if p.startswith("dot-") else p for p in parts)


def load_corpus() -> tuple[list[Case], list[str]]:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    cases: list[Case] = []
    errors: list[str] = []
    seen: set[str] = set()
    for category in CATEGORIES:
        for path in sorted((BENCH / category).glob("*/*/case.yaml")):
            rel = path.relative_to(REPO)
            try:
                meta = load_case_file(path)
                validate(meta, schema, schema)
                if meta["category"] != category:
                    raise SchemaError(f"category {meta['category']!r} but stored under {category}/")
                if meta["id"] in seen:
                    raise SchemaError(f"duplicate case id {meta['id']}")
                seen.add(meta["id"])
                case = Case(path=path.parent, meta=meta)
                files_dir = path.parent / "files"
                for item in sorted(files_dir.rglob("*")) if files_dir.is_dir() else []:
                    if item.is_file():
                        case.files[virtual_path(item.relative_to(files_dir).as_posix())] = (
                            item.read_bytes()
                        )
                cases.append(case)
            except (ValueError, SchemaError, KeyError) as exc:
                errors.append(f"{rel}: {exc}")
    return cases, errors


# ---------------------------------------------------------------------------------------------
# Scanning and scoring
# ---------------------------------------------------------------------------------------------


def _in_range(line: int, item: dict[str, Any]) -> bool:
    if "line" in item:
        return line == item["line"]
    low, high = item["line_range"]
    return low <= line <= high


@dataclass
class RuleScore:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    known_miss: int = 0
    labelled_cases: set[str] = field(default_factory=set)
    fp_cases: list[str] = field(default_factory=list)
    fn_cases: list[str] = field(default_factory=list)
    label_mismatches: list[str] = field(default_factory=list)


def wilson(successes: int, total: int, z: float = 1.959964) -> tuple[float, float] | None:
    if total == 0:
        return None
    p = successes / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def scan(cases: list[Case], rules: set[str]) -> Any:
    from nexvul.core.scan import ScanOptions, run_scan  # noqa: PLC0415 - after corpus checks

    with tempfile.TemporaryDirectory(prefix="nexvul-bench-") as tmp:
        root = Path(tmp) / "corpus"
        if root.resolve().is_relative_to(REPO):
            raise SystemExit("refusing to materialise the corpus inside the repository")
        for case in cases:
            for rel, data in case.files.items():
                target = root / case.id / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
        enabled = ", ".join(sorted(rules))
        (root / ".nexvul.yml").write_text(f"rules:\n  enabled: [{enabled}]\n", encoding="utf-8")
        return run_scan(ScanOptions(root=str(root)))


def score(cases: list[Case], result: Any) -> dict[str, RuleScore]:
    scores: dict[str, RuleScore] = {}
    findings = [*result.findings, *result.suppressed]
    for case in cases:
        prefix = case.id + "/"
        mine = [f for f in findings if f.location.path.startswith(prefix)]
        used: set[int] = set()
        expected = case.meta["expected_findings"]
        non = case.meta["expected_non_findings"]
        for item in [*expected, *non]:
            scores.setdefault(item["rule"], RuleScore()).labelled_cases.add(case.id)
        for item in expected:
            s = scores[item["rule"]]
            hits = [
                i
                for i, f in enumerate(mine)
                if f.rule_id == item["rule"]
                and f.location.path[len(prefix) :] == item["file"]
                and _in_range(f.location.line, item)
                and i not in used
            ]
            if hits:
                s.tp += 1
                used.add(hits[0])
                f = mine[hits[0]]
                if (f.severity.value, f.confidence.value) != (item["severity"], item["confidence"]):
                    s.label_mismatches.append(
                        f"{case.id} line {item['line'] if 'line' in item else item['line_range']}: "
                        f"expected {item['severity']}/{item['confidence']}, got "
                        f"{f.severity.value}/{f.confidence.value}"
                    )
            else:
                s.fn += 1
                s.known_miss += bool(item.get("known_miss"))
                s.fn_cases.append(case.id + (" (known miss)" if item.get("known_miss") else ""))
        for i, f in enumerate(mine):
            if i in used:
                continue
            s = scores.setdefault(f.rule_id, RuleScore())
            s.fp += 1
            hit_non = any(
                n["rule"] == f.rule_id
                and n["file"] == f.location.path[len(prefix) :]
                and _in_range(f.location.line, n)
                for n in non
            )
            s.fp_cases.append(
                f"{case.id} {f.location.path[len(prefix) :]}:{f.location.line}"
                + (" (labelled non-finding)" if hit_non else "")
            )
    return scores


def _ratio(num: int, den: int) -> str:
    if den == 0:
        return "n/a (0 observations)"
    interval = wilson(num, den) or (0.0, 1.0)
    text = f"{num}/{den} = {num / den:.2f} (Wilson 95% {interval[0]:.2f}-{interval[1]:.2f})"
    if den < MIN_OBSERVATIONS:
        text += " - insufficient data"
    return text


def report(cases: list[Case], result: Any, scores: dict[str, RuleScore]) -> str:
    lines = [
        "nexvul benchmark harness v0",
        f"cases: {len(cases)} ("
        + ", ".join(
            f"{cat} {sum(1 for c in cases if c.meta['category'] == cat)}"
            for cat in CATEGORIES
            if any(c.meta["category"] == cat for c in cases)
        )
        + ")",
        f"scan: status {result.completeness.status.value}, "
        f"{result.completeness.files_analysed} of {result.completeness.files_discovered} files "
        f"analysed, rule pack {result.tool.rule_pack_version} {result.tool.rule_pack_sha256[:19]}",
        "",
    ]
    for rule in sorted(scores):
        s = scores[rule]
        n_cases = len(s.labelled_cases)
        lines += [
            f"{rule}",
            f"  labelled cases {n_cases}   TP {s.tp}   FP {s.fp}   FN {s.fn} "
            f"(of which known misses {s.known_miss})",
        ]
        if n_cases < MIN_CASES_FOR_THRESHOLD:
            lines += [
                f"  precision counts TP/(TP+FP) = {s.tp}/{s.tp + s.fp}",
                f"  recall    counts TP/(TP+FN) = {s.tp}/{s.tp + s.fn}",
                f"  DEC-0002: {n_cases} < {MIN_CASES_FOR_THRESHOLD} labelled cases - no ratio, "
                "interval or pass/fail is reported until the corpus reaches 20.",
            ]
        else:
            lines += [
                f"  precision {_ratio(s.tp, s.tp + s.fp)}",
                f"  recall    {_ratio(s.tp, s.tp + s.fn)}",
            ]
        lines += [f"  FP: {c}" for c in s.fp_cases] or ["  FP: none"]
        lines += [f"  FN: {c}" for c in s.fn_cases] or ["  FN: none"]
        lines += [f"  severity/confidence label differs: {m}" for m in s.label_mismatches]
        lines.append("")
    lines.append(
        "Labels are author-proposed; independent double labelling (benchmark-strategy §7) is "
        "pending. A benchmark result is evidence about this corpus only, not about real code."
    )
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    cases, errors = load_corpus()
    if errors:
        sys.stderr.write("invalid corpus; refusing to score:\n" + "\n".join(errors) + "\n")
        return 2
    if not cases:
        sys.stderr.write("no benchmark cases found\n")
        return 2
    rules = {i["rule"] for c in cases for i in c.meta["expected_findings"]} | {
        i["rule"] for c in cases for i in c.meta["expected_non_findings"]
    }
    result = scan(cases, rules)
    if result.completeness.status.value == "failed":
        sys.stderr.write("the scan failed; nothing scored\n")
        return 4
    scores = score(cases, result)
    if "--json" in argv:
        out = {
            rule: {
                "labelled_cases": len(s.labelled_cases),
                "tp": s.tp,
                "fp": s.fp,
                "fn": s.fn,
                "known_miss": s.known_miss,
                "fp_cases": s.fp_cases,
                "fn_cases": s.fn_cases,
                "label_mismatches": s.label_mismatches,
            }
            for rule, s in sorted(scores.items())
        }
        sys.stdout.write(json.dumps(out, indent=2) + "\n")
    else:
        sys.stdout.write(report(cases, result, scores))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
