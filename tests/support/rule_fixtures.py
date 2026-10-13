"""Rule-fixture harness (architecture §11.6, test-strategy §4.1).

Fixture layout under ``tests/rules/<rule>/<category>/case_<nnn>_<slug>/``:

* data files end in ``.fixture`` and are **never** imported, executed or collected. The virtual
  path is the relative path with ``.fixture`` removed and every path component spelled
  ``dot-<name>`` turned into ``.<name>``. So ``dot-cursor/mcp.json.fixture`` is scanned as
  ``.cursor/mcp.json``; the repository itself never contains a real ``.cursor/mcp.json`` or
  ``.mcp.json`` that an editor or agent could load.
* ``expect.txt`` holds the annotations (JSON has no comments, so they cannot be inline):

  ``nexvul-expect: NEX007 file=<virtual path> line=<n> severity=<s> confidence=<c>``
  ``nexvul-expect-not: NEX007 file=<virtual path> reason="..."``  (no finding in that file)
  ``nexvul-known-miss: NEX007 file=<virtual path> line=<n> ref=FND-...``  (asserted still missed)

:func:`scan_virtual` materialises a virtual tree in a temporary directory **outside** the
repository / pytest rootdir and runs the real pipeline (workers, rules, suppressions) on it.
The pipeline reads files through file descriptors, so the bytes have to exist on disk; they are
written as data and never executed.
"""

from __future__ import annotations

import shlex
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from nexvul.core.scan import ScanOptions, run_scan
from nexvul.core.workers import WorkerOptions
from nexvul.findings.result import ScanResult

REPO = Path(__file__).resolve().parents[2]
RULES_DIR = REPO / "tests" / "rules"
FIXTURE_SUFFIX = ".fixture"
EXPECT_FILE = "expect.txt"


@dataclass(frozen=True)
class Expectation:
    rule: str
    file: str
    line: int = 0
    severity: str = ""
    confidence: str = ""
    reason: str = ""
    ref: str = ""


@dataclass
class Case:
    rule: str
    category: str
    name: str
    files: dict[str, bytes] = field(default_factory=dict)
    expect: list[Expectation] = field(default_factory=list)
    expect_not: list[Expectation] = field(default_factory=list)
    known_miss: list[Expectation] = field(default_factory=list)

    @property
    def id(self) -> str:
        return f"{self.category}/{self.name}"


def virtual_path(rel: str) -> str:
    """``dot-cursor/mcp.json.fixture`` -> ``.cursor/mcp.json``."""
    if not rel.endswith(FIXTURE_SUFFIX):
        raise ValueError(f"fixture data files must end in {FIXTURE_SUFFIX}: {rel}")
    parts = rel[: -len(FIXTURE_SUFFIX)].split("/")
    return "/".join("." + p[4:] if p.startswith("dot-") else p for p in parts)


def _fields(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for token in shlex.split(text.split(" # ", 1)[0]):
        if "=" in token:
            key, _, value = token.partition("=")
            out[key] = value
        else:
            out["rule"] = token
    return out


def parse_expect(text: str) -> tuple[list[Expectation], list[Expectation], list[Expectation]]:
    expect: list[Expectation] = []
    expect_not: list[Expectation] = []
    known: list[Expectation] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        kind, _, rest = line.partition(":")
        f = _fields(rest)
        item = Expectation(
            rule=f["rule"],
            file=f["file"],
            line=int(f.get("line", "0")),
            severity=f.get("severity", ""),
            confidence=f.get("confidence", ""),
            reason=f.get("reason", ""),
            ref=f.get("ref", ""),
        )
        {"nexvul-expect": expect, "nexvul-expect-not": expect_not, "nexvul-known-miss": known}[
            kind
        ].append(item)
    return expect, expect_not, known


def load_case(case_dir: Path) -> Case:
    rule = case_dir.parent.parent.name.upper()
    case = Case(rule=rule, category=case_dir.parent.name, name=case_dir.name)
    for path in sorted(case_dir.rglob("*")):
        if path.is_dir() or path.name == EXPECT_FILE:
            continue
        rel = path.relative_to(case_dir).as_posix()
        case.files[virtual_path(rel)] = path.read_bytes()
    case.expect, case.expect_not, case.known_miss = parse_expect(
        (case_dir / EXPECT_FILE).read_text(encoding="utf-8")
    )
    return case


def load_cases(rule_dir: str) -> list[Case]:
    base = RULES_DIR / rule_dir
    return [load_case(d) for d in sorted(base.glob("*/case_*")) if d.is_dir()]


def materialise(files: Mapping[str, bytes], root: Path) -> Path:
    """Write a virtual tree under ``root`` (must be outside the repository)."""
    resolved = root.resolve()
    if resolved == REPO or REPO in resolved.parents:
        raise AssertionError("virtual trees must be written outside the repository")
    for rel, data in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return root


def enable_config(rules: Iterable[str]) -> bytes:
    ids = ", ".join(rules)
    return f"rules:\n  enabled: [{ids}]\n".encode()


def scan_virtual(
    files: Mapping[str, bytes],
    root: Path,
    *,
    enable: Iterable[str] = ("NEX007",),
    ci: bool = False,
    workers: int = 2,
) -> ScanResult:
    """Scan a virtual tree with the real pipeline; ``enable`` turns experimental rules on."""
    tree = dict(files)
    enabled = tuple(enable)
    if enabled and ".nexvul.yml" not in tree:
        tree[".nexvul.yml"] = enable_config(enabled)
    materialise(tree, root)
    return run_scan(
        ScanOptions(root=str(root), ci=ci, worker_options=WorkerOptions(max_workers=workers))
    )
