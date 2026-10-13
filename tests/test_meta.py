"""Meta-tests guarding the repository itself.

1. Fixture naming (architecture §11.6, test-strategy §4.1): no file with a real source extension and
   no ``test_*.py`` / ``*_test.py`` / ``conftest*`` may sit under fixture or benchmark trees, where
   pytest or an interpreter could collect or import it.
2. Banned APIs (SR-01, SR-05, SR-09): nexvul's own source must not contain code-execution,
   unsafe-deserialisation, subprocess, dynamic-import, recursion-limit or ``signal.alarm`` calls.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src" / "nexvul"

FIXTURE_TREES = ("tests/fixtures", "tests/rules", "tests/security/fixtures", "benchmarks")
EXECUTABLE_SUFFIXES = frozenset(
    {".py", ".pyw", ".pyc", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".tsx", ".jsx", ".sh"}
)


#: nexvul's own harness code that lives next to the corpus (benchmark-strategy §2 also plans
#: benchmarks/perf/generator.py). Exact paths only; corpus case files stay ``.fixture``.
HARNESS_FILES = frozenset({"benchmarks/run.py"})


def fixture_violations(base: Path, trees: tuple[str, ...] = FIXTURE_TREES) -> list[str]:
    bad: list[str] = []
    for tree in trees:
        top = base / tree
        if not top.is_dir():
            continue
        for path in sorted(top.rglob("*")):
            if path.is_dir():
                continue
            name = path.name
            if path.relative_to(base).as_posix() in HARNESS_FILES:
                continue
            if (
                path.suffix.lower() in EXECUTABLE_SUFFIXES
                or (name.startswith("test_") and name.endswith(".py"))
                or name.endswith("_test.py")
                or name.startswith("conftest")
            ):
                bad.append(str(path.relative_to(base)))
    return bad


def test_no_executable_fixtures_in_repository() -> None:
    assert fixture_violations(REPO) == []


def test_fixture_checker_catches_violations(tmp_path: Path) -> None:
    for rel in (
        "tests/rules/NEX001/positive/test_positive_001.py",
        "tests/rules/NEX001/positive/case_002.ts",
        "tests/fixtures/conftest.py.fixture",
        "benchmarks/vulnerable/x/agent.py",
        "benchmarks/safe/y_test.py",
    ):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("")
    ok = tmp_path / "tests/rules/NEX001/positive/case_001_ok.py.fixture"
    ok.write_text("")
    assert len(fixture_violations(tmp_path)) == 5


BANNED_CALLS = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "breakpoint",
}
BANNED_ATTRS = {
    ("importlib", "import_module"),
    ("pickle", "load"),
    ("pickle", "loads"),
    ("marshal", "load"),
    ("marshal", "loads"),
    ("shelve", "open"),
    ("yaml", "load"),
    ("yaml", "unsafe_load"),
    ("yaml", "full_load"),
    ("os", "system"),
    ("os", "popen"),
    ("sys", "setrecursionlimit"),
    ("signal", "alarm"),
    ("runpy", "run_path"),
    ("runpy", "run_module"),
}
BANNED_MODULES = {"pickle", "marshal", "shelve", "subprocess", "importlib", "runpy", "ctypes"}
# os.execve in __main__ re-executes *nexvul itself* with -P (architecture §2.2); nothing else may.
ALLOWED = {("__main__.py", "os.execve")}


def _violations(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
            out += [f"import {n}" for n in names if n.split(".")[0] in BANNED_MODULES]
        elif isinstance(node, ast.ImportFrom) and node.module:
            if node.module.split(".")[0] in BANNED_MODULES:
                out.append(f"from {node.module} import")
        elif isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id in BANNED_CALLS:
                out.append(f"{fn.id}()")
            elif isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
                pair = (fn.value.id, fn.attr)
                label = f"{pair[0]}.{pair[1]}"
                if pair in BANNED_ATTRS or (
                    pair[0] == "os"
                    and pair[1].startswith(("exec", "spawn"))
                    and (path.name, label) not in ALLOWED
                ):
                    out.append(label)
    return out


def test_no_banned_apis_in_nexvul_source() -> None:
    files = sorted(SRC.rglob("*.py"))
    assert files, "source tree not found"
    found = {str(p.relative_to(REPO)): v for p in files if (v := _violations(p))}
    assert found == {}


@pytest.mark.parametrize(
    "snippet",
    [
        "eval('1')",
        "import pickle",
        "from subprocess import run",
        "import yaml\nyaml.load(x)",
        "import os\nos.system('x')",
        "import sys\nsys.setrecursionlimit(10**6)",
        "import signal\nsignal.alarm(1)",
        "import os\nos.execv('x', [])",
    ],
)
def test_banned_api_checker_catches(tmp_path: Path, snippet: str) -> None:
    p = tmp_path / "mod.py"
    p.write_text(snippet)
    assert _violations(p)


# 3. Real agent/IDE config filenames (step 4). A committed `.mcp.json`, `.cursor/mcp.json`,
# `.vscode/mcp.json` or `claude_desktop_config.json` under the fixture or benchmark trees could be
# loaded by an editor or coding agent opened on this repository, starting hostile MCP servers.
# Fixtures spell them `dot-cursor/mcp.json.fixture` and similar instead.
CONFIG_TREES = ("tests", "benchmarks")
REAL_CONFIG_NAMES = frozenset(
    {
        ".mcp.json",
        "mcp.json",
        "claude_desktop_config.json",
        "mcp-config.json",
        "mcp_config.json",
        ".claude.json",
        "settings.json",
        "settings.local.json",
    }
)
TOOL_DIRS = frozenset({".cursor", ".vscode", ".claude", ".copilot", ".codeium", ".windsurf"})


def config_name_violations(base: Path, trees: tuple[str, ...] = CONFIG_TREES) -> list[str]:
    bad: list[str] = []
    for tree in trees:
        top = base / tree
        if not top.is_dir():
            continue
        for path in sorted(top.rglob("*")):
            rel = path.relative_to(base)
            if path.is_dir():
                if path.name.lower() in TOOL_DIRS:
                    bad.append(str(rel) + "/")
            elif path.name.lower() in REAL_CONFIG_NAMES:
                bad.append(str(rel))
    return bad


def test_no_real_agent_config_filenames_committed() -> None:
    assert config_name_violations(REPO) == []


def test_config_name_checker_catches_violations(tmp_path: Path) -> None:
    for rel in (
        "tests/rules/NEX007/positive/case_1/.mcp.json",
        "benchmarks/vulnerable/NEX007/x/.cursor/mcp.json",
        "benchmarks/safe/NEX007/y/claude_desktop_config.json",
    ):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("{}")
    ok = tmp_path / "tests/rules/NEX007/positive/case_2/dot-cursor/mcp.json.fixture"
    ok.parent.mkdir(parents=True, exist_ok=True)
    ok.write_text("{}")
    assert len(config_name_violations(tmp_path)) == 4  # 3 files + the .cursor directory
