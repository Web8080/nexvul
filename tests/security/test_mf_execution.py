"""No target file is ever executed, imported or compiled (plan section A; SR-01/02, T-01/01b).

Canary payloads are generated into ``tmp_path`` at test time. If nexvul ever imported, ran or
compiled one of them, it would write a marker into ``$NEXVUL_CANARY_DIR``. The tests also watch
the interpreter's audit events (``import``, ``exec``, ``compile``, ``open``) while discovery and
config loading run against the hostile tree.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from builders import assert_no_canary, canary_source, write_tree

import nexvul
from nexvul.core.config import load_repo_config
from nexvul.core.discovery import discover
from nexvul.core.startup import find_modules_under_roots

pytestmark = pytest.mark.security

# sys.addaudithook cannot be removed; the hook only records while a test has armed it.
_RECORDING: dict[str, Any] = {"armed": False, "root": "", "events": []}


def _audit(event: str, args: tuple[Any, ...]) -> None:
    if not _RECORDING["armed"]:
        return
    if event in ("import", "exec", "compile", "open", "os.exec", "subprocess.Popen", "os.system"):
        _RECORDING["events"].append((event, args))


sys.addaudithook(_audit)


@pytest.fixture
def audit(tmp_path: Path) -> Iterator[list[tuple[str, tuple[Any, ...]]]]:
    _RECORDING["events"] = []  # the test arms recording once its hostile tree is built
    try:
        yield _RECORDING["events"]
    finally:
        _RECORDING["armed"] = False


def _hostile_tree(root: Path) -> None:
    write_tree(
        root,
        {
            "agent/tools.py": canary_source("MF-01") + "\ndef tool():\n    return 1\n",
            "setup.py": canary_source("MF-02-setup"),
            "conftest.py": canary_source("MF-02-conftest"),
            "pkg/__init__.py": canary_source("MF-03"),
            "pkg/x.py": "from pkg import y\n",
            "deco.py": canary_source("MF-05")
            + "\nclass M(type):\n    def __init_subclass__(cls):\n        pass\n",
            "yaml.py": canary_source("MF-06-yaml"),
            "click.py": canary_source("MF-06-click"),
            "typing_extensions.py": canary_source("MF-06-typing_extensions"),
            "sitecustomize.py": canary_source("MF-06-sitecustomize"),
            "usercustomize.py": canary_source("MF-06-usercustomize"),
            "rich/__init__.py": canary_source("MF-06-rich"),
            "encodings/__init__.py": canary_source("MF-06-encodings"),
            "evil.pth": "import os; open(os.path.join("
            "os.environ['NEXVUL_CANARY_DIR'], 'MF-07'), 'w')\n",
            "package.json": '{"scripts": {"preinstall": "touch $NEXVUL_CANARY_DIR/MF-04"}}',
            "pyproject.toml": '[build-system]\nbuild-backend = "pkg"\n',
            ".nexvul.yml": "severity:\n  fail_on: high\n",
        },
    )


def _under(root: Path, value: object) -> bool:
    if isinstance(value, bytes):
        value = os.fsdecode(value)
    if not isinstance(value, str):
        return False
    real = os.path.realpath(value)
    base = os.path.realpath(root)
    return real == base or real.startswith(base + os.sep)


def test_mf01_to_07_discovery_and_config_never_execute_targets(
    tmp_path: Path, canary_dir: Path, audit: list[tuple[str, tuple[Any, ...]]]
) -> None:
    root = tmp_path / "repo"
    _hostile_tree(root)
    _RECORDING["armed"] = True
    loaded = load_repo_config(str(root))
    result = discover(root)
    _RECORDING["armed"] = False

    assert any(event == "open" for event, _ in audit)  # the hook really observed discovery
    assert loaded is not None
    assert "agent/tools.py" in [f.path for f in result.files]
    assert_no_canary(canary_dir)
    assert find_modules_under_roots([str(root)]) == ()

    for event, args in audit:
        if event == "import":
            # args: (module, filename, sys.path, sys.meta_path, sys.path_hooks)
            assert not _under(root, args[1]), f"imported from scan root: {args[0]}"
            assert not any(_under(root, p) for p in (args[2] or [])), "scan root on sys.path"
        elif event in ("exec", "compile"):
            filename = args[1] if len(args) > 1 else None
            assert not _under(root, filename), f"{event} of target file"
        elif event == "open":
            path, mode, flags = args
            if _under(root, path) or (isinstance(path, str) and not os.path.isabs(path)):
                writing = (isinstance(mode, str) and any(c in mode for c in "wax+")) or (
                    isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT)
                )
                assert not writing, "discovery/config opened a target file for writing"
        else:
            pytest.fail(f"process execution during discovery: {event}")


@pytest.mark.parametrize("entry", ["module", "console"])
def test_mf06_sys_path_shadowing_from_cwd(tmp_path: Path, canary_dir: Path, entry: str) -> None:
    """Run nexvul with CWD = hostile repo holding yaml.py, click.py, sitecustomize.py, ..."""
    root = tmp_path / "repo"
    _hostile_tree(root)
    if entry == "module":
        argv = [sys.executable, "-m", "nexvul", "version"]
    else:
        script = Path(sys.executable).parent / "nexvul"
        assert script.exists(), "console script not installed in the test venv"
        argv = [str(script), "version"]
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
    env["NEXVUL_CANARY_DIR"] = str(canary_dir)
    proc = subprocess.run(
        argv, cwd=root, env=env, capture_output=True, text=True, timeout=60, check=False
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == f"nexvul {nexvul.__version__}"
    assert_no_canary(canary_dir)
