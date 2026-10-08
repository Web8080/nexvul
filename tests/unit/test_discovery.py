"""Discovery unit tests: languages, patterns, walk, git index (architecture §4, SR-06, SR-16)."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
from builders import (
    MODE_GITLINK,
    MODE_REGULAR,
    MODE_SYMLINK,
    build_git_index,
    make_git_repo,
    write_tree,
)

from nexvul.core.completeness import LimitHit, SkipReason, Status
from nexvul.core.discovery import (
    DiscoveryError,
    DiscoveryMode,
    DiscoveryOptions,
    GitEntryKind,
    Language,
    detect_language,
    discover,
    parse_git_index,
    pattern_matches,
)

# --------------------------------------------------------------------------------- languages


@pytest.mark.parametrize(
    ("name", "lang"),
    [
        ("a.py", Language.PYTHON),
        ("A.PY", Language.PYTHON),
        ("x.ts", Language.TYPESCRIPT),
        ("x.d.ts", Language.TYPESCRIPT),
        ("x.mts", Language.TYPESCRIPT),
        ("x.tsx", Language.TSX),
        ("x.js", Language.JAVASCRIPT),
        ("x.cjs", Language.JAVASCRIPT),
        ("x.jsx", Language.JSX),
        ("mcp.json", Language.JSON),
        ("a.yml", Language.YAML),
        ("a.yaml", Language.YAML),
        ("pyproject.toml", Language.TOML),
        (".json", Language.JSON),
        ("Makefile", None),
        ("x.py.fixture", None),
        ("x.png", None),
        ("x.", None),
    ],
)
def test_detect_language(name: str, lang: Language | None) -> None:
    assert detect_language(name) is lang


# ---------------------------------------------------------------------------------- patterns


@pytest.mark.parametrize(
    ("pattern", "path", "is_dir", "expected"),
    [
        ("tests", "a/tests/x.py", False, True),
        ("tests", "tests", True, True),
        ("tests", "a/testsx/x.py", False, False),
        ("*.min.js", "web/app.min.js", False, True),
        ("*.min.js", "web/app.js", False, False),
        ("agent/tools", "agent/tools/x.py", False, True),
        ("agent/tools", "src/agent/tools/x.py", False, False),
        ("agent/**", "agent/a/b/c.py", False, True),
        ("**/gen/*.py", "a/b/gen/x.py", False, True),
        ("**/gen/*.py", "gen/x.py", False, True),
        ("**/gen/*.py", "gen/sub/x.py", False, False),
        ("a/*/c", "a/b/c/d.py", False, True),
        ("a/?/c", "a/bb/c", True, False),
        ("vendor/", "vendor", True, True),
        ("vendor/", "vendor", False, False),
        ("vendor/", "vendor/x.py", False, True),
        ("build/", "x/build", False, False),
        ("**", "anything/at/all.py", False, True),
    ],
)
def test_pattern_matches(pattern: str, path: str, is_dir: bool, expected: bool) -> None:
    assert pattern_matches(pattern, path, is_dir=is_dir) is expected


def test_pattern_matching_is_bounded_on_adversarial_input() -> None:
    """MF-42 flavour: many-star patterns against long paths stay fast (no regex, no blow-up)."""
    pattern = "/".join(["**"] * 50 + ["*a*a*a*a*a*a*a*a*a*b"])
    path = "/".join(["a" * 60] * 60)
    assert pattern_matches(pattern, path) is False


# ------------------------------------------------------------------------------------- walk


def opts(**kw: object) -> DiscoveryOptions:
    return DiscoveryOptions(**kw)  # type: ignore[arg-type]


def test_basic_directory_walk_is_sorted_and_complete(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "b.py": "x = 1\n",
            "a/z.ts": "let x = 1\n",
            "a/y.json": "{}",
            "README.md": "# hi\n",
            "img.png": b"\x89PNG\r\n\x1a\n\x00\x00",
        },
    )
    r = discover(tmp_path)
    assert r.mode is DiscoveryMode.DIRECTORY
    assert [f.path for f in r.files] == ["a/y.json", "a/z.ts", "b.py"]
    assert [f.language for f in r.files] == [Language.JSON, Language.TYPESCRIPT, Language.PYTHON]
    assert all(f.tracked is None for f in r.files)
    assert r.completeness.status is Status.COMPLETE
    assert r.completeness.count(SkipReason.UNSUPPORTED_FILE_TYPE) == 2
    assert r.root == os.path.realpath(tmp_path)


def test_discovery_is_deterministic(tmp_path: Path) -> None:
    write_tree(tmp_path, {f"d{i % 7}/f{i}.py": "" for i in range(60)})
    first = discover(tmp_path)
    second = discover(tmp_path)
    assert [f.path for f in first.files] == [f.path for f in second.files]
    assert first.completeness.to_dict() == second.completeness.to_dict()


def test_root_errors(tmp_path: Path) -> None:
    with pytest.raises(DiscoveryError):
        discover(tmp_path / "missing")
    (tmp_path / "f.py").write_text("")
    with pytest.raises(DiscoveryError):
        discover(tmp_path / "f.py")
    with pytest.raises(DiscoveryError):
        discover("/dev")


def test_default_excluded_dirs_in_directory_mode(tmp_path: Path) -> None:
    write_tree(tmp_path, {"node_modules/x.js": "", ".venv/lib/y.py": "", "src/a.py": ""})
    r = discover(tmp_path)
    assert [f.path for f in r.files] == ["src/a.py"]
    assert r.completeness.count(SkipReason.DEFAULT_EXCLUDED_DIR) == 2
    assert r.completeness.status is Status.COMPLETE


def test_config_exclude_files_and_dirs(tmp_path: Path) -> None:
    write_tree(tmp_path, {"gen/a.py": "", "src/a.min.js": "", "src/b.js": ""})
    r = discover(tmp_path, opts(exclude=("gen/", "*.min.js")))
    assert [f.path for f in r.files] == ["src/b.js"]
    assert r.completeness.count(SkipReason.EXCLUDED_BY_CONFIG) == 2
    assert r.completeness.status is Status.COMPLETE


def test_nexvul_dir_is_ordinary_content(tmp_path: Path) -> None:
    write_tree(tmp_path, {".nexvul/cache/x.json": "{}", ".nexvul.yml": "exclude: []\n"})
    r = discover(tmp_path)
    assert [f.path for f in r.files] == [".nexvul.yml", ".nexvul/cache/x.json"]
    assert any(n.startswith("nexvul_dir_present") for n in r.notes)


def test_max_total_bytes(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a.py": "x" * 100, "b.py": "x" * 100})
    r = discover(tmp_path, opts(max_total_bytes=150))
    assert len(r.files) == 1
    assert LimitHit.MAX_TOTAL_BYTES in r.completeness.limits_hit
    assert r.completeness.status is Status.PARTIAL


def test_max_dir_entries(tmp_path: Path) -> None:
    write_tree(tmp_path, {f"f{i}.txt": "" for i in range(30)})
    r = discover(tmp_path, opts(max_dir_entries=10))
    assert LimitHit.MAX_DIR_ENTRIES in r.completeness.limits_hit
    assert r.completeness.status is Status.PARTIAL


def test_time_budget_uses_injected_clock(tmp_path: Path) -> None:
    write_tree(tmp_path, {f"d{i}/f.py": "" for i in range(5)})
    ticks = iter([0.0, 1.0, 1.0, 100.0] + [100.0] * 1000)
    r = discover(tmp_path, opts(time_budget_seconds=5), clock=lambda: next(ticks))
    assert LimitHit.DISCOVERY_TIME_BUDGET in r.completeness.limits_hit
    assert r.completeness.status is Status.PARTIAL
    assert len(r.files) < 5


def test_time_budget_checked_inside_large_directory(tmp_path: Path) -> None:
    write_tree(tmp_path, {f"f{i}.py": "" for i in range(600)})
    calls = iter([0.0, 0.0] + [100.0] * 1000)  # deadline, first dir check, then expired
    r = discover(tmp_path, opts(time_budget_seconds=5), clock=lambda: next(calls))
    assert LimitHit.DISCOVERY_TIME_BUDGET in r.completeness.limits_hit
    assert r.files == ()


def test_empty_file_is_selected(tmp_path: Path) -> None:
    (tmp_path / "e.py").write_bytes(b"")
    r = discover(tmp_path)
    assert [f.size for f in r.files] == [0]


# -------------------------------------------------------------------------------- git index


ENTRIES = [
    (b"README.md", MODE_REGULAR),
    (b"agent/tools.py", MODE_REGULAR),
    (b"agent/toolz.py", MODE_REGULAR),
    (b"link.py", MODE_SYMLINK),
    (b"sub", MODE_GITLINK),
]


@pytest.mark.parametrize("version", [2, 3, 4])
@pytest.mark.parametrize("hash_len", [20, 32])
def test_parse_git_index_versions(version: int, hash_len: int) -> None:
    skip = [b"agent/toolz.py"] if version >= 3 else []
    data = build_git_index(ENTRIES, version=version, hash_len=hash_len, skip_worktree=skip)
    idx = parse_git_index(data)
    assert idx.version == version
    assert idx.hash_len == hash_len
    assert [e.path for e in idx.entries] == [p for p, _ in ENTRIES]
    kinds = [e.kind for e in idx.entries]
    assert kinds[3] is GitEntryKind.SYMLINK and kinds[4] is GitEntryKind.GITLINK
    assert [e.skip_worktree for e in idx.entries] == [False, False, bool(skip), False, False]


def test_parse_git_index_zero_trailer_skiphash() -> None:
    idx = parse_git_index(build_git_index(ENTRIES, trailer="zero"))
    assert len(idx.entries) == len(ENTRIES)


def test_parse_git_index_dedupes_conflict_stages() -> None:
    idx = parse_git_index(build_git_index([(b"a.py", MODE_REGULAR), (b"a.py", MODE_REGULAR)]))
    assert [e.path for e in idx.entries] == [b"a.py"]


def _git() -> str | None:
    return shutil.which("git")


@pytest.mark.skipif(_git() is None, reason="git binary not installed: interop check not run")
@pytest.mark.parametrize("index_version", ["2", "3", "4"])
def test_parser_matches_real_git_index(tmp_path: Path, index_version: str) -> None:
    """Interop: the in-house reader agrees with an index written by real git.

    git is run only on a repository this test creates itself (trusted), never on a scan target.
    """
    git = _git()
    assert git is not None
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(tmp_path),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
    }
    repo = tmp_path / "repo"
    write_tree(repo, {"a.py": "", "dir/b.ts": "", "dir/sub/c.json": "{}", "z.md": ""})

    def run(*args: str) -> None:
        subprocess.run([git, *args], cwd=repo, env=env, check=True, capture_output=True)

    run("init", "-q")
    run("add", "-A")
    if index_version != "2":
        # git only writes v3 when an entry needs extended flags: mark one skip-worktree
        run("update-index", "--skip-worktree", "dir/b.ts")
    run("update-index", "--index-version", index_version)
    idx = parse_git_index((repo / ".git" / "index").read_bytes())
    assert idx.version == int(index_version)
    assert sorted(e.path for e in idx.entries) == [b"a.py", b"dir/b.ts", b"dir/sub/c.json", b"z.md"]
    skipped = {e.path for e in idx.entries if e.skip_worktree}
    assert skipped == (set() if index_version == "2" else {b"dir/b.ts"})


def test_git_mode_marks_tracked_and_scans_untracked(tmp_path: Path) -> None:
    write_tree(tmp_path, {"tracked.py": "", "untracked.py": ""})
    make_git_repo(tmp_path, build_git_index([(b"tracked.py", MODE_REGULAR)]))
    r = discover(tmp_path)
    assert r.mode is DiscoveryMode.GIT
    assert {f.path: f.tracked for f in r.files} == {"tracked.py": True, "untracked.py": False}
    assert r.git_head == "refs/heads/main"
    assert r.completeness.count(SkipReason.VCS_METADATA) == 1
    assert r.completeness.status is Status.COMPLETE


def test_git_mode_tracked_file_in_default_excluded_dir_is_scanned(tmp_path: Path) -> None:
    """Architecture §4.1: a tracked node_modules/evil.js is scanned; untracked siblings are not."""
    write_tree(tmp_path, {"node_modules/evil.js": "", "node_modules/other.js": ""})
    make_git_repo(tmp_path, build_git_index([(b"node_modules/evil.js", MODE_REGULAR)]))
    r = discover(tmp_path)
    assert [(f.path, f.tracked) for f in r.files] == [("node_modules/evil.js", True)]
    assert r.completeness.count(SkipReason.DEFAULT_EXCLUDED_DIR) == 1


def test_git_mode_tracked_missing_on_disk_is_partial(tmp_path: Path) -> None:
    make_git_repo(tmp_path, build_git_index([(b"gone.py", MODE_REGULAR)]))
    r = discover(tmp_path)
    assert r.completeness.count(SkipReason.TRACKED_MISSING_ON_DISK) == 1
    assert r.completeness.status is Status.PARTIAL


def test_git_mode_submodule_not_scanned(tmp_path: Path) -> None:
    write_tree(tmp_path, {"sub/inner.py": "", "a.py": ""})
    make_git_repo(tmp_path, build_git_index([(b"a.py", MODE_REGULAR), (b"sub", MODE_GITLINK)]))
    r = discover(tmp_path)
    assert [f.path for f in r.files] == ["a.py"]
    assert r.completeness.count(SkipReason.SUBMODULE_NOT_SCANNED) == 1


def test_git_mode_tracked_excluded_by_config(tmp_path: Path) -> None:
    write_tree(tmp_path, {"node_modules/evil.js": ""})
    make_git_repo(tmp_path, build_git_index([(b"node_modules/evil.js", MODE_REGULAR)]))
    r = discover(tmp_path, opts(exclude=("*.js",)))
    assert r.files == ()
    assert r.completeness.count(SkipReason.EXCLUDED_BY_CONFIG) == 1


def test_git_index_absent_means_git_mode_with_no_tracked_files(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / "a.py").write_text("")
    r = discover(tmp_path)
    assert r.mode is DiscoveryMode.GIT
    assert [(f.path, f.tracked) for f in r.files] == [("a.py", False)]
    assert r.completeness.status is Status.COMPLETE


def test_use_git_index_false_forces_directory_mode(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a.py": ""})
    make_git_repo(tmp_path, build_git_index([(b"a.py", MODE_REGULAR)]))
    r = discover(tmp_path, opts(use_git_index=False))
    assert r.mode is DiscoveryMode.DIRECTORY


def test_gitdir_pointer_inside_root_is_used(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a.py": "", "b.py": ""})
    real_git = tmp_path / "meta" / "gitdir"
    real_git.mkdir(parents=True)
    (real_git / "index").write_bytes(build_git_index([(b"a.py", MODE_REGULAR)]))
    (real_git / "HEAD").write_bytes(b"0123456789abcdef0123456789abcdef01234567\n")
    (tmp_path / ".git").write_text("gitdir: meta/gitdir\n")
    r = discover(tmp_path)
    assert r.mode is DiscoveryMode.GIT
    assert r.git_head == "0123456789abcdef0123456789abcdef01234567"
    assert {f.path: f.tracked for f in r.files}["a.py"] is True
