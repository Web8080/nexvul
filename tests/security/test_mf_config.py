"""Malicious-input tests for `.nexvul.yml` (plan sections F, H, I, O; SR-15, SR-28, T-04, T-15)."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest
from builders import assert_no_canary

from nexvul.core.completeness import LimitHit, Status
from nexvul.core.config import (
    ChangeStatus,
    ConfigError,
    ConfigErrorCode,
    ConfigSource,
    load_config_file,
    load_repo_config,
    parse_config_bytes,
    resolve_config,
)
from nexvul.core.discovery import DiscoveryOptions, discover

pytestmark = pytest.mark.security

SECRET = "NEXVUL_TEST_SECRET_MARKER_c41d"


def _code(data: bytes) -> ConfigErrorCode:
    with pytest.raises(ConfigError) as exc:
        parse_config_bytes(data)
    return exc.value.code


# -------------------------------------------------------------------------- F: config bombs


@pytest.mark.parametrize(
    "payload",
    [
        b'exclude: !!python/object/apply:os.system ["touch $NEXVUL_CANARY_DIR/MF-30"]\n',
        b"exclude: !!python/name:os.system\n",
        b"rules: !!python/object/new:os.system [x]\n",
        b"severity: !!map {fail_on: high}\n",
        b"exclude: !custom x\n",
        b"%TAG !e! tag:example.com,2000:\n---\nexclude: []\n",
    ],
)
def test_mf30_yaml_tags_rejected_no_canary(payload: bytes, canary_dir: Path) -> None:
    assert _code(payload) is ConfigErrorCode.EXPLICIT_TAG
    assert_no_canary(canary_dir)


@pytest.mark.timeout(10)
def test_mf31_billion_laughs_rejected_fast() -> None:
    lines = ['a0: &a0 ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]']
    for i in range(1, 10):
        prev = f"*a{i - 1}"
        lines.append(f"a{i}: &a{i} [{', '.join([prev] * 9)}]")
    doc = ("\n".join(lines) + "\n").encode()
    start = time.monotonic()
    assert _code(doc) is ConfigErrorCode.ANCHOR_OR_ALIAS
    assert time.monotonic() - start < 2.0


@pytest.mark.parametrize(
    "doc",
    [
        b"severity: &s {fail_on: high}\n",
        b"exclude: &x [a]\nrules: {enabled: *x}\n",
        b"exclude:\n  - &p vendor\n",
        b"base: &b {fail_on: low}\nseverity:\n  <<: *b\n",
    ],
)
def test_mf31_any_anchor_or_alias_rejected(doc: bytes) -> None:
    assert _code(doc) is ConfigErrorCode.ANCHOR_OR_ALIAS


def test_mf31_inline_merge_key_rejected() -> None:
    assert _code(b"severity:\n  <<: {fail_on: low}\n") is ConfigErrorCode.UNKNOWN_KEY


def test_mf32_oversized_config_rejected_before_parse(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    with (root / ".nexvul.yml").open("wb") as fh:
        fh.truncate(50 * 1024 * 1024)  # sparse 50 MB
    with pytest.raises(ConfigError) as exc:
        load_repo_config(str(root))
    assert exc.value.code is ConfigErrorCode.TOO_LARGE


def test_mf32_exactly_at_and_over_cap() -> None:
    body = b"# " + b"x" * (64 * 1024 - 3) + b"\n"
    assert len(body) == 64 * 1024
    parse_config_bytes(body)  # at the cap: fine
    assert _code(body + b"\n") is ConfigErrorCode.TOO_LARGE


def test_mf32_deep_nesting_and_event_flood() -> None:
    assert _code(b"a: " + b"[" * 50 + b"]" * 50 + b"\n") is ConfigErrorCode.TOO_DEEP
    flood = b"exclude: [" + b"a," * 25_000 + b"a]\n"
    assert len(flood) < 64 * 1024
    assert _code(flood) is ConfigErrorCode.TOO_COMPLEX


@pytest.mark.parametrize(
    ("doc", "code"),
    [
        (b"severity:\n  fail_on: high\nseverity:\n  fail_on: low\n", ConfigErrorCode.DUPLICATE_KEY),
        (b"rules:\n  enabled: []\n  enabled: [ASI06]\n", ConfigErrorCode.DUPLICATE_KEY),
        (b"severity:\n  fail_on: high\n  fail_on_typo: low\n", ConfigErrorCode.UNKNOWN_KEY),
        (b"unknown_section: 1\n", ConfigErrorCode.UNKNOWN_KEY),
        (b"analysis:\n  max_files: -1\n", ConfigErrorCode.VALUE),
        (b"analysis:\n  max_files: 1e309\n", ConfigErrorCode.TYPE),
        (b"analysis:\n  max_files: .inf\n", ConfigErrorCode.TYPE),
        (b"analysis:\n  max_files: 10.0\n", ConfigErrorCode.TYPE),
        (b"analysis:\n  max_files: '10'\n", ConfigErrorCode.TYPE),
        (b"analysis:\n  max_files: yes\n", ConfigErrorCode.TYPE),
        (b"analysis:\n  max_files: " + b"9" * 5000 + b"\n", ConfigErrorCode.VALUE),
        (b"analysis:\n  max_files: 0x7fffffffffffffff\n", ConfigErrorCode.VALUE),
        (b"analysis:\n  cross_file: null\n", ConfigErrorCode.TYPE),
        (b"? [a, b]\n: 1\n", ConfigErrorCode.TYPE),
        (b"1: x\n", ConfigErrorCode.TYPE),
        (b"---\nexclude: []\n---\nexclude: []\n", ConfigErrorCode.MULTIPLE_DOCUMENTS),
    ],
)
def test_mf33_duplicate_unknown_and_wrong_types(doc: bytes, code: ConfigErrorCode) -> None:
    """No silent default to "disabled": every malformed value is an error."""
    assert _code(doc) is code


@pytest.mark.parametrize(
    "doc",
    [
        b"rules:\n  patterns: ['(a+)+$']\n",
        b"rules:\n  custom:\n    - regex: '(a|a)*b'\n",
        b"regex: '.*'\n",
    ],
)
def test_mf43_repo_config_cannot_define_regexes(doc: bytes) -> None:
    assert _code(doc) is ConfigErrorCode.UNKNOWN_KEY


# ------------------------------------------------------------------------ H/I: paths & writes


@pytest.mark.parametrize(
    "doc",
    [
        b"exclude: ['/etc']\n",
        b"exclude: ['../../']\n",
        b"exclude: ['../x']\n",
        b"exclude: ['a/../../b']\n",
        b"exclude: ['~/.ssh']\n",
        b"exclude: ['C:/Windows']\n",
        b"exclude: ['..\\\\x']\n",
    ],
)
def test_mf55_config_path_escape_rejected(doc: bytes) -> None:
    assert _code(doc) is ConfigErrorCode.PATH_ESCAPE


def test_mf55_include_key_does_not_exist() -> None:
    assert _code(b"include: ['/etc', '../../']\n") is ConfigErrorCode.UNKNOWN_KEY


@pytest.mark.parametrize(
    "doc",
    [
        b"output: ~/.bashrc\n",
        b"cache_dir: .git/hooks\n",
        b"analysis:\n  cache_dir: /tmp/x\n",
        b"plugins: [evil]\n",
        b"rules:\n  packs: [https://evil.example/pack]\n",
    ],
)
def test_mf59_repo_config_cannot_set_outputs_cache_or_plugins(doc: bytes) -> None:
    assert _code(doc) is ConfigErrorCode.UNKNOWN_KEY


def test_mf105_symlinked_config_not_followed(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    target = tmp_path / "secret.yml"
    target.write_text(f"exclude: ['{SECRET}']\n")
    os.symlink(target, root / ".nexvul.yml")
    with pytest.raises(ConfigError) as exc:
        load_repo_config(str(root))
    assert exc.value.code is ConfigErrorCode.SYMLINK
    assert SECRET not in str(exc.value)


def test_mf105_symlink_to_etc_passwd(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    os.symlink("/etc/passwd", root / ".nexvul.yml")
    with pytest.raises(ConfigError) as exc:
        load_repo_config(str(root))
    assert exc.value.code is ConfigErrorCode.SYMLINK
    assert "root:" not in str(exc.value)


@pytest.mark.timeout(10)
def test_mf105_fifo_config_does_not_block(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    os.mkfifo(root / ".nexvul.yml")
    with pytest.raises(ConfigError) as exc:
        load_repo_config(str(root))
    assert exc.value.code is ConfigErrorCode.NOT_REGULAR_FILE


def test_error_messages_sanitise_attacker_key_names() -> None:
    esc = chr(0x1B)
    with pytest.raises(ConfigError) as exc:
        parse_config_bytes(f'"{esc}[2Jevil\\n": 1\n'.encode())
    assert esc not in str(exc.value)
    assert "\n" not in str(exc.value)


def test_unknown_key_message_contains_no_values() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_config_bytes(f"severity:\n  fail_on: {SECRET}\n".encode())
    assert SECRET not in str(exc.value)


# --------------------------------------------------------------- O: suppression via config


def _repo_cfg(tmp_path: Path, body: str) -> Path:
    root = tmp_path / "repo"
    root.mkdir(exist_ok=True)
    (root / ".nexvul.yml").write_text(body)
    return root


def _head(root: Path):  # type: ignore[no-untyped-def]
    loaded = load_repo_config(str(root))
    assert loaded is not None
    return loaded


def test_mf100_head_disables_rule_ci_not_applied_local_applied(tmp_path: Path) -> None:
    head = _head(_repo_cfg(tmp_path, "rules:\n  disabled: [NEX004]\n"))
    ci = resolve_config(repo=head, ci=True)
    assert "NEX004" not in ci.effective.rules_disabled
    assert [(c.key, c.status) for c in ci.changes] == [("rules.disabled", ChangeStatus.NOT_APPLIED)]
    local = resolve_config(repo=head, ci=False)
    assert "NEX004" in local.effective.rules_disabled
    assert [(c.key, c.status) for c in local.changes] == [("rules.disabled", ChangeStatus.APPLIED)]


def test_mf101_head_excludes_agent_dir(tmp_path: Path) -> None:
    root = _repo_cfg(tmp_path, "exclude: ['agent/**']\n")
    (root / "agent").mkdir()
    (root / "agent" / "evil.py").write_text("x = 1\n")
    resolved = resolve_config(repo=_head(root), ci=True)
    assert resolved.effective.exclude == ()
    assert resolved.not_applied[0].key == "exclude"
    r = discover(root, DiscoveryOptions(exclude=resolved.effective.exclude))
    assert "agent/evil.py" in [f.path for f in r.files]


def test_mf102_head_raises_fail_on(tmp_path: Path) -> None:
    head = _head(_repo_cfg(tmp_path, "severity:\n  fail_on: critical\n"))
    r = resolve_config(repo=head, ci=True)
    assert r.effective.fail_on == "high"
    assert r.not_applied[0].detail == "high -> critical"


def test_mf103_max_files_one_is_partial(tmp_path: Path) -> None:
    root = _repo_cfg(tmp_path, "analysis:\n  max_files: 1\n")
    (root / "a.py").write_text("")
    (root / "b.py").write_text("")
    ci = resolve_config(repo=_head(root), ci=True)
    assert ci.effective.max_files != 1 and ci.not_applied[0].key == "analysis.max_files"
    local = resolve_config(repo=_head(root), ci=False)
    assert local.effective.max_files == 1
    r = discover(root, DiscoveryOptions(max_files=local.effective.max_files))
    assert r.completeness.status is Status.PARTIAL  # honoured locally, but never "complete"
    assert LimitHit.MAX_FILES in r.completeness.limits_hit


def test_mf104_base_strict_head_weakened(tmp_path: Path) -> None:
    base_file = tmp_path / "base.yml"
    base_file.write_text("severity:\n  fail_on: medium\nrules:\n  enabled: [ASI06]\n")
    base = load_config_file(
        str(base_file), source=ConfigSource.BASE_REF, ref="base:3f2c", display_path=".nexvul.yml"
    )
    head = _head(
        _repo_cfg(
            tmp_path,
            "severity:\n  fail_on: critical\nrules:\n  enabled: []\n  disabled: [NEX001]\n",
        )
    )
    r = resolve_config(repo=head, trusted=[base], ci=True)
    assert r.effective.fail_on == "medium"
    assert r.effective.rules_enabled == frozenset({"ASI06"})
    assert r.effective.rules_disabled == frozenset()
    assert {c.key for c in r.not_applied} == {
        "severity.fail_on",
        "rules.enabled",
        "rules.disabled",
    }
    assert r.config_sources[0].ref == "base:3f2c"
    assert r.config_sources[0].source is ConfigSource.BASE_REF
    assert len(r.config_sources[1].sha256) == 64
