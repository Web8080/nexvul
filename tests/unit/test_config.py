"""Config loader and DEC-0004 tighten-only resolution (architecture §3, SR-15, SR-27, SR-28)."""

from __future__ import annotations

from pathlib import Path

import pytest

from nexvul.core import limits
from nexvul.core.config import (
    DEFAULTS,
    ChangeStatus,
    ConfigError,
    ConfigErrorCode,
    ConfigSource,
    ConfigValues,
    LoadedConfig,
    ci_mode_from_env,
    is_rule_selector,
    load_config_file,
    load_repo_config,
    normalise_repo_pattern,
    parse_config_bytes,
    resolve_config,
)

FULL = b"""\
severity:
  fail_on: medium
rules:
  enabled: [ASI06, NEX010]
  disabled: [NEX004]
exclude:
  - ./vendor/
  - "docs//*.md"
frameworks:
  auto_detect: false
analysis:
  cross_file: true
  max_files: 1000
  max_file_size: 2048
"""


def layer(source: ConfigSource = ConfigSource.REPO, **values: object) -> LoadedConfig:
    return LoadedConfig(
        values=ConfigValues(**values),  # type: ignore[arg-type]
        source=source,
        display_path=".nexvul.yml",
        sha256="0" * 64,
        size=0,
        ref="base:abc" if source is ConfigSource.BASE_REF else None,
    )


# ------------------------------------------------------------------------------------ parsing


def test_parse_full_document() -> None:
    v = parse_config_bytes(FULL)
    assert v.fail_on == "medium"
    assert v.rules_enabled == frozenset({"ASI06", "NEX010"})
    assert v.rules_disabled == frozenset({"NEX004"})
    assert v.exclude == ("vendor/", "docs/*.md")
    assert v.auto_detect is False
    assert v.cross_file is True
    assert v.max_files == 1000
    assert v.max_file_size == 2048


@pytest.mark.parametrize("data", [b"", b"# only a comment\n", b"---\n", b"\xef\xbb\xbf"])
def test_empty_documents_are_empty_config(data: bytes) -> None:
    assert parse_config_bytes(data) == ConfigValues()


def test_top_level_must_be_mapping() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_config_bytes(b"- a\n- b\n")
    assert exc.value.code is ConfigErrorCode.TYPE


@pytest.mark.parametrize(
    ("doc", "code"),
    [
        (b"severity:\n  fail_on: urgent\n", ConfigErrorCode.VALUE),
        (b"severity:\n  fail_on: 3\n", ConfigErrorCode.TYPE),
        (b"severity: high\n", ConfigErrorCode.TYPE),
        (b"rules:\n  enabled: ASI06\n", ConfigErrorCode.TYPE),
        (b"rules:\n  enabled: [ASI11]\n", ConfigErrorCode.VALUE),
        (b"rules:\n  enabled: [nex001]\n", ConfigErrorCode.VALUE),
        (b"rules:\n  enabled: [NEX001]\n  disabled: [NEX001]\n", ConfigErrorCode.VALUE),
        (b"frameworks:\n  auto_detect: 'yes please'\n", ConfigErrorCode.TYPE),
        (b"analysis:\n  max_files: true\n", ConfigErrorCode.TYPE),
        (b"analysis:\n  max_files: 0\n", ConfigErrorCode.VALUE),
        (b"analysis:\n  max_file_size: 99999999999\n", ConfigErrorCode.VALUE),
        (b"exclude: vendor\n", ConfigErrorCode.TYPE),
        (b"exclude: [1]\n", ConfigErrorCode.TYPE),
        (b"exclude: ['']\n", ConfigErrorCode.VALUE),
        (b"exclude: ['.']\n", ConfigErrorCode.VALUE),
    ],
)
def test_schema_errors(doc: bytes, code: ConfigErrorCode) -> None:
    with pytest.raises(ConfigError) as exc:
        parse_config_bytes(doc)
    assert exc.value.code is code


def test_list_and_string_caps() -> None:
    many = ("exclude:\n" + "".join(f"  - d{i}\n" for i in range(600))).encode()
    with pytest.raises(ConfigError) as exc:
        parse_config_bytes(many)
    assert exc.value.code is ConfigErrorCode.VALUE
    long = f"exclude: ['{'a' * 600}']\n".encode()
    with pytest.raises(ConfigError):
        parse_config_bytes(long)


def test_not_utf8_and_nul_rejected() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_config_bytes(b"exclude: ['\xff']\n")
    assert exc.value.code is ConfigErrorCode.NOT_UTF8
    with pytest.raises(ConfigError) as exc:
        parse_config_bytes(b"exclude: []\n\x00")
    assert exc.value.code is ConfigErrorCode.NOT_UTF8


def test_syntax_error_reports_line_not_content() -> None:
    with pytest.raises(ConfigError) as exc:
        parse_config_bytes(b"severity:\n  fail_on: [unclosed SECRET_MARKER\n")
    assert exc.value.code is ConfigErrorCode.SYNTAX
    assert "SECRET_MARKER" not in str(exc.value)


def test_rule_selector() -> None:
    assert is_rule_selector("NEX001")
    assert is_rule_selector("ASI10")
    assert not is_rule_selector("ASI00")
    assert not is_rule_selector("NEX1")
    assert not is_rule_selector("NEX" + chr(0x0661) * 3)  # Arabic-Indic digits


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("./a//b/", "a/b/"), ("a/./b", "a/b"), ("**/gen/*.py", "**/gen/*.py"), ("x", "x")],
)
def test_normalise_pattern(raw: str, expected: str) -> None:
    assert normalise_repo_pattern(raw, key="exclude") == expected


@pytest.mark.parametrize(
    "raw", ["/etc", "../x", "a/../../b", "~/x", "C:/x", "c:x", "a\\..\\b", "\\\\srv\\share"]
)
def test_pattern_escape_rejected(raw: str) -> None:
    with pytest.raises(ConfigError) as exc:
        normalise_repo_pattern(raw, key="exclude")
    assert exc.value.code is ConfigErrorCode.PATH_ESCAPE


def test_pattern_control_chars_rejected() -> None:
    with pytest.raises(ConfigError):
        normalise_repo_pattern("a\nb", key="exclude")


def test_load_config_file_records_provenance(tmp_path: Path) -> None:
    p = tmp_path / "base.yml"
    p.write_bytes(FULL)
    loaded = load_config_file(str(p), source=ConfigSource.BASE_REF, ref="base:abc")
    assert loaded.values.fail_on == "medium"
    assert loaded.size == len(FULL)
    assert len(loaded.sha256) == 64
    assert loaded.ref == "base:abc"


def test_load_repo_config_absent(tmp_path: Path) -> None:
    assert load_repo_config(str(tmp_path)) is None


def test_load_repo_config_present(tmp_path: Path) -> None:
    (tmp_path / ".nexvul.yml").write_bytes(b"severity:\n  fail_on: low\n")
    loaded = load_repo_config(str(tmp_path))
    assert loaded is not None
    assert loaded.source is ConfigSource.REPO
    assert loaded.display_path == ".nexvul.yml"
    assert loaded.values.fail_on == "low"


def test_load_config_directory_is_not_regular(tmp_path: Path) -> None:
    (tmp_path / ".nexvul.yml").mkdir()
    with pytest.raises(ConfigError) as exc:
        load_repo_config(str(tmp_path))
    assert exc.value.code in (ConfigErrorCode.NOT_REGULAR_FILE, ConfigErrorCode.UNREADABLE)


# --------------------------------------------------------------------------------- resolution


def test_defaults_without_any_config() -> None:
    r = resolve_config(repo=None, ci=True)
    assert r.effective == DEFAULTS
    assert r.changes == ()
    assert r.effective.sources["severity.fail_on"] == (ConfigSource.DEFAULT,)


def test_local_mode_applies_loosening_but_lists_it() -> None:
    head = layer(fail_on="critical", rules_disabled=frozenset({"NEX004"}))
    r = resolve_config(repo=head, ci=False)
    assert r.effective.fail_on == "critical"
    assert r.effective.rules_disabled == frozenset({"NEX004"})
    assert {c.key for c in r.changes} == {"severity.fail_on", "rules.disabled"}
    assert all(c.status is ChangeStatus.APPLIED for c in r.changes)
    assert r.effective.sources["severity.fail_on"] == (ConfigSource.DEFAULT, ConfigSource.REPO)


def test_ci_mode_applies_tightening_from_head() -> None:
    r = resolve_config(
        repo=layer(
            fail_on="low",
            rules_enabled=frozenset({"ASI06"}),
            cross_file=True,
            auto_detect=True,
            max_files=60_000,
        ),
        ci=True,
    )
    assert r.effective.fail_on == "low"
    assert r.effective.rules_enabled == frozenset({"ASI06"})
    assert r.effective.max_files == 60_000
    assert r.changes == ()


@pytest.mark.parametrize(
    ("values", "key"),
    [
        ({"fail_on": "critical"}, "severity.fail_on"),
        ({"rules_disabled": frozenset({"NEX004"})}, "rules.disabled"),
        ({"exclude": ("agent/",)}, "exclude"),
        ({"auto_detect": False}, "frameworks.auto_detect"),
        ({"cross_file": False}, "analysis.cross_file"),
        ({"max_files": 1}, "analysis.max_files"),
        ({"max_file_size": 10}, "analysis.max_file_size"),
    ],
)
def test_ci_mode_rejects_each_loosening(values: dict[str, object], key: str) -> None:
    r = resolve_config(repo=layer(**values), ci=True)
    assert r.effective == DEFAULTS
    assert [c.key for c in r.not_applied] == [key]
    assert "NOT APPLIED" in r.not_applied[0].display()


def test_ci_base_ref_loosening_is_applied_and_listed() -> None:
    base = layer(ConfigSource.BASE_REF, rules_disabled=frozenset({"NEX004", "NEX005"}))
    head = layer(rules_disabled=frozenset({"NEX004", "NEX009"}))
    r = resolve_config(repo=head, trusted=[base], ci=True)
    # NEX005 re-enabled by head (tightening, applied); NEX009 added by head (loosening, rejected)
    assert r.effective.rules_disabled == frozenset({"NEX004"})
    applied = [c for c in r.changes if c.status is ChangeStatus.APPLIED]
    rejected = r.not_applied
    assert applied and applied[0].source is ConfigSource.BASE_REF
    assert len(rejected) == 1 and "NEX009" in rejected[0].detail
    assert r.effective.sources["rules.disabled"] == (
        ConfigSource.DEFAULT,
        ConfigSource.BASE_REF,
        ConfigSource.REPO,
    )
    assert [p.source for p in r.config_sources] == [ConfigSource.BASE_REF, ConfigSource.REPO]
    assert r.config_sources[0].ref == "base:abc"


def test_ci_head_cannot_remove_base_enabled_rules() -> None:
    base = layer(ConfigSource.BASE_REF, rules_enabled=frozenset({"ASI06", "ASI07"}))
    head = layer(rules_enabled=frozenset({"ASI07", "ASI08"}))
    r = resolve_config(repo=head, trusted=[base], ci=True)
    assert r.effective.rules_enabled == frozenset({"ASI06", "ASI07", "ASI08"})
    assert len(r.not_applied) == 1 and "ASI06" in r.not_applied[0].detail


def test_ci_head_can_remove_base_excludes() -> None:
    base = layer(ConfigSource.BASE_REF, exclude=("vendor/", "gen/"))
    head = layer(exclude=("vendor/",))
    r = resolve_config(repo=head, trusted=[base], ci=True)
    assert r.effective.exclude == ("vendor/",)
    assert r.not_applied == ()


def test_repo_may_never_raise_max_file_size() -> None:
    for ci in (True, False):
        r = resolve_config(repo=layer(max_file_size=limits.HARD_MAX_FILE_SIZE), ci=ci)
        assert r.effective.max_file_size == limits.DEFAULT_MAX_FILE_SIZE
        assert r.not_applied[0].key == "analysis.max_file_size"


def test_trusted_layer_may_raise_max_file_size() -> None:
    user = layer(ConfigSource.USER, max_file_size=limits.HARD_MAX_FILE_SIZE)
    r = resolve_config(repo=None, trusted=[user], ci=True)
    assert r.effective.max_file_size == limits.HARD_MAX_FILE_SIZE


def test_layers_must_have_correct_sources() -> None:
    with pytest.raises(ValueError, match="trusted"):
        resolve_config(repo=None, trusted=[layer(ConfigSource.REPO)], ci=True)
    with pytest.raises(ValueError, match="REPO"):
        resolve_config(repo=layer(ConfigSource.USER), ci=True)


def test_resolution_is_pure_and_deterministic() -> None:
    head = layer(fail_on="critical", exclude=("b/", "a/"))
    assert resolve_config(repo=head, ci=True) == resolve_config(repo=head, ci=True)


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ({}, False),
        ({"CI": "true"}, True),
        ({"CI": "TRUE "}, True),
        ({"GITHUB_ACTIONS": "true"}, True),
        ({"CI": "1"}, False),
        ({"CI": "false"}, False),
    ],
)
def test_ci_mode_from_env(env: dict[str, str], expected: bool) -> None:
    assert ci_mode_from_env(env) is expected
