"""Rule API, frozen registry and selection (architecture §11, DEC-0004 §4, DEC-0012)."""

from __future__ import annotations

from pathlib import Path

import pytest
from nexvul_test_rules import ExplodingRule, PrintRule, ShellCallRule

import nexvul.rules
from nexvul.findings.model import Confidence, Severity
from nexvul.rules.base import Readiness, Rule, RuleMeta, code
from nexvul.rules.registry import BUILTIN_RULES, Registry, builtin_registry


def meta(**kw: object) -> RuleMeta:
    base: dict[str, object] = {
        "id": "NEX100",
        "name": "n",
        "asi": ("ASI06",),
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "readiness": Readiness.DEFAULT,
        "remediation": "r",
    }
    base.update(kw)
    return RuleMeta(**base)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "kw",
    [
        {"id": "X1"},
        {"name": "  "},
        {"remediation": ""},
        {"asi": ()},
        {"asi": ("ASI06", "ASI06")},
        {"asi": ("ASI6",)},
    ],
)
def test_meta_validation(kw: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        meta(**kw)


def test_meta_to_dict_is_canonical() -> None:
    d = meta(asi=("ASI02", "ASI09")).to_dict()
    assert d["asi"] == ["ASI02", "ASI09"]  # order kept: primary first (DEC-0005)
    assert d["severity"] == "high" and d["readiness"] == "default"


def test_empty_registry_is_supported() -> None:
    reg = Registry(())
    assert len(reg) == 0 and list(reg) == [] and reg.ids() == frozenset()
    assert reg.sha256.startswith("sha256:")


def test_builtin_registry_is_frozen_and_ships_only_nex007_experimental() -> None:
    # Step 4: the first real rule. It ships experimental (off by default) because fewer than
    # 20 labelled benchmark cases exist for it (DEC-0002 amendment 1).
    assert isinstance(BUILTIN_RULES, tuple)
    reg = builtin_registry()
    assert reg.ids() == frozenset({"NEX007"})
    nex007 = reg.get("NEX007")
    assert nex007 is not None
    assert nex007.meta.readiness is Readiness.EXPERIMENTAL
    assert nex007.meta.asi == ("ASI07", "ASI04")
    assert reg.sha256.startswith("sha256:") and builtin_registry().sha256 == reg.sha256
    assert reg.pack_version == "0.1.0"
    selection = reg.select(frozenset(), frozenset())
    assert selection.enabled == () and selection.not_enabled == ("NEX007",)
    assert [r.meta.id for r in reg.select(frozenset({"ASI07"}), frozenset()).enabled] == ["NEX007"]


def test_registry_rejects_duplicates_and_non_rules() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        Registry([ShellCallRule(), ShellCallRule()])
    with pytest.raises(TypeError):
        Registry(["NEX001"])  # type: ignore[list-item]


def test_registry_lookup_and_hash_changes_with_metadata() -> None:
    reg = Registry([PrintRule(), ShellCallRule()])
    assert [r.meta.id for r in reg.rules] == ["NEX990", "NEX991"]
    assert reg.get("NEX990") is not None and reg.get("NEX000") is None
    assert reg.sha256 != Registry([ShellCallRule()]).sha256
    assert reg.sha256 != Registry([PrintRule(), ShellCallRule()], pack_version="9").sha256


def test_selection_defaults_experimental_and_enabled_wins() -> None:
    reg = Registry([ShellCallRule(), PrintRule(), ExplodingRule()])
    sel = reg.select(frozenset(), frozenset())
    assert [r.meta.id for r in sel.enabled] == ["NEX990", "NEX993"]
    assert sel.not_enabled == ("NEX991",)
    # experimental rule on by ID; default rule off by ASI selector
    sel = reg.select(frozenset({"NEX991"}), frozenset({"ASI08"}))
    assert [r.meta.id for r in sel.enabled] == ["NEX990", "NEX991"]
    # enabled wins over disabled (DEC-0012)
    sel = reg.select(frozenset({"ASI05"}), frozenset({"NEX990"}))
    assert "NEX990" in [r.meta.id for r in sel.enabled]


def test_code_caps_identifiers() -> None:
    assert code("abc") == "abc"
    capped = code("x" * 200)
    assert len(capped) == 80 and capped.endswith("…")


def test_rule_is_abstract() -> None:
    with pytest.raises(TypeError):
        Rule()  # type: ignore[abstract]


def test_rules_package_never_discovers_plugins() -> None:
    """DEC-0004 §4 / SR-22: no entry-point discovery, no dynamic loading anywhere in nexvul."""
    src = Path(nexvul.rules.__file__).resolve().parents[1]
    for path in src.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "entry_points" not in text, path
        assert "importlib.metadata" not in text, path
        assert "pkg_resources" not in text, path
