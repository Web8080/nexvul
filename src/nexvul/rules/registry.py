"""Frozen built-in rule registry (architecture §11.3, DEC-0004 §4, SR-22, T-25).

Rules come only from the frozen table :data:`BUILTIN_RULES` in this module. nexvul never queries
installed-package entry points, never imports code from other installed distributions and never
loads rules from repository or user config. A co-installed package therefore gets no hook
into nexvul.

Phase 1 ships **no** detection rules: the table is empty, and ``nexvul rules`` / ``explain`` /
``scan`` say so. Tests build their own :class:`Registry` with test-only rules that live under
``tests/`` and are passed in explicitly; they are never added to this table.

The rule-pack hash (SR-27) is the SHA-256 of the canonical JSON of every rule's metadata, in ID
order, and is printed in every output. (The build-time integrity comparison of architecture §11.3
is a later step; see the step-3a handoff.)
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from nexvul.rules.base import Readiness, Rule

#: Version of the built-in rule pack (U07). Bumped whenever the table changes.
RULE_PACK_VERSION: Final = "0.0.0"

#: The frozen table of built-in rule classes. Empty in Phase 1 (no rule ships yet).
BUILTIN_RULES: Final[tuple[type[Rule], ...]] = ()


@dataclass(frozen=True)
class Selection:
    """Rules chosen to run, and why each built-in rule did not run."""

    enabled: tuple[Rule, ...]
    not_enabled: tuple[str, ...]


class Registry:
    """An immutable, ID-indexed set of rule instances."""

    __slots__ = ("_by_id", "_rules", "pack_version")

    def __init__(self, rules: Iterable[Rule], *, pack_version: str = RULE_PACK_VERSION) -> None:
        items = list(rules)
        if not all(isinstance(rule, Rule) for rule in items):
            raise TypeError("registry entries must be Rule instances")
        ordered = sorted(items, key=lambda r: r.meta.id)
        by_id: dict[str, Rule] = {}
        for rule in ordered:
            if rule.meta.id in by_id:
                raise ValueError(f"duplicate rule id {rule.meta.id}")
            by_id[rule.meta.id] = rule
        self._rules: tuple[Rule, ...] = tuple(ordered)
        self._by_id: Mapping[str, Rule] = MappingProxyType(by_id)
        self.pack_version = pack_version

    def __iter__(self) -> Iterator[Rule]:
        return iter(self._rules)

    def __len__(self) -> int:
        return len(self._rules)

    @property
    def rules(self) -> tuple[Rule, ...]:
        return self._rules

    def get(self, rule_id: str) -> Rule | None:
        return self._by_id.get(rule_id)

    def ids(self) -> frozenset[str]:
        return frozenset(self._by_id)

    @property
    def sha256(self) -> str:
        """``sha256:<hex>`` of the canonical metadata of every rule (SR-27)."""
        canonical = json.dumps(
            {"pack_version": self.pack_version, "rules": [r.meta.to_dict() for r in self._rules]},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        return "sha256:" + hashlib.sha256(canonical.encode("ascii")).hexdigest()

    def select(self, enabled: frozenset[str], disabled: frozenset[str]) -> Selection:
        """Apply ``rules.enabled`` / ``rules.disabled`` selectors (rule IDs or ASI IDs).

        A default-on rule runs unless a selector disables it; an experimental rule runs only when
        a selector enables it. Enabled wins over disabled (DEC-0012).
        """
        run: list[Rule] = []
        skipped: list[str] = []
        for rule in self._rules:
            selectors = {rule.meta.id, *rule.meta.asi}
            on = rule.meta.readiness is Readiness.DEFAULT
            if selectors & disabled:
                on = False
            if selectors & enabled:
                on = True
            if on:
                run.append(rule)
            else:
                skipped.append(rule.meta.id)
        return Selection(enabled=tuple(run), not_enabled=tuple(skipped))


def builtin_registry() -> Registry:
    """The registry nexvul ships: built only from :data:`BUILTIN_RULES`."""
    return Registry(cls() for cls in BUILTIN_RULES)
