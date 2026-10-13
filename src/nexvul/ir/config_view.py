"""Read-only tree view over a flattened :class:`~nexvul.ir.model.ConfigDocument`.

The IR stores a JSON document as a flat list of entries with parent indices (the schema stays
non-recursive). This view rebuilds parent -> children lists once and answers the questions
recognisers ask: "member ``url`` of this object", "all members, last occurrence wins", "which keys
are duplicated", "JSON Pointer of this entry". It never recurses, so deep documents cannot
exhaust the stack.

Entries come from a worker that read hostile bytes; the IR decoder has validated their types,
and this view additionally ignores any parent index that does not point *backwards* (a parent
must precede its children), so a malformed document cannot create cycles.
"""

from __future__ import annotations

from collections.abc import Sequence

from nexvul.core import limits
from nexvul.ir.model import ConfigDocument, ConfigEntry, ConfigValueKind


def escape_pointer_token(token: str) -> str:
    """RFC 6901 escaping: ``~`` -> ``~0``, ``/`` -> ``~1``."""
    return token.replace("~", "~0").replace("/", "~1")


def pointer_of(
    entries: Sequence[ConfigEntry],
    index: int,
    *,
    max_chars: int = limits.MAX_CONFIG_POINTER_CHARS,
) -> str:
    """JSON Pointer (RFC 6901) of ``entries[index]``, capped at ``max_chars`` (prefix ``…``).

    Untrusted text: callers must sanitise before display.
    """
    parts: list[str] = []
    seen = 0
    i = index
    while 0 <= i < len(entries) and seen <= len(entries):
        entry = entries[i]
        if entry.parent < 0 or entry.parent >= i:
            break
        parts.append(escape_pointer_token(entry.key) if entry.key is not None else str(entry.item))
        i = entry.parent
        seen += 1
    text = "".join("/" + p for p in reversed(parts))
    if len(text) > max_chars:
        return "…" + text[-(max_chars - 1) :]
    return text


class ConfigTree:
    """Parent/child index over one document. Construction is ``O(entries)``."""

    __slots__ = ("_children", "doc", "entries")

    def __init__(self, doc: ConfigDocument) -> None:
        self.doc = doc
        self.entries: tuple[ConfigEntry, ...] = doc.entries
        children: list[list[int]] = [[] for _ in self.entries]
        for i, entry in enumerate(self.entries):
            if 0 <= entry.parent < i:
                children[entry.parent].append(i)
        self._children = children

    @property
    def root(self) -> int | None:
        """Index of the root value, or ``None`` for an empty document."""
        if self.entries and self.entries[0].parent == -1:
            return 0
        return None

    def kind(self, index: int) -> ConfigValueKind:
        return self.entries[index].kind

    def children(self, index: int) -> list[int]:
        return list(self._children[index])

    def members(self, index: int) -> dict[str, int]:
        """Members of an object as ``key -> entry index``; the last occurrence of a duplicated
        key wins (what ``JSON.parse`` and Python's ``json`` do). Empty for non-objects."""
        if self.entries[index].kind is not ConfigValueKind.OBJECT:
            return {}
        out: dict[str, int] = {}
        for child in self._children[index]:
            key = self.entries[child].key
            if key is not None:
                out[key] = child
        return out

    def occurrences(self, index: int, key: str) -> list[int]:
        """Every occurrence of ``key`` in object ``index``, in document order."""
        if self.entries[index].kind is not ConfigValueKind.OBJECT:
            return []
        return [c for c in self._children[index] if self.entries[c].key == key]

    def duplicated_keys(self, index: int) -> frozenset[str]:
        """Keys that occur more than once directly inside object ``index``."""
        seen: set[str] = set()
        dups: set[str] = set()
        for child in self._children[index]:
            key = self.entries[child].key
            if key is None:
                continue
            if key in seen:
                dups.add(key)
            seen.add(key)
        return frozenset(dups)

    def member(self, index: int, key: str) -> int | None:
        return self.members(index).get(key)

    def items(self, index: int) -> list[int]:
        if self.entries[index].kind is not ConfigValueKind.ARRAY:
            return []
        return list(self._children[index])

    def string(self, index: int | None) -> str | None:
        """The string value of entry ``index`` (``None`` if absent or not a string)."""
        if index is None:
            return None
        entry = self.entries[index]
        return entry.value if entry.kind is ConfigValueKind.STRING else None

    def pointer(self, index: int) -> str:
        return pointer_of(self.entries, index)
