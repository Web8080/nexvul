"""JSON/JSONC configuration reader (parser/json_config.py) and the config IR view."""

from __future__ import annotations

import codecs
import json
import random

import pytest

from nexvul.core import limits
from nexvul.ir.codec import module_from_json, module_to_json
from nexvul.ir.config_view import ConfigTree, escape_pointer_token, pointer_of
from nexvul.ir.model import (
    ConfigDocument,
    ConfigEntry,
    ConfigValueKind,
    FailureReason,
    Location,
    ParseStatus,
)
from nexvul.parser import json_config
from nexvul.parser.json_config import JsonLimits, parse_json_config


def ok(data: bytes | str, lim: JsonLimits | None = None) -> ConfigDocument:
    raw = data.encode() if isinstance(data, str) else data
    module = parse_json_config(raw, "x.json", json_limits=lim)
    assert module.status is ParseStatus.OK, module.failure
    assert module.config is not None
    return module.config


def failure(data: bytes | str, lim: JsonLimits | None = None) -> tuple[FailureReason, str]:
    raw = data.encode() if isinstance(data, str) else data
    module = parse_json_config(raw, "x.json", json_limits=lim)
    assert module.status is ParseStatus.FAILED and module.config is None
    assert module.failure is not None
    return module.failure.reason, module.failure.detail


def test_values_kinds_parents_and_locations() -> None:
    doc = ok('{\n  "a": [1, -2.5e3, true, false, null, "s"],\n  "b": {}\n}\n')
    kinds = [e.kind for e in doc.entries]
    assert kinds == [
        ConfigValueKind.OBJECT,
        ConfigValueKind.ARRAY,
        ConfigValueKind.NUMBER,
        ConfigValueKind.NUMBER,
        ConfigValueKind.BOOL,
        ConfigValueKind.BOOL,
        ConfigValueKind.NULL,
        ConfigValueKind.STRING,
        ConfigValueKind.OBJECT,
    ]
    root, arr = doc.entries[0], doc.entries[1]
    assert root.parent == -1 and root.size == 2 and arr.key == "a" and arr.size == 6
    assert [e.item for e in doc.entries[2:8]] == [0, 1, 2, 3, 4, 5]
    assert [e.value for e in doc.entries[2:8]] == ["1", "-2.5e3", "true", "false", None, "s"]
    assert arr.location == Location(2, 2, 2, 2)  # the member name "a"
    assert doc.entries[8].location.line == 3 and doc.syntax == "json"


def test_columns_are_utf8_byte_offsets_and_crlf_lines() -> None:
    doc = ok('{"é": "x",\r\n "k": 1}')
    assert doc.entries[1].location.col == 1
    assert doc.entries[2].location == Location(2, 1, 2, 1)
    doc = ok('["日本", "x"]')
    assert doc.entries[2].location.col == len('["日本", '.encode())


def test_jsonc_comments_and_trailing_commas_are_noted() -> None:
    module = parse_json_config(b'// c\n{"a": [1, 2,], /* b */ "b": 1,}\n', "x.json")
    assert module.ok and module.config is not None
    assert module.config.syntax == "jsonc" and "jsonc" in module.notes
    assert [e.key for e in module.config.entries if e.key] == ["a", "b"]


def test_duplicate_keys_are_recorded_not_resolved() -> None:
    module = parse_json_config(b'{"s": {"a/b~": 1, "a/b~": 2, "a/b~": 3}, "s": 0}', "x.json")
    doc = module.config
    assert doc is not None and "duplicate_keys" in module.notes
    assert doc.duplicate_keys == ("/s/a~1b~0", "/s")
    assert [e.value for e in doc.entries if e.key == "a/b~"] == ["1", "2", "3"]
    tree = ConfigTree(doc)
    assert tree.root == 0 and tree.member(0, "s") == 5  # last occurrence wins
    assert tree.occurrences(1, "a/b~") == [2, 3, 4]
    assert tree.duplicated_keys(1) == frozenset({"a/b~"})


def test_duplicate_key_list_is_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(limits, "MAX_DUPLICATE_KEYS_LISTED", 2)
    body = ",".join(f'"k{i}": 1, "k{i}": 2' for i in range(4))
    module = parse_json_config(("{" + body + "}").encode(), "x.json")
    assert module.config is not None
    assert len(module.config.duplicate_keys) == 2 and module.config.duplicate_keys_truncated


def test_bom_is_accepted_and_noted() -> None:
    module = parse_json_config(codecs.BOM_UTF8 + b'{"a": 1}', "x.json")
    assert module.ok and "bom" in module.notes


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (b'{"a": 1\x00}', FailureReason.BINARY),
        (codecs.BOM_UTF16_LE + '{"a":1}'.encode("utf-16-le"), FailureReason.NON_UTF8_UNDECODABLE),
        (codecs.BOM_UTF32_BE + b"\x00\x00\x00{", FailureReason.NON_UTF8_UNDECODABLE),
        (b'{"a": "\xff"}', FailureReason.NON_UTF8_UNDECODABLE),
        (b'{"a": NaN}', FailureReason.PARSE_ERROR),
        (b'{"a": Infinity}', FailureReason.PARSE_ERROR),
        (b'{"a": -Infinity}', FailureReason.PARSE_ERROR),
        (b'{"a": 01}', FailureReason.PARSE_ERROR),
        (b'{"a": 1.}', FailureReason.PARSE_ERROR),
        (b'{"a": 1} {}', FailureReason.PARSE_ERROR),
        (b'{"a" 1}', FailureReason.PARSE_ERROR),
        (b"{a: 1}", FailureReason.PARSE_ERROR),
        (b'{"a": 1]', FailureReason.PARSE_ERROR),
        (b"[1}", FailureReason.PARSE_ERROR),
        (b"]", FailureReason.PARSE_ERROR),
        (b'{"a": [1 2]}', FailureReason.PARSE_ERROR),
        (b'{"a": "x\ny"}', FailureReason.PARSE_ERROR),
        (b'{"a": "\\q"}', FailureReason.PARSE_ERROR),
        (b'{"a": "unterminated}', FailureReason.PARSE_ERROR),
        (b'{"a": 1 /* open', FailureReason.PARSE_ERROR),
        (b'{"a": 1', FailureReason.PARSE_ERROR),
        (b'{"a": tru}', FailureReason.PARSE_ERROR),
        (b"[,]", FailureReason.PARSE_ERROR),
        (b'{,"a": 1}', FailureReason.PARSE_ERROR),
        (b'{"a": 1,,}', FailureReason.PARSE_ERROR),
        (b"[" + b"9" * 101 + b"]", FailureReason.PARSE_ERROR),
    ],
)
def test_rejections(data: bytes, reason: FailureReason) -> None:
    got, detail = failure(data)
    assert got is reason
    assert "\n" not in detail and "a" * 3 not in detail  # detail never echoes content


def test_nesting_cap_is_enforced_before_recursion() -> None:
    assert ok("[" * 100 + "]" * 100).entries
    reason, detail = failure("[" * 101 + "]" * 101)
    assert reason is FailureReason.MAX_NESTING and "100" in detail
    reason, _ = failure('{"a":' * 50_000)  # 50k levels: rejected, never parsed recursively
    assert reason is FailureReason.MAX_NESTING


def test_entry_cap_and_literal_caps() -> None:
    reason, _ = failure("[" + ",".join("1" * 1 for _ in range(20)) + "]", JsonLimits(max_entries=5))
    assert reason is FailureReason.MAX_AST_NODES
    module = parse_json_config(
        json.dumps({"k" * 30: "v" * 50}).encode(),
        "x.json",
        json_limits=JsonLimits(max_key_chars=10, max_literal_chars=20),
    )
    assert module.config is not None and module.literals_truncated == 1
    entry = module.config.entries[1]
    assert entry.key == "k" * 10 and entry.value == "v" * 20 and entry.size == 50
    assert entry.truncated


@pytest.mark.parametrize("text", ["", "   \n", "// only a comment\n", "/* x */"])
def test_empty_documents_are_analysed(text: str) -> None:
    module = parse_json_config(text.encode(), "x.json")
    assert module.ok and module.config is not None and module.config.entries == ()
    assert "empty_document" in module.notes


def test_escapes_are_decoded_by_the_stdlib() -> None:
    doc = ok(r'{"ké": "a\"b\\c\/d\u001b\ud800"}')
    entry = doc.entries[1]
    assert entry.key == "ké" and entry.value == 'a"b\\c/d\x1b\ud800'


def test_bidi_and_invisible_characters_are_noted() -> None:
    text = '{"a": "' + chr(0x202E) + " x " + chr(0x200B) + '"}'
    module = parse_json_config(text.encode(), "x.json")
    assert {"bidi_control", "invisible_format_character"} <= set(module.notes)


def test_stdlib_cross_check_is_authoritative() -> None:
    with pytest.raises(json_config._JsonFailureError) as exc:
        json_config._stdlib_check('{"a": 1,}')
    assert exc.value.reason is FailureReason.PARSE_ERROR and "line 1" in exc.value.detail
    with pytest.raises(json_config._JsonFailureError):
        json_config._stdlib_check('{"a": NaN}')


def test_ir_round_trip_through_the_worker_codec() -> None:
    module = parse_json_config(
        b'{"mcpServers": {"x": {"url": "http://e.example/\\ud800"}}, "n": [1, 2.5]}',
        "dir/.mcp.json",
    )
    again = module_from_json(module_to_json(module))
    assert again == module and again.config is not None and again.language == "json"


def test_random_bytes_never_raise() -> None:
    rng = random.Random(7)  # noqa: S311 - deterministic fuzz input, not cryptography
    alphabet = b'{}[]:,"\\ \n\t-0123456789.eEtrufalsn/*\xc3\xa9\xff\x00'
    for _ in range(2_000):
        data = bytes(rng.choice(alphabet) for _ in range(rng.randint(0, 40)))
        module = parse_json_config(data, "f.json")
        assert module.status in (ParseStatus.OK, ParseStatus.FAILED)


def test_large_document_is_linear_enough() -> None:
    doc = {f"s{i}": {"url": f"https://h{i}.example/x", "args": [1, 2, 3]} for i in range(5_000)}
    module = parse_json_config(json.dumps(doc).encode(), "x.json")
    assert module.ok and module.node_count == 1 + 5_000 * 6


# --- config view ---------------------------------------------------------------------------------


def entry(
    parent: int, key: str | None, kind: ConfigValueKind, value: str | None = None
) -> ConfigEntry:
    return ConfigEntry(parent, key, -1, kind, value, 0, False, Location(1, 0, 1, 0))


def test_view_ignores_malformed_parent_indices() -> None:
    entries = (
        entry(-1, None, ConfigValueKind.OBJECT),
        entry(0, "a", ConfigValueKind.STRING, "x"),
        entry(5, "b", ConfigValueKind.STRING, "y"),  # forward parent: ignored
        entry(2, "c", ConfigValueKind.STRING, "z"),  # self-ish cycle candidate: ignored
    )
    tree = ConfigTree(ConfigDocument("json", entries))
    assert tree.members(0) == {"a": 1}
    assert tree.string(1) == "x" and tree.string(None) is None and tree.string(0) is None
    assert tree.members(1) == {} and tree.items(0) == [] and tree.occurrences(1, "a") == []
    assert pointer_of(entries, 3) == "/c"  # the walk stops at the forward (bad) parent
    assert pointer_of(entries, 1) == "/a"


def test_view_items_and_root() -> None:
    doc = ok('[{"a": 1}, 2]')
    tree = ConfigTree(doc)
    assert tree.items(0) == [1, 3] and tree.pointer(2) == "/0/a"
    assert ConfigTree(ConfigDocument("json", ())).root is None
    assert ConfigTree(ConfigDocument("json", (entry(0, None, ConfigValueKind.NULL),))).root is None


def test_pointer_escaping_and_cap() -> None:
    assert escape_pointer_token("a~/b") == "a~0~1b"
    doc = ok(json.dumps({"k" * 400: {"j" * 400: 1}}))
    ptr = pointer_of(doc.entries, 2)
    assert len(ptr) == limits.MAX_CONFIG_POINTER_CHARS and ptr.startswith("…")
