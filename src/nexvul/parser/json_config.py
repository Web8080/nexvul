"""Bounded JSON / JSONC reader for configuration files (step 4; architecture §5.3, §6, §7.3).

Runs **inside the parse worker**, like the Python front end, and turns the bytes of one ``.json``
file into a flat :class:`~nexvul.ir.model.ConfigDocument`. Never raises for any input bytes.

Two passes, both linear in the input size:

1. **A bounded, iterative tokenizer** (no recursion, explicit stack) walks the text once. It
   enforces the nesting cap *before* anything recursive runs, rejects ``NaN``/``Infinity`` and
   other non-JSON literals, rejects number literals longer than ``MAX_JSON_NUMBER_CHARS``, caps
   the number of values (``MAX_CONFIG_ENTRIES``), records every value with its line and UTF-8
   byte column, records duplicate keys (they are kept, never silently resolved), and accepts the
   JSONC extensions VS Code and Cursor allow (``//`` and ``/* */`` comments, trailing commas),
   noting that it did. String tokens are decoded with the stdlib ``json`` module.
2. **The stdlib ``json`` parser** then parses the same text (comments and trailing commas
   blanked out) as an authoritative syntax check, with ``NaN``/``Infinity`` rejected. Because
   the nesting depth is already capped by pass 1, the C scanner's recursion is bounded. A
   document the stdlib rejects is a ``parse_error`` even if pass 1 accepted it, so nexvul never
   reads more into a file than ``json`` would.

What is extracted: every value (objects, arrays, strings, numbers, booleans, null) with its
parent, member key or array position, kind, capped string value, size and location. What is
**not** extracted or interpreted: ``${VAR}``-style references are kept as literal text (never
expanded), ``$ref``/includes are not followed, ``envFile`` and other referenced files are not
read, and no schema is applied. Nothing is executed or fetched.

Failure reasons (``ParseFailure.detail`` never contains file content): ``binary`` (NUL byte),
``non_utf8_undecodable`` (not UTF-8, or a UTF-16/32 BOM), ``max_nesting``, ``max_ast_nodes``
(too many values), ``parse_error`` (syntax, with a line number only).
"""

from __future__ import annotations

import codecs
import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, replace
from typing import Final

from nexvul.core import limits
from nexvul.ir.config_view import escape_pointer_token, pointer_of
from nexvul.ir.model import (
    IR_SCHEMA_VERSION,
    ConfigDocument,
    ConfigEntry,
    ConfigValueKind,
    FailureReason,
    Location,
    ModuleIR,
    ParseStatus,
    failed_module,
)

LANGUAGE: Final = "json"

_BIDI_CONTROLS: Final = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")

# Linear-time patterns (architecture §5.5): disjoint alternatives, possessive repeats, applied
# with ``match`` at a fixed position. No nested ambiguous quantifiers.
_WS: Final = re.compile(r"[ \t\r\n]++")
_STRING: Final = re.compile(r'"(?:[^"\\\x00-\x1f]|\\["\\/bfnrt]|\\u[0-9a-fA-F]{4})*+"')
_NUMBER: Final = re.compile(r"-?(?:0|[1-9][0-9]*+)(?:\.[0-9]++)?(?:[eE][+-]?[0-9]++)?")
_LITERALS: Final = (("true", ConfigValueKind.BOOL), ("false", ConfigValueKind.BOOL))

_UTF16_32_BOMS: Final = (
    codecs.BOM_UTF32_LE,
    codecs.BOM_UTF32_BE,
    codecs.BOM_UTF16_LE,
    codecs.BOM_UTF16_BE,
)


@dataclass(frozen=True)
class JsonLimits:
    max_nesting: int = limits.MAX_NESTING
    max_entries: int = limits.MAX_CONFIG_ENTRIES
    max_literal_chars: int = limits.MAX_LITERAL_CHARS
    max_key_chars: int = limits.MAX_CONFIG_KEY_CHARS
    max_number_chars: int = limits.MAX_JSON_NUMBER_CHARS


class _JsonFailureError(Exception):
    def __init__(self, reason: FailureReason, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def _syntax(line: int, what: str) -> _JsonFailureError:
    return _JsonFailureError(FailureReason.PARSE_ERROR, f"JSON syntax error at line {line}: {what}")


class _Frame:
    __slots__ = ("count", "dups", "index", "is_object", "keys")

    def __init__(self, index: int, is_object: bool) -> None:
        self.index = index
        self.is_object = is_object
        self.count = 0
        self.keys: set[str] = set()
        self.dups: set[str] = set()


# Parser states (what the next token may be).
_VALUE: Final = 0  # a value (root, after ':' or after ',' in an array)
_VALUE_OR_CLOSE: Final = 1  # just after '[' (or after ',' in an array: JSONC trailing comma)
_KEY_OR_CLOSE: Final = 2  # just after '{' (or after ',' in an object: JSONC trailing comma)
_COLON: Final = 3
_COMMA_OR_CLOSE: Final = 4
_KEY_AFTER_COMMA: Final = 5
_VALUE_AFTER_COMMA: Final = 6
_DONE: Final = 7


class _Reader:
    """One pass over ``text``. All state is explicit; nothing recurses."""

    def __init__(self, text: str, lim: JsonLimits) -> None:
        self.text = text
        self.n = len(text)
        self.lim = lim
        self.entries: list[ConfigEntry] = []
        self.stack: list[_Frame] = []
        self.blank: list[tuple[int, int]] = []  # spans to blank for the stdlib re-parse
        self.comments = False
        self.trailing_commas = False
        self.truncated = 0
        self.duplicates: list[str] = []
        self.duplicates_truncated = False
        self._comma = 0  # position of the last ',' (blanked if it turns out to be trailing)
        # incremental line/column tracking (positions are visited in increasing order)
        self._last = 0
        self._line = 1
        self._col = 0

    # -- positions --------------------------------------------------------------------------

    def _loc(self, pos: int) -> tuple[int, int]:
        text = self.text
        newlines = text.count("\n", self._last, pos)
        if newlines:
            self._line += newlines
            start = text.rfind("\n", self._last, pos) + 1
            self._col = len(text[start:pos].encode("utf-8", "surrogatepass"))
        else:
            self._col += len(text[self._last : pos].encode("utf-8", "surrogatepass"))
        self._last = pos
        return self._line, self._col

    def _line_at(self, pos: int) -> int:
        return self._loc(max(pos, self._last))[0]

    # -- lexing -----------------------------------------------------------------------------

    def _skip(self, pos: int) -> int:
        """Skip whitespace and (JSONC) comments."""
        text = self.text
        while pos < self.n:
            m = _WS.match(text, pos)
            if m:
                pos = m.end()
                continue
            if text.startswith("//", pos):
                end = text.find("\n", pos)
                end = self.n if end == -1 else end
                self.blank.append((pos, end))
                self.comments = True
                pos = end
                continue
            if text.startswith("/*", pos):
                end = text.find("*/", pos + 2)
                if end == -1:
                    raise _syntax(self._line_at(pos), "unterminated comment")
                self.blank.append((pos, end + 2))
                self.comments = True
                pos = end + 2
                continue
            break
        return pos

    def _decode_string(self, token: str) -> str:
        value = json.loads(token)  # stdlib decoding of escapes; token already validated
        if not isinstance(value, str):  # pragma: no cover - the pattern only admits strings
            raise _syntax(self._line, "string expected")
        return value

    # -- entries ----------------------------------------------------------------------------

    def _add(  # noqa: PLR0917 - private hot-path helper; positional for speed and brevity
        self,
        kind: ConfigValueKind,
        value: str | None,
        size: int,
        truncated: bool,
        key: str | None,
        key_pos: int,
        value_pos: int,
    ) -> int:
        if len(self.entries) >= self.lim.max_entries:
            raise _JsonFailureError(
                FailureReason.MAX_AST_NODES, f"more than {self.lim.max_entries} JSON values"
            )
        parent = self.stack[-1] if self.stack else None
        item = -1
        if parent is not None:
            if not parent.is_object:
                item = parent.count
            parent.count += 1
        line, col = self._loc(key_pos if key is not None else value_pos)
        key_trunc = False
        if key is not None and len(key) > self.lim.max_key_chars:
            key = key[: self.lim.max_key_chars]
            key_trunc = True
        if key_trunc or truncated:
            self.truncated += 1
        entry = ConfigEntry(
            parent=parent.index if parent is not None else -1,
            key=key,
            item=item,
            kind=kind,
            value=value,
            size=size,
            truncated=truncated or key_trunc,
            location=Location(line=line, col=col, end_line=line, end_col=col),
        )
        self.entries.append(entry)
        return len(self.entries) - 1

    def _note_key(self, key: str) -> None:
        frame = self.stack[-1]
        if key in frame.keys:
            if key not in frame.dups:
                frame.dups.add(key)
                if len(self.duplicates) < limits.MAX_DUPLICATE_KEYS_LISTED:
                    base = pointer_of(self.entries, frame.index) if frame.index else ""
                    pointer = base + "/" + escape_pointer_token(key)
                    cap = limits.MAX_CONFIG_POINTER_CHARS
                    if len(pointer) > cap:
                        pointer = "…" + pointer[-(cap - 1) :]
                    self.duplicates.append(pointer)
                else:
                    self.duplicates_truncated = True
        else:
            frame.keys.add(key)

    # -- main loop --------------------------------------------------------------------------

    def run(self) -> None:
        text = self.text
        lim = self.lim
        pos = self._skip(0)
        if pos >= self.n:
            return  # empty document (whitespace/comments only)
        state = _VALUE
        key: str | None = None
        key_pos = 0
        while True:
            pos = self._skip(pos)
            if pos >= self.n:
                if state == _DONE:
                    return
                raise _syntax(self._line_at(pos), "unexpected end of document")
            ch = text[pos]
            if state == _DONE:
                raise _syntax(self._line_at(pos), "content after the top-level value")

            if state in (_KEY_OR_CLOSE, _KEY_AFTER_COMMA):
                if ch == "}":
                    if state == _KEY_AFTER_COMMA:
                        self._trailing_comma()
                    pos, state = self._close(pos, want_object=True)
                    continue
                if ch != '"':
                    raise _syntax(self._line_at(pos), "member name expected")
                m = _STRING.match(text, pos)
                if not m:
                    raise _syntax(self._line_at(pos), "invalid string")
                key = self._decode_string(m.group())
                key_pos = pos
                self._note_key(key)
                pos = m.end()
                state = _COLON
                continue

            if state == _COLON:
                if ch != ":":
                    raise _syntax(self._line_at(pos), "':' expected")
                pos += 1
                state = _VALUE
                continue

            if state == _COMMA_OR_CLOSE:
                frame = self.stack[-1]
                if ch == ",":
                    self._comma = pos
                    pos += 1
                    state = _KEY_AFTER_COMMA if frame.is_object else _VALUE_AFTER_COMMA
                    continue
                if ch in "}]":
                    pos, state = self._close(pos, want_object=ch == "}")
                    continue
                raise _syntax(self._line_at(pos), "',' or closing bracket expected")

            # a value is expected (_VALUE, _VALUE_OR_CLOSE, _VALUE_AFTER_COMMA)
            if ch == "]" and state in (_VALUE_OR_CLOSE, _VALUE_AFTER_COMMA):
                if state == _VALUE_AFTER_COMMA:
                    self._trailing_comma()
                pos, state = self._close(pos, want_object=False)
                continue
            member_key = key if self.stack and self.stack[-1].is_object else None
            if ch in "{[":
                if len(self.stack) >= lim.max_nesting:
                    raise _JsonFailureError(
                        FailureReason.MAX_NESTING,
                        f"nesting deeper than {lim.max_nesting} at line {self._line_at(pos)}",
                    )
                is_object = ch == "{"
                kind = ConfigValueKind.OBJECT if is_object else ConfigValueKind.ARRAY
                index = self._add(kind, None, 0, False, member_key, key_pos, pos)
                self.stack.append(_Frame(index, is_object))
                pos += 1
                state = _KEY_OR_CLOSE if is_object else _VALUE_OR_CLOSE
                continue
            if ch == '"':
                m = _STRING.match(text, pos)
                if not m:
                    raise _syntax(self._line_at(pos), "invalid string")
                value = self._decode_string(m.group())
                size = len(value)
                trunc = size > lim.max_literal_chars
                if trunc:
                    value = value[: lim.max_literal_chars]
                self._add(ConfigValueKind.STRING, value, size, trunc, member_key, key_pos, pos)
                pos = m.end()
            elif ch == "-" or ch.isdigit():
                m = _NUMBER.match(text, pos)
                if not m:
                    raise _syntax(self._line_at(pos), "invalid number")
                token = m.group()
                if len(token) > lim.max_number_chars:
                    raise _syntax(
                        self._line_at(pos), f"number literal longer than {lim.max_number_chars}"
                    )
                self._add(
                    ConfigValueKind.NUMBER, token, len(token), False, member_key, key_pos, pos
                )
                pos = m.end()
            else:
                for word, kind in (*_LITERALS, ("null", ConfigValueKind.NULL)):
                    if text.startswith(word, pos):
                        value_text = word if kind is ConfigValueKind.BOOL else None
                        self._add(kind, value_text, 0, False, member_key, key_pos, pos)
                        pos += len(word)
                        break
                else:
                    raise _syntax(self._line_at(pos), "value expected")
            state = _COMMA_OR_CLOSE if self.stack else _DONE

    def _trailing_comma(self) -> None:
        self.trailing_commas = True
        self.blank.append((self._comma, self._comma + 1))

    def _close(self, pos: int, *, want_object: bool) -> tuple[int, int]:
        if not self.stack or self.stack[-1].is_object is not want_object:
            raise _syntax(self._line_at(pos), "mismatched closing bracket")
        frame = self.stack.pop()
        self.entries[frame.index] = replace(self.entries[frame.index], size=frame.count)
        return pos + 1, (_COMMA_OR_CLOSE if self.stack else _DONE)

    def cleaned(self) -> str:
        """The text with comments and trailing commas replaced by spaces (newlines kept)."""
        if not self.blank:
            return self.text
        pieces: list[str] = []
        last = 0
        for start, end in sorted(self.blank):
            if start < last:  # pragma: no cover - spans never overlap
                continue
            pieces.append(self.text[last:start])
            span = self.text[start:end]
            pieces.append("".join("\n" if c == "\n" else " " for c in span))
            last = end
        pieces.append(self.text[last:])
        return "".join(pieces)


def _reject_constant(_name: str) -> object:
    raise ValueError("non-finite constant")


def _stdlib_check(text: str) -> None:
    """Authoritative syntax check by the stdlib parser (values discarded)."""
    try:
        json.loads(
            text,
            parse_constant=_reject_constant,
            parse_int=lambda _s: 0,
            parse_float=lambda _s: 0,
            object_pairs_hook=lambda _pairs: 0,
        )
    except (ValueError, RecursionError) as exc:
        line = getattr(exc, "lineno", 0)
        raise _JsonFailureError(
            FailureReason.PARSE_ERROR,
            f"rejected by the stdlib JSON parser at line {line}"
            if line
            else "rejected by the stdlib JSON parser",
        ) from None


def _decode(data: bytes) -> tuple[str, list[str]]:
    notes: list[str] = []
    if data.startswith(_UTF16_32_BOMS):
        raise _JsonFailureError(
            FailureReason.NON_UTF8_UNDECODABLE, "UTF-16/UTF-32 byte-order mark; JSON must be UTF-8"
        )
    if b"\x00" in data:
        raise _JsonFailureError(FailureReason.BINARY, "NUL byte in file")
    if data.startswith(codecs.BOM_UTF8):
        notes.append("bom")
        data = data[len(codecs.BOM_UTF8) :]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise _JsonFailureError(FailureReason.NON_UTF8_UNDECODABLE, "not valid UTF-8") from None
    chars = set(text)
    if chars & _BIDI_CONTROLS:
        notes.append("bidi_control")
    if any(unicodedata.category(c) == "Cf" and c not in _BIDI_CONTROLS for c in chars - {"﻿"}):
        notes.append("invisible_format_character")
    return text, notes


def parse_json_config(data: bytes, path: str, *, json_limits: JsonLimits | None = None) -> ModuleIR:
    """Turn the bytes of one JSON/JSONC file into IR. Never raises for any input bytes.

    ``path`` is the repo-relative path (data only; it is never opened here).
    """
    lim = json_limits or JsonLimits()
    sha = hashlib.sha256(data).hexdigest()
    notes: list[str] = []
    try:
        text, notes = _decode(data)
        reader = _Reader(text, lim)
        reader.run()
        if reader.entries:
            _stdlib_check(reader.cleaned())
    except _JsonFailureError as exc:
        return failed_module(
            language=LANGUAGE,
            path=path,
            module_name="",
            is_package=False,
            reason=exc.reason,
            detail=exc.detail,
            sha256=sha,
            size_bytes=len(data),
            encoding="utf-8" if exc.reason is not FailureReason.NON_UTF8_UNDECODABLE else None,
            notes=tuple(notes),
        )
    except MemoryError:  # pragma: no cover - exercised only under real memory pressure
        return failed_module(
            language=LANGUAGE,
            path=path,
            module_name="",
            is_package=False,
            reason=FailureReason.MEMORY_LIMIT,
            detail="memory exhausted reading JSON",
            sha256=sha,
            size_bytes=len(data),
            notes=tuple(notes),
        )
    if reader.comments or reader.trailing_commas:
        notes.append("jsonc")
    if not reader.entries:
        notes.append("empty_document")
    if reader.duplicates:
        notes.append("duplicate_keys")
    doc = ConfigDocument(
        syntax="jsonc" if (reader.comments or reader.trailing_commas) else "json",
        entries=tuple(reader.entries),
        duplicate_keys=tuple(reader.duplicates),
        duplicate_keys_truncated=reader.duplicates_truncated,
    )
    return ModuleIR(
        schema_version=IR_SCHEMA_VERSION,
        language=LANGUAGE,
        path=path,
        module_name="",
        is_package=False,
        status=ParseStatus.OK,
        sha256=sha,
        size_bytes=len(data),
        encoding="utf-8",
        node_count=len(doc.entries),
        literals_truncated=reader.truncated,
        notes=tuple(notes),
        config=doc,
    )
