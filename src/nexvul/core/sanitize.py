"""Display sanitisation for untrusted strings (filenames, config keys) - SR-10, T-10, T-11, T-30.

This is the single sanitiser for display text. Reporters (Phase 1 step 2+) must route every
untrusted string through :func:`display_text` / :func:`display_path`; they must not write their own.

Guarantees of the returned string:

* contains no C0/C1 control characters, no DEL, no ESC, no newline or carriage return;
* contains no Unicode format characters (category Cf: bidi overrides, zero-width chars, BOM), no
  line/paragraph separators (U+2028/U+2029) and no unpaired surrogates;
* is valid UTF-8 when encoded;
* is unambiguous: a literal backslash is shown as ``\\\\`` so escapes cannot be forged;
* is at most ``max_chars`` characters (plus a short hash suffix) when truncated.

Raw bytes from ``os.fsdecode`` (lone surrogates U+DC80..U+DCFF) are shown as ``\\xNN`` so the
original byte is recoverable for a human.
"""

from __future__ import annotations

import hashlib
import unicodedata

from nexvul.core.limits import MAX_DISPLAY_PATH_CHARS

# Characters that render like a path separator or a dot and could make a name look like a
# different path (MF-68). They are escaped rather than shown.
_CONFUSABLE_PATH_CHARS = frozenset(
    chr(code)
    for code in (
        0x2215,  # DIVISION SLASH
        0x2044,  # FRACTION SLASH
        0x29F8,  # BIG SOLIDUS
        0xFF0F,  # FULLWIDTH SOLIDUS
        0x29F9,  # BIG REVERSE SOLIDUS
        0xFF3C,  # FULLWIDTH REVERSE SOLIDUS
        0x2024,  # ONE DOT LEADER
        0xFF0E,  # FULLWIDTH FULL STOP
    )
)

_ELLIPSIS = chr(0x2026)

_ESCAPED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})


def _escape_char(ch: str) -> str:
    code = ord(ch)
    if 0xDC80 <= code <= 0xDCFF:
        # surrogateescape-decoded raw byte from a non-UTF-8 filename
        return f"\\x{code - 0xDC00:02x}"
    if code <= 0xFF:
        return f"\\x{code:02x}"
    return f"\\u{{{code:04x}}}"


def _needs_escape(ch: str) -> bool:
    if ch == "\\":
        return False  # handled separately
    if ch in _CONFUSABLE_PATH_CHARS:
        return True
    return unicodedata.category(ch) in _ESCAPED_CATEGORIES


def display_text(value: str, *, max_chars: int = MAX_DISPLAY_PATH_CHARS) -> str:
    """Return a single-line, escaped, length-capped rendering of an untrusted string."""
    parts: list[str] = []
    for ch in value:
        if ch == "\\":
            parts.append("\\\\")
        elif _needs_escape(ch):
            parts.append(_escape_char(ch))
        else:
            parts.append(ch)
    out = "".join(parts)
    if len(out) <= max_chars:
        return out
    digest = hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:10]
    keep = max(max_chars - 12, 1)  # room for ellipsis, "~" and a 10-char digest
    # Truncate on token boundaries so an escape sequence is never cut in half.
    used = 0
    head: list[str] = []
    for token in parts:
        if used + len(token) > keep:
            break
        head.append(token)
        used += len(token)
    return f"{''.join(head)}{_ELLIPSIS}~{digest}"


def display_path(value: str | bytes, *, max_chars: int = MAX_DISPLAY_PATH_CHARS) -> str:
    """Sanitise a filesystem path (str with surrogateescape, or raw bytes) for display."""
    text = value.decode("utf-8", "surrogateescape") if isinstance(value, bytes) else value
    return display_text(text, max_chars=max_chars)


def is_display_safe(value: str) -> bool:
    """True when ``value`` contains nothing :func:`display_text` would escape (used by tests)."""
    return all(ch != "\\" and not _needs_escape(ch) for ch in value)
