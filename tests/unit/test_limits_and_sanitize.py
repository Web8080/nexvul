"""Limits are sane; the display sanitiser removes every dangerous character (SR-04, SR-10)."""

from __future__ import annotations

from nexvul.core import limits
from nexvul.core.sanitize import display_path, display_text, is_display_safe

ESC = chr(0x1B)
RLO = chr(0x202E)
ZWSP = chr(0x200B)
LSEP = chr(0x2028)
CSI_C1 = chr(0x9B)
DIV_SLASH = chr(0x2215)


def test_hard_limits_are_ceilings() -> None:
    assert 0 < limits.DEFAULT_MAX_FILES <= limits.HARD_MAX_FILES
    assert 0 < limits.DEFAULT_MAX_FILE_SIZE <= limits.HARD_MAX_FILE_SIZE
    assert limits.BINARY_SNIFF_BYTES <= limits.DEFAULT_MAX_FILE_SIZE
    assert limits.MAX_CONFIG_BYTES == 64 * 1024
    assert limits.MAX_DIR_DEPTH > 0
    assert limits.DISCOVERY_TIME_BUDGET_SECONDS > 0


def test_plain_text_unchanged() -> None:
    assert display_text("agent/tools.py") == "agent/tools.py"
    assert is_display_safe("agent/tools.py")


def test_control_and_escape_characters_escaped() -> None:
    out = display_text(f"a\nb\r{ESC}[2J\x07\x7f{CSI_C1}")
    assert "\n" not in out and "\r" not in out and ESC not in out and CSI_C1 not in out
    assert out == "a\\x0ab\\x0d\\x1b[2J\\x07\\x7f\\x9b"


def test_bidi_zero_width_and_separators_escaped() -> None:
    out = display_text(f"evil{RLO}yp.py{ZWSP}{LSEP}")
    assert RLO not in out and ZWSP not in out and LSEP not in out
    assert "\\u{202e}" in out and "\\u{200b}" in out and "\\u{2028}" in out


def test_confusable_slash_escaped() -> None:
    out = display_text(f"src{DIV_SLASH}agent.py")
    assert DIV_SLASH not in out
    assert "\\u{2215}" in out


def test_backslash_is_escaped_so_escapes_cannot_be_forged() -> None:
    # A literal "\x1b" in a filename must not look like an escaped ESC byte.
    out = display_text("\\x1b")
    assert out == "\\\\x1b"
    assert out != display_text(ESC)


def test_surrogateescape_bytes_shown_as_hex_and_output_is_utf8() -> None:
    out = display_path(b"agent_\xff\xfe.py")
    assert out == "agent_\\xff\\xfe.py"
    out.encode("utf-8")  # must not raise


def test_truncation_with_hash_suffix_and_no_split_escape() -> None:
    long = ESC * 500
    out = display_text(long, max_chars=50)
    assert len(out) <= 50
    assert ESC not in out
    head = out.split(chr(0x2026))[0]
    assert len(head) % 4 == 0  # only whole "\x1b" tokens kept
    assert "~" in out
    # distinct inputs keep distinct suffixes
    assert display_text("a" * 500, max_chars=50) != display_text("a" * 499 + "b", max_chars=50)


def test_unassigned_and_private_use_escaped() -> None:
    assert is_display_safe("caf" + chr(0xE9))  # e-acute is ordinary text
    assert not is_display_safe(chr(0xE000))  # private use
    assert not is_display_safe("\\")
