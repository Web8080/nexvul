"""`.nexvul.yml` loading and trust-aware resolution (architecture §3, SR-15, SR-28, DEC-0004 §1).

Two halves:

1. **Loading** (:func:`parse_config_bytes`, :func:`load_config_file`, :func:`load_repo_config`):
   size cap before parsing, ``O_NOFOLLOW`` open + ``fstat`` regular-file check, strict UTF-8, a
   YAML *event* pass that rejects anchors, aliases, explicit tags, ``%TAG`` directives, multiple
   documents, excessive depth and excessive event counts, then construction with a SafeLoader
   subclass that rejects duplicate and non-string keys, then a strict schema with unknown-key
   rejection and path confinement for every path-like value. Nothing here can execute code:
   only ``yaml.SafeLoader`` machinery is used.

2. **Resolution** (:func:`resolve_config`): a pure function. Trusted layers (built-in defaults,
   then base-branch / user / CLI layers) apply in full. The repository's own config (untrusted,
   possibly a PR head) applies in full locally, but in CI mode only its *tightening* changes are
   applied; every loosening is reported with status ``not_applied`` ("NOT APPLIED").

Repository config can never set output paths, cache locations, plugin sources or regexes: those
keys do not exist in the schema, so they are rejected as unknown keys (MF-43, MF-59).

Error messages never contain config *values* verbatim; key names are passed through the display
sanitiser because they are attacker-controlled.
"""

from __future__ import annotations

import errno
import hashlib
import os
import stat
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any, Final

import yaml
from yaml.events import (
    AliasEvent,
    CollectionEndEvent,
    CollectionStartEvent,
    DocumentStartEvent,
    NodeEvent,
    ScalarEvent,
)
from yaml.nodes import MappingNode, ScalarNode

from nexvul.core import limits
from nexvul.core.sanitize import display_text

CONFIG_FILENAME: Final = ".nexvul.yml"

SEVERITIES: Final = ("info", "low", "medium", "high", "critical")
_SEVERITY_RANK: Final = {name: i for i, name in enumerate(SEVERITIES)}

# Dotted key names: the public vocabulary used in reports (brief §14).
KEY_FAIL_ON: Final = "severity.fail_on"
KEY_RULES_ENABLED: Final = "rules.enabled"
KEY_RULES_DISABLED: Final = "rules.disabled"
KEY_EXCLUDE: Final = "exclude"
KEY_AUTO_DETECT: Final = "frameworks.auto_detect"
KEY_CROSS_FILE: Final = "analysis.cross_file"
KEY_MAX_FILES: Final = "analysis.max_files"
KEY_MAX_FILE_SIZE: Final = "analysis.max_file_size"

ALL_KEYS: Final = (
    KEY_FAIL_ON,
    KEY_RULES_ENABLED,
    KEY_RULES_DISABLED,
    KEY_EXCLUDE,
    KEY_AUTO_DETECT,
    KEY_CROSS_FILE,
    KEY_MAX_FILES,
    KEY_MAX_FILE_SIZE,
)

# Allowed schema: section -> set of allowed sub-keys ("" means a top-level leaf key).
_SCHEMA: Final[dict[str, frozenset[str]]] = {
    "severity": frozenset({"fail_on"}),
    "rules": frozenset({"enabled", "disabled"}),
    "exclude": frozenset(),
    "frameworks": frozenset({"auto_detect"}),
    "analysis": frozenset({"cross_file", "max_files", "max_file_size"}),
}

_OPEN_FLAGS: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)


# ============================================================================================
# Errors
# ============================================================================================


class ConfigErrorCode(StrEnum):
    TOO_LARGE = "too_large"
    NOT_REGULAR_FILE = "not_regular_file"
    SYMLINK = "symlink"
    UNREADABLE = "unreadable"
    NOT_UTF8 = "not_utf8"
    SYNTAX = "syntax"
    ANCHOR_OR_ALIAS = "anchor_or_alias"
    EXPLICIT_TAG = "explicit_tag"
    MULTIPLE_DOCUMENTS = "multiple_documents"
    TOO_DEEP = "too_deep"
    TOO_COMPLEX = "too_complex"
    DUPLICATE_KEY = "duplicate_key"
    UNKNOWN_KEY = "unknown_key"
    TYPE = "type"
    VALUE = "value"
    PATH_ESCAPE = "path_escape"


class ConfigError(Exception):
    """A config file was rejected. Maps to exit code 2. Message is safe to display."""

    def __init__(self, code: ConfigErrorCode, message: str, *, key: str | None = None) -> None:
        self.code = code
        self.key = display_text(key, max_chars=80) if key is not None else None
        where = f" at '{self.key}'" if self.key else ""
        super().__init__(f"config error ({code.value}){where}: {message}")


# ============================================================================================
# Data model
# ============================================================================================


class ConfigSource(StrEnum):
    """Where a value came from, lowest trust last (architecture §3.1)."""

    CLI = "cli"
    USER = "user"
    BASE_REF = "base_ref"
    REPO = "repo"
    DEFAULT = "default"


TRUSTED_SOURCES: Final = frozenset(
    {ConfigSource.CLI, ConfigSource.USER, ConfigSource.BASE_REF, ConfigSource.DEFAULT}
)


@dataclass(frozen=True)
class ConfigValues:
    """Values present in one config layer. ``None`` means "not set in this layer"."""

    fail_on: str | None = None
    rules_enabled: frozenset[str] | None = None
    rules_disabled: frozenset[str] | None = None
    exclude: tuple[str, ...] | None = None
    auto_detect: bool | None = None
    cross_file: bool | None = None
    max_files: int | None = None
    max_file_size: int | None = None


@dataclass(frozen=True)
class LoadedConfig:
    """One parsed config layer with provenance (SR-27)."""

    values: ConfigValues
    source: ConfigSource
    display_path: str
    sha256: str
    size: int
    ref: str | None = None


@dataclass(frozen=True)
class EffectiveConfig:
    fail_on: str
    rules_enabled: frozenset[str]
    rules_disabled: frozenset[str]
    exclude: tuple[str, ...]
    auto_detect: bool
    cross_file: bool
    max_files: int
    max_file_size: int
    #: per-key provenance: every source that contributed to the final value, in apply order
    sources: Mapping[str, tuple[ConfigSource, ...]] = field(default_factory=dict)


DEFAULTS: Final = EffectiveConfig(
    fail_on="high",  # OD-15
    rules_enabled=frozenset(),
    rules_disabled=frozenset(),
    exclude=(),
    auto_detect=True,
    cross_file=True,
    max_files=limits.DEFAULT_MAX_FILES,
    max_file_size=limits.DEFAULT_MAX_FILE_SIZE,
    sources=dict.fromkeys(ALL_KEYS, (ConfigSource.DEFAULT,)),
)


class ChangeStatus(StrEnum):
    APPLIED = "applied"
    NOT_APPLIED = "not_applied"


@dataclass(frozen=True)
class ConfigChange:
    """A protection-weakening (or forbidden) change requested by a config layer.

    These populate ``protections_weakened_by_repo_config`` in every output (SR-15).
    ``detail`` is sanitised display text.
    """

    key: str
    detail: str
    source: ConfigSource
    status: ChangeStatus
    reason: str

    def display(self) -> str:
        label = "NOT APPLIED" if self.status is ChangeStatus.NOT_APPLIED else "APPLIED"
        return f"{self.key}: {self.detail} [{label}] ({self.source.value}: {self.reason})"


@dataclass(frozen=True)
class ConfigProvenance:
    source: ConfigSource
    display_path: str
    sha256: str
    ref: str | None


@dataclass(frozen=True)
class ResolvedConfig:
    effective: EffectiveConfig
    changes: tuple[ConfigChange, ...]
    config_sources: tuple[ConfigProvenance, ...]
    ci: bool

    @property
    def not_applied(self) -> tuple[ConfigChange, ...]:
        return tuple(c for c in self.changes if c.status is ChangeStatus.NOT_APPLIED)


# ============================================================================================
# Path confinement (SR-28, T-08, MF-55)
# ============================================================================================


def normalise_repo_pattern(raw: str, *, key: str) -> str:
    """Validate and normalise a repo-relative path or glob pattern.

    Rejects absolute paths (POSIX, UNC, drive letters), ``~`` expansion, ``..`` components, NUL
    and control characters, and backslashes (which are separators on Windows). Returns the
    pattern with ``./`` prefixes and duplicate separators removed. Never touches the filesystem.
    """
    if not raw:
        raise ConfigError(ConfigErrorCode.VALUE, "empty path", key=key)
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F or 0x80 <= ord(ch) <= 0x9F for ch in raw):
        raise ConfigError(ConfigErrorCode.VALUE, "control character in path", key=key)
    if "\\" in raw:
        raise ConfigError(ConfigErrorCode.PATH_ESCAPE, "backslash in path", key=key)
    if raw.startswith(("/", "~")) or (len(raw) >= 2 and raw[1] == ":" and raw[0].isalpha()):
        raise ConfigError(ConfigErrorCode.PATH_ESCAPE, "absolute path not allowed", key=key)
    parts = [p for p in raw.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise ConfigError(ConfigErrorCode.PATH_ESCAPE, "'..' not allowed in path", key=key)
    if not parts:
        raise ConfigError(ConfigErrorCode.VALUE, "path refers to the repository root", key=key)
    normalised = "/".join(parts)
    if raw.endswith("/"):
        normalised += "/"
    return normalised


# ============================================================================================
# YAML loading
# ============================================================================================


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate keys, non-string keys and merge keys."""

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[str] = set()
        for key_node, _value_node in node.value:
            if isinstance(key_node, ScalarNode) and key_node.tag == "tag:yaml.org,2002:merge":
                raise ConfigError(ConfigErrorCode.UNKNOWN_KEY, "merge keys are not allowed")
            if not isinstance(key_node, ScalarNode) or key_node.tag != "tag:yaml.org,2002:str":
                raise ConfigError(ConfigErrorCode.TYPE, "mapping keys must be plain strings")
            key = str(key_node.value)
            if key in seen:
                raise ConfigError(ConfigErrorCode.DUPLICATE_KEY, "duplicate key", key=key)
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def _check_events(text: str) -> None:
    """Event-level pass: reject anchors/aliases/tags/multi-docs and bound depth and size."""
    depth = 0
    events = 0
    documents = 0
    try:
        for event in yaml.parse(text, Loader=yaml.SafeLoader):
            events += 1
            if events > limits.MAX_CONFIG_EVENTS:
                raise ConfigError(ConfigErrorCode.TOO_COMPLEX, "document too complex")
            if isinstance(event, AliasEvent):
                raise ConfigError(ConfigErrorCode.ANCHOR_OR_ALIAS, "YAML aliases are not allowed")
            if isinstance(event, NodeEvent) and event.anchor is not None:
                raise ConfigError(ConfigErrorCode.ANCHOR_OR_ALIAS, "YAML anchors are not allowed")
            if isinstance(event, ScalarEvent | CollectionStartEvent) and event.tag is not None:
                raise ConfigError(ConfigErrorCode.EXPLICIT_TAG, "explicit YAML tags not allowed")
            if isinstance(event, DocumentStartEvent):
                documents += 1
                if documents > 1:
                    raise ConfigError(
                        ConfigErrorCode.MULTIPLE_DOCUMENTS, "only one YAML document is allowed"
                    )
                if event.tags:
                    raise ConfigError(ConfigErrorCode.EXPLICIT_TAG, "%TAG directives not allowed")
            if isinstance(event, CollectionStartEvent):
                depth += 1
                if depth > limits.MAX_CONFIG_DEPTH:
                    raise ConfigError(ConfigErrorCode.TOO_DEEP, "nesting too deep")
            elif isinstance(event, CollectionEndEvent):
                depth -= 1
    except yaml.MarkedYAMLError as exc:
        line = exc.problem_mark.line + 1 if exc.problem_mark is not None else 0
        raise ConfigError(ConfigErrorCode.SYNTAX, f"invalid YAML near line {line}") from None
    except yaml.YAMLError:
        raise ConfigError(ConfigErrorCode.SYNTAX, "invalid YAML") from None


def _construct(text: str) -> object:
    loader = _StrictLoader(text)
    try:
        return loader.get_single_data()
    except ConfigError:
        raise
    except yaml.MarkedYAMLError as exc:
        line = exc.problem_mark.line + 1 if exc.problem_mark is not None else 0
        raise ConfigError(ConfigErrorCode.SYNTAX, f"invalid YAML near line {line}") from None
    except (yaml.YAMLError, ValueError, OverflowError):
        # ValueError: e.g. integers beyond sys.int_info.default_max_str_digits
        raise ConfigError(ConfigErrorCode.VALUE, "value could not be represented") from None
    finally:
        loader.dispose()


# ============================================================================================
# Schema validation
# ============================================================================================


def _expect_mapping(value: object, key: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ConfigError(ConfigErrorCode.TYPE, "expected a mapping", key=key)
    return value


def _expect_bool(value: object, key: str) -> bool:
    if type(value) is not bool:
        raise ConfigError(ConfigErrorCode.TYPE, "expected true or false", key=key)
    return value


def _expect_int(value: object, key: str, *, minimum: int, maximum: int) -> int:
    if type(value) is not int:  # bool is a subclass of int: reject it explicitly
        raise ConfigError(ConfigErrorCode.TYPE, "expected an integer", key=key)
    if not minimum <= value <= maximum:
        raise ConfigError(
            ConfigErrorCode.VALUE, f"must be between {minimum} and {maximum}", key=key
        )
    return value


def _expect_str(value: object, key: str) -> str:
    if not isinstance(value, str):
        raise ConfigError(ConfigErrorCode.TYPE, "expected a string", key=key)
    if len(value) > limits.MAX_CONFIG_STRING_CHARS:
        raise ConfigError(ConfigErrorCode.VALUE, "string too long", key=key)
    return value


def _expect_str_list(value: object, key: str) -> list[str]:
    if not isinstance(value, list):
        raise ConfigError(ConfigErrorCode.TYPE, "expected a list", key=key)
    if len(value) > limits.MAX_CONFIG_LIST_ITEMS:
        raise ConfigError(ConfigErrorCode.VALUE, "too many items", key=key)
    return [_expect_str(item, key) for item in value]


def is_rule_selector(value: str) -> bool:
    """``NEX`` + 3 digits (rule id) or ``ASI01``..``ASI10`` (category). No regex (SR-09)."""
    if len(value) == 6 and value.startswith("NEX") and value[3:].isdigit() and value.isascii():
        return True
    if len(value) == 5 and value.startswith("ASI") and value[3:].isdigit() and value.isascii():
        return 1 <= int(value[3:]) <= 10
    return False


def _rule_set(value: object, key: str) -> frozenset[str]:
    items = _expect_str_list(value, key)
    for item in items:
        if not is_rule_selector(item):
            raise ConfigError(ConfigErrorCode.VALUE, "expected NEXnnn or ASI01..ASI10", key=key)
    return frozenset(items)


def validate_document(doc: object) -> ConfigValues:
    """Strict schema check of a constructed YAML document (unknown keys rejected)."""
    if doc is None:
        return ConfigValues()
    top = _expect_mapping(doc, "<root>")
    values: dict[str, Any] = {}
    for section, body in top.items():
        if section not in _SCHEMA:
            raise ConfigError(ConfigErrorCode.UNKNOWN_KEY, "unknown key", key=section)
        if section == "exclude":
            patterns = _expect_str_list(body, KEY_EXCLUDE)
            values["exclude"] = tuple(
                dict.fromkeys(normalise_repo_pattern(p, key=KEY_EXCLUDE) for p in patterns)
            )
            continue
        sub = _expect_mapping(body, section)
        for name, value in sub.items():
            dotted = f"{section}.{name}"
            if name not in _SCHEMA[section]:
                raise ConfigError(ConfigErrorCode.UNKNOWN_KEY, "unknown key", key=dotted)
            if dotted == KEY_FAIL_ON:
                sev = _expect_str(value, dotted)
                if sev not in _SEVERITY_RANK:
                    allowed = ", ".join(SEVERITIES)
                    raise ConfigError(
                        ConfigErrorCode.VALUE, f"expected one of {allowed}", key=dotted
                    )
                values["fail_on"] = sev
            elif dotted == KEY_RULES_ENABLED:
                values["rules_enabled"] = _rule_set(value, dotted)
            elif dotted == KEY_RULES_DISABLED:
                values["rules_disabled"] = _rule_set(value, dotted)
            elif dotted == KEY_AUTO_DETECT:
                values["auto_detect"] = _expect_bool(value, dotted)
            elif dotted == KEY_CROSS_FILE:
                values["cross_file"] = _expect_bool(value, dotted)
            elif dotted == KEY_MAX_FILES:
                values["max_files"] = _expect_int(
                    value, dotted, minimum=1, maximum=limits.HARD_MAX_FILES
                )
            elif dotted == KEY_MAX_FILE_SIZE:
                values["max_file_size"] = _expect_int(
                    value, dotted, minimum=1, maximum=limits.HARD_MAX_FILE_SIZE
                )
    enabled = values.get("rules_enabled", frozenset())
    disabled = values.get("rules_disabled", frozenset())
    if enabled & disabled:
        raise ConfigError(
            ConfigErrorCode.VALUE, "a rule is both enabled and disabled", key=KEY_RULES_DISABLED
        )
    return ConfigValues(**values)


def parse_config_bytes(data: bytes) -> ConfigValues:
    """Parse and validate config bytes. Raises :class:`ConfigError`; never executes anything."""
    if len(data) > limits.MAX_CONFIG_BYTES:
        raise ConfigError(ConfigErrorCode.TOO_LARGE, f"larger than {limits.MAX_CONFIG_BYTES} bytes")
    if b"\x00" in data:
        raise ConfigError(ConfigErrorCode.NOT_UTF8, "NUL byte in config")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ConfigError(ConfigErrorCode.NOT_UTF8, "config is not valid UTF-8") from None
    _check_events(text)
    return validate_document(_construct(text))


# ============================================================================================
# File access
# ============================================================================================


def _read_config_fd(fd: int) -> bytes:
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        raise ConfigError(ConfigErrorCode.NOT_REGULAR_FILE, "config is not a regular file")
    if st.st_size > limits.MAX_CONFIG_BYTES:
        raise ConfigError(ConfigErrorCode.TOO_LARGE, f"larger than {limits.MAX_CONFIG_BYTES} bytes")
    chunks: list[bytes] = []
    remaining = limits.MAX_CONFIG_BYTES + 1
    while remaining > 0:
        chunk = os.read(fd, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    if len(data) > limits.MAX_CONFIG_BYTES:  # file grew after fstat
        raise ConfigError(ConfigErrorCode.TOO_LARGE, f"larger than {limits.MAX_CONFIG_BYTES} bytes")
    return data


def _open_config(path: str, dir_fd: int | None) -> int:
    try:
        return os.open(path, _OPEN_FLAGS, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            raise ConfigError(ConfigErrorCode.SYMLINK, "config file is a symlink") from None
        if isinstance(exc, FileNotFoundError):
            raise
        raise ConfigError(ConfigErrorCode.UNREADABLE, "config file could not be opened") from None


def load_config_file(
    path: str,
    *,
    source: ConfigSource,
    ref: str | None = None,
    dir_fd: int | None = None,
    display_path: str | None = None,
) -> LoadedConfig:
    """Open (no symlinks), size-check, read (bounded) and parse one config file."""
    fd = _open_config(path, dir_fd)
    try:
        data = _read_config_fd(fd)
    finally:
        os.close(fd)
    values = parse_config_bytes(data)
    return LoadedConfig(
        values=values,
        source=source,
        display_path=display_text(display_path if display_path is not None else path),
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
        ref=ref,
    )


def load_repo_config(root: str) -> LoadedConfig | None:
    """Load ``<root>/.nexvul.yml`` as an untrusted layer, or ``None`` if there is none.

    The root is opened as a directory (it is given by the trusted user) and the config is opened
    relative to it with ``O_NOFOLLOW``: a symlinked ``.nexvul.yml`` is a config error (MF-105)
    and its target is never read.
    """
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
    try:
        return load_config_file(
            CONFIG_FILENAME,
            source=ConfigSource.REPO,
            dir_fd=root_fd,
            display_path=CONFIG_FILENAME,
        )
    except FileNotFoundError:
        return None
    finally:
        os.close(root_fd)


# ============================================================================================
# Resolution: tighten-only in CI (DEC-0004 §1, architecture §3.3) - pure functions
# ============================================================================================


def _fmt_items(items: Iterable[str]) -> str:
    return display_text(", ".join(sorted(items)), max_chars=160)


@dataclass
class _Builder:
    cfg: EffectiveConfig
    changes: list[ConfigChange]

    def set(self, key: str, attr: str, value: object, source: ConfigSource) -> None:
        sources = dict(self.cfg.sources)
        prior = sources.get(key, ())
        sources[key] = (*prior, source) if source not in prior else prior
        changes: dict[str, Any] = {attr: value, "sources": sources}
        self.cfg = replace(self.cfg, **changes)

    def note(
        self, key: str, detail: str, source: ConfigSource, status: ChangeStatus, reason: str
    ) -> None:
        self.changes.append(ConfigChange(key, detail, source, status, reason))


def _apply_layer(b: _Builder, layer: LoadedConfig, *, tighten_only: bool) -> None:
    """Apply one layer. When ``tighten_only`` is set, loosening parts are reported, not applied.

    Direction of each key (architecture §3.3):

    ============================  ==================================  ======================
    key                           tightening                          loosening
    ============================  ==================================  ======================
    severity.fail_on              lower threshold                     raise threshold
    rules.enabled                 add selectors                       remove selectors
    rules.disabled                remove selectors                    add selectors
    exclude                       remove patterns                     add patterns
    frameworks.auto_detect        true                                false
    analysis.cross_file           true                                false
    analysis.max_files            raise (<= HARD_MAX_FILES)           lower
    analysis.max_file_size        (repo: never raise)                 lower
    ============================  ==================================  ======================
    """
    v = layer.values
    src = layer.source
    cur = b.cfg
    is_repo = src is ConfigSource.REPO
    loosen_status = ChangeStatus.NOT_APPLIED if tighten_only else ChangeStatus.APPLIED
    reason_ci = "loosening from untrusted repository config in CI mode"
    reason_listed = "loosening honoured (outside CI mode or from a trusted source)"
    reason = reason_ci if tighten_only else reason_listed

    if v.fail_on is not None and v.fail_on != cur.fail_on:
        if _SEVERITY_RANK[v.fail_on] > _SEVERITY_RANK[cur.fail_on]:
            b.note(KEY_FAIL_ON, f"{cur.fail_on} -> {v.fail_on}", src, loosen_status, reason)
            if not tighten_only:
                b.set(KEY_FAIL_ON, "fail_on", v.fail_on, src)
        else:
            b.set(KEY_FAIL_ON, "fail_on", v.fail_on, src)

    if v.rules_enabled is not None and v.rules_enabled != cur.rules_enabled:
        removed = cur.rules_enabled - v.rules_enabled
        if removed:
            b.note(KEY_RULES_ENABLED, f"remove {_fmt_items(removed)}", src, loosen_status, reason)
        new = (cur.rules_enabled | v.rules_enabled) if tighten_only else v.rules_enabled
        if new != cur.rules_enabled:
            b.set(KEY_RULES_ENABLED, "rules_enabled", frozenset(new), src)

    if v.rules_disabled is not None and v.rules_disabled != cur.rules_disabled:
        added = v.rules_disabled - cur.rules_disabled
        if added:
            b.note(KEY_RULES_DISABLED, f"add {_fmt_items(added)}", src, loosen_status, reason)
        new_d = (cur.rules_disabled & v.rules_disabled) if tighten_only else v.rules_disabled
        if new_d != cur.rules_disabled:
            b.set(KEY_RULES_DISABLED, "rules_disabled", frozenset(new_d), src)

    if v.exclude is not None and v.exclude != cur.exclude:
        added_ex = [p for p in v.exclude if p not in cur.exclude]
        if added_ex:
            b.note(KEY_EXCLUDE, f"add {_fmt_items(added_ex)}", src, loosen_status, reason)
        new_ex = tuple(p for p in cur.exclude if p in v.exclude) if tighten_only else v.exclude
        if new_ex != cur.exclude:
            b.set(KEY_EXCLUDE, "exclude", new_ex, src)

    for key, attr in ((KEY_AUTO_DETECT, "auto_detect"), (KEY_CROSS_FILE, "cross_file")):
        new_b: bool | None = getattr(v, attr)
        old_b: bool = getattr(cur, attr)
        if new_b is not None and new_b != old_b:
            if new_b is False:
                b.note(key, "true -> false", src, loosen_status, reason)
                if not tighten_only:
                    b.set(key, attr, new_b, src)
            else:
                b.set(key, attr, new_b, src)

    if v.max_files is not None and v.max_files != cur.max_files:
        if v.max_files < cur.max_files:
            b.note(KEY_MAX_FILES, f"{cur.max_files} -> {v.max_files}", src, loosen_status, reason)
            if not tighten_only:
                b.set(KEY_MAX_FILES, "max_files", v.max_files, src)
        else:
            b.set(KEY_MAX_FILES, "max_files", v.max_files, src)

    if v.max_file_size is not None and v.max_file_size != cur.max_file_size:
        detail = f"{cur.max_file_size} -> {v.max_file_size}"
        if v.max_file_size > cur.max_file_size and is_repo:
            b.note(
                KEY_MAX_FILE_SIZE,
                detail,
                src,
                ChangeStatus.NOT_APPLIED,
                "repository config may not raise resource limits",
            )
        elif v.max_file_size < cur.max_file_size:
            b.note(KEY_MAX_FILE_SIZE, detail, src, loosen_status, reason)
            if not tighten_only:
                b.set(KEY_MAX_FILE_SIZE, "max_file_size", v.max_file_size, src)
        else:
            b.set(KEY_MAX_FILE_SIZE, "max_file_size", v.max_file_size, src)


def resolve_config(
    *,
    repo: LoadedConfig | None,
    trusted: Sequence[LoadedConfig] = (),
    ci: bool,
    defaults: EffectiveConfig = DEFAULTS,
) -> ResolvedConfig:
    """Pure resolution of the effective config (no I/O).

    ``trusted`` layers (e.g. the base-branch config passed with ``--config-base``, user config,
    CLI flags) are applied in order, in full; loosenings they make are still listed with status
    ``applied``. ``repo`` is the scanned tree's own ``.nexvul.yml`` (in CI: the PR head). In CI
    mode only its tightening changes apply and every loosening is reported as ``not_applied``.
    Outside CI mode it applies in full and every loosening is listed as ``applied``.
    """
    b = _Builder(cfg=defaults, changes=[])
    provenance: list[ConfigProvenance] = []
    for layer in trusted:
        if layer.source not in TRUSTED_SOURCES:
            raise ValueError("trusted layers must come from a trusted source")
        _apply_layer(b, layer, tighten_only=False)
        provenance.append(
            ConfigProvenance(layer.source, layer.display_path, layer.sha256, layer.ref)
        )
    if repo is not None:
        if repo.source is not ConfigSource.REPO:
            raise ValueError("repo layer must have source REPO")
        _apply_layer(b, repo, tighten_only=ci)
        provenance.append(ConfigProvenance(repo.source, repo.display_path, repo.sha256, repo.ref))
    return ResolvedConfig(
        effective=b.cfg, changes=tuple(b.changes), config_sources=tuple(provenance), ci=ci
    )


def ci_mode_from_env(env: Mapping[str, str]) -> bool:
    """CI mode is on when ``CI`` or ``GITHUB_ACTIONS`` is ``true`` (architecture §3.3)."""
    return any(env.get(name, "").strip().lower() == "true" for name in ("CI", "GITHUB_ACTIONS"))
