"""JSON encoding and strict decoding of the IR (architecture §5.2 IPC, §6.4; SR-01).

The decoder is also the supervisor's schema check for what a parse worker sends back, so it is
strict: exact key sets, exact primitive types (``bool`` is not accepted for ``int``), known enum
values only, a supported schema major version, no ``NaN``/``Infinity`` and no duplicate keys.
Nothing here uses ``pickle``; only ``json`` is used.

The IR schema is not recursive (see :mod:`nexvul.ir.model`), so the decoder's own recursion is
bounded by the schema depth (a handful of levels), whatever the input. Decoders are compiled once
per type, because the supervisor decodes every worker result on its single thread.
"""

from __future__ import annotations

import dataclasses
import json
import types
import typing
from collections.abc import Callable
from enum import StrEnum
from functools import cache
from typing import Any, Final, NoReturn, Union

from nexvul.ir.model import IR_SCHEMA_VERSION, ModuleIR

_SUPPORTED_MAJOR: Final = IR_SCHEMA_VERSION.split(".", 1)[0]


class IRDecodeError(ValueError):
    """The JSON is not a valid IR document. The message is composed by nexvul only."""


def to_dict(obj: Any) -> Any:
    """Convert an IR object to JSON-ready builtins (dicts, lists, str, int, bool, None)."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: to_dict(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
    if isinstance(obj, StrEnum):
        return obj.value
    if isinstance(obj, tuple):
        return [to_dict(item) for item in obj]
    if obj is None or isinstance(obj, (str, int)):
        return obj
    raise TypeError(f"not an IR value: {type(obj).__name__}")


def module_to_json(module: ModuleIR) -> bytes:
    """Serialise one :class:`ModuleIR` as compact UTF-8 JSON.

    ``ensure_ascii=True`` keeps lone surrogates (non-UTF-8 file names, surrogate-escaped text)
    representable as ``\\udcxx`` escapes, so the output is always valid UTF-8.
    """
    return json.dumps(
        to_dict(module), ensure_ascii=True, allow_nan=False, separators=(",", ":")
    ).encode("ascii")


def _reject_constant(name: str) -> Any:
    raise IRDecodeError("non-finite number in IR JSON")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise IRDecodeError("duplicate key in IR JSON")
        out[key] = value
    return out


def loads_strict(data: bytes) -> Any:
    """Parse JSON bytes with duplicate-key and non-finite-number rejection.

    Raises :class:`IRDecodeError` for any malformed input, including nesting deep enough to hit
    the interpreter's recursion guard inside the C JSON scanner.
    """
    try:
        text = data.decode("utf-8")
        return json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)
    except IRDecodeError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError, MemoryError) as exc:
        raise IRDecodeError(f"malformed IR JSON ({type(exc).__name__})") from None


Decoder = Callable[[Any], Any]


def _fail(message: str) -> NoReturn:
    raise IRDecodeError(message)


def _str(value: Any) -> Any:
    return value if isinstance(value, str) else _fail("expected string")


def _bool(value: Any) -> Any:
    return value if isinstance(value, bool) else _fail("expected boolean")


def _int(value: Any) -> Any:
    return value if type(value) is int else _fail("expected integer")


_PRIMITIVES: Final[dict[Any, Decoder]] = {str: _str, bool: _bool, int: _int}


@cache
def _decoder(tp: Any) -> Decoder:
    """Build (once per type) a strict decoder for one IR type annotation."""
    if tp in _PRIMITIVES:
        return _PRIMITIVES[tp]
    origin = typing.get_origin(tp)
    if origin in (Union, types.UnionType):
        args = typing.get_args(tp)
        nullable = type(None) in args
        options = [_decoder(a) for a in args if a is not type(None)]

        def union(value: Any) -> Any:
            if value is None:
                return None if nullable else _fail("null not allowed")
            for option in options:
                try:
                    return option(value)
                except IRDecodeError:
                    continue
            _fail("value does not match any allowed type")

        return union
    if origin is tuple:
        item_tp, ellipsis = typing.get_args(tp)
        if ellipsis is not Ellipsis:  # pragma: no cover - schema only uses tuple[X, ...]
            raise TypeError("IR tuples must be homogeneous")
        item = _decoder(item_tp)

        def array(value: Any) -> Any:
            if not isinstance(value, list):
                _fail("expected array")
            return tuple(item(v) for v in value)

        return array
    if isinstance(tp, type) and issubclass(tp, StrEnum):
        members = {m.value: m for m in tp}

        def enum(value: Any) -> Any:
            if not isinstance(value, str) or value not in members:
                _fail(f"invalid {tp.__name__} value")
            return members[value]

        return enum
    if isinstance(tp, type) and dataclasses.is_dataclass(tp):
        return _dataclass_decoder(tp)
    raise TypeError(f"unsupported IR type: {tp!r}")  # pragma: no cover - schema bug


def _dataclass_decoder(cls: type[Any]) -> Decoder:
    hints = typing.get_type_hints(cls)
    names = tuple(f.name for f in dataclasses.fields(cls))
    keyset = frozenset(names)
    fields = [(name, _decoder(hints[name])) for name in names]

    def decode(value: Any) -> Any:
        if not isinstance(value, dict):
            _fail(f"{cls.__name__}: expected object")
        if value.keys() != keyset:
            _fail(f"{cls.__name__}: unexpected or missing keys")
        return cls(**{name: dec(value[name]) for name, dec in fields})

    return decode


def from_dict[T](cls: type[T], value: Any) -> T:
    """Strictly decode builtins produced by :func:`to_dict` back into ``cls``."""
    result: T = _decoder(typing.cast(Any, cls))(value)
    return result


def module_from_dict(value: Any) -> ModuleIR:
    """Decode a :class:`ModuleIR`, checking the schema major version first."""
    if not isinstance(value, dict):
        raise IRDecodeError("ModuleIR: expected object")
    version = value.get("schema_version")
    if not isinstance(version, str) or version.split(".", 1)[0] != _SUPPORTED_MAJOR:
        raise IRDecodeError("ModuleIR: unsupported schema_version")
    return from_dict(ModuleIR, value)


def module_from_json(data: bytes) -> ModuleIR:
    return module_from_dict(loads_strict(data))
