"""A small JSON Schema draft-04 validator for the vendored SARIF 2.1.0 schema (no dependency).

Implements every keyword the official SARIF schema uses: ``$ref`` (local ``#/definitions/...``),
``type``, ``enum``, ``pattern``, ``format`` (``uri``, ``uri-reference``, ``date-time``),
``minimum``, ``maximum``, ``minItems``, ``uniqueItems``, ``items``, ``properties``, ``required``,
``additionalProperties``, ``anyOf``, ``oneOf``. Keywords it does not know raise, so the validator
cannot silently pass a schema it does not understand.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlsplit

_KNOWN = frozenset(
    {
        "$schema",
        "id",
        "title",
        "description",
        "default",
        "definitions",
        "$ref",
        "type",
        "enum",
        "pattern",
        "format",
        "minimum",
        "maximum",
        "minItems",
        "uniqueItems",
        "items",
        "properties",
        "required",
        "additionalProperties",
        "anyOf",
        "oneOf",
    }
)

_DATE_TIME = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})", flags=re.ASCII
)


def _is_type(value: Any, name: str) -> bool:
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, int | float) and not isinstance(value, bool)
    if name == "boolean":
        return isinstance(value, bool)
    if name == "null":
        return value is None
    return isinstance(value, {"object": dict, "array": list, "string": str}[name])


def _format_ok(value: str, fmt: str) -> bool:
    if fmt == "date-time":
        return _DATE_TIME.fullmatch(value) is not None
    if any(ch.isspace() or ch in '<>"{}|^`' for ch in value):
        return False
    if fmt == "uri":
        parts = urlsplit(value)
        return (
            bool(parts.scheme)
            and re.fullmatch(r"[A-Za-z][A-Za-z0-9+.\-]*", parts.scheme) is not None
        )
    return fmt == "uri-reference"


class Draft04:
    def __init__(self, schema: dict[str, Any]) -> None:
        self.root = schema

    def _resolve(self, ref: str) -> dict[str, Any]:
        if not ref.startswith("#/"):
            raise ValueError(f"only local refs are supported: {ref}")
        node: Any = self.root
        for part in ref[2:].split("/"):
            node = node[part]
        return dict(node)

    def errors(
        self, value: Any, schema: dict[str, Any] | None = None, path: str = "$"
    ) -> list[str]:
        schema = self.root if schema is None else schema
        unknown = set(schema) - _KNOWN
        if unknown:
            raise ValueError(f"unsupported keywords {sorted(unknown)} at {path}")
        if "$ref" in schema:
            return self.errors(value, self._resolve(schema["$ref"]), path)
        out: list[str] = []
        if "type" in schema:
            types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
            if not any(_is_type(value, t) for t in types):
                return [f"{path}: expected {types}, got {type(value).__name__}"]
        if "enum" in schema and value not in schema["enum"]:
            out.append(f"{path}: {value!r} not in enum")
        if isinstance(value, str):
            if "pattern" in schema and not re.search(schema["pattern"], value):
                out.append(f"{path}: {value!r} does not match {schema['pattern']}")
            if "format" in schema and not _format_ok(value, schema["format"]):
                out.append(f"{path}: {value!r} is not a valid {schema['format']}")
        if _is_type(value, "number"):
            if "minimum" in schema and value < schema["minimum"]:
                out.append(f"{path}: {value} below minimum {schema['minimum']}")
            if "maximum" in schema and value > schema["maximum"]:
                out.append(f"{path}: {value} above maximum {schema['maximum']}")
        if isinstance(value, list):
            if "minItems" in schema and len(value) < schema["minItems"]:
                out.append(f"{path}: fewer than {schema['minItems']} items")
            if schema.get("uniqueItems"):
                seen = [json.dumps(v, sort_keys=True) for v in value]
                if len(set(seen)) != len(seen):
                    out.append(f"{path}: items are not unique")
            if isinstance(schema.get("items"), dict):
                for i, item in enumerate(value):
                    out += self.errors(item, schema["items"], f"{path}[{i}]")
        if isinstance(value, dict):
            props = schema.get("properties", {})
            for key in schema.get("required", []):
                if key not in value:
                    out.append(f"{path}: missing {key}")
            extra = schema.get("additionalProperties", True)
            for key, item in value.items():
                if key in props:
                    out += self.errors(item, props[key], f"{path}.{key}")
                elif extra is False:
                    out.append(f"{path}: unexpected key {key}")
                elif isinstance(extra, dict):
                    out += self.errors(item, extra, f"{path}.{key}")
        if "anyOf" in schema and not any(not self.errors(value, s, path) for s in schema["anyOf"]):
            out.append(f"{path}: matches none of anyOf")
        if "oneOf" in schema:
            matches = sum(1 for s in schema["oneOf"] if not self.errors(value, s, path))
            if matches != 1:
                out.append(f"{path}: matches {matches} of oneOf (need exactly 1)")
        return out
