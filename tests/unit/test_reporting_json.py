"""JSON reporter: versioned schema, completeness block, provenance, golden file (J01, SR-18/27)."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

import pytest
from result_factory import SCENARIOS, t04

from nexvul.findings.model import REPORT_SCHEMA_VERSION
from nexvul.reporting.json_report import (
    UNTRUSTED_FIELDS,
    is_nexvul_report,
    render_json,
    report_dict,
)

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "src/nexvul/schemas/report-1.0.0.json"
GOLDEN = Path(__file__).resolve().parents[1] / "golden" / "json"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

_TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "boolean": bool,
    "null": type(None),
}


def _is_type(value: Any, name: str) -> bool:
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, int | float) and not isinstance(value, bool)
    return isinstance(value, _TYPES[name])


def validate(value: Any, schema: dict[str, Any], path: str = "$") -> list[str]:
    """Subset of JSON Schema 2020-12 used by the shipped schema (no external dependency)."""
    errors: list[str] = []
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_is_type(value, t) for t in types):
            return [f"{path}: expected {types}, got {type(value).__name__}"]
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: {value!r} not in enum")
    if "pattern" in schema and isinstance(value, str) and not re.search(schema["pattern"], value):
        errors.append(f"{path}: {value!r} does not match {schema['pattern']}")
    if "minimum" in schema and isinstance(value, int) and value < schema["minimum"]:
        errors.append(f"{path}: below minimum")
    if isinstance(value, dict):
        props = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: missing {key}")
        for key, item in value.items():
            if key in props:
                errors += validate(item, props[key], f"{path}.{key}")
            elif schema.get("additionalProperties") is False:
                errors.append(f"{path}: unexpected key {key}")
            elif isinstance(schema.get("additionalProperties"), dict):
                errors += validate(item, schema["additionalProperties"], f"{path}.{key}")
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{path}: too few items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{path}: too many items")
        for i, item in enumerate(value):
            errors += validate(item, schema.get("items", {}), f"{path}[{i}]")
    return errors


def test_validator_catches_errors() -> None:
    bad = report_dict(t04())
    del bad["completeness"]
    bad["findings"][0]["severity"] = "huge"
    bad["extra"] = 1
    errors = validate(bad, SCHEMA)
    assert any("missing completeness" in e for e in errors)
    assert any("not in enum" in e for e in errors)
    assert any("unexpected key extra" in e for e in errors)


@pytest.mark.parametrize("scenario", list(SCENARIOS))
def test_every_scenario_validates_against_shipped_schema(scenario: str) -> None:
    for pretty in (True, False):
        data = json.loads(render_json(SCENARIOS[scenario](), pretty=pretty))
        assert validate(data, SCHEMA) == []


def test_schema_version_and_required_completeness() -> None:
    assert "completeness" in SCHEMA["required"]
    data = report_dict(t04())
    assert data["nexvul"]["schema_version"] == REPORT_SCHEMA_VERSION
    keys = list(data)
    order = ["nexvul", "scan", "completeness", "summary", "findings", "suppressed"]
    assert [k for k in keys if k in order] == order  # J01 key order
    assert data["summary"]["exit_code"] == 1
    assert data["summary"]["by_severity"] == {
        "critical": 1,
        "high": 2,
        "medium": 1,
        "low": 1,
        "info": 0,
    }
    assert data["suppressed"][0]["suppressed"] is True
    assert data["completeness"]["suppressed"]["inline"] == 1
    assert data["config"]["sources"][0]["source"] == "repo"
    assert data["scan"]["target"] == "my-agent-project"  # basename only, no absolute path
    assert set(UNTRUSTED_FIELDS) <= set(data["untrusted_fields"])


def test_pretty_and_compact() -> None:
    assert "\n  " in render_json(t04(), pretty=True)
    compact = render_json(t04(), pretty=False)
    assert compact.count("\n") == 1 and compact.endswith("\n")


def test_is_nexvul_report() -> None:
    assert is_nexvul_report(render_json(t04(), pretty=True).encode()[:256])
    assert is_nexvul_report(render_json(t04(), pretty=False).encode()[:256])
    assert not is_nexvul_report(b'{"other": 1}')
    assert not is_nexvul_report(b"# README\n")


def test_json_golden() -> None:
    text = render_json(SCENARIOS["T17-ci"](), pretty=True)
    path = GOLDEN / "T17-ci.json"
    if os.environ.get("NEXVUL_UPDATE_GOLDEN") == "1":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    assert json.loads(text) == json.loads(path.read_text(encoding="utf-8"))
    assert text.encode("utf-8").decode("utf-8") == text
