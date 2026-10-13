"""IR serialisation round-trip and strict decoding (architecture §5.2 IPC, §6; SR-01)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from nexvul.core.completeness import SkipReason
from nexvul.ir import (
    IR_SCHEMA_VERSION,
    AnalysisLimited,
    Assignment,
    CallSite,
    ClassDecl,
    ConstType,
    Decorator,
    ExprKind,
    ExprSummary,
    FailureReason,
    FunctionDecl,
    ImportRecord,
    IRDecodeError,
    Keyword,
    LimitedReason,
    Location,
    ModuleIR,
    Parameter,
    ParamKind,
    ParseStatus,
    ResolutionStatus,
    ReturnFact,
    StringConstant,
    SymbolRef,
    failed_module,
    from_dict,
    module_from_dict,
    module_from_json,
    module_to_json,
    to_dict,
)
from nexvul.ir.codec import loads_strict

LOC = Location(1, 0, 1, 10)


def _full_module() -> ModuleIR:
    ref = SymbolRef("m.invoke", "langchain_openai.ChatOpenAI.invoke", ResolutionStatus.INSTANCE)
    arg = ExprSummary(ExprKind.CONSTANT, "'hi'", None, ConstType.STR, "hi", False, (), False)
    big = ExprSummary(ExprKind.CONSTANT, "1", None, ConstType.INT, 2**62)
    flag = ExprSummary(ExprKind.CONSTANT, "False", None, ConstType.BOOL, False)
    none = ExprSummary(ExprKind.CONSTANT, "None", None, ConstType.NONE, None)
    name = ExprSummary(
        ExprKind.NAME, "q", SymbolRef("q", None, ResolutionStatus.DYNAMIC), names=("q",)
    )
    deco = Decorator(SymbolRef("tool", "x.tool", ResolutionStatus.IMPORTED), True, (arg,), (), LOC)
    return ModuleIR(
        schema_version=IR_SCHEMA_VERSION,
        language="python",
        path="agent/\udcff.py",  # surrogate-escaped non-UTF-8 name must survive JSON
        module_name="agent.x",
        is_package=False,
        status=ParseStatus.OK,
        sha256="ab" * 32,
        size_bytes=10,
        encoding="utf-8",
        node_count=42,
        literals_truncated=1,
        imports=(
            ImportRecord("pkg.mod", "y", "z", "pkg.mod.y", 1, "mod", LOC, "<module>"),
            ImportRecord("os", None, "os", "os", 0, "os", LOC, "<module>"),
        ),
        functions=(
            FunctionDecl(
                "run",
                "Agent.run",
                LOC,
                True,
                True,
                (deco,),
                (Parameter("q", ParamKind.POSITIONAL, "str", arg),),
                "str",
                "Agent",
            ),
        ),
        classes=(
            ClassDecl("Agent", "Agent", LOC, (ref,), (Keyword("metaclass", name),), (), "<module>"),
        ),
        calls=(
            CallSite(
                ref,
                (arg, big),
                (Keyword("verify", flag), Keyword(None, none)),
                LOC,
                "<module>",
                True,
            ),
        ),
        assignments=(Assignment(("m",), name, LOC, "<module>", "=", None),),
        returns=(ReturnFact(None, LOC, "Agent.run"),),
        strings=(StringConstant("x" * 5, 50, True, LOC, "<module>"),),
        limited=(AnalysisLimited(LimitedReason.EXEC_OF_COMPUTED, LOC, "<module>"),),
        notes=("bom",),
    )


def test_round_trip_full_module() -> None:
    module = _full_module()
    data = module_to_json(module)
    data.decode("ascii")  # ensure_ascii: always valid UTF-8, lone surrogates escaped
    assert module_from_json(data) == module
    assert from_dict(ModuleIR, json.loads(data)) == module


def test_round_trip_failed_module() -> None:
    module = failed_module(
        language="python",
        path="a.py",
        module_name="a",
        is_package=False,
        reason=FailureReason.MAX_NESTING,
        detail="nesting exceeds 100 at line 1",
    )
    assert not module.ok
    assert module_from_json(module_to_json(module)) == module


def test_json_contains_no_pickle_and_is_plain_json() -> None:
    data = module_to_json(_full_module())
    assert not data.startswith(b"\x80")  # pickle protocol 2+ header
    assert isinstance(json.loads(data), dict)


def test_failure_reasons_are_skip_reasons() -> None:
    """The supervisor folds FailureReason into the ledger by value."""
    for reason in FailureReason:
        assert SkipReason(reason.value).value == reason.value


def test_to_dict_rejects_non_ir_values() -> None:
    with pytest.raises(TypeError):
        to_dict(1.5)
    with pytest.raises(TypeError):
        to_dict({"a": 1})


def _good() -> dict[str, Any]:
    return json.loads(module_to_json(_full_module()))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.pop("path"),
        lambda d: d.update(extra=1),
        lambda d: d.update(size_bytes=True),  # bool is not int
        lambda d: d.update(size_bytes="10"),
        lambda d: d.update(status="maybe"),
        lambda d: d.update(status=1),
        lambda d: d.update(is_package=0),
        lambda d: d.update(path=None),
        lambda d: d.update(imports={"a": 1}),
        lambda d: d.update(failure=[]),
        lambda d: d["calls"][0].update(args="x"),
        lambda d: d["calls"][0]["args"][0].update(value=[1]),
        lambda d: d["calls"][0]["args"][0].update(value=1.5),
        lambda d: d["calls"][0].update(callee=None),
        lambda d: d.update(schema_version="9.0.0"),
        lambda d: d.update(schema_version=1),
    ],
)
def test_strict_decoder_rejects(mutate: Any) -> None:
    data = _good()
    mutate(data)
    with pytest.raises(IRDecodeError):
        module_from_dict(data)


def test_decoder_rejects_non_object() -> None:
    with pytest.raises(IRDecodeError):
        module_from_dict([1])


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a": 1, "a": 2}',
        b'{"a": NaN}',
        b'{"a": Infinity}',
        b"\xff\xfe",
        b"{not json",
        b"[" * 100_000 + b"]" * 100_000,
    ],
)
def test_loads_strict_rejects(raw: bytes) -> None:
    with pytest.raises(IRDecodeError):
        loads_strict(raw)


def test_module_ok_property() -> None:
    assert _full_module().ok
