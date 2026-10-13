"""Python front end: facts extracted into the IR (architecture §6, §7.1 in-file part)."""

from __future__ import annotations

import ast
import codecs
import sys
import textwrap

import pytest

from nexvul.ir import (
    ConstType,
    ExprKind,
    FailureReason,
    LimitedReason,
    ModuleIR,
    ParamKind,
    ResolutionStatus,
    module_from_json,
    module_to_json,
)
from nexvul.parser import python as py
from nexvul.parser.python import ParseLimits, detect_newer_syntax, module_name_for, parse_python


def parse(src: str, path: str = "pkg/sub/mod.py", **kw: int) -> ModuleIR:
    ir = parse_python(textwrap.dedent(src).encode(), path, parse_limits=ParseLimits(**kw))
    assert ir.ok, ir.failure
    assert module_from_json(module_to_json(ir)) == ir  # every parsed module round-trips
    return ir


def callees(ir: ModuleIR) -> dict[str, tuple[str | None, ResolutionStatus]]:
    return {c.callee.written: (c.callee.resolved, c.callee.status) for c in ir.calls}


def test_module_name_for() -> None:
    assert module_name_for("a/b/c.py") == ("a.b.c", False)
    assert module_name_for("a/b/__init__.py") == ("a.b", True)
    assert module_name_for("./x.pyi") == ("x", False)
    assert module_name_for("__init__.py") == ("", True)
    assert module_name_for("noext") == ("noext", False)


def test_imports_and_aliases() -> None:
    ir = parse(
        """
        import os
        import os.path
        import langchain_openai as lo
        import a.b.c as abc
        from openai import OpenAI as Client, AsyncOpenAI
        from __future__ import annotations
        os.system("x")
        os.path.join("a")
        lo.ChatOpenAI()
        abc.f()
        Client().chat.completions.create(model="m")
        AsyncOpenAI()
        """
    )
    bound = {i.bound: i.resolved for i in ir.imports}
    assert bound == {
        "os": "os",
        "lo": "langchain_openai",
        "abc": "a.b.c",
        "Client": "openai.OpenAI",
        "AsyncOpenAI": "openai.AsyncOpenAI",
        "annotations": "__future__.annotations",
    }
    c = callees(ir)
    assert c["os.system"] == ("os.system", ResolutionStatus.IMPORTED)
    assert c["os.path.join"] == ("os.path.join", ResolutionStatus.IMPORTED)
    assert c["lo.ChatOpenAI"] == ("langchain_openai.ChatOpenAI", ResolutionStatus.IMPORTED)
    assert c["abc.f"] == ("a.b.c.f", ResolutionStatus.IMPORTED)
    assert c["Client().chat.completions.create"] == (
        "openai.OpenAI.chat.completions.create",
        ResolutionStatus.INSTANCE,
    )


def test_relative_imports() -> None:
    ir = parse(
        """
        from . import sibling
        from .helpers import load as ld
        from .. import top
        from ...beyond import x
        from .star import *
        """,
        path="pkg/sub/mod.py",
    )
    got = {i.bound: (i.module, i.resolved, i.level) for i in ir.imports}
    assert got["sibling"] == ("pkg.sub", "pkg.sub.sibling", 1)
    assert got["ld"] == ("pkg.sub.helpers", "pkg.sub.helpers.load", 1)
    assert got["top"] == ("pkg", "pkg.top", 2)
    assert got["x"] == (None, None, 3)
    star = [i for i in ir.imports if i.name == "*"]
    assert star and star[0].module == "pkg.sub.star" and star[0].bound is None
    reasons = {f.reason for f in ir.limited}
    assert reasons == {LimitedReason.RELATIVE_IMPORT_BEYOND_TOP, LimitedReason.STAR_IMPORT}


def test_relative_import_from_package_init() -> None:
    ir = parse("from .core import Agent\n", path="pkg/__init__.py")
    assert ir.is_package and ir.module_name == "pkg"
    assert ir.imports[0].resolved == "pkg.core.Agent"
    top = parse("from . import x\n", path="top.py")
    assert top.imports[0].resolved is None


def test_calls_keywords_and_constants() -> None:
    ir = parse(
        """
        import requests
        requests.get(url, timeout=None, verify=False, retries=3, ratio=1.5, data=b"x",
                     big=10**30, c=1j, e=..., huge=123456789012345678901234567890, **extra)
        """
    )
    call = ir.calls[0]
    assert call.callee.resolved == "requests.get"
    assert call.args[0].kind is ExprKind.NAME and call.args[0].names == ("url",)
    kw = {k.name: k.value for k in call.keywords}
    assert kw["timeout"].const_type is ConstType.NONE and kw["timeout"].value is None
    assert kw["verify"].const_type is ConstType.BOOL and kw["verify"].value is False
    assert kw["retries"].value == 3 and kw["retries"].const_type is ConstType.INT
    assert kw["ratio"].const_type is ConstType.FLOAT and kw["ratio"].value == "1.5"
    assert kw["data"].const_type is ConstType.BYTES
    assert kw["c"].const_type is ConstType.COMPLEX
    assert kw["e"].const_type is ConstType.ELLIPSIS
    assert (
        kw["huge"].const_type is ConstType.INT
        and kw["huge"].value == "123456789012345678901234567890"
    )
    assert kw["big"].kind is ExprKind.OTHER
    assert None in kw and kw[None].names == ("extra",)


def test_decorators() -> None:
    ir = parse(
        """
        from mcp.server.fastmcp import FastMCP
        from langchain_core.tools import tool
        import functools
        mcp = FastMCP("srv")

        @mcp.tool(name="delete_file", description="d")
        def delete_file(path: str) -> str:
            return path

        @tool
        @functools.lru_cache(maxsize=None)
        def search(q):
            pass

        @dataclass
        class Cfg:
            pass
        """
    )
    fns = {f.name: f for f in ir.functions}
    d = fns["delete_file"].decorators[0]
    assert d.is_call and d.target.resolved == "mcp.server.fastmcp.FastMCP.tool"
    assert d.target.status is ResolutionStatus.INSTANCE
    assert {k.name for k in d.keywords} == {"name", "description"}
    s = fns["search"].decorators
    assert [x.target.resolved for x in s] == ["langchain_core.tools.tool", "functools.lru_cache"]
    assert [x.is_call for x in s] == [False, True]
    cls = ir.classes[0]
    assert cls.decorators[0].target.status is ResolutionStatus.UNRESOLVED
    # Decorator calls are also call sites.
    assert "mcp.tool" in callees(ir)


def test_intra_module_binding_and_attribute_chains() -> None:
    ir = parse(
        """
        from langchain_openai import ChatOpenAI
        import requests
        m = ChatOpenAI(model="gpt")
        m.invoke("hi")
        alias = m
        alias.batch([])
        get = requests.get
        get("u")
        r = m.invoke("x")
        r.content.strip()
        m("direct")
        m = something_else()
        m.invoke("again")
        a.b.c.d.e()
        x[0].call()
        """
    )
    c = [(x.callee.written, x.callee.resolved, x.callee.status) for x in ir.calls]
    assert ("m.invoke", "langchain_openai.ChatOpenAI.invoke", ResolutionStatus.INSTANCE) in c
    assert ("alias.batch", "langchain_openai.ChatOpenAI.batch", ResolutionStatus.INSTANCE) in c
    assert ("get", "requests.get", ResolutionStatus.IMPORTED) in c
    assert (
        "r.content.strip",
        "langchain_openai.ChatOpenAI.invoke.content.strip",
        ResolutionStatus.INSTANCE,
    ) in c
    assert ("m", "langchain_openai.ChatOpenAI.__call__", ResolutionStatus.INSTANCE) in c
    # Rebinding to something unresolved drops the old binding (no stale resolution).
    assert c[-3] == ("m.invoke", None, ResolutionStatus.DYNAMIC)
    assert c[-2] == ("a.b.c.d.e", None, ResolutionStatus.UNRESOLVED)
    assert c[-1][2] is ResolutionStatus.DYNAMIC
    assert ir.assignments[0].targets == ("m",)
    assert ir.assignments[0].value is not None
    assert ir.assignments[0].value.ref is not None
    assert ir.assignments[0].value.ref.resolved == "langchain_openai.ChatOpenAI"


def test_self_attribute_binding_and_methods() -> None:
    ir = parse(
        """
        from langchain_openai import ChatOpenAI
        class Agent(Base):
            llm = None
            def __init__(self):
                self.llm = ChatOpenAI()
                self.cache = {}
            def run(self, q):
                self.llm.invoke(q)
                self.helper(q)
                def inner():
                    self.llm.stream(q)
                return inner
            @staticmethod
            def nothing():
                pass
        """,
        path="agent.py",
    )
    c = callees(ir)
    assert c["self.llm.invoke"] == ("langchain_openai.ChatOpenAI.invoke", ResolutionStatus.INSTANCE)
    assert c["self.helper"] == ("agent.Agent.helper", ResolutionStatus.LOCAL)
    assert c["self.llm.stream"][0] == "langchain_openai.ChatOpenAI.stream"
    fns = {f.qualname: f for f in ir.functions}
    assert set(fns) == {"Agent.__init__", "Agent.run", "Agent.run.inner", "Agent.nothing"}
    assert fns["Agent.run"].is_method and not fns["Agent.run.inner"].is_method
    assert ir.classes[0].bases[0].status is ResolutionStatus.UNRESOLVED
    scopes = {x.callee.written: x.scope for x in ir.calls}
    assert scopes["self.llm.stream"] == "Agent.run.inner"


def test_local_functions_resolve_to_module_qualname() -> None:
    ir = parse(
        """
        def helper(): pass
        class K: pass
        helper()
        K().go()
        print(len([]))
        undefined_thing()
        """,
        path="app/main.py",
    )
    c = callees(ir)
    assert c["helper"] == ("app.main.helper", ResolutionStatus.LOCAL)
    assert c["K().go"] == ("app.main.K.go", ResolutionStatus.INSTANCE)
    assert c["print"] == ("builtins.print", ResolutionStatus.BUILTIN)
    assert c["undefined_thing"] == (None, ResolutionStatus.UNRESOLVED)


def test_function_parameters_shadow_module_bindings() -> None:
    ir = parse(
        """
        import requests
        def f(requests, *args, k=1, **kw):
            requests.get("x")
        def g(a, /, b=2, *, c):
            pass
        """
    )
    assert callees(ir)["requests.get"] == (None, ResolutionStatus.DYNAMIC)
    params = {p.name: p for f in ir.functions for p in f.params}
    assert params["args"].kind is ParamKind.VAR_POSITIONAL
    assert params["kw"].kind is ParamKind.VAR_KEYWORD
    assert params["k"].kind is ParamKind.KEYWORD_ONLY and params["k"].default is not None
    assert params["a"].kind is ParamKind.POSITIONAL_ONLY
    assert params["b"].default is not None and params["b"].default.value == 2
    assert params["c"].default is None


def test_fstrings_walrus_and_strings() -> None:
    ir = parse(
        '''
        """Module docstring."""
        name = "world"
        prompt = f"Hello {name!r:>10} and {get_user()}"
        if (n := len(prompt)) > 3:
            pass
        '''
    )
    strings = [s.value for s in ir.strings]
    assert "Module docstring." in strings and "world" in strings
    assert not any(s.startswith("Hello") for s in strings)  # f-string parts are not constants
    fassign = next(a for a in ir.assignments if a.targets == ("prompt",))
    assert fassign.value is not None and fassign.value.kind is ExprKind.FSTRING
    assert set(fassign.value.names) == {"name", "get_user"}
    assert "get_user" in callees(ir)
    walrus = next(a for a in ir.assignments if a.operator == ":=")
    assert walrus.targets == ("n",)


def test_string_literal_cap() -> None:
    ir = parse(f"s = {'A' * 50!r}\nt = 'short'\n", max_literal_chars=10)
    big = ir.strings[0]
    assert big.truncated and big.length == 50 and len(big.value) == 10
    assert ir.literals_truncated == 1
    assign = ir.assignments[0].value
    assert assign is not None and assign.value_truncated
    assert (
        parse("b = " + repr(b"B" * 50) + "\n", max_literal_chars=10)
        .assignments[0]
        .value.value_truncated
    )  # type: ignore[union-attr]


def test_match_statement() -> None:
    ir = parse(
        """
        import shutil
        match command:
            case {"action": "delete", "path": p, **rest}:
                shutil.rmtree(p)
            case [first, *others]:
                handle(first)
            case Point(x=0) as pt:
                use(pt)
            case _:
                pass
        """
    )
    c = callees(ir)
    assert c["shutil.rmtree"] == ("shutil.rmtree", ResolutionStatus.IMPORTED)
    assert "handle" in c and "use" in c


def test_async_await_and_with() -> None:
    ir = parse(
        """
        import aiohttp
        async def fetch(url):
            async with aiohttp.ClientSession() as session:
                r = await session.get(url)
                async for chunk in r.content:
                    process(chunk)
            with open(url) as fh:
                fh.read()
            await asyncio.sleep(1)
        """
    )
    fn = ir.functions[0]
    assert fn.is_async
    c = {x.callee.written: x for x in ir.calls}
    assert c["session.get"].callee.resolved == "aiohttp.ClientSession.get"
    assert c["session.get"].awaited
    assert not c["aiohttp.ClientSession"].awaited
    assert c["fh.read"].callee.resolved == "builtins.open.read"
    assert c["asyncio.sleep"].awaited


def test_type_hints() -> None:
    ir = parse(
        """
        from typing import Annotated
        from pydantic import Field
        def f(x: Annotated[int, Field(gt=0)], y: "Forward") -> list[str]:
            z: dict[str, int] = {}
            w: int
            return []
        type Alias = list[int]
        """
    )
    fn = ir.functions[0]
    assert fn.returns == "list[str]"
    assert fn.params[0].annotation is not None and "Annotated" in fn.params[0].annotation
    assert "Field" in callees(ir)
    ann = [a for a in ir.assignments if a.annotation]
    assert {a.operator for a in ann} == {"=", ":"}


def test_lambdas_and_comprehensions() -> None:
    ir = parse(
        """
        import json
        x = 5
        f = lambda x, k=json.dumps({}): x.call()
        out = [json.loads(x) for x in items if x]
        d = {k: v.strip() for k, v in pairs}
        g = (y.go() for y in ys)
        s = {z for z in zs}
        """
    )
    c = [(x.callee.written, x.callee.resolved, x.scope) for x in ir.calls]
    assert ("x.call", None, "<module>.<lambda>") in c
    assert ("json.dumps", "json.dumps", "<module>") in c
    assert ("json.loads", "json.loads", "<module>") in c
    assert ("v.strip", None, "<module>") in c
    lam = next(a for a in ir.assignments if a.targets == ("f",))
    assert lam.value is not None and lam.value.kind is ExprKind.LAMBDA


def test_loops_exceptions_aug_assign_and_returns() -> None:
    ir = parse(
        """
        import os
        for os in []:
            os.remove("x")
        try:
            pass
        except Exception as os:
            os.args
        total = 0
        total += 1
        a, (b, *c) = 1, (2, 3)
        d[0] = f()
        def r():
            return
        def q():
            return compute()
        """
    )
    assert callees(ir)["os.remove"] == (None, ResolutionStatus.DYNAMIC)
    aug = next(a for a in ir.assignments if a.operator == "+=")
    assert aug.targets == ("total",)
    assert {r.scope for r in ir.returns} == {"r", "q"}
    assert any(r.value is None for r in ir.returns)


def test_analysis_limited_facts() -> None:
    ir = parse(
        """
        import importlib
        exec(code)
        eval("1")
        importlib.import_module(name)
        importlib.import_module("fixed")
        __import__("os")
        getattr(obj, "attr")
        getattr(obj, "add_" + kind)(x)
        setattr(obj, name, 1)
        """
    )
    reasons = [f.reason for f in ir.limited]
    assert reasons.count(LimitedReason.EXEC_OF_COMPUTED) == 2
    assert reasons.count(LimitedReason.DYNAMIC_IMPORT) == 1
    assert reasons.count(LimitedReason.GETATTR_COMPUTED) == 2


def test_class_keywords_and_nested_class() -> None:
    ir = parse(
        """
        class Outer(metaclass=Meta):
            class Inner:
                def m(self):
                    self.x()
        """
    )
    assert [c.qualname for c in ir.classes] == ["Outer", "Outer.Inner"]
    assert ir.classes[0].keywords[0].name == "metaclass"
    assert callees(ir)["self.x"] == ("pkg.sub.mod.Outer.Inner.x", ResolutionStatus.LOCAL)


def test_render_bounds() -> None:
    node = ast.parse("f(" * 50 + ")" * 50, mode="eval").body
    text = py.render(node)
    assert "..." in text and len(text) <= 200
    long_call = ast.parse("g(1, 2, 3, 4, a=1, b=2, c=3, d=4)", mode="eval").body
    assert py.render(long_call).endswith(", ...)")
    samples = "[1, 2, 3, 4, 5]", "(a,)", "{1}", "{}", "{1: 2}", "x[1]", "f(*a)", "-x", "a @ b"
    for src in samples:
        assert py.render(ast.parse(src, mode="eval").body)
    assert py.render(None) == ""


def test_referenced_names_are_bounded() -> None:
    src = "f(" + ", ".join(f"v{i}" for i in range(100)) + ")"
    names, truncated = py._referenced_names(ast.parse(src, mode="eval").body)
    assert truncated and len(names) <= 32
    deep = ast.parse("+".join(["a"] * 400), mode="eval").body
    _, truncated2 = py._referenced_names(deep)
    assert truncated2


def test_very_long_identifier_becomes_dynamic() -> None:
    long = "x" * 2000
    ir = parse(f"import {long}\n{long}.go()\n")
    assert ir.calls[0].callee.resolved is None
    assert ir.calls[0].callee.status is ResolutionStatus.DYNAMIC
    ir2 = parse(f"def {long}(): pass\nclass {long.upper()}: pass\n{long}()\n")
    assert ir2.calls[0].callee.status is ResolutionStatus.DYNAMIC


def test_long_attribute_chain_is_dynamic() -> None:
    chain = "a" + ".b" * 40
    ir = parse(f"import a\n{chain}()\n")
    assert ir.calls[0].callee.status is ResolutionStatus.DYNAMIC
    calls = "x" + ".y()" * 40
    ir2 = parse(f"import x\n{calls}\n")
    assert ir2.calls[0].callee.status is ResolutionStatus.DYNAMIC


# ---- decoding notes ------------------------------------------------------------------------


def test_decoding_notes() -> None:
    bom = parse_python(codecs.BOM_UTF8 + b"x = 1\n", "a.py")
    assert bom.ok and "bom" in bom.notes and bom.encoding == "utf-8-sig"
    latin = parse_python(b"# -*- coding: latin-1 -*-\nx = '\xff'\n", "a.py")
    assert latin.ok and "non_utf8_coding_cookie" in latin.notes
    assert latin.strings[0].value == "\xff"
    bidi = parse_python("s = '\u202e evil'\n".encode(), "a.py")
    assert "bidi_control" in bidi.notes
    zw = parse_python("s = 'a\u200bb'\n".encode(), "a.py")
    assert "invisible_format_character" in zw.notes


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (b"x = '\xff\xfe'\n", FailureReason.NON_UTF8_UNDECODABLE),
        (b"# coding: utf-8\nx = '\xff'\n", FailureReason.NON_UTF8_UNDECODABLE),
        (b"# coding: nope-42\nx = 1\n", FailureReason.NON_UTF8_UNDECODABLE),
        (b"# coding: rot13\nx = 1\n", FailureReason.NON_UTF8_UNDECODABLE),
        (b"x = 1\n\x00\n", FailureReason.PARSE_ERROR),
        (b"def (:\n", FailureReason.PARSE_ERROR),
        (b"x = 1" + b"0" * 10_000 + b"\n", FailureReason.PARSE_ERROR),
    ],
)
def test_typed_failures(data: bytes, reason: FailureReason) -> None:
    ir = parse_python(data, "a.py")
    assert not ir.ok and ir.failure is not None
    assert ir.failure.reason is reason
    assert ir.sha256 and ir.size_bytes == len(data)


def test_failure_detail_never_echoes_source() -> None:
    secret = "sk-SECRETMARKER"
    ir = parse_python(f"x = {secret} = = (\n".encode(), "a.py")
    assert ir.failure is not None
    assert secret not in ir.failure.detail and "SECRETMARKER" not in module_to_json(ir).decode()


# ---- newer-syntax detection ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("src", "runtime", "expected"),
    [
        ("x = t'hi {a}'\n", (3, 13), (3, 14)),
        ("x = rt'hi'\n", (3, 12), (3, 14)),
        ("x = t 'hi'\n", (3, 13), None),
        ("x = t'hi'\n", (3, 14), None),
        ("try:\n  pass\nexcept A, B:\n  pass\n", (3, 13), (3, 14)),
        ("try:\n  pass\nexcept (A, B) as e:\n  pass\n", (3, 13), None),
        ("try:\n  pass\nexcept A as e:\n  pass\n", (3, 13), None),
        ("try:\n  pass\nexcept A\n", (3, 13), None),
        ("try:\n  pass\nexcept f(a, b):\n  pass\n", (3, 13), None),
        ("def f[T = int](x): pass\n", (3, 12), (3, 13)),
        ("class C[T = int]: pass\n", (3, 12), (3, 13)),
        ("def f[T: (int, str)](x): pass\n", (3, 12), None),
        ("def f(x=1): pass\n", (3, 12), None),
        ("type\n", (3, 12), None),
        ("def f\n", (3, 12), None),
        ("x = (\n", (3, 12), None),
    ],
)
def test_detect_newer_syntax(
    src: str, runtime: tuple[int, int], expected: tuple[int, int] | None
) -> None:
    found = detect_newer_syntax(src, runtime)
    assert (found[1] if found else None) == expected


def test_newer_syntax_is_classified_on_this_runtime() -> None:
    ir = parse_python(b"name = 'x'\nmsg = t'hello {name}'\n", "a.py")
    if sys.version_info >= (3, 14):
        assert ir.ok
    else:
        assert ir.failure is not None
        assert ir.failure.reason is FailureReason.SYNTAX_UNSUPPORTED_BY_RUNTIME
        assert "3.14" in ir.failure.detail


# ---- limits and iterative walkers ----------------------------------------------------------


def test_node_limit() -> None:
    ir = parse_python(
        b"x = [" + b"1, " * 1000 + b"]\n", "a.py", parse_limits=ParseLimits(max_ast_nodes=500)
    )
    assert ir.failure is not None and ir.failure.reason is FailureReason.MAX_AST_NODES


def test_nesting_limit_is_configurable() -> None:
    src = b"x = " + b"(" * 20 + b"1" + b")" * 20 + b"\n"
    assert parse_python(src, "a.py").ok
    ir = parse_python(src, "a.py", parse_limits=ParseLimits(max_nesting=10))
    assert ir.failure is not None and ir.failure.reason is FailureReason.MAX_NESTING


def _deep_binop(depth: int) -> ast.Module:
    expr: ast.expr = ast.Constant(1)
    for _ in range(depth):
        expr = ast.BinOp(left=expr, op=ast.Add(), right=ast.Constant(1))
    call = ast.Call(func=ast.Name("f", ast.Load()), args=[expr], keywords=[])
    # No ast.fix_missing_locations: it is itself recursive. Positions default to 0 in the IR.
    return ast.Module(
        body=[ast.Assign(targets=[ast.Name("x", ast.Store())], value=call)], type_ignores=[]
    )


def test_walkers_are_iterative_on_200k_deep_tree() -> None:
    """MF-16: a tree far deeper than the recursion limit is walked without RecursionError."""
    tree = _deep_binop(200_000)
    assert py.count_nodes(tree, 10_000_000) > 600_000
    extractor = py._Extractor("m", False, ParseLimits())
    extractor.run(tree)
    assert extractor.calls[0].callee.written == "f"
    assert extractor.calls[0].args[0].names_truncated  # visit cap reached, flagged
    assert len(extractor.calls[0].args[0].text) <= 200
    with pytest.raises(py._ParseFailureError):
        py.count_nodes(tree, 1000)


def test_instance_call_results_and_plain_with() -> None:
    ir = parse(
        """
        from langchain_openai import ChatOpenAI
        m = ChatOpenAI()
        out = m("q")
        out.content.strip()
        m("q").content
        ChatOpenAI()().run()
        with lock:
            go()
        """
    )
    c = callees(ir)
    assert c["out.content.strip"][0] == "langchain_openai.ChatOpenAI.__call__.content.strip"
    assert c["go"] == (None, ResolutionStatus.UNRESOLVED)
    assert c["ChatOpenAI()().run"] == (None, ResolutionStatus.DYNAMIC)


def test_deep_indentation_in_process() -> None:
    src = "".join(" " * i + "if x:\n" for i in range(150)) + " " * 150 + "pass\n"
    ir = parse_python(src.encode(), "a.py")
    assert ir.failure is not None and ir.failure.reason is FailureReason.MAX_NESTING
