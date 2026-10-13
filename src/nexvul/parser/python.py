"""Python front end: source bytes -> :class:`~nexvul.ir.model.ModuleIR` (architecture §5.3-5.4, §6).

Static analysis only (SR-01). The file is decoded exactly as CPython would (PEP 263 cookie, BOM),
checked against per-file limits, parsed with :func:`ast.parse` on **text**, and walked to extract
facts. Nothing is imported, executed or evaluated; ``ast.parse`` only builds a syntax tree.

Order of per-file checks (architecture §5.3): decode -> null bytes -> token-stream nesting
estimate -> ``ast.parse`` -> node count -> fact extraction. Every failure becomes a typed
:class:`~nexvul.ir.model.ParseFailure`; ``RecursionError``, ``MemoryError``, ``SyntaxError`` and
``ValueError`` never escape (SR-05). All walkers use an explicit stack; the only recursion left
(expression rendering and chained-call resolution) is depth-capped by constants in
:mod:`nexvul.core.limits`. ``sys.setrecursionlimit`` is never touched.

This module is designed to run inside a disposable worker process (:mod:`nexvul.core.workers`),
which provides the hard wall-clock and memory bounds that in-process code cannot.
"""

from __future__ import annotations

import ast
import bisect
import builtins
import codecs
import hashlib
import io
import sys
import tokenize
import unicodedata
import warnings
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Final

from nexvul.core import limits
from nexvul.ir.model import (
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
    SuppressionComment,
    SymbolRef,
    failed_module,
)

LANGUAGE: Final = "python"

#: Filename given to ``ast.parse``. A fixed sentinel, never the target path, so audit events and
#: error objects never carry repository paths (MF-161).
AST_FILENAME: Final = "<nexvul-target>"

MODULE_SCOPE: Final = "<module>"

_BIDI_CONTROLS: Final = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
_UTF8_NAMES: Final = frozenset({"utf-8", "utf-8-sig"})
_BUILTIN_NAMES: Final = frozenset(dir(builtins))
_NESTING_MESSAGES: Final = (
    "too many nested",
    "too many levels of indentation",
    "too many statically nested blocks",
    "too complex",
    "nested too deeply",
)
_EXEC_CALLEES: Final = frozenset({"builtins.exec", "builtins.eval", "builtins.compile"})
_IMPORT_CALLEES: Final = frozenset({"builtins.__import__", "importlib.import_module"})
_GETATTR_CALLEES: Final = frozenset(
    {"builtins.getattr", "builtins.setattr", "builtins.hasattr", "builtins.delattr"}
)
_INT64_MIN: Final = -(2**63)
_INT64_MAX: Final = 2**63 - 1


@dataclass(frozen=True)
class ParseLimits:
    """Per-file parse limits (architecture §5.3). Defaults from :mod:`nexvul.core.limits`."""

    max_nesting: int = limits.MAX_NESTING
    max_ast_nodes: int = limits.MAX_AST_NODES
    max_literal_chars: int = limits.MAX_LITERAL_CHARS


class _ParseFailureError(Exception):
    def __init__(self, reason: FailureReason, detail: str) -> None:
        super().__init__(reason.value)
        self.reason = reason
        self.detail = detail


# =============================================================================================
# Paths, decoding and pre-parse checks
# =============================================================================================


def module_name_for(path: str) -> tuple[str, bool]:
    """Derive a dotted module name from a repo-relative path (``a/b/__init__.py`` -> ``a.b``).

    Purely textual; the repo model (architecture §7.1) re-roots names for ``src/`` layouts.
    """
    text = path.replace("\\", "/")
    for suffix in (".py", ".pyi", ".pyw"):
        if text.endswith(suffix):
            text = text[: -len(suffix)]
            break
    parts = [p for p in text.split("/") if p not in ("", ".")]
    is_package = bool(parts) and parts[-1] == "__init__"
    if is_package:
        parts = parts[:-1]
    return ".".join(parts), is_package


def decode_source(data: bytes) -> tuple[str, str, tuple[str, ...]]:
    """Decode like CPython (``tokenize.detect_encoding``: BOM, PEP 263 cookie).

    Returns ``(text, codec_name, notes)``. Raises ``_ParseFailureError`` with
    ``non_utf8_undecodable`` for unknown/invalid cookies and undecodable bytes.
    """
    notes: list[str] = []
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
    except SyntaxError:
        raise _ParseFailureError(
            FailureReason.NON_UTF8_UNDECODABLE,
            "invalid coding declaration, or not UTF-8 without one",
        ) from None
    try:
        text = data.decode(encoding)
        name = codecs.lookup(encoding).name
    except (UnicodeDecodeError, LookupError):
        raise _ParseFailureError(
            FailureReason.NON_UTF8_UNDECODABLE, "bytes not decodable in the declared encoding"
        ) from None
    if data.startswith(codecs.BOM_UTF8):
        notes.append("bom")
    if name not in _UTF8_NAMES:
        notes.append("non_utf8_coding_cookie")
    chars = set(text)
    if chars & _BIDI_CONTROLS:
        notes.append("bidi_control")
    if any(unicodedata.category(c) == "Cf" and c not in _BIDI_CONTROLS for c in chars - {"\ufeff"}):
        notes.append("invisible_format_character")
    return text, name, tuple(notes)


def _tokens(text: str) -> Iterator[tokenize.TokenInfo]:
    return tokenize.generate_tokens(io.StringIO(text).readline)


def check_nesting(text: str, max_nesting: int) -> None:
    """Estimate bracket + indentation nesting from the token stream before ``ast.parse``.

    Raises ``_ParseFailureError(max_nesting)`` when the estimate exceeds ``max_nesting`` or when
    CPython's own tokenizer reports a nesting limit. Other tokenizer errors are left for
    ``ast.parse`` to report, so the classification of ordinary syntax errors stays CPython's.
    """
    depth = 0
    indent = 0
    try:
        for tok in _tokens(text):
            if tok.type == tokenize.OP:
                if tok.string in "([{":
                    depth += 1
                elif tok.string in ")]}":
                    depth = max(0, depth - 1)
            elif tok.type == tokenize.INDENT:
                indent += 1
            elif tok.type == tokenize.DEDENT:
                indent = max(0, indent - 1)
            if depth + indent > max_nesting:
                raise _ParseFailureError(
                    FailureReason.MAX_NESTING,
                    f"nesting exceeds {max_nesting} at line {tok.start[0]}",
                )
    except (SyntaxError, tokenize.TokenError) as exc:
        if _is_nesting_message(str(exc)):
            raise _ParseFailureError(FailureReason.MAX_NESTING, "tokenizer nesting limit") from None
    except RecursionError:  # pragma: no cover - the C tokenizer does not recurse per token
        raise _ParseFailureError(FailureReason.MAX_NESTING, "tokenizer recursion") from None


def _is_nesting_message(message: str) -> bool:
    lowered = message.lower()
    return any(m in lowered for m in _NESTING_MESSAGES)


# Constructs newer than some supported runtime, detected on the token stream only after
# ``ast.parse`` failed (architecture §5.4). (feature description, minimum Python version).
_TSTRING: Final = ("template string literal", (3, 14))
_EXCEPT_NO_PARENS: Final = ("unparenthesised except tuple", (3, 14))
_TYPE_PARAM_DEFAULT: Final = ("type parameter default", (3, 13))


def detect_newer_syntax(
    text: str, runtime: tuple[int, int] | None = None
) -> tuple[str, tuple[int, int]] | None:
    """Return ``(feature, min_version)`` for the first construct the runtime cannot parse.

    Heuristic and conservative: only used to classify a file that already failed to parse as
    ``syntax_unsupported_by_runtime`` instead of ``parse_error``.
    """
    current = runtime or (sys.version_info.major, sys.version_info.minor)
    toks: list[tokenize.TokenInfo] = []
    try:
        for tok in _tokens(text):
            toks.append(tok)
    except (SyntaxError, tokenize.TokenError):
        pass  # analyse the prefix that did tokenize
    for i, tok in enumerate(toks):
        nxt = toks[i + 1] if i + 1 < len(toks) else None
        if (
            current < _TSTRING[1]
            and tok.type == tokenize.NAME
            and tok.string.lower() in ("t", "rt", "tr")
            and nxt is not None
            and nxt.type in _STRING_START_TYPES
            and nxt.start == tok.end
        ):
            return _TSTRING
        if (
            current < _EXCEPT_NO_PARENS[1]
            and tok.type == tokenize.NAME
            and tok.string == "except"
            and _except_tuple_without_parens(toks, i + 1)
        ):
            return _EXCEPT_NO_PARENS
        if (
            current < _TYPE_PARAM_DEFAULT[1]
            and tok.type == tokenize.NAME
            and tok.string in ("def", "class", "type")
            and _type_param_default(toks, i + 1)
        ):
            return _TYPE_PARAM_DEFAULT
    return None


_STRING_START_TYPES: Final = frozenset(
    {tokenize.STRING, getattr(tokenize, "FSTRING_START", tokenize.STRING)}
)


def _except_tuple_without_parens(toks: list[tokenize.TokenInfo], start: int) -> bool:
    depth = 0
    saw_comma = False
    for tok in toks[start:]:
        if tok.type == tokenize.OP:
            if tok.string in "([{":
                depth += 1
            elif tok.string in ")]}":
                depth -= 1
            elif depth == 0 and tok.string == ",":
                saw_comma = True
            elif depth == 0 and tok.string == ":":
                return saw_comma
        elif depth == 0 and (
            (tok.type == tokenize.NAME and tok.string == "as")
            or tok.type in (tokenize.NEWLINE, tokenize.NL)
        ):
            return False
    return False


def _type_param_default(toks: list[tokenize.TokenInfo], start: int) -> bool:
    if start + 1 >= len(toks) or toks[start].type != tokenize.NAME:
        return False
    if toks[start + 1].string != "[":
        return False
    depth = 0
    for tok in toks[start + 1 :]:
        if tok.type != tokenize.OP:
            continue
        if tok.string in "([{":
            depth += 1
        elif tok.string in ")]}":
            depth -= 1
            if depth == 0:
                return False
        elif tok.string == "=" and depth == 1:
            return True
    return False


def parse_tree(text: str, max_nesting: int) -> ast.Module:
    """``ast.parse`` with every failure mapped to a typed reason (SR-05)."""
    if "\x00" in text:
        raise _ParseFailureError(FailureReason.PARSE_ERROR, "null byte in source")
    check_nesting(text, max_nesting)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # SyntaxWarning text could echo source
            return ast.parse(text, filename=AST_FILENAME, mode="exec")
    except SyntaxError as exc:
        if _is_nesting_message(exc.msg or ""):
            raise _ParseFailureError(FailureReason.MAX_NESTING, "parser nesting limit") from None
        newer = detect_newer_syntax(text)
        if newer is not None:
            feature, (major, minor) = newer
            raise _ParseFailureError(
                FailureReason.SYNTAX_UNSUPPORTED_BY_RUNTIME,
                f"{feature} requires Python {major}.{minor}; running "
                f"{sys.version_info.major}.{sys.version_info.minor}",
            ) from None
        line = exc.lineno if isinstance(exc.lineno, int) else 0
        raise _ParseFailureError(
            FailureReason.PARSE_ERROR, f"syntax error at line {line}"
        ) from None
    except RecursionError:
        raise _ParseFailureError(FailureReason.MAX_NESTING, "parser recursion guard") from None
    except MemoryError as exc:
        # CPython reports its own parser-stack guard as MemoryError("... too complex ...").
        if _is_nesting_message(str(exc)):
            raise _ParseFailureError(FailureReason.MAX_NESTING, "parser stack limit") from None
        raise _ParseFailureError(FailureReason.MEMORY_LIMIT, "memory exhausted in parser") from None
    except (ValueError, OverflowError):
        raise _ParseFailureError(FailureReason.PARSE_ERROR, "parser rejected input") from None


def count_nodes(tree: ast.AST, max_nodes: int) -> int:
    """Count AST nodes iteratively; raise ``max_ast_nodes`` as soon as the cap is exceeded."""
    count = 0
    stack: list[ast.AST] = [tree]
    while stack:
        node = stack.pop()
        count += 1
        if count > max_nodes:
            raise _ParseFailureError(FailureReason.MAX_AST_NODES, f"more than {max_nodes} nodes")
        stack.extend(ast.iter_child_nodes(node))
    return count


# =============================================================================================
# Fact extraction
# =============================================================================================


@dataclass(frozen=True)
class _Binding:
    status: ResolutionStatus
    target: str | None


_UNKNOWN: Final = _Binding(ResolutionStatus.DYNAMIC, None)


@dataclass
class _Scope:
    qualname: str
    kind: str  # module | function | class | lambda | comprehension
    parent: _Scope | None  # lookup parent (class scopes are skipped by nested functions)
    env: dict[str, _Binding] = field(default_factory=dict)
    self_name: str | None = None
    class_qualname: str | None = None
    class_attrs: dict[str, _Binding] | None = None

    def lookup(self, name: str) -> _Binding | None:
        scope: _Scope | None = self
        while scope is not None:
            if name in scope.env:
                return scope.env[name]
            scope = scope.parent
        return None


def _loc(node: ast.AST) -> Location:
    line = getattr(node, "lineno", 0) or 0
    col = getattr(node, "col_offset", 0) or 0
    end_line = getattr(node, "end_lineno", None) or line
    end_col = getattr(node, "end_col_offset", None)
    return Location(
        line=line, col=col, end_line=end_line, end_col=col if end_col is None else end_col
    )


def _cap(text: str, n: int = limits.MAX_EXPR_TEXT_CHARS) -> str:
    return text if len(text) <= n else text[: n - 3] + "..."


_BINOPS: Final[dict[type[ast.AST], str]] = {
    ast.Add: "+",
    ast.Sub: "-",
    ast.Mult: "*",
    ast.Div: "/",
    ast.Mod: "%",
    ast.Pow: "**",
    ast.FloorDiv: "//",
    ast.MatMult: "@",
    ast.BitOr: "|",
    ast.BitAnd: "&",
    ast.BitXor: "^",
    ast.LShift: "<<",
    ast.RShift: ">>",
}


def render(node: ast.AST | None, depth: int = 0) -> str:
    """Bounded source-like rendering. Recursion is capped at ``MAX_EXPR_RENDER_DEPTH``."""
    if node is None:
        return ""
    if depth > limits.MAX_EXPR_RENDER_DEPTH:
        return "..."
    d = depth + 1
    out: str
    if isinstance(node, ast.Name):
        out = node.id
    elif isinstance(node, ast.Attribute):
        out = f"{render(node.value, d)}.{node.attr}"
    elif isinstance(node, ast.Call):
        parts = [render(a, d) for a in node.args[:3]]
        parts += [f"{k.arg or '**'}={render(k.value, d)}" for k in node.keywords[:3]]
        more = ", ..." if len(node.args) > 3 or len(node.keywords) > 3 else ""
        out = f"{render(node.func, d)}({', '.join(parts)}{more})"
    elif isinstance(node, ast.Constant):
        value = node.value
        out = repr(value[:40]) if isinstance(value, (str, bytes)) else _const_text(value)
        out = _cap(out, 48)
    elif isinstance(node, ast.JoinedStr):
        out = 'f"..."'
    elif isinstance(node, ast.Subscript):
        out = f"{render(node.value, d)}[{render(node.slice, d)}]"
    elif isinstance(node, ast.BinOp):
        op = _BINOPS.get(type(node.op), "?")
        out = f"{render(node.left, d)} {op} {render(node.right, d)}"
    elif isinstance(node, ast.Starred):
        out = f"*{render(node.value, d)}"
    elif isinstance(node, ast.Await):
        out = f"await {render(node.value, d)}"
    elif isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        inner = ", ".join(render(e, d) for e in node.elts[:4])
        more = ", ..." if len(node.elts) > 4 else ""
        brackets = {ast.Tuple: "()", ast.List: "[]", ast.Set: "{}"}[type(node)]
        out = f"{brackets[0]}{inner}{more}{brackets[1]}"
    elif isinstance(node, ast.Dict):
        out = "{...}" if node.keys else "{}"
    else:
        out = f"<{type(node).__name__}>"
    return _cap(out)


def _const_text(value: object) -> str:
    if value is Ellipsis:
        return "..."
    if isinstance(value, int) and not isinstance(value, bool):
        try:
            return str(value)
        except ValueError:  # pragma: no cover - parser rejects such literals first
            return "<int>"
    return repr(value)


_KIND_BY_TYPE: Final[dict[type[ast.AST], ExprKind]] = {
    ast.Name: ExprKind.NAME,
    ast.Attribute: ExprKind.ATTRIBUTE,
    ast.Call: ExprKind.CALL,
    ast.Constant: ExprKind.CONSTANT,
    ast.JoinedStr: ExprKind.FSTRING,
    ast.List: ExprKind.COLLECTION,
    ast.Tuple: ExprKind.COLLECTION,
    ast.Set: ExprKind.COLLECTION,
    ast.Dict: ExprKind.COLLECTION,
    ast.ListComp: ExprKind.COLLECTION,
    ast.SetComp: ExprKind.COLLECTION,
    ast.DictComp: ExprKind.COLLECTION,
    ast.GeneratorExp: ExprKind.COLLECTION,
    ast.Lambda: ExprKind.LAMBDA,
    ast.Subscript: ExprKind.SUBSCRIPT,
    ast.Starred: ExprKind.STARRED,
    ast.Await: ExprKind.AWAIT,
}

_COMPREHENSIONS: Final = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)


class _Extractor:
    """Single iterative pre-order walk that records facts in source order."""

    def __init__(self, module_name: str, is_package: bool, lim: ParseLimits) -> None:
        self.module_name = module_name
        self.package_parts = module_name.split(".") if module_name else []
        if not is_package and self.package_parts:
            self.package_parts = self.package_parts[:-1]
        self.lim = lim
        self.imports: list[ImportRecord] = []
        self.functions: list[FunctionDecl] = []
        self.classes: list[ClassDecl] = []
        self.calls: list[CallSite] = []
        self.assignments: list[Assignment] = []
        self.returns: list[ReturnFact] = []
        self.strings: list[StringConstant] = []
        self.limited: list[AnalysisLimited] = []
        self.literals_truncated = 0
        self.awaited: set[int] = set()

    # -- naming --------------------------------------------------------------------------------

    def _qualify(self, qualname: str) -> str | None:
        full = f"{self.module_name}.{qualname}" if self.module_name else qualname
        return full if len(full) <= limits.MAX_DOTTED_NAME_CHARS else None

    @staticmethod
    def _join(base: str | None, attrs: list[str]) -> str | None:
        if base is None:
            return None
        full = ".".join([base, *attrs]) if attrs else base
        return full if len(full) <= limits.MAX_DOTTED_NAME_CHARS else None

    def _name_binding(self, name: str, scope: _Scope) -> _Binding:
        found = scope.lookup(name)
        if found is not None:
            return found
        if name in _BUILTIN_NAMES:
            return _Binding(ResolutionStatus.BUILTIN, f"builtins.{name}")
        return _Binding(ResolutionStatus.UNRESOLVED, None)

    def ref(self, node: ast.AST, scope: _Scope, depth: int = 0) -> SymbolRef:
        """Resolve a callee / decorator / base expression. Depth-capped for chained calls."""
        written = render(node)
        if depth > limits.MAX_ATTRIBUTE_CHAIN:
            return SymbolRef(written, None, ResolutionStatus.DYNAMIC)
        if isinstance(node, ast.Name):
            binding = self._name_binding(node.id, scope)
            return self._symbol(written, binding, [])
        if isinstance(node, ast.Attribute):
            attrs: list[str] = []
            cur: ast.AST = node
            while isinstance(cur, ast.Attribute) and len(attrs) <= limits.MAX_ATTRIBUTE_CHAIN:
                attrs.append(cur.attr)
                cur = cur.value
            attrs.reverse()
            if isinstance(cur, ast.Attribute):
                return SymbolRef(written, None, ResolutionStatus.DYNAMIC)
            if isinstance(cur, ast.Name):
                if scope.self_name is not None and cur.id == scope.self_name:
                    return self._self_ref(written, attrs, scope)
                return self._symbol(written, self._name_binding(cur.id, scope), attrs)
            if isinstance(cur, ast.Call):
                inner = self.ref(cur.func, scope, depth + 1)
                if inner.resolved is not None:
                    target = inner.resolved
                    if inner.status is ResolutionStatus.INSTANCE and isinstance(cur.func, ast.Name):
                        target = f"{target}.__call__"
                    resolved = self._join(target, attrs)
                    if resolved is not None:
                        return SymbolRef(written, resolved, ResolutionStatus.INSTANCE)
            return SymbolRef(written, None, ResolutionStatus.DYNAMIC)
        return SymbolRef(written, None, ResolutionStatus.DYNAMIC)

    def _self_ref(self, written: str, attrs: list[str], scope: _Scope) -> SymbolRef:
        attrs_map = scope.class_attrs or {}
        if attrs and attrs[0] in attrs_map:
            return self._symbol(written, attrs_map[attrs[0]], attrs[1:])
        if scope.class_qualname is None:  # pragma: no cover - self_name implies a class
            return SymbolRef(written, None, ResolutionStatus.DYNAMIC)
        base = self._qualify(scope.class_qualname)
        return self._symbol(written, _Binding(ResolutionStatus.LOCAL, base), attrs)

    def _symbol(self, written: str, binding: _Binding, attrs: list[str]) -> SymbolRef:
        if binding.target is None:
            status = (
                ResolutionStatus.UNRESOLVED
                if binding.status is ResolutionStatus.UNRESOLVED
                else ResolutionStatus.DYNAMIC
            )
            return SymbolRef(written, None, status)
        resolved = self._join(binding.target, attrs)
        if resolved is None:
            return SymbolRef(written, None, ResolutionStatus.DYNAMIC)
        return SymbolRef(written, resolved, binding.status)

    def _binding_of_value(self, value: ast.AST | None, scope: _Scope) -> _Binding:
        """What a name is bound to after ``name = value`` (simple intra-module binding)."""
        if isinstance(value, ast.Await):
            value = value.value
        if isinstance(value, ast.Call):
            callee = self.ref(value.func, scope)
            if callee.resolved is None:
                return _UNKNOWN
            target = callee.resolved
            if callee.status is ResolutionStatus.INSTANCE and isinstance(value.func, ast.Name):
                target = f"{target}.__call__"
            return _Binding(ResolutionStatus.INSTANCE, target)
        if isinstance(value, (ast.Name, ast.Attribute)):
            r = self.ref(value, scope)
            return _Binding(r.status, r.resolved) if r.resolved is not None else _UNKNOWN
        return _UNKNOWN

    # -- summaries -----------------------------------------------------------------------------

    def summarise(self, node: ast.AST, scope: _Scope) -> ExprSummary:
        kind = _KIND_BY_TYPE.get(type(node), ExprKind.OTHER)
        text = render(node)
        ref: SymbolRef | None = None
        const_type: ConstType | None = None
        value: str | int | bool | None = None
        truncated = False
        if isinstance(node, (ast.Name, ast.Attribute)):
            ref = self.ref(node, scope)
        elif isinstance(node, ast.Call):
            ref = self.ref(node.func, scope)
        elif isinstance(node, ast.Constant):
            const_type, value, truncated = self._constant(node.value)
        names, names_truncated = _referenced_names(node)
        return ExprSummary(
            kind=kind,
            text=text,
            ref=ref,
            const_type=const_type,
            value=value,
            value_truncated=truncated,
            names=names,
            names_truncated=names_truncated,
        )

    def _constant(self, v: object) -> tuple[ConstType, str | int | bool | None, bool]:
        cap = self.lim.max_literal_chars
        if isinstance(v, str):
            return ConstType.STR, v[:cap], len(v) > cap
        if isinstance(v, bool):
            return ConstType.BOOL, v, False
        if v is None:
            return ConstType.NONE, None, False
        if isinstance(v, int):
            if _INT64_MIN <= v <= _INT64_MAX:
                return ConstType.INT, v, False
            text = _const_text(v)
            return ConstType.INT, text[:cap], len(text) > cap
        if isinstance(v, float):
            return ConstType.FLOAT, repr(v), False
        if isinstance(v, complex):
            return ConstType.COMPLEX, repr(v), False
        if isinstance(v, bytes):
            return ConstType.BYTES, repr(v[:cap]), len(v) > cap
        return ConstType.ELLIPSIS, None, False

    def _keywords(self, keywords: list[ast.keyword], scope: _Scope) -> tuple[Keyword, ...]:
        return tuple(Keyword(name=k.arg, value=self.summarise(k.value, scope)) for k in keywords)

    def _decorators(self, nodes: list[ast.expr], scope: _Scope) -> tuple[Decorator, ...]:
        out: list[Decorator] = []
        for d in nodes:
            if isinstance(d, ast.Call):
                out.append(
                    Decorator(
                        target=self.ref(d.func, scope),
                        is_call=True,
                        args=tuple(self.summarise(a, scope) for a in d.args),
                        keywords=self._keywords(d.keywords, scope),
                        location=_loc(d),
                    )
                )
            else:
                out.append(Decorator(self.ref(d, scope), False, (), (), _loc(d)))
        return tuple(out)

    def _params(self, args: ast.arguments, scope: _Scope) -> tuple[Parameter, ...]:
        out: list[Parameter] = []
        positional = [*args.posonlyargs, *args.args]
        defaults: list[ast.expr | None] = [None] * (len(positional) - len(args.defaults))
        defaults += list(args.defaults)
        for i, (a, default) in enumerate(zip(positional, defaults, strict=True)):
            kind = ParamKind.POSITIONAL_ONLY if i < len(args.posonlyargs) else ParamKind.POSITIONAL
            out.append(self._param(a, kind, default, scope))
        if args.vararg is not None:
            out.append(self._param(args.vararg, ParamKind.VAR_POSITIONAL, None, scope))
        for a, kw_default in zip(args.kwonlyargs, args.kw_defaults, strict=True):
            out.append(self._param(a, ParamKind.KEYWORD_ONLY, kw_default, scope))
        if args.kwarg is not None:
            out.append(self._param(args.kwarg, ParamKind.VAR_KEYWORD, None, scope))
        return tuple(out)

    def _param(
        self, a: ast.arg, kind: ParamKind, default: ast.expr | None, scope: _Scope
    ) -> Parameter:
        return Parameter(
            name=a.arg,
            kind=kind,
            annotation=render(a.annotation) if a.annotation is not None else None,
            default=self.summarise(default, scope) if default is not None else None,
        )

    # -- the walk ------------------------------------------------------------------------------

    def run(self, tree: ast.Module) -> None:
        module_scope = _Scope(qualname=MODULE_SCOPE, kind="module", parent=None)
        # Stack items: (node, scope) to visit, or a zero-arg callable to run (post actions).
        stack: list[tuple[ast.AST, _Scope] | Callable[[], None]] = []
        self._push(stack, list(tree.body), module_scope)
        while stack:
            item = stack.pop()
            if callable(item):
                item()
                continue
            node, scope = item
            self._visit(node, scope, stack)

    @staticmethod
    def _push(
        stack: list[tuple[ast.AST, _Scope] | Callable[[], None]],
        nodes: list[ast.AST],
        scope: _Scope,
    ) -> None:
        """Push so that ``nodes`` are visited in source order."""
        stack.extend((n, scope) for n in reversed(nodes))

    def _visit(
        self,
        node: ast.AST,
        scope: _Scope,
        stack: list[tuple[ast.AST, _Scope] | Callable[[], None]],
    ) -> None:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            self._import(node, scope)
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._function(node, scope, stack)
            return
        if isinstance(node, ast.ClassDef):
            self._class(node, scope, stack)
            return
        if isinstance(node, ast.Lambda):
            inner = _Scope(f"{scope.qualname}.<lambda>", "lambda", _lookup_parent(scope))
            for a in _all_args(node.args):
                inner.env[a.arg] = _UNKNOWN
            self._push(stack, [*node.args.defaults, *_present(node.args.kw_defaults)], scope)
            stack.append((node.body, inner))
            return
        if isinstance(node, _COMPREHENSIONS):
            inner = _Scope(scope.qualname, "comprehension", scope)
            for gen in node.generators:
                for name in _target_names(gen.target):
                    inner.env[name] = _UNKNOWN
            self._push(stack, list(ast.iter_child_nodes(node)), inner)
            return
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            self._assignment(node, scope, stack)
            return
        if isinstance(node, (ast.For, ast.AsyncFor)):
            stack.extend((n, scope) for n in reversed([*node.body, *node.orelse]))
            stack.append(lambda: self._bind_unknown(node.target, scope))
            stack.append((node.iter, scope))
            return
        if isinstance(node, (ast.With, ast.AsyncWith)):
            self._with(node, scope, stack)
            return
        if isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
            scope.env[node.name] = _UNKNOWN
        elif isinstance(node, ast.MatchMapping) and node.rest:
            scope.env[node.rest] = _UNKNOWN
        elif isinstance(node, ast.Return):
            value = self.summarise(node.value, scope) if node.value is not None else None
            self.returns.append(ReturnFact(value, _loc(node), scope.qualname))
        elif isinstance(node, ast.Await):
            self.awaited.add(id(node.value))
        elif isinstance(node, ast.Call):
            self._call(node, scope)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            self._string(node, node.value, scope)
        elif isinstance(node, ast.JoinedStr):
            # Literal parts of an f-string are not separate string constants.
            kids = [v for v in node.values if not isinstance(v, ast.Constant)]
            self._push(stack, list(kids), scope)
            return
        self._push(stack, list(ast.iter_child_nodes(node)), scope)

    def _string(self, node: ast.Constant, value: str, scope: _Scope) -> None:
        cap = self.lim.max_literal_chars
        truncated = len(value) > cap
        if truncated:
            self.literals_truncated += 1
        self.strings.append(
            StringConstant(value[:cap], len(value), truncated, _loc(node), scope.qualname)
        )

    def _call(self, node: ast.Call, scope: _Scope) -> None:
        callee = self.ref(node.func, scope)
        if callee.status is ResolutionStatus.INSTANCE and isinstance(node.func, ast.Name):
            callee = SymbolRef(
                callee.written, self._join(callee.resolved, ["__call__"]), callee.status
            )
        site = CallSite(
            callee=callee,
            args=tuple(self.summarise(a, scope) for a in node.args),
            keywords=self._keywords(node.keywords, scope),
            location=_loc(node),
            scope=scope.qualname,
            awaited=id(node) in self.awaited,
        )
        self.calls.append(site)
        self._limited_for(site, node, scope)

    def _limited_for(self, site: CallSite, node: ast.Call, scope: _Scope) -> None:
        name = site.callee.resolved
        reason: LimitedReason | None = None
        if name in _EXEC_CALLEES:
            reason = LimitedReason.EXEC_OF_COMPUTED
        elif name in _IMPORT_CALLEES and not _is_str_const(node.args[:1]):
            reason = LimitedReason.DYNAMIC_IMPORT
        elif name in _GETATTR_CALLEES and not _is_str_const(node.args[1:2]):
            reason = LimitedReason.GETATTR_COMPUTED
        if reason is not None:
            self.limited.append(AnalysisLimited(reason, _loc(node), scope.qualname))

    def _import(self, node: ast.Import | ast.ImportFrom, scope: _Scope) -> None:
        loc = _loc(node)
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    bound, resolved = alias.asname, alias.name
                else:
                    bound = alias.name.split(".", 1)[0]
                    resolved = bound
                self.imports.append(
                    ImportRecord(
                        alias.name, None, bound, resolved, 0, alias.name, loc, scope.qualname
                    )
                )
                scope.env[bound] = _Binding(ResolutionStatus.IMPORTED, resolved)
            return
        module = self._absolute_module(node.module, node.level)
        if node.level and module is None:
            self.limited.append(
                AnalysisLimited(LimitedReason.RELATIVE_IMPORT_BEYOND_TOP, loc, scope.qualname)
            )
        for alias in node.names:
            if alias.name == "*":
                self.limited.append(AnalysisLimited(LimitedReason.STAR_IMPORT, loc, scope.qualname))
                self.imports.append(
                    ImportRecord(
                        module, "*", None, None, node.level, node.module, loc, scope.qualname
                    )
                )
                continue
            bound = alias.asname or alias.name
            full = self._join(module, [alias.name]) if module else None
            self.imports.append(
                ImportRecord(
                    module,
                    alias.name,
                    bound,
                    full,
                    node.level,
                    node.module,
                    loc,
                    scope.qualname,
                )
            )
            scope.env[bound] = _Binding(ResolutionStatus.IMPORTED, full) if full else _UNKNOWN

    def _absolute_module(self, written: str | None, level: int) -> str | None:
        if level == 0:
            return written
        climb = level - 1
        if climb >= len(self.package_parts):
            return None  # climbs above the top-level package (CPython: ImportError)
        base = self.package_parts[: len(self.package_parts) - climb]
        parts = [*base, *([written] if written else [])]
        return ".".join(parts) or None

    def _function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        scope: _Scope,
        stack: list[tuple[ast.AST, _Scope] | Callable[[], None]],
    ) -> None:
        qual = node.name if scope.kind == "module" else f"{scope.qualname}.{node.name}"
        is_method = scope.kind == "class"
        inner = _Scope(qual, "function", _lookup_parent(scope))
        for a in _all_args(node.args):
            inner.env[a.arg] = _UNKNOWN
        if is_method:
            positional = [*node.args.posonlyargs, *node.args.args]
            if positional:
                inner.self_name = positional[0].arg
            inner.class_qualname = scope.qualname
            inner.class_attrs = scope.class_attrs
        elif scope.self_name is not None:  # nested function inside a method keeps `self`
            inner.self_name = scope.self_name
            inner.class_qualname = scope.class_qualname
            inner.class_attrs = scope.class_attrs
        self.functions.append(
            FunctionDecl(
                name=node.name,
                qualname=qual,
                location=_loc(node),
                is_async=isinstance(node, ast.AsyncFunctionDef),
                is_method=is_method,
                decorators=self._decorators(node.decorator_list, scope),
                params=self._params(node.args, scope),
                returns=render(node.returns) if node.returns is not None else None,
                scope=scope.qualname,
            )
        )
        target = self._qualify(qual)
        scope.env[node.name] = _Binding(ResolutionStatus.LOCAL, target) if target else _UNKNOWN
        self._push(stack, list(node.body), inner)
        outer: list[ast.AST] = [*node.decorator_list, *node.args.defaults]
        outer += _present(node.args.kw_defaults)
        outer += [a.annotation for a in _all_args(node.args) if a.annotation is not None]
        if node.returns is not None:
            outer.append(node.returns)
        outer += list(getattr(node, "type_params", []))
        self._push(stack, outer, scope)

    def _class(
        self,
        node: ast.ClassDef,
        scope: _Scope,
        stack: list[tuple[ast.AST, _Scope] | Callable[[], None]],
    ) -> None:
        qual = node.name if scope.kind == "module" else f"{scope.qualname}.{node.name}"
        inner = _Scope(qual, "class", scope, class_attrs={})
        self.classes.append(
            ClassDecl(
                name=node.name,
                qualname=qual,
                location=_loc(node),
                bases=tuple(self.ref(b, scope) for b in node.bases),
                keywords=self._keywords(node.keywords, scope),
                decorators=self._decorators(node.decorator_list, scope),
                scope=scope.qualname,
            )
        )
        target = self._qualify(qual)
        scope.env[node.name] = _Binding(ResolutionStatus.LOCAL, target) if target else _UNKNOWN
        self._push(stack, list(node.body), inner)
        outer: list[ast.AST] = [*node.decorator_list, *node.bases]
        outer += [k.value for k in node.keywords]
        outer += list(getattr(node, "type_params", []))
        self._push(stack, outer, scope)

    def _assignment(
        self,
        node: ast.Assign | ast.AnnAssign | ast.AugAssign | ast.NamedExpr,
        scope: _Scope,
        stack: list[tuple[ast.AST, _Scope] | Callable[[], None]],
    ) -> None:
        targets: list[ast.expr]
        value: ast.expr | None
        annotation: str | None = None
        if isinstance(node, ast.Assign):
            targets, value, op = list(node.targets), node.value, "="
        elif isinstance(node, ast.AnnAssign):
            targets, value, op = [node.target], node.value, ":" if node.value is None else "="
            annotation = render(node.annotation)
        elif isinstance(node, ast.AugAssign):
            targets, value = [node.target], node.value
            op = _BINOPS.get(type(node.op), "?") + "="
        else:
            targets, value, op = [node.target], node.value, ":="
        self.assignments.append(
            Assignment(
                targets=tuple(render(t) for t in targets),
                value=self.summarise(value, scope) if value is not None else None,
                location=_loc(node),
                scope=scope.qualname,
                operator=op,
                annotation=annotation,
            )
        )
        if isinstance(node, ast.AugAssign) or value is None:
            binding = _UNKNOWN
        else:
            binding = self._binding_of_value(value, scope)
        bind_targets = [] if isinstance(node, ast.AnnAssign) and value is None else targets

        def bind() -> None:
            for t in bind_targets:
                self._bind(t, binding, scope)

        stack.append(bind)
        self._push(stack, list(ast.iter_child_nodes(node)), scope)

    def _with(
        self,
        node: ast.With | ast.AsyncWith,
        scope: _Scope,
        stack: list[tuple[ast.AST, _Scope] | Callable[[], None]],
    ) -> None:
        stack.extend((n, scope) for n in reversed(node.body))
        for item in reversed(node.items):
            if item.optional_vars is not None:
                binding = self._binding_of_value(item.context_expr, scope)
                target = item.optional_vars
                stack.append(self._binder(target, binding, scope))
                stack.append((target, scope))
            stack.append((item.context_expr, scope))

    def _binder(self, target: ast.AST, binding: _Binding, scope: _Scope) -> Callable[[], None]:
        def bind() -> None:
            self._bind(target, binding, scope)

        return bind

    def _bind(self, target: ast.AST, binding: _Binding, scope: _Scope) -> None:
        if isinstance(target, ast.Name):
            scope.env[target.id] = binding
        elif (
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and scope.self_name is not None
            and target.value.id == scope.self_name
            and scope.class_attrs is not None
        ):
            scope.class_attrs[target.attr] = binding
        else:
            self._bind_unknown(target, scope)

    @staticmethod
    def _bind_unknown(target: ast.AST, scope: _Scope) -> None:
        for name in _target_names(target):
            scope.env[name] = _UNKNOWN


def _lookup_parent(scope: _Scope) -> _Scope | None:
    return scope.parent if scope.kind == "class" else scope


def _all_args(args: ast.arguments) -> list[ast.arg]:
    out = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    if args.vararg is not None:
        out.append(args.vararg)
    if args.kwarg is not None:
        out.append(args.kwarg)
    return out


def _present(nodes: list[ast.expr | None]) -> list[ast.AST]:
    return [n for n in nodes if n is not None]


def _target_names(target: ast.AST) -> list[str]:
    """Names bound by an assignment target (tuple/list/starred unpacking), iteratively."""
    names: list[str] = []
    stack = [target]
    while stack:
        node = stack.pop()
        if isinstance(node, ast.Name):
            names.append(node.id)
        elif isinstance(node, (ast.Tuple, ast.List)):
            stack.extend(node.elts)
        elif isinstance(node, ast.Starred):
            stack.append(node.value)
    return names


def _is_str_const(nodes: list[ast.expr]) -> bool:
    return (
        len(nodes) == 1 and isinstance(nodes[0], ast.Constant) and isinstance(nodes[0].value, str)
    )


def _referenced_names(node: ast.AST) -> tuple[tuple[str, ...], bool]:
    """Names read by an expression, bounded by ``MAX_EXPR_VISIT_NODES`` / ``MAX_EXPR_NAMES``."""
    names: list[str] = []
    seen: set[str] = set()
    stack = [node]
    visited = 0
    truncated = False
    while stack:
        cur = stack.pop()
        visited += 1
        if visited > limits.MAX_EXPR_VISIT_NODES:
            truncated = True
            break
        if isinstance(cur, ast.Name):
            if cur.id not in seen:
                if len(names) >= limits.MAX_EXPR_NAMES:
                    truncated = True
                    break
                seen.add(cur.id)
                names.append(cur.id)
            continue
        children = list(ast.iter_child_nodes(cur))
        stack.extend(reversed(children))
    return tuple(names), truncated


# =============================================================================================
# Suppression comments (architecture §11.5, SR-17, T-17)
# =============================================================================================

_SUPPRESSION_PREFIX: Final = "nexvul:"
_NON_CODE_TOKENS: Final = frozenset(
    {
        tokenize.COMMENT,
        tokenize.NL,
        tokenize.NEWLINE,
        tokenize.INDENT,
        tokenize.DEDENT,
        tokenize.ENDMARKER,
        tokenize.ENCODING,
    }
)


def _is_suppression_comment(body: str) -> bool:
    """True when a comment body is aimed at nexvul (``nexvul:`` after optional whitespace).

    Invisible format characters and whitespace before the prefix are skipped for this test only,
    so a comment hiding a bidi override in front of ``nexvul:`` is still recorded and later
    rejected by the supervisor instead of being silently ignored. ``nexvul-expect:`` fixture
    annotations do not match.
    """
    head = "".join(
        ch for ch in body[:64] if not ch.isspace() and unicodedata.category(ch) != "Cf"
    ).casefold()
    return head.startswith(_SUPPRESSION_PREFIX)


def extract_suppression_comments(
    text: str,
    *,
    max_comments: int = limits.MAX_SUPPRESSION_COMMENTS_PER_FILE,
    max_chars: int = limits.MAX_SUPPRESSION_COMMENT_CHARS,
) -> tuple[tuple[SuppressionComment, ...], bool]:
    """Collect ``# nexvul:`` comments from real COMMENT tokens of already-parsed source.

    Returns ``(comments, overflowed)``. A trailing comment targets its own line; a comment on a
    line without code targets the next line that holds code (screen-inventory C03).
    """
    code_lines: set[int] = set()
    found: list[tuple[str, bool, Location, bool]] = []
    overflowed = False
    try:
        for tok in _tokens(text):
            if tok.type == tokenize.COMMENT:
                body = tok.string[1:]
                if not _is_suppression_comment(body):
                    continue
                if len(found) >= max_comments:
                    overflowed = True
                    continue
                line, col = tok.start
                trailing = line in code_lines
                loc = Location(line, col, tok.end[0], tok.end[1])
                found.append((body[:max_chars], len(body) > max_chars, loc, trailing))
            elif tok.type not in _NON_CODE_TOKENS:
                code_lines.update(range(tok.start[0], tok.end[0] + 1))
    except (SyntaxError, tokenize.TokenError):  # pragma: no cover - text already parsed by ast
        return (), False
    ordered = sorted(code_lines)
    comments: list[SuppressionComment] = []
    for body, truncated, loc, trailing in found:
        if trailing:
            target = loc.line
        else:
            index = bisect.bisect_right(ordered, loc.line)
            target = ordered[index] if index < len(ordered) else 0
        comments.append(SuppressionComment(body, truncated, loc, target))
    return tuple(comments), overflowed


# =============================================================================================
# Entry point
# =============================================================================================


def parse_python(data: bytes, path: str, *, parse_limits: ParseLimits | None = None) -> ModuleIR:
    """Turn the bytes of one Python file into IR. Never raises for any input bytes.

    ``path`` is the repo-relative path (data only; it is never opened here).
    """
    lim = parse_limits or ParseLimits()
    module_name, is_package = module_name_for(path)
    sha = hashlib.sha256(data).hexdigest()
    encoding: str | None = None
    notes: tuple[str, ...] = ()
    try:
        text, encoding, notes = decode_source(data)
        tree = parse_tree(text, lim.max_nesting)
        node_count = count_nodes(tree, lim.max_ast_nodes)
        extractor = _Extractor(module_name, is_package, lim)
        extractor.run(tree)
        suppressions, overflowed = extract_suppression_comments(text)
        if overflowed:
            notes = (*notes, "suppression_comments_truncated")
    except _ParseFailureError as exc:
        return failed_module(
            language=LANGUAGE,
            path=path,
            module_name=module_name,
            is_package=is_package,
            reason=exc.reason,
            detail=exc.detail,
            sha256=sha,
            size_bytes=len(data),
            encoding=encoding,
            notes=notes,
        )
    except RecursionError:  # pragma: no cover - walkers are iterative; defence in depth
        return failed_module(
            language=LANGUAGE,
            path=path,
            module_name=module_name,
            is_package=is_package,
            reason=FailureReason.MAX_NESTING,
            detail="recursion guard in IR builder",
            sha256=sha,
            size_bytes=len(data),
            encoding=encoding,
            notes=notes,
        )
    except MemoryError:  # pragma: no cover - exercised only under real memory pressure
        return failed_module(
            language=LANGUAGE,
            path=path,
            module_name=module_name,
            is_package=is_package,
            reason=FailureReason.MEMORY_LIMIT,
            detail="memory exhausted building IR",
            sha256=sha,
            size_bytes=len(data),
            encoding=encoding,
            notes=notes,
        )
    return ModuleIR(
        schema_version=IR_SCHEMA_VERSION,
        language=LANGUAGE,
        path=path,
        module_name=module_name,
        is_package=is_package,
        status=ParseStatus.OK,
        sha256=sha,
        size_bytes=len(data),
        encoding=encoding,
        node_count=node_count,
        literals_truncated=extractor.literals_truncated,
        imports=tuple(extractor.imports),
        functions=tuple(extractor.functions),
        classes=tuple(extractor.classes),
        calls=tuple(extractor.calls),
        assignments=tuple(extractor.assignments),
        returns=tuple(extractor.returns),
        strings=tuple(extractor.strings),
        limited=tuple(extractor.limited),
        suppressions=suppressions,
        notes=notes,
    )
