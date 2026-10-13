"""Language-neutral per-file IR (architecture §6), Phase 1 subset.

Design rules (architecture §6.4):

* Every type is a **frozen dataclass** built only from ``str``, ``int``, ``bool``, ``None``,
  ``StrEnum``, tuples and other IR dataclasses, so it serialises to plain JSON
  (:mod:`nexvul.ir.codec`) and can be validated strictly when it crosses the worker boundary.
* The schema is **not recursive**: an expression is summarised once (:class:`ExprSummary`), it is
  never stored as a tree. JSON nesting depth is therefore bounded by the schema itself.
* Per-file IR is a pure function of the file bytes, its repo-relative path, the language and
  :data:`IR_SCHEMA_VERSION`. Cross-file resolution is a later pass (architecture §7.1).
* Every string that comes from the scanned repository (names, literals, paths, rendered
  expressions) is **untrusted data**. It is never interpreted, evaluated or rendered as markup;
  reporters must pass it through ``nexvul.core.sanitize`` (T-23).

Deviations from the architecture sketch (§6.1), recorded in the step-2 handoff:

* The file path lives once on :class:`ModuleIR`, not on every node, to keep IR small.
* Phase 1 records *facts* (imports, calls, assignments, declarations, literals) rather than a full
  node graph. Node kinds such as ``Loop`` or ``TryCatch`` are added when a shipping rule needs them
  (architecture §1.3).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

#: Semantic version of the IR JSON shape. Bump the minor version for additive changes and the
#: major version for anything a consumer of an older version would misread.
IR_SCHEMA_VERSION: Final = "0.1.0"

#: Column unit used by every :class:`Location` produced by the Python front end. CPython's
#: ``col_offset`` counts UTF-8 bytes of the decoded line (SR-29: reporters declare columnKind).
COLUMN_UNIT_UTF8_BYTES: Final = "utf8_bytes"


class ParseStatus(StrEnum):
    """Outcome of turning one file into IR."""

    OK = "ok"
    FAILED = "failed"


class FailureReason(StrEnum):
    """Why a file produced no IR. Values equal ``nexvul.core.completeness.SkipReason`` values so
    the supervisor can fold them into the completeness ledger without a translation table."""

    PARSE_ERROR = "parse_error"
    MAX_NESTING = "max_nesting"
    MAX_AST_NODES = "max_ast_nodes"
    MEMORY_LIMIT = "memory_limit"
    NON_UTF8_UNDECODABLE = "non_utf8_undecodable"
    SYNTAX_UNSUPPORTED_BY_RUNTIME = "syntax_unsupported_by_runtime"
    MAX_FILE_SIZE = "max_file_size"
    BINARY = "binary"
    CHANGED_DURING_SCAN = "changed_during_scan"
    OPEN_FAILED = "open_failed"
    PARSER_UNAVAILABLE = "parser_unavailable"


class ResolutionStatus(StrEnum):
    """How a name or dotted reference was resolved inside one file (architecture §6.2 SymbolRef).

    ``resolved_local_shadow`` (§7.1) is assigned later by the repo model, never by a parser.
    """

    IMPORTED = "imported"  # bound by an import; ``resolved`` is the imported dotted name
    LOCAL = "local"  # a function or class defined in this module; ``resolved`` is its qualname
    INSTANCE = "instance"  # attribute of a value produced by calling ``resolved``'s prefix
    BUILTIN = "builtin"  # an unbound name that is a builtin of the running interpreter
    UNRESOLVED = "unresolved"  # a plain name with no visible binding
    DYNAMIC = "dynamic"  # computed reference (subscript, call on unknown value, ...)


class ExprKind(StrEnum):
    """Coarse kind of a summarised expression."""

    NAME = "name"
    ATTRIBUTE = "attribute"
    CALL = "call"
    CONSTANT = "constant"
    FSTRING = "fstring"
    COLLECTION = "collection"  # list, tuple, set, dict and their comprehensions
    LAMBDA = "lambda"
    SUBSCRIPT = "subscript"
    STARRED = "starred"
    AWAIT = "await"
    OTHER = "other"


class ConstType(StrEnum):
    """Type of a literal constant held in :class:`ExprSummary`."""

    STR = "str"
    INT = "int"
    BOOL = "bool"
    NONE = "none"
    FLOAT = "float"  # value kept as text (JSON has no inf/nan)
    COMPLEX = "complex"  # value kept as text
    BYTES = "bytes"  # value kept as (capped) text
    ELLIPSIS = "ellipsis"


class ParamKind(StrEnum):
    POSITIONAL_ONLY = "positional_only"
    POSITIONAL = "positional"
    VAR_POSITIONAL = "var_positional"
    KEYWORD_ONLY = "keyword_only"
    VAR_KEYWORD = "var_keyword"


class LimitedReason(StrEnum):
    """Why static analysis is limited at a location (architecture §6.2 ``AnalysisLimited``)."""

    DYNAMIC_IMPORT = "dynamic_import"  # __import__/importlib.import_module with computed name
    EXEC_OF_COMPUTED = "exec_of_computed"  # exec/eval/compile of anything
    GETATTR_COMPUTED = "getattr_computed"  # getattr/setattr/hasattr with a non-literal name
    STAR_IMPORT = "star_import"  # from x import *
    RELATIVE_IMPORT_BEYOND_TOP = "relative_import_beyond_top"


@dataclass(frozen=True)
class Location:
    """Source span. Lines are 1-based as reported by CPython's tokenizer; columns are 0-based in
    the module's ``column_unit``. ``0`` means "unknown" for nodes CPython gives no position."""

    line: int
    col: int
    end_line: int
    end_col: int


@dataclass(frozen=True)
class SymbolRef:
    """A reference as written plus its in-file resolution.

    ``written`` is a bounded rendering (``"m.invoke"``, ``"OpenAI().chat.create"``);
    ``resolved`` is a dotted name (``"langchain_openai.ChatOpenAI.invoke"``) or ``None``.
    """

    written: str
    resolved: str | None
    status: ResolutionStatus


@dataclass(frozen=True)
class ExprSummary:
    """Bounded, non-recursive summary of one expression (call argument, assigned value, ...).

    * ``text``: rendering capped at ``MAX_EXPR_TEXT_CHARS`` and ``MAX_EXPR_RENDER_DEPTH``.
    * ``ref``: resolution for names, attributes and the callee of a call; ``None`` otherwise.
    * ``const_type`` / ``value``: set only for ``kind == constant``. ``value`` is ``str`` for
      strings (capped at ``MAX_LITERAL_CHARS``) and for float/complex/bytes text, ``int`` for
      ints that fit in 64 bits (else text), ``bool`` for booleans, ``None`` for ``None``.
    * ``names``: local names read by the expression (for taint, architecture §8), capped.
    """

    kind: ExprKind
    text: str
    ref: SymbolRef | None = None
    const_type: ConstType | None = None
    value: str | int | bool | None = None
    value_truncated: bool = False
    names: tuple[str, ...] = ()
    names_truncated: bool = False


@dataclass(frozen=True)
class Keyword:
    """A keyword argument. ``name is None`` means ``**mapping``."""

    name: str | None
    value: ExprSummary


@dataclass(frozen=True)
class CallSite:
    """One call expression. ``scope`` is the qualified name of the enclosing function or class
    (``"<module>"`` at top level). ``awaited`` is true for ``await f(...)``."""

    callee: SymbolRef
    args: tuple[ExprSummary, ...]
    keywords: tuple[Keyword, ...]
    location: Location
    scope: str
    awaited: bool = False


@dataclass(frozen=True)
class ImportRecord:
    """One imported name.

    ``import a.b as c``      -> module="a.b", name=None,  bound="c"
    ``import a.b``           -> module="a.b", name=None,  bound="a"
    ``from .x import y as z``-> module=<resolved absolute>, name="y", bound="z", level=1,
                                written_module="x"
    ``from x import *``      -> name="*", bound=None
    ``resolved`` is the dotted name the bound identifier refers to (``None`` when the relative
    import climbs above the path-derived top-level package).
    """

    module: str | None
    name: str | None
    bound: str | None
    resolved: str | None
    level: int
    written_module: str | None
    location: Location
    scope: str


@dataclass(frozen=True)
class Decorator:
    """A decorator. For ``@app.tool(name="x")`` ``target`` is ``app.tool`` and ``is_call``."""

    target: SymbolRef
    is_call: bool
    args: tuple[ExprSummary, ...]
    keywords: tuple[Keyword, ...]
    location: Location


@dataclass(frozen=True)
class Parameter:
    name: str
    kind: ParamKind
    annotation: str | None
    default: ExprSummary | None


@dataclass(frozen=True)
class FunctionDecl:
    """A function or method. ``qualname`` is dotted within the module (``"Agent.run"``,
    ``"outer.<locals>.inner"``-style nesting is written ``"outer.inner"``)."""

    name: str
    qualname: str
    location: Location
    is_async: bool
    is_method: bool
    decorators: tuple[Decorator, ...]
    params: tuple[Parameter, ...]
    returns: str | None
    scope: str


@dataclass(frozen=True)
class ClassDecl:
    name: str
    qualname: str
    location: Location
    bases: tuple[SymbolRef, ...]
    keywords: tuple[Keyword, ...]
    decorators: tuple[Decorator, ...]
    scope: str


@dataclass(frozen=True)
class Assignment:
    """A binding: ``=``, augmented ``+=``, annotated ``x: T = v`` or walrus ``(x := v)``.

    ``targets`` are rendered targets (``"x"``, ``"self.llm"``, ``"d[...]"``, ``"(a, b)"``).
    ``value`` is ``None`` for an annotation without a value.
    """

    targets: tuple[str, ...]
    value: ExprSummary | None
    location: Location
    scope: str
    operator: str = "="  # "=", "+=", ..., ":=", ":"
    annotation: str | None = None


@dataclass(frozen=True)
class ReturnFact:
    value: ExprSummary | None
    location: Location
    scope: str


@dataclass(frozen=True)
class StringConstant:
    """A string literal, docstrings included. Literal parts of f-strings are not recorded here;
    the f-string is summarised as an :class:`ExprSummary` of kind ``fstring`` where it is used.

    ``value`` is capped at ``MAX_LITERAL_CHARS``; ``length`` is the original length.
    """

    value: str
    length: int
    truncated: bool
    location: Location
    scope: str


@dataclass(frozen=True)
class AnalysisLimited:
    reason: LimitedReason
    location: Location
    scope: str


@dataclass(frozen=True)
class ParseFailure:
    """Why no IR was produced. ``detail`` is composed by nexvul only (line numbers, limit
    values); it never contains file content or parser messages, which may echo source text."""

    reason: FailureReason
    detail: str


@dataclass(frozen=True)
class ModuleIR:
    """Container for one file's IR.

    ``path`` is the repo-relative path as given by discovery (untrusted text; may contain
    surrogate escapes for non-UTF-8 names). ``module_name`` is derived from the path only
    (``a/b/__init__.py`` -> ``a.b``); the repo model re-roots it for ``src/`` layouts (§7.1).
    ``notes`` are trusted codes composed by nexvul (``non_utf8_coding_cookie``, ``bidi_control``,
    ``bom``) - never text from the file.
    """

    schema_version: str
    language: str
    path: str
    module_name: str
    is_package: bool
    status: ParseStatus
    failure: ParseFailure | None = None
    sha256: str = ""
    size_bytes: int = 0
    encoding: str | None = None
    column_unit: str = COLUMN_UNIT_UTF8_BYTES
    node_count: int = 0
    literals_truncated: int = 0
    imports: tuple[ImportRecord, ...] = ()
    functions: tuple[FunctionDecl, ...] = ()
    classes: tuple[ClassDecl, ...] = ()
    calls: tuple[CallSite, ...] = ()
    assignments: tuple[Assignment, ...] = ()
    returns: tuple[ReturnFact, ...] = ()
    strings: tuple[StringConstant, ...] = ()
    limited: tuple[AnalysisLimited, ...] = ()
    notes: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.status is ParseStatus.OK


def failed_module(
    *,
    language: str,
    path: str,
    module_name: str,
    is_package: bool,
    reason: FailureReason,
    detail: str,
    sha256: str = "",
    size_bytes: int = 0,
    encoding: str | None = None,
    notes: tuple[str, ...] = (),
) -> ModuleIR:
    """Build the IR for a file that could not be parsed."""
    return ModuleIR(
        schema_version=IR_SCHEMA_VERSION,
        language=language,
        path=path,
        module_name=module_name,
        is_package=is_package,
        status=ParseStatus.FAILED,
        failure=ParseFailure(reason=reason, detail=detail),
        sha256=sha256,
        size_bytes=size_bytes,
        encoding=encoding,
        notes=notes,
    )
