"""Python MCP SDK HTTP client calls with a constant URL (step 4, deliberately narrow).

Recognised only when the callee **resolves through an import** to one of the Python ``mcp`` SDK
HTTP client functions (research §6.1):

* ``mcp.client.streamable_http.streamablehttp_client(url, headers=None, ..., auth=None)`` (v1)
* ``mcp.client.streamable_http.streamable_http_client(url, *, http_client=None, ...)`` (v1.x)
* ``mcp.client.sse.sse_client(url, headers=None, ..., auth=None)``

and the URL is a **string constant** (first positional argument or ``url=``). Anything that is
not literal - a variable, an f-string, ``**kwargs``, ``*args`` - is skipped (a documented false
negative), because the rule prefers precision.

An authentication argument is considered present when the call passes ``headers``, ``auth``,
``http_client`` or ``httpx_client_factory`` (anything but a literal ``None``), or a second
positional argument (``headers`` for the v1 functions). Values are never inspected or copied.

Not recognised (documented): ``langchain_mcp_adapters.MultiServerMCPClient({...})`` (the IR keeps
only a 200-character rendering of a dict literal, not its structure, so a precise check is not
possible yet), ``mcp.Client(...)`` of SDK 2.x (signature unverified), TypeScript clients.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Final

from nexvul.ir.model import CallSite, ConstType, ExprKind, ExprSummary, Location, ModuleIR

HTTP_CLIENT_FUNCTIONS: Final[dict[str, str]] = {
    "mcp.client.streamable_http.streamablehttp_client": "streamablehttp_client",
    "mcp.client.streamable_http.streamable_http_client": "streamable_http_client",
    "mcp.client.sse.sse_client": "sse_client",
}
_AUTH_KEYWORDS: Final = frozenset({"headers", "auth", "http_client", "httpx_client_factory"})


@dataclass(frozen=True)
class McpHttpClientCall:
    path: str
    function: str  # short name, e.g. "streamablehttp_client"
    written: str  # callee as written (untrusted, capped by the parser)
    url: str
    location: Location
    auth_arguments: tuple[str, ...]  # names only
    transport: str  # "http" or "sse"


def _is_none(expr: ExprSummary) -> bool:
    return expr.kind is ExprKind.CONSTANT and expr.const_type is ConstType.NONE


def _const_str(expr: ExprSummary) -> str | None:
    if (
        expr.kind is ExprKind.CONSTANT
        and expr.const_type is ConstType.STR
        and isinstance(expr.value, str)
        and not expr.value_truncated
    ):
        return expr.value
    return None


def _inspect(module: ModuleIR, call: CallSite) -> McpHttpClientCall | None:
    resolved = call.callee.resolved
    if resolved is None or resolved not in HTTP_CLIENT_FUNCTIONS:
        return None
    if any(k.name is None for k in call.keywords) or any(
        a.kind is ExprKind.STARRED for a in call.args
    ):
        return None  # **kwargs / *args: the arguments are not statically known
    url_expr: ExprSummary | None = call.args[0] if call.args else None
    for kw in call.keywords:
        if kw.name == "url":
            url_expr = kw.value
    if url_expr is None:
        return None
    url = _const_str(url_expr)
    if url is None:
        return None
    auth = [kw.name for kw in call.keywords if kw.name in _AUTH_KEYWORDS and not _is_none(kw.value)]
    if len(call.args) > 1 and not _is_none(call.args[1]):
        auth.append("headers (positional)")
    function = HTTP_CLIENT_FUNCTIONS[resolved]
    return McpHttpClientCall(
        path=module.path,
        function=function,
        written=call.callee.written,
        url=url,
        location=call.location,
        auth_arguments=tuple(a for a in auth if a is not None),
        transport="sse" if function == "sse_client" else "http",
    )


def find_http_client_calls(module: ModuleIR) -> Iterator[McpHttpClientCall]:
    """Constant-URL MCP SDK HTTP client calls in one Python module."""
    if not module.ok or module.language != "python":
        return
    for call in module.calls:
        found = _inspect(module, call)
        if found is not None:
            yield found
