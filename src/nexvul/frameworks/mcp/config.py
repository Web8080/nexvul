"""Recogniser for MCP client configuration files (architecture §7.3; research protocols/mcp.md §5).

Input: the IR of one JSON/JSONC file (:class:`~nexvul.ir.model.ConfigDocument`), never bytes.
Output: an :class:`McpConfig` describing the server entries, or ``None`` when the file is not an
MCP client config. Pure function, no I/O.

A file is recognised only by **file name and structure** together (fake-metadata resistance,
research §5.5): the top-level value must be an object holding the client's servers key
(``mcpServers``, or ``servers`` for VS Code's ``.vscode/mcp.json``) whose value is an object, and
at least one entry in it must be an object with a string ``command`` or ``url``. A file merely
*named* ``mcp.json`` with other keys is not an MCP config.

Recognised shapes (verified in the research pass; others are deliberately absent):

=============================== ============== ================================================
file                            servers key    client
=============================== ============== ================================================
``claude_desktop_config.json``  mcpServers     Claude Desktop
``.mcp.json``                   mcpServers     Claude Code project scope (also read by VS Code)
``.cursor/mcp.json``            mcpServers     Cursor project
``.vscode/mcp.json``            servers        VS Code workspace
``.copilot/mcp-config.json``    mcpServers     GitHub Copilot CLI / VS Code user config
any other ``*.json``            mcpServers     unknown client: recognised by structure only
=============================== ============== ================================================

Windsurf (``serverUrl``), Zed, Continue, Cline, Gemini CLI and Codex shapes are ``UNVERIFIED`` in
the research and are not recognised (documented false negatives). ``~/.claude.json``
``projects[*].mcpServers`` is user-home state, not a repository file, and is not recognised.

For each server entry the recogniser reports the transport, the URL (if any) and every
**authentication indicator** found in the same entry. Authentication indicators are names only;
values are never copied out of the IR here, so a literal secret cannot be echoed by a rule.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from nexvul.ir.config_view import ConfigTree
from nexvul.ir.model import ConfigValueKind, Location, ModuleIR


class McpClient(StrEnum):
    CLAUDE_DESKTOP = "claude_desktop"
    CLAUDE_CODE = "claude_code_project"
    CURSOR = "cursor_project"
    VSCODE = "vscode_workspace"
    COPILOT = "copilot"
    UNKNOWN_CLIENT = "unknown_client"


CLIENT_LABELS: Final[dict[McpClient, str]] = {
    McpClient.CLAUDE_DESKTOP: "Claude Desktop config",
    McpClient.CLAUDE_CODE: "Claude Code project config (.mcp.json)",
    McpClient.CURSOR: "Cursor project config (.cursor/mcp.json)",
    McpClient.VSCODE: "VS Code workspace config (.vscode/mcp.json)",
    McpClient.COPILOT: "Copilot MCP config (mcp-config.json)",
    McpClient.UNKNOWN_CLIENT: "file with the mcpServers shape used by MCP clients",
}

#: Clients whose handling of ``url`` entries was verified in the research pass. For the others a
#: remote entry may be ignored by the client, so rules cap confidence at medium.
URL_SUPPORT_VERIFIED: Final = frozenset(
    {McpClient.CLAUDE_CODE, McpClient.CURSOR, McpClient.VSCODE, McpClient.COPILOT}
)


class Transport(StrEnum):
    STDIO = "stdio"
    HTTP = "http"  # streamable HTTP (``http``, ``streamable-http``, ``streamableHttp``)
    SSE = "sse"  # deprecated HTTP+SSE
    UNKNOWN = "unknown"


_HTTP_TYPES: Final = frozenset({"http", "streamable-http", "streamable_http", "streamablehttp"})
_SSE_TYPES: Final = frozenset({"sse"})

#: Member names (normalised: lower-case, ``-``/``_`` removed) whose presence with a non-empty
#: value counts as an authentication setting in a server entry. Lenient on purpose: an unknown
#: auth-looking key suppresses the "no authentication" finding (precision over recall).
_AUTH_KEY_FRAGMENTS: Final = (
    "auth",  # auth, oauth, authorization, authorization_token, authProvider, ...
    "token",
    "bearer",
    "apikey",
    "secret",
    "credential",
    "password",
    "headershelper",
)

#: Header names (normalised) that carry credentials.
_AUTH_HEADER_FRAGMENTS: Final = (
    "auth",
    "token",
    "key",
    "secret",
    "session",
    "cookie",
    "bearer",
    "credential",
    "password",
    "signature",
)

#: Variable-reference markers (Claude Code ``${VAR}``, Cursor ``${env:X}``, VS Code
#: ``${input:id}``, mustache-style templates). A header whose value is a reference is treated as
#: a credential supplied at runtime.
_REFERENCE_MARKERS: Final = ("${", "{{", "$env:", "%env")


def _norm(name: str) -> str:
    return name.lower().replace("-", "").replace("_", "")


@dataclass(frozen=True)
class McpServer:
    name: str
    entry: int  # index of the server object in ConfigDocument.entries
    location: Location
    transport: Transport
    declared_type: str | None
    url: str | None
    url_entry: int | None
    url_location: Location | None
    has_command: bool
    auth: tuple[str, ...]  # names of auth indicators found (never values)
    header_names: tuple[str, ...]  # every header name (never values), capped
    duplicated_keys: tuple[str, ...]  # keys repeated inside this entry
    is_last_occurrence: bool  # False when a later entry with the same name overrides this one
    url_occurrences: int


@dataclass(frozen=True)
class McpConfig:
    path: str
    client: McpClient
    servers_key: str
    servers: tuple[McpServer, ...]
    syntax: str

    @property
    def label(self) -> str:
        return CLIENT_LABELS[self.client]


def _client_for(path: str) -> tuple[McpClient, tuple[str, ...]]:
    parts = path.lower().split("/")
    name = parts[-1]
    parent = parts[-2] if len(parts) > 1 else ""
    if name == "claude_desktop_config.json":
        return McpClient.CLAUDE_DESKTOP, ("mcpServers",)
    if name == ".mcp.json":
        return McpClient.CLAUDE_CODE, ("mcpServers",)
    if name == "mcp.json" and parent == ".cursor":
        return McpClient.CURSOR, ("mcpServers",)
    if name == "mcp.json" and parent == ".vscode":
        return McpClient.VSCODE, ("servers",)
    if name == "mcp-config.json" and parent == ".copilot":
        return McpClient.COPILOT, ("mcpServers",)
    return McpClient.UNKNOWN_CLIENT, ("mcpServers",)


def _non_empty(tree: ConfigTree, index: int) -> bool:
    entry = tree.entries[index]
    if entry.kind is ConfigValueKind.STRING:
        return bool(entry.value and entry.value.strip())
    if entry.kind in (ConfigValueKind.OBJECT, ConfigValueKind.ARRAY):
        return entry.size > 0
    if entry.kind is ConfigValueKind.BOOL:
        return entry.value == "true"
    return entry.kind is ConfigValueKind.NUMBER


def _headers(tree: ConfigTree, index: int | None) -> tuple[list[str], list[str]]:
    """``(header names, auth indicators)`` of a ``headers`` object (last occurrence wins)."""
    if index is None or tree.kind(index) is not ConfigValueKind.OBJECT:
        return [], []
    names: list[str] = []
    auth: list[str] = []
    for name, child in tree.members(index).items():
        if len(names) < 32:
            names.append(name)
        value = tree.string(child)
        if value is None or not value.strip():
            continue
        lowered = value.lower()
        if any(f in _norm(name) for f in _AUTH_HEADER_FRAGMENTS) or any(
            m in lowered for m in _REFERENCE_MARKERS
        ):
            auth.append(f"headers.{name}")
    return names, auth


def _server(tree: ConfigTree, name: str, index: int, is_last: bool) -> McpServer | None:
    if tree.kind(index) is not ConfigValueKind.OBJECT:
        return None
    members = tree.members(index)
    url_index = members.get("url")
    url = tree.string(url_index)
    command = tree.string(members.get("command"))
    declared = tree.string(members.get("type"))
    if declared is None:
        declared = tree.string(members.get("transport"))
    if url is None and command is None:
        return None
    kind = declared.strip().lower() if declared is not None else None
    if kind is None:
        transport = Transport.STDIO if command is not None else Transport.HTTP
    elif kind == "stdio":
        transport = Transport.STDIO
    elif kind in _HTTP_TYPES:
        transport = Transport.HTTP
    elif kind in _SSE_TYPES:
        transport = Transport.SSE
    else:
        transport = Transport.UNKNOWN

    header_names, auth = _headers(tree, members.get("headers"))
    request_init = members.get("requestInit")
    if request_init is not None and tree.kind(request_init) is ConfigValueKind.OBJECT:
        more_names, more_auth = _headers(tree, tree.member(request_init, "headers"))
        header_names += more_names
        auth += [f"requestInit.{a}" for a in more_auth]
    for key, child in members.items():
        if key in ("headers", "requestInit", "url", "command", "type", "transport", "env"):
            continue
        if any(f in _norm(key) for f in _AUTH_KEY_FRAGMENTS) and _non_empty(tree, child):
            auth.append(key)
    return McpServer(
        name=name,
        entry=index,
        location=tree.entries[index].location,
        transport=transport,
        declared_type=declared,
        url=url,
        url_entry=url_index if url is not None else None,
        url_location=tree.entries[url_index].location if url_index is not None else None,
        has_command=command is not None,
        auth=tuple(auth),
        header_names=tuple(header_names),
        duplicated_keys=tuple(sorted(tree.duplicated_keys(index))),
        is_last_occurrence=is_last,
        url_occurrences=len(tree.occurrences(index, "url")),
    )


def recognise_config(module: ModuleIR) -> McpConfig | None:
    """Return the MCP client config described by ``module``, or ``None``."""
    doc = module.config
    if doc is None or not module.ok:
        return None
    tree = ConfigTree(doc)
    root = tree.root
    if root is None or tree.kind(root) is not ConfigValueKind.OBJECT:
        return None
    client, keys = _client_for(module.path)
    for key in keys:
        servers_index = tree.member(root, key)
        if servers_index is None or tree.kind(servers_index) is not ConfigValueKind.OBJECT:
            continue
        children = [c for c in tree.children(servers_index) if tree.entries[c].key is not None]
        last_by_name: dict[str, int] = {}
        for child in children:
            last_by_name[tree.entries[child].key or ""] = child
        servers: list[McpServer] = []
        for child in children:
            name = tree.entries[child].key or ""
            server = _server(tree, name, child, last_by_name[name] == child)
            if server is not None:
                servers.append(server)
        if servers:
            return McpConfig(
                path=module.path,
                client=client,
                servers_key=key,
                servers=tuple(servers),
                syntax=doc.syntax,
            )
    return None
