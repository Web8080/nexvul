"""NEX007 - MCP connection without authentication or over cleartext (ASI07; ASI04).

Detection class: config (docs/detection-taxonomy.md NEX007). Experimental thin slice: fewer than
20 labelled benchmark cases exist, so per DEC-0002 the rule ships off by default.

Flags, and only flags:

1. An MCP client config entry (see :mod:`nexvul.frameworks.mcp.config`) whose transport is HTTP
   or SSE and whose literal ``url`` is ``http://`` (cleartext) to a host that is not loopback -
   whether or not credentials are configured (credentials would then travel in cleartext).
   Severity high (medium for private-network hosts), confidence high.
2. The same, with an ``https://`` URL to a non-loopback host and **no authentication indicator in
   the same entry** (headers carrying credentials or variable references, ``auth``/``oauth``/
   bearer/token keys, user-info in the URL, a credential query parameter). Severity medium (low
   for private-network hosts), confidence medium: MCP authorization is optional in the spec, and a
   client may negotiate OAuth at connect time from the server's protected-resource metadata,
   which a static scan cannot see (research §3; taxonomy §3.2 control-absence = medium).
3. The same two conditions for Python ``mcp`` SDK HTTP client calls with a constant URL
   (:mod:`nexvul.frameworks.mcp.python_client`).

Not flagged: stdio servers (``command``), loopback / ``0.0.0.0`` destinations, templated URLs
(``${VAR}``), unknown transport types. Confidence is capped at medium for files recognised by
structure only and for Claude Desktop configs (remote ``url`` entries are not verified to be
used by that client). Messages never contain header values, user-info or query values.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from nexvul.core.sanitize import display_path
from nexvul.findings.model import Confidence, Severity
from nexvul.frameworks.mcp.config import (
    URL_SUPPORT_VERIFIED,
    McpConfig,
    McpServer,
    Transport,
    recognise_config,
)
from nexvul.frameworks.mcp.endpoints import Endpoint, HostClass, parse_endpoint
from nexvul.frameworks.mcp.python_client import McpHttpClientCall, find_http_client_calls
from nexvul.ir.config_view import pointer_of
from nexvul.ir.model import ModuleIR
from nexvul.rules.base import (
    EvidenceDraft,
    Match,
    Readiness,
    Rule,
    RuleContext,
    RuleDoc,
    RuleMeta,
    code,
)

RULE_ID = "NEX007"

_AUTH_SEARCHED = (
    "headers carrying credentials (Authorization, *token*, *key*, cookies) or a variable "
    "reference, an auth/oauth block, bearer/token/apiKey keys, a headersHelper, user-info in "
    "the URL, a credential query parameter"
)

_LOOKS_FOR = (
    "MCP client configurations that connect to a remote MCP server over cleartext http://, or "
    "over https:// with no authentication configured in the same server entry.\n"
    "Files read: claude_desktop_config.json, .mcp.json, .cursor/mcp.json, .vscode/mcp.json "
    "(servers), .copilot/mcp-config.json, and any other .json file whose top level has an "
    "mcpServers object of server entries (recognised by structure; confidence capped at medium). "
    "Python: streamablehttp_client(), streamable_http_client() and sse_client() from the mcp SDK "
    "called with a constant URL.\n"
    "An entry counts as authenticated when it has a credential-bearing header (or a header whose "
    "value is a ${VAR}/${env:X}/${input:id} reference), an auth/oauth block, a bearer/token/apiKey "
    "key, a headersHelper, user-info in the URL or a credential query parameter."
)
_WHY = (
    "A remote MCP server's tools run with whatever authority the client gives them, and tool "
    "results flow straight into the model's context. Over cleartext http:// anyone on the "
    "network path can read or rewrite tool descriptions, tool calls and results, and capture any "
    "token sent. Without authentication, anyone who can reach the server can call its tools, and "
    "the client cannot tell a spoofed server from the real one. OWASP ASI07 scenario 1 "
    "(semantic injection via unencrypted communications) and the MCP security best practices "
    "describe both."
)
_FIX = (
    "Use https:// for every non-loopback MCP server. Configure authentication for remote "
    "servers: an Authorization header taken from an environment variable or a VS Code input "
    "(never a literal token in a committed file), or the client's OAuth support. For local "
    "development servers, connect to localhost or 127.0.0.1, or use the stdio transport."
)
_NOT_DETECTED = (
    "Authentication configured outside this file: on the server, in a gateway or reverse proxy, "
    "or negotiated by the client through OAuth discovery at connect time (an https:// finding "
    "without auth is therefore medium confidence).\n"
    "Configs generated at runtime, servers added through a client CLI or UI (for example "
    "'claude mcp add'), and client configs outside the repository (user home, IDE settings).\n"
    "URLs built from variables (${VAR}, f-strings, environment lookups): reported as nothing.\n"
    "Windsurf, Zed, Continue, Cline, Gemini CLI and Codex config shapes (not verified yet); "
    "YAML/TOML configs; TypeScript MCP clients; langchain-mcp-adapters MultiServerMCPClient.\n"
    "Malicious tool descriptions, token passthrough, weak or leaked credentials, unpinned "
    "'npx -y' stdio servers (a separate supply-chain concern, not this rule)."
)
_FLAGGED = (
    '    { "mcpServers": {\n'
    '        "search": { "type": "http", "url": "http://mcp.example.com/mcp" } } }'
)
_NOT_FLAGGED = (
    '    { "mcpServers": {\n'
    '        "search": { "type": "http", "url": "https://mcp.example.com/mcp",\n'
    '                    "headers": { "Authorization": "Bearer ${MCP_TOKEN}" } },\n'
    '        "files": { "command": "npx",\n'
    '                   "args": ["-y", "@modelcontextprotocol/server-filesystem"] },\n'
    '        "dev": { "type": "http", "url": "http://localhost:8000/mcp" } } }'
)

META = RuleMeta(
    id=RULE_ID,
    name="MCP connection without authentication or over cleartext",
    asi=("ASI07", "ASI04"),
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    readiness=Readiness.EXPERIMENTAL,
    remediation=(
        "Use https:// for remote MCP servers and configure authentication (an Authorization "
        "header from an environment variable or input, or the client's OAuth support)."
    ),
    references=(
        "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization",
        "https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices",
        "https://modelcontextprotocol.io/specification/2025-11-25/basic/transports",
        "docs/rules/NEX007.md",
    ),
    cwe=("CWE-319", "CWE-306"),
    languages=("json", "python"),
    doc=RuleDoc(
        looks_for=_LOOKS_FOR,
        why_it_matters=_WHY,
        how_to_fix=_FIX,
        not_detected=_NOT_DETECTED,
        example_flagged=_FLAGGED,
        example_not_flagged=_NOT_FLAGGED,
        asi_names=("ASI07 Insecure Inter-Agent Communication", "ASI04"),
        status_note=(
            "Experimental thin slice: off by default (fewer than 20 labelled benchmark cases, "
            "DEC-0002). Enable with rules.enabled: [NEX007] in .nexvul.yml."
        ),
        suppression_note=(
            "JSON has no comments, so findings in .json configs cannot be suppressed inline. "
            "Use .nexvul.yml: add the file to exclude, or list NEX007 under rules.disabled. "
            "Inline suppression works for Python findings."
        ),
    ),
)


def _severity(cleartext: bool, host_class: HostClass) -> Severity:
    if cleartext:
        return Severity.MEDIUM if host_class is HostClass.PRIVATE else Severity.HIGH
    return Severity.LOW if host_class is HostClass.PRIVATE else Severity.MEDIUM


def _host_words(endpoint: Endpoint) -> str:
    if endpoint.host_class is HostClass.PRIVATE:
        return "a private-network host"
    return "a non-loopback host"


def _url_auth(endpoint: Endpoint) -> list[str]:
    found: list[str] = []
    if endpoint.has_userinfo:
        found.append("user-info in the URL")
    if endpoint.query_credential:
        found.append("credential query parameter")
    return found


def _message(
    subject: str, endpoint: Endpoint, transport_words: str, auth: list[str], *, cleartext: bool
) -> str:
    where = f"uses {transport_words} at {endpoint.display}"
    if cleartext and auth:
        names = ", ".join(code(a, 40) for a in auth[:4])
        return (
            f"{subject} {where}, over cleartext http:// to {_host_words(endpoint)}. "
            f"Its authentication settings ({names}) are sent over that unencrypted connection."
        )
    if cleartext:
        return (
            f"{subject} {where}, over cleartext http:// to {_host_words(endpoint)}. "
            "No authentication setting (headers, auth block, bearer/OAuth) was found in this "
            "config entry."
        )
    return (
        f"{subject} {where}, {_host_words(endpoint)}. No authentication setting (headers, auth "
        "block, bearer/OAuth) was found in this config entry; the client may still negotiate "
        "OAuth at connect time, which a static scan cannot see."
    )


def _value_evidence(module: ModuleIR, server: McpServer, endpoint: Endpoint) -> str:
    pointer = ""
    if module.config is not None and server.url_entry is not None:
        pointer = pointer_of(module.config.entries, server.url_entry)
    declared = f", declared type {code(server.declared_type, 30)}" if server.declared_type else ""
    return f"{pointer} = {endpoint.display} (transport {server.transport.value}{declared})"


class McpConnectionWithoutAuth(Rule):
    meta = META

    def check(self, ctx: RuleContext) -> Iterable[Match]:
        for module in ctx.modules:
            if module.config is not None:
                config = recognise_config(module)
                if config is not None:
                    yield from self._config_matches(module, config)
            elif module.language == "python":
                for call in find_http_client_calls(module):
                    match = self._python_match(call)
                    if match is not None:
                        yield match

    # -- config files --------------------------------------------------------------------------

    def _config_matches(self, module: ModuleIR, config: McpConfig) -> Iterator[Match]:
        for server in config.servers:
            match = self._server_match(module, config, server)
            if match is not None:
                yield match

    def _server_match(self, module: ModuleIR, config: McpConfig, server: McpServer) -> Match | None:
        if server.transport not in (Transport.HTTP, Transport.SSE) or server.url is None:
            return None
        endpoint = parse_endpoint(server.url)
        if endpoint is None or endpoint.scheme not in ("http", "https"):
            return None
        if not endpoint.off_machine:
            return None
        auth = list(server.auth) + _url_auth(endpoint)
        cleartext = endpoint.cleartext
        if not cleartext and auth:
            return None
        confidence = Confidence.HIGH if cleartext else Confidence.MEDIUM
        limitations: list[str] = []
        if config.client not in URL_SUPPORT_VERIFIED:
            confidence = Confidence.MEDIUM
            limitations.append(
                "whether this client uses url entries from this file was not verified"
            )
        evidence = [
            EvidenceDraft(
                kind="recognised_as",
                description=(
                    f"MCP client config: {config.label}; top-level '{config.servers_key}' object "
                    "with server entries"
                ),
            ),
            EvidenceDraft(
                kind="config_value", description=_value_evidence(module, server, endpoint)
            ),
            EvidenceDraft(
                kind="auth_search",
                description=(
                    f"Looked for: {_AUTH_SEARCHED}. Found: "
                    + (", ".join(code(a, 40) for a in auth[:6]) if auth else "none")
                ),
            ),
        ]
        if server.url_occurrences > 1 or not server.is_last_occurrence:
            confidence = Confidence.MEDIUM
            what = (
                f"key 'url' appears {server.url_occurrences} times in this entry"
                if server.url_occurrences > 1
                else f"server name '{code(server.name, 40)}' appears more than once"
            )
            evidence.append(
                EvidenceDraft(
                    kind="duplicate_keys",
                    description=(
                        f"{what}; JSON.parse-based clients use the last occurrence. This finding "
                        "is reported for the occurrence evaluated here."
                    ),
                )
            )
        transport_words = (
            "the deprecated SSE transport"
            if server.transport is Transport.SSE
            else "an HTTP transport"
        )
        subject = (
            f"The MCP server entry '{code(server.name, 60)}' in "
            f"{display_path(config.path, max_chars=80)}"
        )
        return Match(
            path=module.path,
            location=server.url_location or server.location,
            message=_message(subject, endpoint, transport_words, auth, cleartext=cleartext),
            evidence=tuple(evidence),
            severity=_severity(cleartext, endpoint.host_class),
            confidence=confidence,
            context=f"config|{config.servers_key}|{server.name}|{server.url}",
            limitations=tuple(limitations),
        )

    # -- Python SDK client calls -----------------------------------------------------------------

    def _python_match(self, call: McpHttpClientCall) -> Match | None:
        endpoint = parse_endpoint(call.url)
        if endpoint is None or endpoint.scheme not in ("http", "https"):
            return None
        if not endpoint.off_machine:
            return None
        auth = list(call.auth_arguments) + _url_auth(endpoint)
        cleartext = endpoint.cleartext
        if not cleartext and auth:
            return None
        transport_words = (
            "the deprecated SSE transport" if call.transport == "sse" else "an HTTP transport"
        )
        shown = display_path(call.path, max_chars=80)
        subject = f"The MCP client call {code(call.function)}() in {shown}"
        message = _message(subject, endpoint, transport_words, auth, cleartext=cleartext)
        message = message.replace("in this config entry", "in this call's arguments")
        return Match(
            path=call.path,
            location=call.location,
            message=message,
            evidence=(
                EvidenceDraft(
                    kind="recognised_as",
                    description=(
                        f"Python mcp SDK client function {code(call.function)}() (import-resolved)"
                    ),
                ),
                EvidenceDraft(
                    kind="auth_search",
                    description=(
                        "Looked for: headers, auth, http_client or httpx_client_factory "
                        "arguments, user-info in the URL, a credential query parameter. Found: "
                        + (", ".join(auth) if auth else "none")
                    ),
                ),
            ),
            severity=_severity(cleartext, endpoint.host_class),
            confidence=Confidence.HIGH if cleartext else Confidence.MEDIUM,
            context=f"python|{call.function}|{call.url}",
        )
