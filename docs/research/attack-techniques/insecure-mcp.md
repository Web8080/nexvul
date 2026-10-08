# Insecure MCP Servers and Clients

## attack

The Model Context Protocol (MCP) connects agents to tool/resource servers over `stdio` or HTTP (Streamable HTTP / SSE). Insecure MCP deployments expose agents and hosts through: unauthenticated HTTP servers, cleartext transports, local servers launched from arbitrary startup commands, servers exposing shell/filesystem/network tools with no scoping, token passthrough, over-broad OAuth scopes, session IDs used as authentication, and dynamic tool lists that change after review. This file covers **configuration and implementation weaknesses**; malicious tool *content* is covered in tool-poisoning.md.

## preconditions

- The project defines or consumes MCP servers (client config such as `.mcp.json` / `mcpServers` blocks, or server code using an MCP SDK).
- At least one of: HTTP transport without authorization; non-loopback `http://` endpoint; startup command that downloads and runs code (`npx <pkg>`, `uvx <pkg>`) without pinning; server tools wrapping shell, filesystem or arbitrary HTTP; server forwarding client tokens to downstream APIs.

## attack_flow

1. **Unauthenticated remote server:** an HTTP MCP server bound to a reachable interface with no authorization lets any network peer list and call its tools (including dangerous ones).
2. **Local server compromise:** a client config contains a startup command; a malicious or typosquatted package (or an embedded `&& curl ...`) runs with the user's privileges. The MCP spec lists this as "Local MCP Server Compromise".
3. **Token passthrough / confused deputy:** a server accepts tokens not issued to it and forwards them downstream, bypassing audience checks; the spec states servers "MUST NOT accept any tokens that were not explicitly issued for the MCP server".
4. **Session hijack:** a server treats a session ID as proof of identity; the spec states servers "MUST NOT use sessions for authentication".
5. **Over-broad tool surface:** a server exposes `run_command(cmd: str)` or `read_file(path: str)` with no allowlist; any prompt injection reaching the agent becomes host compromise.

## observable_code_patterns

```jsonc
// Client config: remote server over cleartext, no auth header/token
{ "mcpServers": { "crm": { "url": "http://crm.internal.example:8080/mcp" } } }

// Client config: unpinned package executed at startup
{ "mcpServers": { "fs": { "command": "npx", "args": ["-y", "some-fs-server"] } } }
```

```python
# Server: shell tool with unconstrained argument
@mcp.tool()
def run(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout

# Server: HTTP transport bound to all interfaces, no auth configured (illustrative)
mcp.run(transport="streamable-http", host="0.0.0.0", port=8000)

# Server: token passthrough
token = request.headers["Authorization"]
requests.get(DOWNSTREAM_API, headers={"Authorization": token})
```

## possible_static_signals

- Config: `url` with `http://` scheme and non-loopback host (`localhost`, `127.0.0.1`, `::1` excluded).
- Config: remote server entry with no `headers`/auth/OAuth fields (exact key names vary by client -- needs per-client schema).
- Config: `command` of `npx`/`uvx`/`pipx run`/`docker run` with unpinned package/image reference, or containing shell metacharacters (`&&`, `|`, `;`, `$(`).
- Server code: tool decorated function whose parameter flows into `subprocess`/`os.system`/`eval`/`open()`/`requests` without validation (taint: tool param -> dangerous sink).
- Server code: HTTP transport bind to `0.0.0.0` with no auth middleware detected.
- Server code: inbound `Authorization` header forwarded verbatim to an outbound HTTP call.
- Server code: tool list mutated at runtime and `notifications/tools/list_changed` emitted (dynamic tool surface).

## false_positive_cases

- Loopback HTTP servers in development, or servers reachable only inside a private network/service mesh that enforces mTLS outside the repo.
- Auth enforced by a reverse proxy / API gateway not visible in the code.
- `npx` used with a pinned version or a first-party package from the same monorepo.
- Shell tools that are intentionally the product (e.g. a terminal MCP server) -- still worth an informational finding, but not "vulnerable".
- Example/demo configs in docs.

## false_negative_cases

- Client configs living outside the repo (user home directory, IDE settings) -- not scanned.
- Servers discovered dynamically from registries at runtime.
- Auth that exists but is broken (weak token validation, wrong audience) -- not distinguishable statically without deep semantics.
- Tool content changing between sessions ("rug pull").
- Dangerous behaviour inside compiled/binary MCP servers or remote servers whose source is not in the repo.

## framework_examples

```python
# Python MCP SDK, FastMCP style (illustrative)
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("ops")

@mcp.tool()
def read(path: str) -> str:          # no path restriction
    return open(path).read()

# OpenAI Agents SDK consuming a stdio server launched from an unpinned package (illustrative)
from agents.mcp import MCPServerStdio
server = MCPServerStdio(params={"command": "npx", "args": ["-y", "third-party-mcp"]})

# LangChain MCP adapters connecting over cleartext HTTP (illustrative)
client = MultiServerMCPClient({"crm": {"url": "http://10.0.0.5/mcp", "transport": "streamable_http"}})
```

## owasp_mapping

- **Primary:** ASI04 (Agentic Supply Chain) for untrusted/unpinned servers and startup commands; ASI07 (Insecure Inter-Agent Communication) for unauthenticated/cleartext transports -- OWASP's ASI07 scenario 5 is "Agent-in-the-Middle via MCP descriptor poisoning" and mitigation 6 names MCP in protocol pinning (PDF pp. 28-29).
- **Secondary:** ASI02 (Tool Misuse) for over-broad tools; ASI05 (Unexpected Code Execution) for shell/eval tools; ASI03 for token passthrough and over-broad scopes.
- Brief §16 places "MCP connection without auth" under ASI07; this is consistent with OWASP's ASI07 text on unauthenticated channels.

## confidence

**High for config-level signals** (scheme, host, presence of auth fields, startup command shape) -- these are literal values. **Medium for server-code taint** (tool param -> sink). **Low** for whether auth is really enforced when it is delegated to infrastructure.

## references

- MCP Security Best Practices (confused deputy, token passthrough, SSRF, session hijacking, local server compromise, scope minimization): https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices
- MCP Authorization specification: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
- OWASP Practical Guide for Secure MCP Server Development: https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/
- OWASP Top 10 for Agentic Applications 2026 (ASI02, ASI04, ASI07): https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- OWASP MCP Tool Poisoning: https://community.owasp.org/attacks/MCP_Tool_Poisoning
