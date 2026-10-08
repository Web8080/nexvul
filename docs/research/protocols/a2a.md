# Agent2Agent (A2A) Protocol — Static-Analysis Research (ASI07)

> Researched 2026-10-08. Spec: **1.0.0** = "Latest Released Version" at
> https://a2a-protocol.org/latest/specification/ (earlier: 0.3.0, 0.2.6, 0.1.0; 1.0.0 release date not
> shown on page). Python SDK `a2a-sdk` **1.2.2** (`a2aproject/a2a-python`, release-please manifest),
> implements 1.0 with a 0.3 compatibility mode. `UNVERIFIED` = not confirmed this pass.

## 1. Agent Card location (verified)

| Version | Well-known path | Evidence |
|---|---|---|
| 1.0.0 | `/.well-known/agent-card.json` (spec §8.2, IANA §14.3 suffix `agent-card.json`) | spec |
| 0.3.0 | `/.well-known/agent-card.json` | spec v0.3.0; `a2a-python` v0.3.0 `AGENT_CARD_WELL_KNOWN_PATH`, with `PREV_AGENT_CARD_WELL_KNOWN_PATH = '/.well-known/agent.json'` |
| ≤0.2.x | `/.well-known/agent.json` | `a2a-python` v0.2.16 `constants.py` |

Extended (authenticated) card: 0.3 JSON-RPC `agent/getAuthenticatedExtendedCard`, REST path
`/agent/authenticatedExtendedCard` (SDK constant); 1.0 capability `capabilities.extendedAgentCard`.
Discovery alternatives: registries, direct configuration.

Recogniser: detect static card files (`agent-card.json`, `agent.json`, `*.a2a.json`) and in-code
`AgentCard(...)` constructions; handle both path generations.

## 2. Agent Card format

**1.0 (`AgentCard`, §4.4.1):** `name`, `description`, `supportedInterfaces[]` (each `AgentInterface`
carries `url`, protocol binding and `protocolVersion`), `provider`, `version`, `documentationUrl`,
`capabilities` (`streaming`, `pushNotifications`, `extendedAgentCard`, extensions), `securitySchemes`
(map), `securityRequirements` (list), `defaultInputModes`, `defaultOutputModes`, `skills[]`,
`signatures[]`, `iconUrl`. No top-level `url`/`security` in 1.0.

**0.3.0:** top-level `url`, `preferredTransport`, `additionalInterfaces`, `protocolVersion`,
`security` (OpenAPI-style requirement list), `securitySchemes`, `supportsAuthenticatedExtendedCard`,
`signatures`, `skills`, `capabilities`.

**Security schemes (1.0 §4.5.1, OpenAPI-derived), exactly one of:**
- `apiKeySecurityScheme {location: query|header|cookie, name}`
- `httpAuthSecurityScheme {scheme, bearerFormat?}`
- `oauth2SecurityScheme {flows, oauth2MetadataUrl?}`
- `openIdConnectSecurityScheme {openIdConnectUrl}`
- `mtlsSecurityScheme {description}`
(0.3 used OpenAPI-like `type: apiKey|http|oauth2|openIdConnect|mutualTLS` JSON objects.)

**Card signing (§8.4):** JWS (RFC 7515) over JCS-canonicalised card (RFC 8785); protected header
MUST include `alg`, `kid`; `signatures` excluded from signed content; clients SHOULD verify when present.

## 3. Authn / authz expectations
- Identity is **not** carried in A2A payloads; it is established at the transport (HTTP headers,
  mTLS) per the card's declared schemes (0.3 spec; 1.0 keeps transport-level auth).
- Servers must reject missing/invalid credentials and should send an auth challenge (1.0 §3.3.2).
- **Authorization is per operation**: servers must check authz on every operation and scope results
  to the caller; the authz model is agent-defined (§13).
- Production traffic MUST be encrypted (HTTPS/TLS; TLS 1.3 recommended, §7.1/§13); clients SHOULD
  verify server certificates (§7.2).
- Extended Agent Card operation MUST require authentication; must not leak internal URLs/credentials.
- Push notifications: agent MUST include credentials in webhook calls, should apply 10–30 s
  timeouts, exponential backoff, and **validate webhook URLs against SSRF** (reject private, loopback,
  link-local); clients MUST validate webhook authenticity.
- Version header `A2A-Version: Major.Minor`; extensions header `A2A-Extensions`. Media type
  `application/a2a+json`.

## 4. Transports / operations
Bindings: JSON-RPC (§9), gRPC (§10), HTTP+JSON/REST (§11), custom (§12).
- 1.0 operation names: `SendMessage`, `SendStreamingMessage`, `GetTask`, `ListTasks`, `CancelTask`,
  `SubscribeToTask`, push-config ops, extended card (REST e.g. `POST /message:send`).
- 0.3 JSON-RPC methods: `message/send`, `message/stream`, `tasks/get`, `tasks/cancel`,
  `tasks/resubscribe`, `tasks/pushNotificationConfig/set` (+get/list/delete), `agent/getAuthenticatedExtendedCard`.
- 1.0 removed the `kind` discriminator (breaking); legacy names (e.g. `MessageSendParams` →
  `SendMessageRequest`) aliased, removal "0.5.0 or later" per Appendix A.

## 5. SDK APIs

**Python `a2a-sdk` 1.2.2 (main):**
- Server: `a2a.server.agent_execution.AgentExecutor` (implement `execute`/`cancel`),
  `RequestContext`; `a2a.server.request_handlers.DefaultRequestHandler`, `LegacyRequestHandler`,
  `GrpcHandler`; `a2a.server.tasks.InMemoryTaskStore`, `DatabaseTaskStore`,
  `InMemoryPushNotificationConfigStore`, `DatabasePushNotificationConfigStore`, `TaskUpdater`;
  routes `a2a.server.routes.create_agent_card_routes`, `create_jsonrpc_routes`, `create_rest_routes`,
  `ServerCallContextBuilder`.
- Client: `a2a.client.ClientFactory`, `create_client`, `Client`, `ClientConfig`, `AuthInterceptor`,
  `CredentialService`, `InMemoryContextCredentialStore`, `AgentCardResolutionError`, `minimal_agent_card`.
- Constants: `AGENT_CARD_WELL_KNOWN_PATH='/.well-known/agent-card.json'`, `DEFAULT_RPC_URL='/'`,
  `VERSION_HEADER='A2A-Version'`.
- 0.2/0.3-era app classes widely used in samples: `A2AStarletteApplication(agent_card=, http_handler=)`,
  `A2AFastAPIApplication`, `A2ARESTFastAPIApplication`, legacy `A2AClient`, `A2ACardResolver`
  (`a2a.server.apps` / `a2a.client`) — exact import modules `UNVERIFIED` (only `JSONRPCApplication`
  and `CallContextBuilder` confirmed in `a2a/server/apps/__init__.py`).
- Types: `AgentCard`, `AgentSkill`, `AgentCapabilities` (`a2a.types`) — `UNVERIFIED` module for 1.x.

**JS `@a2a-js/sdk`:** `A2AExpressApp`, `DefaultRequestHandler`, `InMemoryTaskStore`, `A2AClient` —
all `UNVERIFIED` this pass.

**Framework integrations:** CrewAI native `A2AClientConfig`/`A2AServerConfig` (source-verified, see
`frameworks/crewai.md`: client `auth=None`, `timeout=120`, `max_turns=10` defaults; server
`security=[]`, `security_schemes={}` defaults). Google ADK `RemoteA2aAgent` / `to_a2a()`,
LangGraph Server A2A endpoint, Microsoft Agent Framework A2A — `UNVERIFIED`.

## 6. Statically detectable weaknesses

| # | Weakness | Static evidence | FP note |
|---|---|---|---|
| A1 | **Agent card advertises no auth** | Card JSON / `AgentCard(...)` with empty or missing `securitySchemes` and `securityRequirements`/`security`; CrewAI `A2AServerConfig` without `security_schemes` | Internal-only agents behind mTLS mesh / gateway; public read-only agents may be intentionally open. Medium confidence. |
| A2 | **Declared auth not enforced** | Card declares schemes but server app is mounted (`create_jsonrpc_routes`, `A2AStarletteApplication.build()`, Express app) with no auth middleware / `ServerCallContextBuilder` that checks credentials | Auth may be enforced in reverse proxy; flag "no identified enforcement". |
| A3 | **Plain-HTTP endpoint** | Card `url` / `supportedInterfaces[].url` or client endpoint `http://` non-loopback | Spec requires TLS in production; dev localhost is fine. High confidence when non-loopback. |
| A4 | **Unauthenticated outbound A2A client** | `ClientFactory`/`A2AClient`/`A2AClientConfig(endpoint=...)` with no `auth`/`AuthInterceptor`/headers | Calling public agents may be intentional; pair with A6 for severity. |
| A5 | **Unverified remote card** | Client resolves card from runtime-variable URL (user input, config from network) with no signature verification and no allowlist | Card signing is optional (SHOULD verify when present). Low/medium. |
| A6 | **Sensitive context sent to remote agent** | Dataflow: secrets/PII/full history (`messages`, session items) → `send_message`/`SendMessage` payload | Needs taint; confidence depends on sensitivity classification. |
| A7 | **Remote agent output trusted as instructions / persisted** | A2A response → system prompt, memory store, or privileged tool call; CrewAI `trust_remote_completion_status=True` | Overlaps ASI06; requires dataflow. |
| A8 | **Push-notification webhook SSRF** | Server accepts client-supplied push `url` with no private-range validation (custom `PushNotificationSender`) | SDK default sender behaviour `UNVERIFIED`. |
| A9 | **Secrets in card / extended card** | Literal tokens, internal hostnames, credentials in `agent-card.json` or `extended_skills` | Use secret-shape detection; redact. |
| A10 | **API key in query** | `apiKeySecurityScheme.location == "query"` / 0.3 `in: "query"` | Spec-legal but leaks via logs; low. |
| A11 | **Unbounded agent↔agent loop** | Client `max_turns` set very high / bypassed; A2A client calls inside an agent loop with no turn cap; mutual A2A references | CrewAI default `max_turns=10` bounds it. |
| A12 | **Server bound to all interfaces without auth** | `uvicorn.run(app, host="0.0.0.0")` + A1/A2 | Containers; combine signals. |

## 7. Limits of static analysis
Cannot verify that a remote agent actually validates tokens, that mesh mTLS exists, that the
published card at runtime equals the repo file, or the remote agent's identity. Findings must say
"no authentication was identified in the scanned code/config", never "the agent is unauthenticated".
