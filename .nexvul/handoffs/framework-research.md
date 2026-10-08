# Handoff: Framework Intelligence + MCP/A2A Protocol Research

**Date:** 2026-10-08
**Author:** Framework Intelligence Agent (with MCP and A2A security research)
**Status:** Complete for Phase 0 (research only; no scanner code; nothing committed)

## Summary
Mapped construction, tools, sources, sinks, controls, inter-agent comms and **limit defaults** for 8
frameworks plus the MCP and A2A protocols. Defaults were read from upstream **source code** wherever
possible (raw GitHub files at main/tags), because several docs pages disagree with source. Names not
confirmed are marked `UNVERIFIED` in each file.

## Files written
| File | Content |
|---|---|
| `docs/research/protocols/mcp.md` | Spec 2026-07-28 (current) vs 2025-11-25, transports, auth, tools/annotations, 4 client config formats, Py/TS SDK APIs, 18 detectable misconfigs with FP notes |
| `docs/research/protocols/a2a.md` | A2A 1.0.0, Agent Card path history, card/security-scheme format, authn/authz rules, SDK APIs, 12 detectable weaknesses |
| `docs/research/frameworks/{langgraph,langchain,openai-agents-sdk,crewai,autogen}.md` | Full maps |
| `docs/research/frameworks/{llamaindex,vercel-ai-sdk,langchainjs}.md` | Brief maps |
| `docs/research/frameworks/README.md` | Framework × role matrix; limit-defaults table; rule-design consequences |

## Findings that change rule design
1. **MCP 2026-07-28 is a breaking revision:** stateless, no `initialize`, no `Mcp-Session-Id`, no GET
   stream; HTTP+SSE, Roots/Sampling/Logging and Dynamic Client Registration deprecated. Recognisers
   must handle both eras. MCP auth is OPTIONAL in spec — "no auth" is a risk finding, not non-compliance.
2. **MCP Python SDK 2.x renamed `FastMCP` → `MCPServer`** (`mcp.server.fastmcp` import now fails);
   standalone `fastmcp` package is a separate lineage. DNS-rebinding protection is only auto-enabled for
   localhost hosts (Py) and is `false` by default on TS v1 `StreamableHTTPServerTransport`.
3. **Unpinned `npx -y` is in the official MCP quickstart** → must be low/informational or it will
   dominate findings.
4. **LangGraph recursion default changed:** 25 (≤1.0.5) → 10000 (1.0.6) → 10007 (main); docs say 1000.
   LangChain `create_agent` hard-sets 9999. LangGraph.js stays 25. Severity needs lockfile version.
5. **Bounded-by-default frameworks** (do not flag "missing limit"): OpenAI Agents (10 turns), CrewAI
   (`max_iter` 25), LangChain classic (15), LlamaIndex (20), Vercel `generateText` (1 step).
   **Unbounded by default:** AutoGen 0.4 teams (`max_turns=None`, no termination).
6. **Approval is off by default in every framework**; each has a distinct approval API (matrix §1).
7. **A2A card path:** `/.well-known/agent-card.json` (0.3.0+, 1.0); legacy `/.well-known/agent.json` (≤0.2.x).
   CrewAI ships native A2A with `auth=None` client default and empty server `security_schemes`.
8. AutoGen is in **maintenance mode**; successor Microsoft Agent Framework not yet researched.

## Open items / risks
- Confirm all `UNVERIFIED` names before recognisers rely on them (notably TS MCP v2 client classes,
  `fastmcp` defaults, A2A app import paths, `@a2a-js/sdk`, AG2 1.x defaults, LangChain.js HITL export).
- Not researched: Microsoft Agent Framework, Google ADK, Pydantic AI, Semantic Kernel, Smolagents,
  Mastra, other MCP clients (Windsurf, Zed, Codex `config.toml`).
- Pre-1.0 SDKs (OpenAI Agents 0.23) and fast-moving Vercel AI SDK (v7) need version-ranged recognisers.

## Suggested next consumers
Detection Rule Engineer (limit table → ASI08 rules), MCP Security agent (misconfig table M1–M18),
A2A Security agent (A1–A12), Memory Security agent (sink lists), False Positive Hunter (FP notes per file).
