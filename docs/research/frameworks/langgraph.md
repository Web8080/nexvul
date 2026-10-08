# LangGraph (Python; JS notes inline) — Framework Recogniser Research

> Researched 2026-10-08. Versions: `langgraph` 1.x (main branch inspected 2026-10-08; tags 1.0.5, 1.0.6
> compared). Docs: https://docs.langchain.com/oss/python/langgraph/ . Names marked `UNVERIFIED`
> were not confirmed against official docs/source in this pass.

## 1. Agent / graph construction

| API | Import | Notes |
|---|---|---|
| `StateGraph(State)` | `langgraph.graph` | `.add_node(name?, fn)`, `.add_edge(a, b)`, `.add_conditional_edges(src, router, path_map?)`, `START`, `END` |
| `.compile(checkpointer=, store=, interrupt_before=, interrupt_after=, cache=, name=, debug=)` | — | `checkpointer`/`cache` documented on Graph API page; `store` on memory page; `interrupt_*` on interrupts page |
| `Command(goto=, update=, resume=, graph=Command.PARENT)` | `langgraph.types` | Dynamic routing; `graph=Command.PARENT` jumps to parent graph (used for handoffs) |
| `Send(node, state)` | `langgraph.types` | Map-reduce fan-out from conditional edges |
| `create_react_agent(model, tools, ...)` | `langgraph.prebuilt` | **Deprecated in v1** in favour of `langchain.agents.create_agent` (still present, decorated `@deprecated` in `chat_agent_executor.py`). Still very common in scanned code. |
| `ToolNode(tools)`, `tools_condition` | `langgraph.prebuilt` | Executes tool calls from the last AI message |
| Functional API `@entrypoint`, `@task` | `langgraph.func` | `UNVERIFIED` param list in this pass |

Sources: https://docs.langchain.com/oss/python/langgraph/graph-api ·
https://docs.langchain.com/oss/python/releases/langgraph-v1

JS: `@langchain/langgraph` exports `StateGraph`, `Annotation`, `START`, `END`, `Command`, `Send`,
`interrupt`, `MemorySaver`; `createReactAgent` from `@langchain/langgraph/prebuilt` (exact v1 status
`UNVERIFIED`).

## 2. Tools
Tools are LangChain tools (`@tool` from `langchain.tools` / `langchain_core.tools`, `StructuredTool`,
`BaseTool` subclasses) bound to a model (`model.bind_tools(tools)`) and executed by `ToolNode` or
custom nodes. See `langchain.md`. Recogniser: resolve the list passed to `ToolNode(...)`,
`create_react_agent(tools=...)`, `bind_tools(...)`.

## 3. Untrusted-data SOURCES
- Graph input: `graph.invoke({"messages": [...user...]}, config)` / `.stream()` / `.ainvoke()`; when
  the argument derives from a web request (FastAPI/Flask handler param) it is user-controlled.
- `ToolMessage` contents produced by `ToolNode` (tool outputs, esp. web/HTTP/browser/MCP tools).
- Retriever outputs used inside nodes (LangChain retrievers, `vectorstore.similarity_search`).
- `interrupt()` return value / `Command(resume=...)` payload (human-supplied; trusted only if the
  resume channel is authenticated).
- `runtime.store.search(...)` / `store.get(...)` results (previously persisted memory → re-entry
  point for ASI06 poisoning).
- MCP tools via `langchain-mcp-adapters` (`MultiServerMCPClient`, `load_mcp_tools`) — `UNVERIFIED` names.

## 4. SINKS (persistence / prompt construction)

| Sink | API | Source |
|---|---|---|
| Checkpointer (thread state incl. full message history) | `InMemorySaver`/`MemorySaver` (`langgraph.checkpoint.memory`), `SqliteSaver` (`langgraph.checkpoint.sqlite` — path `UNVERIFIED` this pass), `PostgresSaver.from_conn_string(...)` (`langgraph.checkpoint.postgres`), `AsyncPostgresSaver` | https://docs.langchain.com/oss/python/langgraph/persistence |
| Long-term Store (cross-thread) | `store.put(namespace, key, value)`, `store.aput`, `store.search(ns, query=, limit=)`, `store.get`; classes `InMemoryStore(index={"embed":..., "dims":...})` (`langgraph.store.memory`), `PostgresStore` (`langgraph.store.postgres`), `AsyncPostgresStore` (`.aio`), `RedisStore` (`langgraph.store.redis`) | https://docs.langchain.com/oss/python/langgraph/add-memory |
| Store access in nodes | `runtime: Runtime[Ctx]` → `runtime.store`; or a `store: BaseStore` kw param | same |
| State updates returned by nodes | `return {"messages": [...]}` / `Command(update=...)` → persisted by checkpointer | graph-api |
| System prompt | `SystemMessage(content=f"...{x}...")`, `prompt=` arg of `create_react_agent`, f-strings in node that prepend to messages | — |

**Memory-security nuance:** checkpointer state is *thread-scoped* conversation persistence; Store is
*long-term, cross-thread* memory. ASI06 rules should rate untrusted content → `store.put` higher
than → checkpointer (which only replays within the same thread). `InMemorySaver`/`InMemoryStore` are
non-persistent across restarts (lower impact, still cross-turn).

## 5. CONTROLS

| Control | API | Default when unset |
|---|---|---|
| Step limit | `config={"recursion_limit": N}` on `invoke/stream` (top-level config key, not `configurable`); env `LANGGRAPH_DEFAULT_RECURSION_LIMIT` | **Version-dependent (source-verified):** ≤1.0.5 → **25**; 1.0.6 → **10000**; main (2026-10-08) → **10007** (sentinel tweak, cf. 1.1.4 changelog "avoid recursion limit default sentinel collision"). Docs page says "Starting in version 1.0.6, the default recursion limit is set to 1000 steps" — **docs disagree with source**; trust source. `langchain_core` `DEFAULT_RECURSION_LIMIT = 25` applies to plain Runnables. Exceeding → `GraphRecursionError`. |
| Human approval | `interrupt(value)` (`langgraph.types`) + `Command(resume=...)`; requires a checkpointer and `thread_id` | none — no approval unless coded |
| Static breakpoints | `compile(interrupt_before=[...], interrupt_after=[...])` | none; docs say these are for debugging, `interrupt()` preferred for HITL |
| Node retry | `RetryPolicy(initial_interval=0.5, backoff_factor=2.0, max_interval=128.0, max_attempts=3, jitter=True)` passed via `add_node(..., retry_policy=...)` (kwarg name `retry_policy` vs `retry` — `UNVERIFIED`) | no retries unless set |
| Caching | `CachePolicy(key_func, ttl)`; `compile(cache=...)` | ttl none = no expiry |
| Node / run timeout | `step_timeout` attribute on compiled Pregel — `UNVERIFIED` | no timeout |
| Tool allow-list | the explicit tools list given to `ToolNode` / `bind_tools` | — |

Sources: graph-api, interrupts https://docs.langchain.com/oss/python/langgraph/interrupts , source
https://github.com/langchain-ai/langgraph/blob/main/libs/langgraph/langgraph/_internal/_config.py ,
https://github.com/langchain-ai/langgraph/blob/main/libs/langgraph/langgraph/types.py

**Implication:** On LangGraph ≥1.0.6, *not* setting `recursion_limit` means effectively ~10k steps —
for ASI08 "unbounded iteration" this is close to unlimited. nexvul must read the resolved version from
`uv.lock`/`poetry.lock`/`requirements*.txt` before choosing severity; if unknown, state the range.

## 6. Inter-agent communication
- Subgraphs as nodes; `Command(goto="agent_b", graph=Command.PARENT, update=...)` handoffs.
- `langgraph_supervisor.create_supervisor(agents, model, output_mode="full_history"|"last_message")`,
  `create_handoff_tool` — README now says "We now recommend using the supervisor pattern directly via
  tools rather than this library" (https://github.com/langchain-ai/langgraph-supervisor-py).
- `langgraph_swarm` `create_swarm`, `create_handoff_tool` — `UNVERIFIED` this pass.
- Remote graphs: `RemoteGraph` (`langgraph.pregel.remote`) calling a LangGraph Server over HTTP with
  `api_key` / headers — `UNVERIFIED` signature; relevant to ASI07 (remote agent without auth).
- Cycle detection: build the node/edge graph from `add_edge`/`add_conditional_edges` path maps and
  `Command[Literal[...]]` annotations; a cycle is normal for agent loops (agent↔tools) — only flag
  cycles that lack a conditional exit to `END` *and* rely on a large/unset recursion_limit.

## 7. False-positive notes
- The agent↔tools loop is the canonical ReAct design; never flag the cycle itself.
- `InMemorySaver` in tests/notebooks is common; downgrade findings under `tests/`, `examples/`, `*.ipynb`.
- `interrupt()` may be in a helper function called from many nodes — need inter-procedural reach.
