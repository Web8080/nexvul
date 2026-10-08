# Framework Research — Index and Matrices

> Framework Intelligence Agent, Phase 0, 2026-10-08. Per-framework detail and source links live in the
> linked files. `UNVERIFIED` items in those files must be confirmed before a recogniser depends on them.
> Protocols: [`../protocols/mcp.md`](../protocols/mcp.md), [`../protocols/a2a.md`](../protocols/a2a.md).

| File | Framework | Version researched |
|---|---|---|
| [langgraph.md](langgraph.md) | LangGraph (Py) | 1.x main; tags 1.0.5/1.0.6 compared |
| [langchain.md](langchain.md) | LangChain (Py) v1 + classic | `langchain` 1.x, `langchain-classic` |
| [openai-agents-sdk.md](openai-agents-sdk.md) | OpenAI Agents SDK | Py 0.23.1, JS core 0.19.0 |
| [crewai.md](crewai.md) | CrewAI | 1.15.25 |
| [autogen.md](autogen.md) | AutoGen AgentChat / 0.2 / AG2 | agentchat 0.7.5 (maintenance mode), 0.2 branch, ag2 1.1.2 |
| [llamaindex.md](llamaindex.md) | LlamaIndex | core 0.14.25 |
| [vercel-ai-sdk.md](vercel-ai-sdk.md) | Vercel AI SDK | `ai` 7.0.133 |
| [langchainjs.md](langchainjs.md) | LangChain.js / LangGraph.js | `langchain` 1.5.15 |

## 1. Framework × role matrix

| Framework | Agent construction | Tool definition | Untrusted SOURCES | Persistent SINKS | Approval / HITL | Iteration limit | Inter-agent |
|---|---|---|---|---|---|---|---|
| LangGraph | `StateGraph(...).compile()`, `create_react_agent` (deprecated) | LC tools via `ToolNode`, `bind_tools` | graph input, `ToolMessage`, retrievers, `store.search` | checkpointer (`*Saver`), `store.put/aput`, node state | `interrupt()` + `Command(resume=)`; `interrupt_before/after` | `config["recursion_limit"]` | subgraphs, `Command(goto, graph=PARENT)`, supervisor/swarm libs, `RemoteGraph` |
| LangChain v1 | `create_agent(model, tools, system_prompt, middleware, checkpointer, store)` | `@tool`, `StructuredTool`, `BaseTool`, toolkits | web loaders, requests tools, search tools, retrievers, tool outputs | `add_documents/add_texts/from_*`, chat histories, checkpointer/store | `HumanInTheLoopMiddleware(interrupt_on=)` | 9999 (factory) + `ModelCallLimit`/`ToolCallLimit` middleware | sub-agent-as-tool, handoffs, router |
| LangChain classic | `AgentExecutor(...)`, `initialize_agent` | same | same | `ConversationBufferMemory.save_context`, `*ChatMessageHistory.add_*` | `HumanApprovalCallbackHandler` (UNVERIFIED) | `max_iterations`, `max_execution_time` | — |
| OpenAI Agents SDK | `Agent(...)`, `Runner.run(...)` / `run()` | `@function_tool`, `tool({...})`, hosted tools | run input, tool outputs, MCP servers, session replay | `Session` impls (`SQLiteSession`, `RedisSession`, `SQLAlchemySession`, ...) | `needs_approval` / `needsApproval`; `HostedMCPTool` `require_approval`; guardrails | `max_turns` / `maxTurns` | `handoffs=[...]`, `handoff(...)`, `as_tool()` |
| CrewAI | `Agent`, `Task`, `Crew.kickoff`, Flows | `@tool`, `BaseTool`, `crewai_tools`, `mcps=` | `kickoff(inputs)`, tools, knowledge, trigger payloads, A2A replies | `Memory.remember*`, legacy STM/LTM/Entity, Flow `@persist` | `Task.human_input`, guardrails | `Agent.max_iter`, `max_execution_time` | `allow_delegation`, hierarchical manager, `Task.context`, native A2A |
| AutoGen 0.4+ | `AssistantAgent`, teams | callables / `FunctionTool`, `McpWorkbench` | `run(task)`, peer messages, tools | `Memory.add(MemoryContent)`, `save_state` | `CodeExecutorAgent(approval_func)`, `UserProxyAgent`, `HandoffTermination` | team `max_turns`, termination conditions, `max_tool_iterations` | group chats, Swarm, Magentic-One, gRPC runtime |
| AutoGen 0.2 / AG2 | `ConversableAgent`, `UserProxyAgent`, `GroupChat` | `register_function`, `register_for_llm/execution` | messages, code results | `Teachability`, RAG agents | `human_input_mode` | `max_consecutive_auto_reply`, `max_round` | `GroupChatManager`, nested chats |
| LlamaIndex | `FunctionAgent`, `ReActAgent`, `AgentWorkflow` | `FunctionTool.from_defaults`, `QueryEngineTool`, ToolSpecs | web readers, retrievers, tool results | `index.insert`, `from_documents`, `vector_store.add`, `Memory` | `InputRequiredEvent`/`HumanResponseEvent` | `run(max_iterations=)` | `AgentWorkflow` handoff + `can_handoff_to` |
| Vercel AI SDK | `generateText/streamText`, `ToolLoopAgent` | `tool({inputSchema, execute, needsApproval})` | request `messages`, tools, MCP | app code only (`onFinish` DB writes, `embed` + DB upsert) | `needsApproval` | `stopWhen` (`maxSteps` v4) | none built-in |
| LangChain.js | `createAgent`, LangGraph.js | `tool()`, `DynamicStructuredTool` | Cheerio/Puppeteer loaders, retrievers | `addDocuments`, savers, `store.put` | HITL middleware (UNVERIFIED path), `interrupt` | `recursionLimit` | as Python |
| MCP (server side) | `FastMCP`/`MCPServer`, `McpServer` | `@mcp.tool()`, `registerTool` | tool args from any client | server-specific | spec: host should confirm; annotations are hints | n/a | n/a |
| A2A | `AgentExecutor` + routes/apps | skills in Agent Card | remote agent messages | task stores | n/a | client `max_turns` (CrewAI 10) | the protocol itself |

## 2. "Limit defaults when unset"

Values are source-verified unless marked. "Unbounded" means no framework limit; external timeouts
(HTTP server, provider) may still apply.

| Framework | Limit | Default when unset | Explicit-unbounded value | Evidence |
|---|---|---|---|---|
| LangGraph (Py) | `recursion_limit` | ≤1.0.5: **25**; 1.0.6: **10000**; main: **10007**; docs claim 1000 (docs ≠ source) | very large int | `_internal/_config.py` at tags/main |
| LangGraph (Py) | node `RetryPolicy` | not applied unless set; when set: `max_attempts=3`, `initial_interval=0.5`, `backoff_factor=2.0`, `max_interval=128.0` | — | `types.py` |
| LangGraph.js | `recursionLimit` | **25** | — | `langgraphjs/libs/langgraph/src/constants.ts` |
| langchain-core Runnables | `recursion_limit` | **25** | — | `runnables/config.py` |
| LangChain v1 `create_agent` | recursion | **9999** (hard-set in factory) | caller config override | `langchain_v1/.../factory.py` |
| LangChain v1 middleware | model/tool call limits | **none** (middleware absent; `thread_limit`/`run_limit` None) | — | docs built-in middleware |
| LangChain v1 retry middleware | `max_retries` | **2** when middleware used | — | docs |
| LangChain classic `AgentExecutor` | `max_iterations` / `max_execution_time` | **15** / **None** | `max_iterations=None` | `langchain_classic/agents/agent.py` |
| OpenAI Agents (Py/JS) | `max_turns` / `maxTurns` | **10** | `None` ("disable the turn limit") / `null` | `run_config.py`, `runner/constants.ts` |
| OpenAI Agents | tool `timeout` | **None** | — | `tool.py` |
| OpenAI Agents | `needs_approval` | **False** | — | `tool.py` |
| CrewAI | `Agent.max_iter` | **25** | large int | `base_agent.py` |
| CrewAI | `Agent.max_execution_time` / `max_rpm` | **None** / **None** | — | `agent/core.py`, `base_agent.py` |
| CrewAI | `Agent.max_retry_limit` | **2** | — | `agent/core.py` |
| CrewAI | `allow_delegation` | **False** | — | `base_agent.py` |
| CrewAI | `Task.human_input` | **False** | — | `task.py` |
| CrewAI | `Task.guardrail_max_retries` | **3** | — | `task.py` |
| CrewAI A2A client | `timeout` / `max_turns` / `auth` | **120 s** / **10** / **None** | — | `a2a/config.py` |
| AutoGen 0.4+ | team `max_turns` | **None (unbounded)** | — | `_round_robin_group_chat.py`, `_selector_group_chat.py`, `_swarm_group_chat.py` |
| AutoGen 0.4+ | `termination_condition` | **None** | — | same |
| AutoGen 0.4+ | `MagenticOneGroupChat` | `max_turns=20`, `max_stalls=3` | `max_turns=None` | `_magentic_one_group_chat.py` |
| AutoGen 0.4+ | `AssistantAgent.max_tool_iterations` | **1** | — | `_assistant_agent.py` |
| AutoGen 0.4+ | `CodeExecutorAgent.approval_func` | **None** | — | `_code_executor_agent.py` |
| AutoGen 0.2 | `max_consecutive_auto_reply` | **100** (class constant) | — | `conversable_agent.py` (0.2) |
| AutoGen 0.2 | `GroupChat.max_round` | **10** | — | `groupchat.py` (0.2) |
| AutoGen 0.2 | `UserProxyAgent` | `human_input_mode="ALWAYS"`, `code_execution_config={}` (exec on); Docker default via `AUTOGEN_USE_DOCKER="True"` | `use_docker=False` | `user_proxy_agent.py`, `code_utils.py` |
| AG2 1.x | same params | **UNVERIFIED** for 1.x | — | — |
| LlamaIndex | agent `max_iterations` | **20** | — | `agent/workflow/base_agent.py` |
| LlamaIndex | agent / AgentWorkflow `timeout` | **None** | — | same, `multi_agent_workflow.py` |
| LlamaIndex | plain `Workflow.timeout` | **45.0 s** | `None` | workflows-py `workflow.py` |
| Vercel AI SDK v7 | `generateText/streamText` `stopWhen` | **`isStepCount(1)`** | `isLoopFinished()` | `generate-text.ts` |
| Vercel AI SDK v7 | `ToolLoopAgent` `stopWhen` | **`isStepCount(20)`** | `isLoopFinished()` | `tool-loop-agent.ts` |
| Vercel AI SDK | `maxRetries` / `timeout` | **2** / **none** | `maxRetries: 0` disables retry | `generate-text.ts` |
| MCP Py SDK | HTTP host / port | `127.0.0.1` / `8000`; DNS-rebinding protection auto **only** for localhost hosts | `host="0.0.0.0"` | `server.py` v1 & v2 |
| MCP TS SDK v1 | `enableDnsRebindingProtection` | **false** (deprecated option); `createMcpExpressApp` host `127.0.0.1` auto-protect | `host:'0.0.0.0'` | `webStandardStreamableHttp.ts`, `docs/server.md` |

### Rule-design consequences
1. "Missing limit" ≠ "unbounded". Only AutoGen 0.4 teams (no `max_turns`, no termination), explicit
   `None`/`isLoopFinished()`, and LangGraph ≥1.0.6 / `create_agent` (~10k) are effectively unbounded.
2. Severity for LangGraph depends on the **resolved version** — the scanner must read lockfiles
   (static, no install) and report the range when unknown.
3. Approval defaults are **off** everywhere; ASI09 rules must look for the framework-specific
   approval API (table §1) before reporting.
