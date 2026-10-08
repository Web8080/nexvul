# OpenAI Agents SDK (Python + JS/TS) — Framework Recogniser Research

> Researched 2026-10-08 from source: `openai-agents` (Python) **0.23.1** (`openai/openai-agents-python`
> main, `pyproject.toml`), `@openai/agents-core` **0.19.0** (`openai/openai-agents-js` main).
> Docs: https://openai.github.io/openai-agents-python/ · https://openai.github.io/openai-agents-js/ .
> Pre-1.0 → API churn expected; pin recognisers to version ranges. `UNVERIFIED` = not confirmed.

## 1. Agent construction

**Python** (`from agents import Agent, Runner`):
`Agent(name, instructions=str|callable, prompt=Prompt|DynamicPromptFunction, handoff_description=,
tools=[], mcp_servers=[], mcp_config=MCPConfig(), handoffs=[], model=, model_settings=,
input_guardrails=[], output_guardrails=[], output_type=, hooks=, tool_use_behavior=,
reset_tool_choice=True)` (fields confirmed in `src/agents/agent.py`; `instructions` and
`tool_use_behavior` names from docs).
Run: `Runner.run(agent, input, context=, max_turns=DEFAULT_MAX_TURNS, hooks=, run_config=,
session=)`, `Runner.run_sync(...)`, `Runner.run_streamed(...)`.

**JS/TS** (`import { Agent, run, tool } from '@openai/agents'`): `new Agent({ name, instructions,
tools, handoffs, mcpServers, inputGuardrails, outputGuardrails, outputType, model })`;
`run(agent, input, { maxTurns, session, stream, context })`; `Agent.create(...)`; `new Runner(config)`.

## 2. Tools
- Python: `@function_tool` (decorator; signature in `src/agents/tool.py`):
  `name_override, description_override, docstring_style, use_docstring_info=True,
  failure_error_function, strict_mode=True, is_enabled=True, needs_approval=False,
  tool_input_guardrails=None, tool_output_guardrails=None, timeout=None,
  timeout_behavior="error_as_result", defer_loading=False, allowed_callers=None, ...`.
  `FunctionTool(...)` class for manual construction.
- JS: `tool({ name, description, parameters: z.object(...), execute, needsApproval, timeoutMs })`.
- Hosted / built-in tools (Python exports): `WebSearchTool`, `FileSearchTool`, `CodeInterpreterTool`,
  `ImageGenerationTool`, `ComputerTool`, `LocalShellTool`, `ShellTool` (with
  `ShellToolLocalEnvironment` / container environments and `ShellToolContainerNetworkPolicy*`),
  `ApplyPatchTool`, `HostedMCPTool(tool_config=..., on_approval_request=...)`, `ToolSearchTool`.
- Agents as tools: `agent.as_tool(tool_name, tool_description, ..., max_turns=None, session=None,
  needs_approval=...)` (Python).

## 3. SOURCES
- `Runner.run(..., input=...)` / JS `run(agent, input)` from HTTP handlers (user input).
- Tool outputs: `ToolCallOutputItem`, function tool return values; `WebSearchTool` /
  `FileSearchTool` results; `ComputerTool` screenshots; MCP tool results.
- MCP servers: `MCPServerStdio(params={command, args, env})`, `MCPServerStreamableHttp(params={url,
  headers, ...})`, `MCPServerSse` (exports confirmed in `src/agents/mcp/__init__.py`), with
  `tool_filter`/`create_static_tool_filter`; JS `MCPServerStdio`, `MCPServerStreamableHttp`
  (`UNVERIFIED` exact JS option names).
- Session history replay (`session.get_items()`) — previously stored items re-enter context.
- Handoff input (`HandoffInputData`) — content passed between agents.

## 4. SINKS
- **Sessions (persistent conversation memory):** core `SQLiteSession(session_id, db_path?)`,
  `OpenAIConversationsSession`, `OpenAIResponsesCompactionSession`; extensions
  (`agents.extensions.memory`): `RedisSession`, `SQLAlchemySession`, `AdvancedSQLiteSession`,
  `AsyncSQLiteSession`, `DaprSession`, `MongoDBSession`, `EncryptedSession`. Writes via
  `Runner.run(..., session=s)` (automatic) or `session.add_items([...])`.
- **System prompt:** `instructions=` f-string / callable `def instructions(ctx, agent) -> str`
  including untrusted data; `prompt=` dynamic prompt function.
- **Vector store:** hosted `FileSearchTool(vector_store_ids=[...])` reads; writes happen via the
  OpenAI Files/Vector Stores API (`client.vector_stores.files.create`/`upload_and_poll` — outside the
  Agents SDK; `UNVERIFIED` method names).

## 5. CONTROLS and defaults

| Control | API | Default when unset |
|---|---|---|
| Turn limit | Py `Runner.run(max_turns=)`; JS `run(..., { maxTurns })` | **10** (`DEFAULT_MAX_TURNS = 10` in Py `run_config.py` and JS `runner/constants.ts`). Py docstring: "Pass `None` to disable the turn limit" → `max_turns=None` is **explicitly unbounded**. JS also accepts `null`. Exceeding raises `MaxTurnsExceeded`. |
| Agent-as-tool turns | `as_tool(max_turns=None)` | `None` here means "use runner default" vs unbounded — `UNVERIFIED`; treat as needs-context |
| Tool approval (HITL) | Py `@function_tool(needs_approval=True|callable)`; JS `tool({ needsApproval })`; run pauses with `ToolApprovalItem`/interruptions, resume via `RunState` (`state.approve(...)`/`reject(...)` — method names `UNVERIFIED`) | `False` — no approval |
| Hosted MCP approval | `HostedMCPTool(tool_config={"require_approval": "never"|"always"|{...}}, on_approval_request=)` | `require_approval` default `UNVERIFIED` — flag explicit `"never"` |
| Tool timeout | Py `@function_tool(timeout=seconds)`; JS `timeoutMs` | **None** — no timeout |
| Model retries | `ModelSettings` / `RetryPolicy`, `ModelRetrySettings` (exports) | `UNVERIFIED` defaults; underlying `openai` client `max_retries` default 2 (provider) `UNVERIFIED` here |
| Guardrails | `@input_guardrail`, `@output_guardrail` (agent-level, raise `*TripwireTriggered`); `@tool_input_guardrail`, `@tool_output_guardrail` (per tool) | none |
| Tool enablement | `is_enabled=` on tools and handoffs | `True` |
| MCP tool allow-list | `MCPServer*(tool_filter=create_static_tool_filter(allowed_tool_names=[...]))` | all tools exposed |
| Shell network policy | `ShellToolContainerNetworkPolicyAllowlist/Disabled` | `UNVERIFIED` default |

Sources: https://github.com/openai/openai-agents-python/blob/main/src/agents/run.py ,
`run_config.py`, `tool.py`, `agent.py`, `handoffs/__init__.py`, `mcp/__init__.py`,
`extensions/memory/__init__.py`; https://github.com/openai/openai-agents-js/blob/main/packages/agents-core/src/runner/constants.ts ,
`src/tool.ts`.

## 6. Inter-agent comms
- **Handoffs:** `Agent(handoffs=[agent_b, handoff(agent_c, ...)])`; `handoff(agent,
  tool_name_override=, tool_description_override=, on_handoff=, input_type=, input_filter=,
  is_enabled=True)`; `HandoffInputData`, `HandoffInputFilter`; history helpers
  `nest_handoff_history`, `default_handoff_history_mapper`. Default: **full conversation history is
  passed** to the receiving agent unless an `input_filter` trims it (sensitive-context propagation,
  ASI07) — default behaviour claim `UNVERIFIED` in docs this pass; confirm before shipping a rule.
- **Agents as tools:** `agent.as_tool(...)` (orchestrator retains control).
- Cycle risk: A.handoffs ∋ B and B.handoffs ∋ A is common (triage ↔ specialist); bounded by
  `max_turns` (10 default) — only flag combined with `max_turns=None`.
- Realtime/voice agents (`RealtimeAgent`) — out of scope this pass.

## 7. False-positive notes
- `max_turns` absent ⇒ bounded at 10 — **do not** report unbounded iteration.
- `LocalShellTool`/`ShellTool` with `ShellToolContainer*Environment` is sandboxed by design; local
  environment is the risky variant.
- `needs_approval` may be a callable policy — treat any non-`False` value as an approval control.
