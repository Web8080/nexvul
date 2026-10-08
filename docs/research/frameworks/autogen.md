# AutoGen (AgentChat 0.4+, legacy 0.2) and the AG2 fork — Recogniser Research

> Researched 2026-10-08 from source. `microsoft/autogen` main: `autogen-agentchat` **0.7.5**;
> README: "AutoGen is now in maintenance mode … New users should start with Microsoft Agent
> Framework" (https://github.com/microsoft/agent-framework). Legacy 0.2 read from branch `0.2`.
> AG2 fork: `ag2ai/ag2`, PyPI `ag2`, `pyproject.toml` version **1.1.2**.
> Docs: https://microsoft.github.io/autogen/stable/ · https://docs.ag2.ai/ . `UNVERIFIED` = not confirmed.

**Three code lineages to recognise** (by import roots — never by the word "autogen" alone):
1. `autogen_agentchat`, `autogen_core`, `autogen_ext` → AgentChat 0.4+ (Microsoft, maintenance mode).
2. `import autogen` / `from autogen import ConversableAgent` with `pyautogen<=0.2.x` → legacy 0.2.
3. `ag2` package (also installs import name `autogen`) → AG2 fork continuing the 0.2 API. Lineage 2
   vs 3 is ambiguous from imports alone; disambiguate via lockfile (`pyautogen` vs `ag2`/`autogen`).
4. Microsoft Agent Framework (`agent_framework`) is the successor — **out of scope this pass**
   (`UNVERIFIED`); flag as future recogniser.

## A. AgentChat 0.4+ (`autogen_agentchat`)

### Construction & tools
- `AssistantAgent(name, model_client, tools=[fn | FunctionTool | BaseTool], workbench=McpWorkbench(...),
  handoffs=[str|Handoff], memory=[Memory], system_message=, reflect_on_tool_use=,
  max_tool_iterations=1, tool_call_summary_format=, model_context=)` (fields in
  `agents/_assistant_agent.py`).
- Other agents: `UserProxyAgent(input_func=)`, `CodeExecutorAgent(code_executor=, approval_func=)`,
  `SocietyOfMindAgent`, `MessageFilterAgent`, `BaseChatAgent`.
- Tools: plain Python callables auto-wrapped, `autogen_core.tools.FunctionTool(func, description)`.
- MCP (`autogen_ext.tools.mcp`): `McpWorkbench`, `mcp_server_tools(server_params)`,
  `StdioServerParams`, `SseServerParams`, `StreamableHttpServerParams`, `*McpToolAdapter`.
- Code executors (`autogen_ext.code_executors.*`): `LocalCommandLineCodeExecutor` (host exec),
  `DockerCommandLineCodeExecutor`, `JupyterCodeExecutor` — module paths `UNVERIFIED` this pass.

### SOURCES
`team.run(task=...)` / `run_stream(task=...)` / `agent.on_messages(...)` input; tool results
(`FunctionExecutionResult`, `ToolCallSummaryMessage`); MCP tools; `UserProxyAgent` input; messages
from other participants in a group chat (every peer's output is input to the next speaker).

### SINKS
- Memory protocol `autogen_core.memory`: `Memory`, `MemoryContent`, `ListMemory`; writes via
  `await memory.add(MemoryContent(content=..., mime_type=MemoryMimeType.TEXT))`; memory content is
  injected into the model context via `update_context` (→ system/context promotion).
  `ChromaDBVectorMemory`, `RedisMemory`, `Mem0Memory` in `autogen_ext.memory.*` — `UNVERIFIED` names.
- State persistence: `await team.save_state()` / `agent.save_state()` → JSON written by user code;
  `load_state(...)` re-hydrates (`UNVERIFIED` exact signatures).
- `system_message=` f-strings.

### CONTROLS and defaults (source-verified unless noted)

| Control | API | Default when unset |
|---|---|---|
| Tool loop per turn | `AssistantAgent(max_tool_iterations=)` | **1** (`Field(default=1, ge=1)`) |
| Team turn cap | `RoundRobinGroupChat/SelectorGroupChat/Swarm(max_turns=)` | **None — unbounded** |
| Team termination | `termination_condition=` | **None** — with `max_turns=None` and no condition the team runs until an agent stops / external cancel |
| Termination conditions | `autogen_agentchat.conditions`: `MaxMessageTermination`, `TextMentionTermination`, `StopMessageTermination`, `TokenUsageTermination`, `HandoffTermination`, `TimeoutTermination`, `ExternalTermination`, `SourceMatchTermination`, `TextMessageTermination`, `FunctionCallTermination`, `FunctionalTermination` (combinable with `|`, `&`) | — |
| Magentic-One | `MagenticOneGroupChat(max_turns=20, max_stalls=3)` | **20 turns, 3 stalls** |
| Selector | `SelectorGroupChat(allow_repeated_speaker=False, max_selector_attempts=3)` | as shown |
| Code approval | `CodeExecutorAgent(approval_func=)` (`ApprovalRequest`/`ApprovalResponse`) | **None — no approval** |
| Human in loop | `UserProxyAgent` participant; `HandoffTermination(target="user")` | none |
| Cancellation | `CancellationToken` | none |

Sources: https://github.com/microsoft/autogen/tree/main/python/packages/autogen-agentchat/src/autogen_agentchat
(`teams/_group_chat/_round_robin_group_chat.py`, `_selector_group_chat.py`, `_swarm_group_chat.py`,
`_magentic_one/_magentic_one_group_chat.py`, `agents/_code_executor_agent.py`, `conditions/__init__.py`).

### Inter-agent comms
`RoundRobinGroupChat`, `SelectorGroupChat` (LLM picks next speaker), `Swarm` (handoff-driven via
`HandoffMessage`; `AssistantAgent(handoffs=[...])`), `MagenticOneGroupChat` (orchestrator),
`SocietyOfMindAgent` (team-as-agent), `GraphFlow`/`DiGraphBuilder` (directed graph workflows —
`UNVERIFIED` names; important for cycle detection). Distributed runtime `autogen_core`
`GrpcWorkerAgentRuntime` / host (`autogen_ext.runtimes.grpc`) — remote agents over gRPC, auth/TLS
options `UNVERIFIED` → ASI07 candidate.

## B. Legacy 0.2 (`autogen`, `pyautogen`) — source branch `0.2`

| Item | API | Default when unset |
|---|---|---|
| Base agent | `ConversableAgent(name, system_message, llm_config, human_input_mode, max_consecutive_auto_reply, code_execution_config, function_map, is_termination_msg)` | `human_input_mode="TERMINATE"`, `code_execution_config=False` |
| `AssistantAgent` | subclass | `human_input_mode="NEVER"`, code exec False |
| `UserProxyAgent` | subclass | `human_input_mode="ALWAYS"`, **`code_execution_config={}` (code execution ON)** |
| Auto-reply cap | `max_consecutive_auto_reply` | `None` → class `MAX_CONSECUTIVE_AUTO_REPLY = 100` |
| Docker for code exec | `code_execution_config={"use_docker": ...}` / env `AUTOGEN_USE_DOCKER` | env default `"True"` → Docker if available; **`use_docker=False` = host execution** |
| Group chat rounds | `GroupChat(agents, messages, max_round=)` | **10** |
| Speaker selection | `speaker_selection_method` | `"auto"` (LLM) |
| Manager | `GroupChatManager(groupchat, llm_config)` | — |
| Tools | `register_function(f, caller=, executor=, description=)`, `@agent.register_for_llm()`, `@agent.register_for_execution()`, `function_map={...}` | — |
| Nested / sequential | `initiate_chat(recipient, message, max_turns=)`, `initiate_chats([...])`, `register_nested_chats` | `initiate_chat(max_turns=None)` → bounded by auto-reply cap `UNVERIFIED` |
| Memory/RAG | `RetrieveUserProxyAgent` (`autogen.agentchat.contrib.retrieve_user_proxy_agent`), `Teachability` (persistent memo DB) | — |

Key risky combo (0.2): `UserProxyAgent(human_input_mode="NEVER", code_execution_config={"use_docker":
False, ...})` = LLM-generated code runs on host with no human — high-signal ASI10/ASI09.

## C. AG2 fork
Continues the 0.2 programming model (`ConversableAgent`, `GroupChat`, `register_function`) under
`ag2ai/ag2`, version 1.1.2. Module layout in 1.x differs from 0.2 (e.g. `autogen/agentchat/groupchat/`
not found at the 0.2 path) — exact current defaults (`max_round`, auto-reply cap) **UNVERIFIED for
AG2 1.x**; assume 0.2 defaults only when lockfile shows `pyautogen<0.3`.

## False-positive notes
- `max_turns=None` on a team that *has* a `termination_condition` is bounded by that condition —
  only flag when both are absent (or the condition can never fire, e.g. text mention never produced).
- `UserProxyAgent` in 0.4 is just human input (no code exec) — do not apply 0.2 semantics.
- `max_tool_iterations=1` default means AgentChat single-agent tool loops are bounded per turn.
