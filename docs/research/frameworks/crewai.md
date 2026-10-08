# CrewAI — Framework Recogniser Research

> Researched 2026-10-08 from source `crewAIInc/crewAI` main, `lib/crewai/src/crewai/__init__.py`
> `__version__ = "1.15.25"`. Docs: https://docs.crewai.com/ . Field defaults below are
> **source-verified** (Pydantic `Field(default=...)`) unless marked `UNVERIFIED`.
> Source files: `agents/agent_builder/base_agent.py`, `agent/core.py`, `task.py`, `crew.py`,
> `memory/unified_memory.py`, `a2a/config.py`.

## 1. Construction
- `Agent(role, goal, backstory, llm=, tools=[], allow_delegation=, max_iter=, max_rpm=,
  max_execution_time=, max_retry_limit=, memory=, knowledge_sources=, guardrail=, planning=,
  reasoning=, mcps=[...], a2a=[...], step_callback=, inject_date=, ...)`
- `Task(description, expected_output, agent=, tools=, context=[tasks], async_execution=,
  human_input=, guardrail=/guardrails=, guardrail_max_retries=, output_pydantic=, callback=, ...)`
- `Crew(agents, tasks, process=Process.sequential|Process.hierarchical, manager_llm=,
  manager_agent=, memory=, cache=, max_rpm=, planning=, knowledge_sources=, embedder=)` →
  `crew.kickoff(inputs={...})`, `kickoff_async`, `kickoff_for_each`.
- YAML-driven projects: `@CrewBase` class with `@agent`, `@task`, `@crew` decorators and
  `config/agents.yaml`, `config/tasks.yaml` (role/goal/backstory strings with `{placeholders}`
  interpolated from `kickoff(inputs=...)`). Recogniser must read these YAML files as prompt sources.
- **Flows:** `class MyFlow(Flow[State])` with `@start()`, `@listen(method)`, `@router(method)`,
  `@persist` (state persistence, default SQLite — `UNVERIFIED` backend detail), `flow.kickoff()`.
  Flow `@router` + `@listen` can form cycles (ASI08 cycle analysis).

## 2. Tools
- `@tool("Name")` decorator (`from crewai.tools import tool`), `BaseTool` subclass with `_run`,
  `args_schema`; tools attach at Agent or Task level (task-level overrides agent-level).
- `crewai_tools` package: `ScrapeWebsiteTool`, `SerperDevTool`, `WebsiteSearchTool`, `FileReadTool`,
  `FileWriterTool`, `DirectoryReadTool`, `CodeInterpreterTool` (Agent-level code exec flags are now
  **deprecated**: "CodeInterpreterTool is no longer available. Use dedicated sandbox services"),
  `MCPServerAdapter` — exact current tool list `UNVERIFIED` (separate repo).
- MCP: `Agent(mcps=["https://server.com/path", "notion", "...#tool_name"])` — string refs; external
  URLs and bare slugs for connected integrations; `#tool` suffix narrows to one tool.

## 3. SOURCES
- `crew.kickoff(inputs={...})` values (often from HTTP handler / CLI) interpolated into
  role/goal/backstory/description templates → **direct prompt construction from user input**.
- Tool outputs (scrapers, search, file readers, MCP tools).
- `knowledge_sources` (`StringKnowledgeSource`, `PDFKnowledgeSource`, `CrewDoclingSource` for URLs —
  `UNVERIFIED` class list) → embedded and retrieved into prompts.
- Task `context=[other_task]` outputs (inter-agent data flow).
- `allow_crewai_trigger_context` / `crewai_trigger_payload` injection (Task field) — external
  trigger payloads reach prompts.
- A2A remote agent responses (`Agent(a2a=[A2AClientConfig(...)])`).

## 4. SINKS
- **Unified memory** (`crewai.memory.Memory`, `MemoryScope`, `MemorySlice`): `remember(...)`,
  `remember_many(...)`, `extract_memories(content)`, `update(...)`, `recall(...)`, `forget`.
  Enabled by `Crew(memory=True)` / `Agent(memory=True)` (auto-saves task outputs) or explicit
  instance. Older releases used `ShortTermMemory`, `LongTermMemory`, `EntityMemory`,
  `UserMemory`/`ExternalMemory` (Mem0) — still in many repos; treat as sinks.
- Knowledge storage (embeddings of knowledge sources; vector store, Chroma by default `UNVERIFIED`).
- Flow state with `@persist`.
- Prompt sinks: `role`, `goal`, `backstory`, Task `description`/`expected_output` strings and YAML.

## 5. CONTROLS and defaults (source-verified)

| Control | Field | Default when unset |
|---|---|---|
| Agent iteration cap | `Agent.max_iter` | **25** |
| Agent timeout | `Agent.max_execution_time` | **None** (no timeout) |
| Rate limit | `Agent.max_rpm`, `Crew.max_rpm` | **None** |
| Error retries | `Agent.max_retry_limit` | **2** |
| Delegation | `Agent.allow_delegation` | **False** (older 0.x releases defaulted to True — `UNVERIFIED` exact version of flip; check lockfile) |
| Code execution | `Agent.allow_code_execution` | `False`, **deprecated**; `code_execution_mode` `"safe"`, deprecated |
| Human review | `Task.human_input` | **False** |
| Output guardrail | `Task.guardrail`/`guardrails`, `Agent.guardrail` | None; `guardrail_max_retries` **3** |
| Crew memory | `Crew.memory` | **False** |
| Agent memory | `Agent.memory` | None → falls back to crew memory |
| Tool cache | `Crew.cache` | **False** (opt-in) |
| Process | `Crew.process` | `Process.sequential` |
| Planning | `Agent.planning` | False |
| Context window | `Agent.respect_context_window` | True (summarises) |
| A2A client timeout | `A2AClientConfig.timeout` | **120 s** |
| A2A client turns | `A2AClientConfig.max_turns` | **10** |
| A2A client auth | `A2AClientConfig.auth` | **None** |
| A2A trust | `trust_remote_completion_status` | False |

## 6. Inter-agent comms
- **Delegation:** `allow_delegation=True` injects "Delegate work to coworker" / "Ask question to
  coworker" tools (names `UNVERIFIED` current) → any agent in the crew can be invoked; recursive
  delegation is bounded only by `max_iter`.
- **Hierarchical process:** `manager_llm`/`manager_agent` delegates to all agents.
- **Task context chaining:** `Task(context=[t1, t2])`.
- **A2A (native):** `Agent(a2a=[A2AClientConfig(endpoint=..., auth=..., timeout=120, max_turns=10)])`
  and `A2AServerConfig(security=[], security_schemes={}, signing_config=None,
  protocol_version="0.3.0", ...)`; JSON-RPC server default `agent_card_path="/.well-known/agent-card.json"`.
  Server `security`/`security_schemes` default **empty** → exposed agent advertises no auth.
  (See `protocols/a2a.md`.)

## 7. False-positive notes
- `allow_delegation=True` in a two-agent crew with bounded `max_iter` is a design choice; rate as
  ASI10 contributor only in capability combinations.
- `human_input=True` is the approval control — credit it for ASI09 on that task's tools.
- `kickoff(inputs=...)` with constants (CLI demo) is not user-controlled.
