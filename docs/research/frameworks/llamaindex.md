# LlamaIndex (Python) — Brief Recogniser Research

> Researched 2026-10-08 from source `run-llama/llama_index` main, `llama-index-core` **0.14.25**;
> `llama-index-workflows` (`run-llama/workflows-py`). Docs: https://docs.llamaindex.ai/ .

## Construction
- Workflow agents (`llama_index.core.agent.workflow`): `FunctionAgent`, `ReActAgent`,
  `CodeActAgent`, `AgentWorkflow`, `BaseWorkflowAgent`; e.g.
  `FunctionAgent(name=, description=, system_prompt=, tools=[...], llm=, can_handoff_to=[...])`;
  `await agent.run(user_msg=..., ctx=Context(agent), max_iterations=?)`.
- Multi-agent: `AgentWorkflow(agents=[...], root_agent="name", timeout=None)`; built-in `handoff(ctx,
  to_agent, reason)` tool restricted by each agent's `can_handoff_to`.
- Legacy (pre-0.12): `ReActAgent.from_tools(...)`, `OpenAIAgent`, `AgentRunner` — `max_iterations`
  default 10 in legacy ReAct (`UNVERIFIED`, check lockfile).
- Custom `Workflow` subclasses with `@step` (event-driven; cycles possible).

## Tools
`FunctionTool.from_defaults(fn=, name=, description=, return_direct=False)`,
`QueryEngineTool.from_defaults(query_engine, name, description)`, `ToolSpec` classes from
`llama-index-tools-*` (e.g. requests, code interpreter); plain callables are auto-wrapped.
`McpToolSpec`/`BasicMCPClient` (`llama-index-tools-mcp`) — `UNVERIFIED`.

## SOURCES
Readers: `SimpleWebPageReader`, `BeautifulSoupWebReader`, `TrafilaturaWebReader`
(`llama-index-readers-web`), `SimpleDirectoryReader` (local; lower risk); retrievers
`index.as_retriever().retrieve(q)`, `index.as_query_engine().query(q)`; tool outputs
(`ToolCallResult`); `agent.run(user_msg=...)` input.

## SINKS
- Index writes: `VectorStoreIndex.from_documents(docs)`, `index.insert(doc)`, `index.insert_nodes`,
  `index.refresh_ref_docs`; vector stores `vector_store.add(nodes)`; ingestion
  `IngestionPipeline(...).run(documents=...)` with `vector_store=`; `storage_context.persist()`.
- Memory: `llama_index.core.memory.Memory` (`Memory.from_defaults(session_id=, token_limit=)`),
  memory blocks (`StaticMemoryBlock`, `FactExtractionMemoryBlock`, `VectorMemoryBlock`) persisting
  to SQL (`async_database_uri`) — names `UNVERIFIED` beyond `Memory`; legacy `ChatMemoryBuffer`.
- `Context` serialisation `ctx.to_dict()` → persisted by user code.
- `system_prompt=` construction.

## CONTROLS and defaults (source-verified)

| Control | API | Default when unset |
|---|---|---|
| Agent iterations | `run(..., max_iterations=)` | **20** (`DEFAULT_MAX_ITERATIONS = 20` in `agent/workflow/base_agent.py`; same constant used by `AgentWorkflow`) |
| Agent/AgentWorkflow timeout | `FunctionAgent(timeout=)`, `AgentWorkflow(timeout=)` | **None** (explicitly passed to `Workflow.__init__`) |
| Plain `Workflow` timeout | `Workflow(timeout=)` | **45.0 s** (workflows-py `workflow.py`) |
| Handoff restriction | `can_handoff_to=[...]` | `None` ⇒ may hand off to any agent (inferred from `handoff()` check: only restricts when set) |
| Human in the loop | `InputRequiredEvent` / `HumanResponseEvent` via `ctx.wait_for_event` | none |
| Tool return_direct | `FunctionTool(return_direct=False)` | False |

## FP notes
Ingesting local docs at build time is not ASI06; flag only network/user/tool-derived content
reaching `insert`/`from_documents`/`vector_store.add`.
