# LangChain (Python) — Framework Recogniser Research

> Researched 2026-10-08 against `langchain` 1.x (package `libs/langchain_v1` on master), legacy
> `langchain-classic`, `langchain-core`, `langchain-community` (now in its own repo
> `langchain-ai/langchain-community`). Docs: https://docs.langchain.com/oss/python/langchain/ .
> `UNVERIFIED` = not confirmed this pass.

## 1. Agent construction (three eras — recognise all)

| Era | API | Import | Status |
|---|---|---|---|
| v1 (current) | `create_agent(model, tools=None, *, system_prompt=None, middleware=(), response_format=None, state_schema=None, context_schema=None, checkpointer=None, store=None, interrupt_before=None, interrupt_after=None, debug=False, name=None, cache=None, ...)` | `langchain.agents` | Returns a compiled LangGraph `CompiledStateGraph` → LangGraph controls apply |
| LangGraph prebuilt | `create_react_agent(...)` | `langgraph.prebuilt` | Deprecated in favour of `create_agent` |
| Legacy (0.x) | `AgentExecutor(agent=, tools=, max_iterations=, max_execution_time=, early_stopping_method=, handle_parsing_errors=, return_intermediate_steps=)`; constructors `create_tool_calling_agent`, `create_react_agent` (LC), `create_openai_functions_agent`, `initialize_agent` | `langchain.agents` (0.x) → `langchain_classic.agents` (v1) | Legacy; still pervasive in OSS repos |

Sources: https://docs.langchain.com/oss/python/langchain/agents ; source
https://github.com/langchain-ai/langchain/blob/master/libs/langchain_v1/langchain/agents/factory.py ,
https://github.com/langchain-ai/langchain/blob/master/libs/langchain/langchain_classic/agents/agent.py

## 2. Tool definition / registration / invocation
- `@tool` decorator (`langchain.tools` in v1 docs; `langchain_core.tools` canonical) — function
  docstring becomes the description; `@tool("name", return_direct=..., args_schema=...)`.
- `StructuredTool.from_function(func=, name=, description=, args_schema=)`, `BaseTool` subclass with
  `_run`/`_arun`, `Tool(name, func, description)` (legacy).
- Registration: `tools=[...]` list into `create_agent` / `AgentExecutor`; `model.bind_tools(tools)`.
- Invocation: model emits `tool_calls`; executed by the agent loop (`ToolNode` inside create_agent),
  or manually `tool.invoke({...})`.
- Toolkits: `FileManagementToolkit(root_dir=, selected_tools=)`, `RequestsToolkit(requests_wrapper=,
  allow_dangerous_requests=)`, `SQLDatabaseToolkit`, `OpenAPIToolkit` (`langchain_community.agent_toolkits`).
- High-risk built-ins: `ShellTool` (`langchain_community.tools`), `PythonREPLTool`
  (`langchain_experimental.tools`), `RequestsGetTool/PostTool/...` (`langchain_community.tools.requests.tool`)
  which **raise unless `allow_dangerous_requests=True`** (source-verified, default `False`);
  `ShellToolMiddleware(workspace_root=tmpdir, execution_policy=host, shell_command="/bin/bash")`.

## 3. SOURCES (untrusted data)
- Web loaders: `WebBaseLoader`, `RecursiveUrlLoader`, `AsyncHtmlLoader`, `SitemapLoader`,
  `PlaywrightURLLoader`, `UnstructuredURLLoader` (`langchain_community.document_loaders`) →
  `.load()`, `.lazy_load()`, `.aload()` return `Document`s.
- HTTP tools/wrappers: `RequestsWrapper`, `TextRequestsWrapper`, requests tools, `TavilySearch`,
  `DuckDuckGoSearchRun`, `SerpAPIWrapper`, `BraveSearch` (module paths vary → resolve via imports).
- Retrievers: `vectorstore.as_retriever(...).invoke(q)`, `similarity_search*`, `max_marginal_relevance_search`,
  `MultiQueryRetriever`, `EnsembleRetriever` — retrieved docs are untrusted if the store ingests
  external content.
- Tool outputs: return values of any tool; `ToolMessage.content`; `intermediate_steps`.
- User input: `agent.invoke({"messages": [...]})` / `executor.invoke({"input": ...})` fed from a
  request handler.
- MCP tools: `langchain_mcp_adapters` (`MultiServerMCPClient`, `load_mcp_tools`) — names `UNVERIFIED`.

## 4. SINKS
- **Vector store writes:** `add_documents`, `aadd_documents`, `add_texts`, `aadd_texts`,
  `from_documents`, `from_texts`, `afrom_*`, `upsert` (some stores), `add_embeddings` (FAISS)
  on any `VectorStore` subclass (`Chroma`, `FAISS`, `PGVector`, `Pinecone`/`PineconeVectorStore`,
  `Qdrant`/`QdrantVectorStore`, `Weaviate`, `Milvus`, `ElasticsearchStore`, `InMemoryVectorStore`, ...).
  Also `index(docs, record_manager, vector_store)` (`langchain.indexes`/`langchain_core.indexing`).
- **Legacy memory** (`langchain_classic.memory`): `ConversationBufferMemory`,
  `ConversationSummaryMemory`, `VectorStoreRetrieverMemory`, `.save_context(inputs, outputs)`;
  chat history stores `RedisChatMessageHistory`, `SQLChatMessageHistory`,
  `PostgresChatMessageHistory`, `.add_message/.add_messages/.add_user_message/.add_ai_message`;
  `RunnableWithMessageHistory(get_session_history=...)`.
- **v1 memory:** `create_agent(checkpointer=..., store=...)` → LangGraph sinks (see `langgraph.md`).
- **System-prompt construction:** `system_prompt=` (str or `SystemMessage`) built from f-strings /
  `.format()` / `ChatPromptTemplate.from_messages([("system", "...{var}...")])` where `var` is
  retrieved/tool/user content ("retrieved content promoted to trusted instructions", ASI06).
- Dynamic system prompt middleware `@dynamic_prompt` — `UNVERIFIED` decorator name this pass.

## 5. CONTROLS and defaults

| Control | API | Default when unset |
|---|---|---|
| Iteration limit (legacy) | `AgentExecutor(max_iterations=)` | **15** (source: `max_iterations: int | None = 15`); `None` = unlimited |
| Wall-clock (legacy) | `AgentExecutor(max_execution_time=)` | **None** (no timeout) |
| Early stop (legacy) | `early_stopping_method` | `"force"` |
| Step limit (v1 `create_agent`) | inherits LangGraph; factory hard-sets `{"recursion_limit": 9_999}` via `with_config` (source comment links langgraph#7313) | **9999** unless caller overrides in `invoke(config=...)` |
| Model-call cap | `ModelCallLimitMiddleware(thread_limit=, run_limit=, exit_behavior="end")` | no limit |
| Tool-call cap | `ToolCallLimitMiddleware(tool_name=None, thread_limit=, run_limit=, exit_behavior="continue")` | no limit |
| Retries | `ModelRetryMiddleware` / `ToolRetryMiddleware(max_retries=2, backoff_factor=2.0, initial_delay=1.0, max_delay=60.0, jitter=True, on_failure="continue")` | middleware absent ⇒ no framework retry (model client may retry; e.g. OpenAI client `max_retries` – provider-specific) |
| Human approval | `HumanInTheLoopMiddleware(interrupt_on={"tool_name": True | {"allowed_decisions": ["approve","edit","reject"]}})` — requires checkpointer | none |
| PII guard | `PIIMiddleware(pii_type, strategy="redact", apply_to_input=True, apply_to_output=False, apply_to_tool_results=False)` | tool results NOT scanned by default |
| Tool selection | `LLMToolSelectorMiddleware(max_tools=None)` | no limit |
| Dangerous HTTP opt-in | `allow_dangerous_requests` | `False` (setting `True` is a strong signal) |
| Legacy approval | `HumanApprovalCallbackHandler` (`langchain_community.callbacks`) — `UNVERIFIED` current path | none |

Middleware source: https://docs.langchain.com/oss/python/langchain/middleware/built-in (import
`from langchain.agents.middleware import ...`).

## 6. Inter-agent comms
Sub-agents as tools (an agent's `.invoke` wrapped in `@tool`), handoffs via state/`Command`,
router, skills (docs: https://docs.langchain.com/oss/python/langchain/multi-agent). Deep Agents
(`deepagents`) for planning/sub-agents/filesystem — `create_deep_agent` name `UNVERIFIED`.

## 7. False-positive notes
- `max_iterations=None` is explicit unbounded → high-signal; *missing* `max_iterations` on
  AgentExecutor is bounded (15) → do **not** flag as unbounded.
- `create_agent` without explicit limit is bounded at 9999 steps — practically unbounded for cost /
  cascading (ASI08) but not infinite; message should say so precisely.
- Ingesting the project's own static docs into a vector store (`DirectoryLoader("./docs")`) is not
  external-content poisoning; restrict ASI06 sources to network/user/tool-output origins.
- `ShellTool` in a sandboxed container is still flagged for capability combination but with context.
