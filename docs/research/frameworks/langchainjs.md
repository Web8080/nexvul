# LangChain.js / LangGraph.js — Brief Recogniser Research

> Researched 2026-10-08 from source: `langchain-ai/langchainjs` `libs/langchain` **1.5.15**;
> `langchain-ai/langgraphjs`. Docs: https://docs.langchain.com/oss/javascript/ .

## Construction
- `createAgent({ model, tools, systemPrompt, middleware, checkpointer, store, ... })` from
  `"langchain"` (returns a LangGraph agent; `agent.withConfig({ recursionLimit })`).
- LangGraph.js: `StateGraph`, `Annotation.Root`, `START`, `END`, `Command`, `Send`, `interrupt`
  (`@langchain/langgraph`); `MemorySaver`/`InMemoryStore`; `createReactAgent` from
  `@langchain/langgraph/prebuilt` (legacy).
- Legacy: `AgentExecutor` (`langchain/agents`), `maxIterations` default 15 `UNVERIFIED` for JS.

## Tools
`tool(fn, { name, description, schema: z.object(...) })` from `@langchain/core/tools` (also
re-exported by `langchain`), `DynamicStructuredTool`, `StructuredTool` subclasses; MCP via
`@langchain/mcp-adapters` `MultiServerMCPClient` (`UNVERIFIED`).

## SOURCES / SINKS
- Sources: `CheerioWebBaseLoader`, `PuppeteerWebBaseLoader`, `RecursiveUrlLoader`
  (`@langchain/community/document_loaders/web/*`), retrievers, tool outputs, request bodies.
- Sinks: `vectorStore.addDocuments`, `addVectors`, `fromDocuments`, `fromTexts`; checkpointers
  (`MemorySaver`, `@langchain/langgraph-checkpoint-postgres` `PostgresSaver`, sqlite); `store.put`;
  `systemPrompt` construction.

## CONTROLS and defaults

| Control | API | Default when unset |
|---|---|---|
| Step limit (LangGraph.js) | `{ recursionLimit }` in invoke/stream config | **25** (`DEFAULT_RECURSION_LIMIT = 25` in `langgraphjs/libs/langgraph/src/constants.ts`, source-verified 2026-10-08) — differs from Python ≥1.0.6 |
| `createAgent` limit | inherits graph config unless `withConfig` | 25 assumed — whether `createAgent` overrides (as Python sets 9999) `UNVERIFIED` |
| Middleware (exports in `src/agents/middleware/index.ts`) | `modelCallLimitMiddleware`, `toolCallLimitMiddleware`, `modelRetryMiddleware`, `toolRetryMiddleware`, `piiMiddleware`, `piiRedactionMiddleware`, `llmToolSelectorMiddleware`, `openAIModerationMiddleware`, `summarizationMiddleware`, `contextEditingMiddleware`, `dynamicSystemPromptMiddleware`, `todoListMiddleware`, `toolErrorMiddleware`, `modelFallbackMiddleware` | defaults assumed to mirror Python (no limits) — `UNVERIFIED` |
| Human approval | `humanInTheLoopMiddleware({ interruptOn })` — not in that index file; export location `UNVERIFIED`; LangGraph `interrupt()` confirmed in docs | none |

## FP notes
Same as Python (`langchain.md`, `langgraph.md`); note the 25 vs ~10k recursion-default divergence
between JS and Python when writing ASI08 messages.
