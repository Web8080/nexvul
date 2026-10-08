# Vercel AI SDK (TypeScript) — Brief Recogniser Research

> Researched 2026-10-08 from source `vercel/ai` main: package `ai` **7.0.133**, `@ai-sdk/mcp` 2.0.71.
> Docs: https://ai-sdk.dev/docs . Major-version API churn is high (v4 → v5 → v6 → v7): recognisers
> must branch on the resolved `ai` version from `package-lock.json`/`pnpm-lock.yaml`.

## Construction
- Core calls: `generateText({ model, system, prompt|messages, tools, stopWhen, maxRetries, timeout,
  abortSignal })`, `streamText(...)`, `generateObject`, `streamObject`.
- Agent class: `new ToolLoopAgent({ model, instructions?, tools, stopWhen })` (v6+; deprecated alias
  `Experimental_Agent`); `agent.generate(...)`, `agent.stream(...)`.
- v4: `maxSteps` option instead of `stopWhen`.

## Tools
`tool({ description, inputSchema: z.object(...), execute, needsApproval? })` (`inputSchema` in
v5+; `parameters` in v4). Tools without `execute` are client-side (forwarded to UI). Provider tools
(`openai.tools.webSearch()`, `anthropic.tools.bash_*`, computer use) — names `UNVERIFIED`.
MCP: `createMCPClient` / `experimental_createMCPClient({ transport })` from `@ai-sdk/mcp` (or `ai`
in v4/v5) → `await client.tools()` — names `UNVERIFIED` per version.

## SOURCES / SINKS
- Sources: request body in Next.js route handlers (`await req.json()` → `messages`), `useChat`
  client messages (fully user-controlled, including forged `assistant`/`tool` roles), tool results,
  MCP tools, fetch()-based tools.
- Sinks: no built-in memory/vector store — persistence is app code (`saveChat`, DB writes in
  `onFinish`), embeddings via `embed`/`embedMany` then user-chosen vector DB `upsert`. `system:`
  string construction from retrieved data.

## CONTROLS and defaults (source-verified, v7 main)

| Control | API | Default when unset |
|---|---|---|
| Step limit (`generateText`/`streamText`) | `stopWhen` | **`isStepCount(1)`** — single step (no tool loop) |
| Step limit (`ToolLoopAgent`) | `stopWhen` | **`isStepCount(20)`** |
| Unbounded loop marker | `stopWhen: isLoopFinished()` (exported stop condition) | explicit — loop until model stops |
| Stop helpers | `isStepCount(n)`, `hasToolCall(name)`, `isLoopFinished()`; v5/v6 name `stepCountIs(n)` (`UNVERIFIED` whether v7 keeps alias) | — |
| Retries | `maxRetries` | **2** ("Set to 0 to disable") |
| Timeout | `timeout` (ms), `abortSignal` | **none** |
| Tool approval | `tool({ needsApproval })` | none |
| v4 | `maxSteps` | **1** (`UNVERIFIED` from memory; confirm against v4 tag) |

Source: https://github.com/vercel/ai/blob/main/packages/ai/src/generate-text/generate-text.ts ,
`src/agent/tool-loop-agent.ts`, `src/generate-text/stop-condition.ts`,
`packages/provider-utils/src/types/tool.ts`.

## FP notes
`stopWhen: isStepCount(50)` is bounded — rate ASI08 only on `isLoopFinished()` or absurd counts
combined with high-impact tools. Next.js route handlers lacking auth are an app concern; only
relevant when they expose tool-executing agents.
