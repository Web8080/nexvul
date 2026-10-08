# Indirect Prompt Injection

## attack

An attacker embeds malicious instructions in content an AI agent processes (documents, web pages, tool outputs, emails, database records) rather than in direct user input. The agent's LLM cannot reliably distinguish data from instructions when both arrive through the same channel, so the injected instructions are treated as legitimate directives.

## preconditions

- Agent processes external or untrusted content (web pages, documents, tool responses, emails, database records).
- Processed content reaches the LLM's context window alongside system instructions or user messages.
- Agent has tools or capabilities that can produce side effects (file access, API calls, data exfiltration).
- No content sanitization or trust-boundary enforcement between data ingestion and LLM reasoning.

## attack_flow

1. Attacker identifies content sources the agent reads (URLs, documents, tool outputs, shared repositories).
2. Attacker crafts payload with instructions hidden in that content (invisible text, comment fields, metadata, Unicode tricks, or natural-language directives).
3. Agent retrieves or receives the poisoned content during normal operation.
4. Content enters the LLM context alongside legitimate instructions.
5. LLM follows injected instructions -- may call tools, exfiltrate data, modify behavior, or suppress warnings.
6. Agent executes the attacker's intent using its legitimate capabilities.

## observable_code_patterns

```python
# Pattern: External content flows directly into LLM context without sanitization
response = requests.get(url)
result = agent.run(response.text)  # untrusted web content -> LLM

# Pattern: Tool output consumed without validation
tool_result = tool.execute(params)
messages.append({"role": "tool", "content": tool_result})  # unvalidated tool output -> context

# Pattern: RAG retrieval piped into system/user messages
docs = vectorstore.similarity_search(query)
context = "\n".join([d.page_content for d in docs])
prompt = f"Use this context: {context}\n\nAnswer: {query}"
```

## possible_static_signals

- External HTTP responses or file reads flowing into LLM invocation arguments without intermediate validation or sanitization calls.
- Tool output concatenated directly into prompt strings or message lists.
- Retrieved documents (from vector stores, databases) injected into system prompts or user messages.
- Absence of content-type checking, length limiting, or character filtering between data source and LLM call.

## false_positive_cases

- Legitimate RAG pipelines that intentionally feed retrieved documents into context (this is the intended use case; the risk is in the absence of trust boundaries, not in the retrieval itself).
- Internal-only document retrieval where all sources are trusted and access-controlled.
- Tool outputs from trusted, self-hosted tools with validated schemas.

## false_negative_cases

- Injection via metadata fields not visible in code (HTTP headers, PDF metadata, image EXIF).
- Multi-hop injection: content passes through intermediate processing that obscures the data flow.
- Injection through framework abstractions that hide the data path (e.g., LangChain's built-in document loaders).
- Encoded payloads (Base64, Unicode homoglyphs, zero-width characters) that bypass string-level checks.

## framework_examples

```python
# LangChain: RetrievalQA chain -- documents from vectorstore reach LLM directly
# VULNERABLE PATTERN (illustrative)
from langchain.chains import RetrievalQA
qa = RetrievalQA.from_chain_type(llm=llm, retriever=vectorstore.as_retriever())
result = qa.invoke(user_query)  # retrieved docs may contain injected instructions

# LangGraph: tool node passes tool output into state without filtering
# VULNERABLE PATTERN (illustrative)
def tool_node(state):
    tool_result = call_tool(state["pending_tool_call"])
    return {"messages": state["messages"] + [{"role": "tool", "content": tool_result}]}

# CrewAI: agent with web search tool
# VULNERABLE PATTERN (illustrative)
from crewai import Agent, Task
researcher = Agent(
    role="Researcher",
    tools=[web_search_tool],  # web content reaches agent context unfiltered
    allow_delegation=True
)

# OpenAI Agents SDK: agent processes external content
# VULNERABLE PATTERN (illustrative)
from openai.agents import Agent, WebSearchTool
agent = Agent(
    tools=[WebSearchTool()],
    instructions="Research and summarize the topic."
)
# Web search results enter the agent's context directly

# MCP: tool response contains injected instructions
# VULNERABLE PATTERN (illustrative, server-side)
# See insecure-mcp.md for the full MCP tool poisoning pattern
```

## owasp_mapping

- **Primary:** ASI01 (Agent Goal Hijack) -- indirect prompt injection is the primary mechanism for goal hijacking.
- **Secondary:** ASI06 (Memory & Context Poisoning) -- when injected content persists in memory.
- **LLM Top 10:** LLM01:2025 (Prompt Injection).

## confidence

**High.** Indirect prompt injection is the most well-documented attack against AI agents. Multiple academic papers (PoisonedRAG at USENIX Security 2025, MemoryGraft, MINJA), real-world CVEs (CVE-2025-53773 GitHub Copilot CVSS 9.6, CVE-2025-54135 CurXecute), and OWASP's own classification confirm this as a primary threat. Static detection of the data flow from untrusted source to LLM context is feasible, though evasion through framework abstractions is a significant false-negative risk.

## references

- OWASP Top 10 for Agentic Applications 2026 -- ASI01: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- OWASP LLM Top 10 -- LLM01 Prompt Injection: https://genai.owasp.org/llm-top-10/
- PoisonedRAG (USENIX Security 2025): academic paper on RAG corpus poisoning
- MemoryGraft: https://arxiv.org/html/2512.16962
- Prompt Injection Defense Guide: https://www.getmaxim.ai/articles/prompt-injection-defense-for-production-ai-agents-a-complete-2026-guide/
- Indirect Prompt Injection overview: https://zealynx.io/glossary/indirect-prompt-injection
