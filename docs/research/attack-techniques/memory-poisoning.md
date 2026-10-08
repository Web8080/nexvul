# Memory Poisoning

## attack

An attacker plants false or malicious information in an agent's persistent memory (vector stores, long-term memory, conversation history, checkpoints, embeddings). Unlike prompt injection which affects a single interaction, memory poisoning persists across sessions -- the agent recalls the corrupted data in future tasks, altering its behavior indefinitely.

## preconditions

- Agent uses persistent memory (vector store, long-term memory, conversation store, checkpoints).
- External or untrusted content can reach the memory store (directly or via agent processing).
- Memory entries are not validated, provenance-tagged, or integrity-checked before influencing future reasoning.
- No separation between trusted and untrusted memory sources.

## attack_flow

1. Attacker identifies how content reaches the agent's memory (documents indexed into vector store, conversation history, tool outputs stored for future reference, shared knowledge bases).
2. Attacker crafts content designed to be retrieved in future sessions -- semantically similar to likely future queries.
3. Poisoned content is ingested into the memory store through a legitimate channel (indexed document, processed email, stored tool output, shared repository).
4. In a future session, the agent retrieves the poisoned memory during normal operation.
5. The agent treats the retrieved content as trusted context and follows any embedded instructions or acts on false information.

## observable_code_patterns

```python
# Pattern: External content stored in vector store without validation
web_content = requests.get(url).text
docs = text_splitter.split_text(web_content)
vectorstore.add_texts(docs)  # untrusted web content -> persistent memory

# Pattern: Tool output persisted to memory
tool_result = tool.execute(params)
memory.save_context({"input": query}, {"output": tool_result})  # unvalidated tool output -> memory

# Pattern: User input stored in long-term memory
agent_memory.add_memory(user_message)  # user-controlled content -> persistent state

# Pattern: Retrieved memory used as trusted instructions
retrieved = vectorstore.similarity_search(query)
system_prompt = f"Context: {retrieved[0].page_content}\n\nInstructions: ..."
```

## possible_static_signals

- Calls to `vectorstore.add_texts()`, `vectorstore.add_documents()`, `memory.save_context()`, `memory.add_memory()`, or equivalent, where the input originates from untrusted sources (HTTP responses, user input, tool outputs, external documents).
- Absence of validation, sanitization, or provenance tagging between data ingestion and memory storage.
- Retrieved memory content injected into system prompts or treated as instructions.
- Shared memory stores accessed by multiple agents without access controls.
- No TTL, expiration, or audit mechanism on stored memories.

## false_positive_cases

- Legitimate knowledge-base construction from trusted, access-controlled sources.
- Memory stores populated only from vetted internal documents.
- Development/test environments with seed data.
- Memory systems with robust provenance tracking and validation.

## false_negative_cases

- Memory poisoning through multi-hop paths (content processed by one agent, then stored by another).
- Poisoned content that is semantically valid but factually false -- hard to detect statically.
- Framework-level memory management that hides the storage call.
- Cross-agent memory sharing through shared databases not visible in the code being scanned.

## framework_examples

```python
# LangChain: ConversationBufferMemory stores unvalidated content
# VULNERABLE PATTERN (illustrative)
from langchain.memory import ConversationBufferMemory
memory = ConversationBufferMemory()
memory.save_context(
    {"input": user_query},
    {"output": agent_response}  # if agent_response includes tool output from untrusted source
)

# LangChain: FAISS vectorstore populated from web scraping
# VULNERABLE PATTERN (illustrative)
from langchain.vectorstores import FAISS
from langchain.document_loaders import WebBaseLoader
loader = WebBaseLoader("https://untrusted-source.example.com")
docs = loader.load()
vectorstore = FAISS.from_documents(docs, embeddings)  # untrusted web content -> persistent index

# LangGraph: checkpoint persists state including tool results
# VULNERABLE PATTERN (illustrative)
from langgraph.checkpoint.memory import MemorySaver
checkpointer = MemorySaver()
graph = create_graph().compile(checkpointer=checkpointer)
# Tool results persist in checkpointed state across sessions

# CrewAI: long-term memory enabled
# VULNERABLE PATTERN (illustrative)
from crewai import Crew
crew = Crew(
    agents=[researcher, writer],
    memory=True,  # enables persistent memory without provenance controls
    long_term_memory=True
)

# AutoGen: teachable agent stores lessons from conversations
# VULNERABLE PATTERN (illustrative)
from autogen.agentchat.contrib import TeachableAgent
agent = TeachableAgent("learner", llm_config=llm_config)
# Agent learns from conversation and stores lessons -- content could be attacker-controlled
```

## owasp_mapping

- **Primary:** ASI06 (Memory & Context Poisoning).
- **Secondary:** ASI01 (Agent Goal Hijack) -- poisoned memory can redirect goals in future sessions.
- **LLM Top 10:** LLM04:2025 (Data and Model Poisoning), LLM08:2025 (Vector and Embedding Weaknesses).

## confidence

**High.** Memory poisoning is well-documented in academic research (PoisonedRAG at USENIX Security 2025, MemoryGraft, MINJA, AgentPoison). The Gemini Memory Attack demonstrated real-world impact. Static detection of untrusted content flowing into persistent memory stores is feasible -- this is a taint-analysis problem (untrusted source -> memory sink) that nexvul is designed to handle.

## references

- OWASP Top 10 for Agentic Applications 2026 -- ASI06: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- PoisonedRAG (USENIX Security 2025): academic paper on RAG corpus poisoning
- MemoryGraft: https://arxiv.org/html/2512.16962
- Memory poisoning analysis: https://workos.com/blog/ai-agent-memory-poisoning
- Pillar Security -- Agent Memory and Context Poisoning: https://www.pillar.security/sail/agent-memory-and-context-poisoning
- Security Scientist -- RAG Poisoning: https://www.securityscientist.net/blog/rag-poisoning/
