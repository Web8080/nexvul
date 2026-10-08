# Context Poisoning

## attack

An attacker manipulates the runtime context of an AI agent -- the information available during a single session or reasoning cycle -- to alter its behavior. Unlike memory poisoning (which persists across sessions), context poisoning targets the current execution context: system prompts, conversation history, retrieved documents, tool outputs, or environment variables that shape the agent's decisions in the current interaction.

## preconditions

- Agent assembles context from multiple sources (system prompts, user input, tool outputs, retrieved documents, environment variables, configuration).
- At least one context source is attacker-controllable or attacker-influenceable.
- Agent does not enforce trust boundaries between context sources of different provenance.

## attack_flow

1. Attacker identifies which context sources the agent consumes during a session.
2. Attacker manipulates one or more sources: injects content into a shared document, poisons a tool response, modifies an environment variable, or crafts a conversation history.
3. The poisoned context enters the agent's reasoning alongside trusted context.
4. The agent's decisions are influenced by the poisoned context -- it may take different actions, produce different outputs, or bypass controls.

## observable_code_patterns

```python
# Pattern: Context assembled from mixed-trust sources without separation
context = system_prompt + retrieved_docs + tool_outputs + user_input
response = llm.generate(context)  # all sources treated equally

# Pattern: Environment variables in prompts
import os
system_prompt = f"You are an agent for {os.getenv('COMPANY_NAME')}. API key: {os.getenv('API_KEY')}"

# Pattern: Conversation history from shared/external source
history = database.get_conversation(session_id)  # could be tampered
messages = history + [{"role": "user", "content": current_input}]
```

## possible_static_signals

- Context assembly from multiple sources without trust-level tagging or separation.
- Environment variables or configuration values interpolated into prompts.
- Conversation history loaded from external stores without integrity verification.
- Retrieved documents concatenated with system instructions in the same message.
- Absence of context-source attribution in the message construction.

## false_positive_cases

- Legitimate multi-source context assembly with proper trust boundaries.
- Environment variables used for non-sensitive configuration (model name, temperature).
- Conversation history from authenticated, integrity-protected stores.

## false_negative_cases

- Context poisoning through framework-managed context (not visible in user code).
- Poisoning through side channels (timing, ordering of context elements).
- Subtle factual manipulation that does not contain obvious directive language.

## framework_examples

```python
# LangChain: Multiple context sources combined
# VULNERABLE PATTERN (illustrative)
from langchain.prompts import ChatPromptTemplate
prompt = ChatPromptTemplate.from_messages([
    ("system", system_instructions),
    ("system", f"Reference data: {retrieved_context}"),  # mixed trust levels
    ("human", "{user_input}")
])

# LangGraph: State accumulates context from multiple nodes
# VULNERABLE PATTERN (illustrative)
def process_node(state):
    # State contains outputs from previous nodes, some of which processed untrusted content
    combined = state["system_context"] + state["tool_results"] + state["user_messages"]
    return {"response": llm.invoke(combined)}

# CrewAI: Agent context includes outputs from other agents
# VULNERABLE PATTERN (illustrative)
task = Task(
    description="Analyze the data",
    context=[previous_task],  # output from previous task may be tainted
    agent=analyst
)
```

## owasp_mapping

- **Primary:** ASI06 (Memory & Context Poisoning) -- the context dimension.
- **Secondary:** ASI01 (Agent Goal Hijack) -- context poisoning can redirect agent goals.
- **LLM Top 10:** LLM01:2025 (Prompt Injection).

## confidence

**Medium.** Context poisoning overlaps significantly with indirect prompt injection and memory poisoning. The distinction is temporal (single session vs. persistent) and architectural (runtime context assembly vs. storage). Static detection of mixed-trust context assembly is partially feasible but requires understanding the trust level of each source, which is often not expressible in code alone.

## references

- OWASP Top 10 for Agentic Applications 2026 -- ASI06: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- Pillar Security -- Agent Memory and Context Poisoning: https://www.pillar.security/sail/agent-memory-and-context-poisoning
