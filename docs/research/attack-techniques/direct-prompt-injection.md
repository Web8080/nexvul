# Direct Prompt Injection

## attack

An attacker provides crafted input directly to an AI agent through the user-facing interface (chat, API, form field) to override the system prompt, extract hidden instructions, bypass safety controls, or cause the agent to perform unintended actions. Unlike indirect injection, the attacker is the direct user of the system.

## preconditions

- Agent accepts user input that reaches the LLM context.
- Agent relies on system-prompt-level restrictions rather than backend enforcement for access control.
- Agent has tools or capabilities that the user should not be able to invoke directly.

## attack_flow

1. Attacker interacts with the agent through its normal user interface.
2. Attacker crafts input designed to override system instructions (e.g., "Ignore previous instructions and...").
3. LLM processes the injected instructions alongside or in place of system instructions.
4. Agent performs actions the system prompt was designed to prevent (data disclosure, tool misuse, safety bypass).

## observable_code_patterns

```python
# Pattern: User input concatenated into prompt without separation
prompt = f"{system_prompt}\n\nUser: {user_input}\n\nAssistant:"
response = llm.generate(prompt)

# Pattern: No input validation before LLM invocation
user_message = request.body["message"]
result = agent.run(user_message)  # raw user input -> agent

# Pattern: System prompt as sole access control
system_prompt = "You are a customer service agent. Never reveal internal data."
# No backend enforcement of this restriction
```

## possible_static_signals

- User input concatenated directly into prompt templates without sanitization.
- Absence of input validation or filtering before LLM invocation.
- Security-critical restrictions expressed only in system prompts with no backend enforcement.
- String formatting or f-strings that embed user input into prompt strings.

## false_positive_cases

- Legitimate prompt templates that use user input as data (the risk is in the absence of enforcement, not in the template pattern itself).
- Applications where the user is intentionally given full control over the prompt (development tools, prompt playgrounds).
- Systems with robust backend enforcement that makes the system prompt a defense-in-depth layer rather than the sole control.

## false_negative_cases

- User input that passes through preprocessing that appears safe but does not block injection.
- Encoded or obfuscated injection payloads.
- Multi-turn attacks that gradually shift context across multiple messages.
- Framework abstractions that hide the prompt construction.

## framework_examples

```python
# LangChain: ChatPromptTemplate with user input
# VULNERABLE PATTERN (illustrative)
from langchain.prompts import ChatPromptTemplate
prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a helpful assistant. Never run delete commands."),
    ("human", "{user_input}")  # system-prompt-only restriction
])
chain = prompt | llm | output_parser

# AutoGen: UserProxyAgent accepts user messages
# VULNERABLE PATTERN (illustrative)
from autogen import UserProxyAgent, AssistantAgent
user_proxy = UserProxyAgent("user", human_input_mode="NEVER")
# Agent processes input without validation; system message is sole guardrail

# OpenAI Agents SDK: instructions as sole control
# VULNERABLE PATTERN (illustrative)
agent = Agent(
    instructions="Never access files outside /public/",
    tools=[file_read_tool, file_write_tool]
)
# File access restriction is prompt-level only, not enforced in tool implementation
```

## owasp_mapping

- **Primary:** ASI01 (Agent Goal Hijack) -- direct prompt injection is a goal-hijacking vector.
- **Secondary:** ASI02 (Tool Misuse and Exploitation) -- when injection leads to misuse of legitimate tools.
- **LLM Top 10:** LLM01:2025 (Prompt Injection).

## confidence

**High.** Direct prompt injection is the foundational LLM attack. However, it is less relevant to agentic-specific scanning than indirect injection because it requires the attacker to be the direct user. For nexvul, the static signal is primarily the absence of backend enforcement for restrictions expressed in system prompts.

## references

- OWASP LLM Top 10 -- LLM01 Prompt Injection: https://genai.owasp.org/llm-top-10/
- OWASP Top 10 for Agentic Applications 2026 -- ASI01: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
