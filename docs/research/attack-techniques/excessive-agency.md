# Excessive Agency

## attack

An AI agent is granted more functionality, permissions, or autonomy than its task requires. This creates an enlarged attack surface: if the agent is compromised (via prompt injection, tool poisoning, or other vectors), the attacker inherits all of the agent's excessive capabilities. Even without an external attacker, over-permissioned agents can cause harm through misalignment or unexpected behavior.

## preconditions

- Agent has access to tools or capabilities beyond what its intended task requires.
- Agent operates with credentials that grant broader access than needed.
- Agent can take high-impact actions without human approval or policy gates.
- Insufficient separation between read and write capabilities.

## attack_flow

1. Agent is deployed with broad tool access, shared credentials, or unrestricted autonomy.
2. An attacker compromises the agent (via prompt injection, tool poisoning, etc.) OR the agent misinterprets its instructions.
3. The agent uses its excessive capabilities to perform actions the operator did not intend -- accessing sensitive data, modifying systems, exfiltrating information.
4. Because the agent had legitimate access, the actions appear authorized in logs.

## observable_code_patterns

```python
# Pattern: Agent with many powerful tools
agent = create_agent(
    tools=[
        web_search, file_read, file_write, file_delete,
        database_query, database_write, database_delete,
        send_email, execute_shell, deploy_to_production,
        manage_users, access_credentials
    ]
)

# Pattern: Shared high-privilege credentials
agent_config = {
    "api_key": os.getenv("ADMIN_API_KEY"),  # admin key for a read-only task
    "database_url": os.getenv("PROD_DATABASE_URL")  # production DB for a dev task
}

# Pattern: No iteration or action limits
while not done:
    result = agent.step()  # unbounded loop with no max iterations
```

## possible_static_signals

- Large number of tools assigned to a single agent (especially mix of read and write tools).
- Destructive tools (delete, drop, send, deploy, execute) without corresponding approval gates.
- Admin or production credentials in agent configuration.
- Shell execution tools (`subprocess`, `os.system`, `exec`) available to agents.
- Absence of `max_iterations`, `max_turns`, or similar bounds on agent loops.
- Write/delete tools combined with network access tools on the same agent.

## false_positive_cases

- Development or admin agents intentionally granted broad access.
- Agents with many tools but strong per-tool authorization at the backend.
- Tools that have destructive-sounding names but are sandboxed or read-only in practice.

## false_negative_cases

- Excessive permissions granted through credential scope rather than visible tool assignment.
- Framework-level tool registration that is not visible in the scanned code.
- Dynamic tool discovery that adds capabilities at runtime.
- Permissions inherited from the runtime environment rather than explicitly configured.

## framework_examples

```python
# LangChain: Agent with excessive tools
# VULNERABLE PATTERN (illustrative)
from langchain.agents import create_react_agent
from langchain.tools import ShellTool
agent = create_react_agent(
    llm=llm,
    tools=[ShellTool(), file_tool, db_tool, email_tool]  # shell + network + data
)

# LangGraph: No iteration limit on agent loop
# VULNERABLE PATTERN (illustrative)
from langgraph.prebuilt import create_react_agent
graph = create_react_agent(model, tools)
config = {"configurable": {"thread_id": "1"}}
# No recursion_limit set -- defaults may be very high

# CrewAI: Agent with delegation and no limits
# VULNERABLE PATTERN (illustrative)
from crewai import Agent
agent = Agent(
    role="Manager",
    tools=[shell_tool, file_tool, api_tool],
    allow_delegation=True,  # can delegate to any other agent
    max_iter=None  # no iteration limit
)

# AutoGen: Code execution without constraints
# VULNERABLE PATTERN (illustrative)
from autogen import AssistantAgent, UserProxyAgent
user_proxy = UserProxyAgent(
    "user",
    human_input_mode="NEVER",  # no human oversight
    code_execution_config={"work_dir": "/", "use_docker": False}  # root FS, no sandbox
)

# OpenAI Agents SDK: Agent with broad tool access
# VULNERABLE PATTERN (illustrative)
from openai.agents import Agent
agent = Agent(
    tools=[code_interpreter, file_search, web_browse, shell_exec],
    instructions="Complete the task autonomously."
)
```

## owasp_mapping

- **Primary:** ASI10 (Rogue Agents) -- excessive agency is the precondition for rogue behavior.
- **Secondary:** ASI02 (Tool Misuse and Exploitation) -- more tools means more misuse surface.
- **Secondary:** ASI03 (Identity and Privilege Abuse) -- excessive credentials.
- **LLM Top 10:** LLM06:2025 (Excessive Agency) -- direct mapping.

## confidence

**High.** Excessive agency is directly detectable through static analysis: tool counts, tool types (destructive vs. read-only), credential configuration, iteration limits, and approval gates are all visible in code. This is one of the most promising areas for nexvul rules. The Replit incident (July 2025) demonstrates real-world impact.

## references

- OWASP Top 10 for Agentic Applications 2026 -- ASI10: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- OWASP LLM Top 10 -- LLM06 Excessive Agency: https://genai.owasp.org/llm-top-10/
- DeepInspect -- Excessive Agency: https://www.deepinspect.ai/blog/excessive-agency
- DeepInspect -- AI Agent Tool Permissions: https://www.deepinspect.ai/blog/ai-agent-tool-permissions
- Actenon Scan (static scanner): https://pypi.org/project/actenon-scan/
