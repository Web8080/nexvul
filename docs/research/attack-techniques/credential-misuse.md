# Credential Misuse

## attack

An agent operates with credentials (API keys, tokens, session cookies, service accounts) that are overly broad, improperly scoped, shared across agents, or not rotated. A compromised or manipulated agent can leverage these credentials to access resources far beyond its intended scope. The confused-deputy problem is a specific variant: a high-privilege agent acts on a low-privilege caller's request, and downstream systems see only the agent's credentials.

## preconditions

- Agent uses credentials with broader scope than the current task requires.
- Credentials are shared between agents, hardcoded, or long-lived.
- No per-task credential scoping or just-in-time issuance.
- Downstream systems authorize based on the agent's identity, not the original caller's.

## attack_flow

1. Agent is configured with overly broad credentials (admin API key, personal access token, shared service account).
2. Attacker compromises the agent (prompt injection, tool poisoning) OR a low-privilege user invokes the agent.
3. The agent makes API calls, database queries, or file accesses using its broad credentials.
4. Downstream systems authorize the actions based on the agent's identity.
5. The attacker or low-privilege user gains access to resources they should not reach.
6. Audit logs attribute the actions to the agent's identity, obscuring the actual initiator.

## observable_code_patterns

```python
# Pattern: Hardcoded or environment-loaded admin credentials
agent_config = {
    "api_key": os.getenv("ADMIN_API_KEY"),
    "database_url": os.getenv("PROD_DB_URL"),
}

# Pattern: Personal token used for agent
headers = {"Authorization": f"Bearer {os.getenv('GITHUB_TOKEN')}"}
# Token scope is whatever the developer set -- often full repo access

# Pattern: Shared credentials across agents
shared_key = os.getenv("SHARED_API_KEY")
agent_a = Agent(api_key=shared_key)
agent_b = Agent(api_key=shared_key)

# Pattern: No delegation chain -- agent acts as itself
def handle_request(user_request):
    # Agent uses its own credentials regardless of who asked
    return agent.run(user_request)  # confused deputy
```

## possible_static_signals

- Environment variable names suggesting admin or production credentials (`ADMIN_`, `PROD_`, `MASTER_`, `ROOT_`).
- Same credential variable used across multiple agent configurations.
- Hardcoded API keys or tokens in agent setup code.
- Absence of per-request credential scoping or delegation token patterns.
- Credentials loaded at module level and shared across all agent invocations.
- No credential rotation or expiration configuration.

## false_positive_cases

- Development environments where broad credentials are intentional and the environment is isolated.
- Agents that legitimately need broad access (admin tools used by administrators).
- Environment variable names that suggest admin scope but are actually scoped appropriately.

## false_negative_cases

- Credential scope determined at the identity provider level, not visible in code.
- Credentials injected through runtime environment (Kubernetes secrets, vault) without visible references.
- Implicit credentials (default service account on cloud platforms).
- Credential delegation handled by middleware not in the scanned codebase.

## framework_examples

```python
# LangChain: API key configuration
# VULNERABLE PATTERN (illustrative)
from langchain_openai import ChatOpenAI
llm = ChatOpenAI(api_key=os.getenv("OPENAI_API_KEY"))
# Key may have broader org-level access than this agent needs

# CrewAI: Shared configuration
# VULNERABLE PATTERN (illustrative)
from crewai import Crew, Agent
researcher = Agent(role="Researcher", llm_config={"api_key": shared_key})
writer = Agent(role="Writer", llm_config={"api_key": shared_key})  # same key

# MCP: Server with hardcoded credentials
# VULNERABLE PATTERN (illustrative)
{
    "mcpServers": {
        "database": {
            "command": "npx",
            "args": ["@mcp/postgres", "--connection-string", "postgres://admin:password@prod-db:5432/main"]
        }
    }
}

# AutoGen: Agent with production database access
# VULNERABLE PATTERN (illustrative)
assistant = AssistantAgent("analyst", llm_config=llm_config)
# Assistant can generate SQL that runs against production with admin credentials
```

## owasp_mapping

- **Primary:** ASI03 (Identity and Privilege Abuse).
- **Secondary:** ASI10 (Rogue Agents) -- excessive credentials enable rogue behavior.
- **LLM Top 10:** LLM06:2025 (Excessive Agency) -- excessive permissions dimension.

## confidence

**Medium.** Static detection can identify some credential misuse patterns (hardcoded credentials, overly broad environment variable names, shared credentials). However, the actual scope of credentials is determined at the identity provider level and is not visible in code. Detection is limited to heuristic patterns and configuration analysis. The confused-deputy pattern is particularly hard to detect statically because it depends on the authorization model of downstream systems.

## references

- OWASP Top 10 for Agentic Applications 2026 -- ASI03: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- Obsidian Security -- Confused Deputy: https://www.obsidiansecurity.com/confused-deputy
- Zitadel -- AI Agent Impersonation: https://zitadel.com/blog/ai-agent-impersonation
- Aembit -- AI Agent Identity Security: https://aembit.io/blog/5-security-considerations-for-managing-ai-agents-and-their-identities/
