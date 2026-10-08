# Agent Impersonation

## attack

An attacker creates a fake agent or forges the identity of a legitimate agent to infiltrate a multi-agent system. The impersonating agent can intercept messages, inject malicious instructions, exfiltrate data, or execute unauthorized actions while appearing to be a trusted component. In protocol-based systems (A2A, MCP), this can involve forging Agent Cards, spoofing discovery responses, or hijacking communication channels.

## preconditions

- Multi-agent system where agents communicate or delegate to each other.
- Insufficient agent identity verification (no cryptographic authentication, no mutual TLS, no signed messages).
- Agent discovery mechanism that can be spoofed (DNS, registry, broadcast).
- Agents trust messages from peers without verifying the sender's identity.

## attack_flow

1. Attacker identifies a multi-agent system and the communication protocol used.
2. Attacker creates a fake agent that mimics a legitimate agent's identity (name, capabilities, Agent Card).
3. Fake agent registers with the system or responds to discovery queries.
4. Legitimate agents route messages or delegate tasks to the impersonating agent.
5. Impersonating agent intercepts sensitive data, injects malicious responses, or performs unauthorized actions.
6. Actions appear to come from the legitimate agent in logs and audit trails.

## observable_code_patterns

```python
# Pattern: Agent communication without identity verification
def send_to_agent(agent_url, message):
    requests.post(agent_url, json=message)  # no auth, no identity check

# Pattern: Agent discovery without validation
def discover_agents(registry_url):
    agents = requests.get(registry_url).json()
    return agents  # no verification of agent identities

# Pattern: Trust based on self-reported identity
def handle_agent_message(message):
    sender = message["from"]  # self-reported, not verified
    if sender in trusted_agents:
        process(message)
```

## possible_static_signals

- HTTP requests to agent endpoints without authentication headers or mutual TLS.
- Agent discovery from registries without validation of returned agent metadata.
- Trust decisions based on self-reported agent names or roles rather than cryptographic identity.
- Absence of message signing or verification in inter-agent communication.
- Agent-to-agent communication over unencrypted channels (HTTP instead of HTTPS).

## false_positive_cases

- Development environments where agents communicate on localhost without auth.
- Systems where agent identity is verified at a network layer not visible in application code (service mesh, mTLS at infrastructure level).
- Internal-only agent systems behind a VPN or private network.

## false_negative_cases

- Identity verification delegated to middleware or infrastructure not in the scanned code.
- Framework-managed agent communication where the auth layer is hidden.
- Discovery through trusted registries that have their own verification.

## framework_examples

```python
# CrewAI: Delegation without identity verification
# VULNERABLE PATTERN (illustrative)
from crewai import Agent
manager = Agent(
    role="Manager",
    allow_delegation=True,  # can delegate to any agent in the crew
    # No verification that delegated-to agent is legitimate
)

# AutoGen: Group chat without agent authentication
# VULNERABLE PATTERN (illustrative)
from autogen import GroupChat, GroupChatManager
groupchat = GroupChat(
    agents=[agent_a, agent_b, agent_c],
    # No authentication between agents
    # Any agent in the group is trusted
)

# A2A Protocol: Agent Card without verification
# VULNERABLE PATTERN (illustrative)
agent_card = requests.get(f"{agent_url}/.well-known/agent.json").json()
# Card is trusted without cryptographic verification
capabilities = agent_card["capabilities"]

# MCP: Remote server without authentication
# VULNERABLE PATTERN (illustrative)
{
    "mcpServers": {
        "partner-agent": {
            "url": "https://partner.example.com/mcp"
            # No API key, no mTLS, no OAuth
        }
    }
}
```

## owasp_mapping

- **Primary:** ASI07 (Insecure Inter-Agent Communication).
- **Secondary:** ASI03 (Identity and Privilege Abuse) -- impersonation is an identity attack.
- **LLM Top 10:** No direct mapping (agent-architecture-specific).

## confidence

**Medium.** Static detection can identify the absence of authentication in inter-agent communication patterns (missing auth headers, unverified discovery, self-reported identity). However, many multi-agent systems handle identity at an infrastructure layer not visible in application code. The A2A protocol and framework-level agent communication patterns are still evolving, making detection rules fragile.

## references

- OWASP Top 10 for Agentic Applications 2026 -- ASI07: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- Zitadel -- AI Agent Impersonation: https://zitadel.com/blog/ai-agent-impersonation
- JumpCloud -- Agentic Impersonation: https://jumpcloud.com/it-index/agentic-impersonation-vs-legacy-identity-exploitation
- Habler et al. -- A2A Security Analysis: https://awesomepapers.io/papers/habler2025building
- Palo Alto Networks -- A2A Protocol Risks: https://live.paloaltonetworks.com/t5/community-blogs/safeguarding-ai-agents-an-in-depth-look-at-a2a-protocol-risks/ba-p/1235996
