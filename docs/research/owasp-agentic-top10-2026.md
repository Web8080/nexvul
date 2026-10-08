# OWASP Top 10 for Agentic Applications (2026)

> Verified against primary and high-quality secondary OWASP GenAI Security Project sources.
> Research date: 2026-10-08.

## Publication Details

- **Title:** OWASP Top 10 for Agentic Applications for 2026
- **Published:** December 9, 2025 (edition labeled 2026)
- **Publisher:** OWASP GenAI Security Project (genai.owasp.org)
- **Contributors:** More than 100 industry experts, researchers, and practitioners (per OWASP's own description)
- **Version:** The initial release is labeled 2026. A "State of Agentic AI Security and Governance 2.01" document dated June 2026 exists as a companion, but the Top 10 list version is unconfirmed beyond the 2026 edition label.
- **Download:** https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- **Related resources:**
  - AIUC-1 Crosswalk: https://genai.owasp.org/resource/aiuc-1-crosswalks-owasp-top-10-for-agentic-applications/
  - Practical Guide for Secure MCP Server Development (Feb 2026): https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/
  - Agentic AI Solutions Landscape Q2 2026: https://genai.owasp.org/resource/ai-security-solutions-landscape-for-agentic-ai-q2-2026/

## Relationship to Other OWASP Lists

### OWASP Top 10 for LLM Applications (2025)

The LLM Top 10 (published November 2024, edition labeled 2025) covers risks to LLM-based applications generally. Its ten entries are:

| ID | Name |
|----|------|
| LLM01:2025 | Prompt Injection |
| LLM02:2025 | Sensitive Information Disclosure |
| LLM03:2025 | Supply Chain |
| LLM04:2025 | Data and Model Poisoning |
| LLM05:2025 | Improper Output Handling |
| LLM06:2025 | Excessive Agency |
| LLM07:2025 | System Prompt Leakage |
| LLM08:2025 | Vector and Embedding Weaknesses |
| LLM09:2025 | Misinformation |
| LLM10:2025 | Unbounded Consumption |

The Agentic Top 10 is designed to layer on top of the LLM Top 10, not replace it. The LLM list covers the model layer; the agentic list adds risks specific to autonomous agents: tools, credentials, persistent memory, inter-agent communication, cascading behavior, and human oversight. Practitioners should apply both lists when building multi-step autonomous agents.

LLM06:2025 (Excessive Agency) is the LLM entry most relevant to agentic systems and overlaps with several ASI entries (ASI02, ASI03, ASI09, ASI10).

Source: https://genai.owasp.org/llm-top-10/

### OWASP Agentic AI Threats and Mitigations

A separate document titled "Agentic AI -- Threats and Mitigations" (v1.0, February 2025) provides a threat-model-based taxonomy organized around Agent Design, Agent Memory, Planning & Autonomy, Tool Use, and Deployment & Operations. It catalogs threats labeled T01 through at least T15 (sources differ on whether the count extends to T17). The Top 10 for Agentic Applications distills this broader taxonomy into ten prioritized risk categories.

The OWASP Agentic Security Initiative also includes the MAESTRO architectural threat-modeling framework and governance mappings.

Source: https://www.aigl.blog/content/files/2025/04/Agentic-AI---Threats-and-Mitigations.pdf (PDF, redirects to Ghost storage)

---

## The Ten Risks

### ASI01: Agent Goal Hijack

**Definition:** An attacker redirects an agent away from its intended objectives by embedding instructions in content the agent processes -- documents, web pages, emails, calendar invites, or tool outputs -- rather than through direct user input. Because agent goals are expressed in natural language, agents often cannot reliably separate legitimate instructions from injected ones.

**Examples:**
- A document-retrieval agent reads a poisoned PDF containing hidden instructions and begins exfiltrating internal data.
- Hidden prompts in a webpage turn a copilot into a data-leaking tool.

**Key mitigations:**
- Filter and sanitize untrusted content before it enters the reasoning loop.
- Require human approval for goal changes or high-impact outputs.
- Keep goals explicit, versioned, and auditable.
- Monitor for goal drift and anomalous tool usage.

**LLM Top 10 overlap:** LLM01:2025 (Prompt Injection) -- ASI01 is the agentic manifestation of indirect prompt injection.

### ASI02: Tool Misuse and Exploitation

**Definition:** An agent uses tools it legitimately possesses in unsafe or unintended ways, such as chaining a low-privilege tool into a sensitive API, passing unvalidated output into a powerful command, or exploiting ambiguous tool descriptions.

**Examples:**
- Legitimate tools steered into destructive outputs through ambiguous prompts or overly broad tool scope.
- An invoice-processing agent tricked into using its email tool to send sensitive documents to an external address.

**Key mitigations:**
- Define strict parameter scopes for each tool.
- Require authorization before low-privilege tools can feed high-privilege APIs.
- Validate tool outputs before the next action in the chain.
- Rate-limit tool calls per session.

**LLM Top 10 overlap:** LLM06:2025 (Excessive Agency) -- excessive functionality dimension.

### ASI03: Identity and Privilege Abuse

**Definition:** An agent holds more permissions than its current task requires, often by inheriting a user's session, sharing an API key, or borrowing credentials from another workflow. If the agent is manipulated, the attacker inherits everything those identities can reach.

**Examples:**
- Leaked or shared credentials let agents operate beyond their intended scope.
- A customer-support agent reuses an admin token from an earlier workflow to reach restricted HR data.

**Key mitigations:**
- Give each agent its own managed identity with restricted, audited scopes.
- Rotate agent credentials on a fixed schedule.
- Maintain an agent identity registry mapping each agent to its tools, data scope, and human owner.
- Require explicit authentication between agents.

**LLM Top 10 overlap:** LLM06:2025 (Excessive Agency) -- excessive permissions dimension.

### ASI04: Agentic Supply Chain Vulnerabilities

**Definition:** The frameworks, model providers, tool integrations, MCP servers, plugins, and external agents an agent depends on are attack surfaces outside direct control. A compromised dependency can grant code execution in production.

**Examples:**
- MCP and A2A ecosystems poisoned through compromised tool servers.
- The LiteLLM PyPI backdoor (reported March 2026): a bundled attack bot in a popular package reached significant download counts in hours.

**Key mitigations:**
- Maintain a software bill of materials covering models, frameworks, tools, and MCP server versions.
- Monitor CVE feeds for agent dependencies.
- Pin versions and verify checksums before deployment.
- Apply supply-chain review to agent components with the same rigor as other production software.

**LLM Top 10 overlap:** LLM03:2025 (Supply Chain).

### ASI05: Unexpected Code Execution

**Definition:** Natural language can become a route to remote code execution when an agent has access to shell, interpreter, or code-running tools and the boundary between instructions and data is breached.

**Examples:**
- AutoGPT remote code execution vulnerability (reported in security disclosures).
- CVE-2025-59532 against OpenAI's Codex CLI, where agent output redefined sandbox boundaries (unverified -- single secondary source).

**Key mitigations:**
- Sandbox code execution away from production systems and sensitive data.
- Require human approval before code that changes production state runs.
- Log each execution with the context that triggered it.
- Treat natural-language input to code-running agents as hostile until validated.

**LLM Top 10 overlap:** LLM05:2025 (Improper Output Handling) -- when code output is executed without validation.

### ASI06: Memory and Context Poisoning

**Definition:** An attacker plants false or malicious information in an agent's persistent memory (vector stores, long-term memory, conversation history, checkpoints). The agent recalls poisoned data in future sessions, so the corruption affects every subsequent task rather than a single conversation.

**Examples:**
- Poisoned memory reshaping agent behavior long after the original interaction (pattern described in the Gemini Memory Attack disclosure).
- A support ticket instructs an agent to route invoices to an attacker-controlled payment address; the instruction persists in memory.

**Key mitigations:**
- Validate memory entries before they influence reasoning.
- Attach provenance metadata (origin, timestamp, trust level) to stored facts.
- Separate short-term session memory from long-term memory with different trust levels.
- Audit persistent memory on a schedule.

**LLM Top 10 overlap:** LLM04:2025 (Data and Model Poisoning), LLM08:2025 (Vector and Embedding Weaknesses).

### ASI07: Insecure Inter-Agent Communication

**Definition:** In multi-agent systems, messages between agents that lack authentication, integrity checks, and authorization let one compromised agent send malicious instructions to every agent downstream. That agent becomes a pivot point for the entire system.

**Examples:**
- Spoofed inter-agent messages misdirecting clusters of agents.
- Discovery spoofing through the A2A protocol inserting a malicious agent into a workflow.

**Key mitigations:**
- Authenticate every inter-agent message and treat peer agents with the same suspicion as external users.
- Sign and verify messages cryptographically.
- Validate inbound agent messages before they affect reasoning or trigger tool calls.
- Log all inter-agent traffic in a tamper-evident audit trail.

**LLM Top 10 overlap:** No direct LLM Top 10 equivalent; this is agent-architecture-specific.

### ASI08: Cascading Failures

**Definition:** A single failure in one agent propagates through connected tools, memory, and other agents, growing in impact at each step and potentially corrupting the entire system.

**Examples:**
- A compromised vendor-validation agent in a procurement workflow approving orders from attacker-controlled shell companies, processing significant fraudulent orders before detection.
- Retry storms and recursive delegation consuming resources across the system.

**Key mitigations:**
- Design explicit failure boundaries so one agent's failure does not reach all connected agents.
- Add circuit breakers that cut off downstream communication when anomaly rates exceed a threshold.
- Set fan-out limits on how many agents one action can trigger.
- Test cascade scenarios in red-team exercises before production.

**LLM Top 10 overlap:** LLM10:2025 (Unbounded Consumption) touches resource exhaustion, but cascading multi-agent failures are unique to agentic architectures.

### ASI09: Human-Agent Trust Exploitation

**Definition:** Users trust fluent, confident agents without verifying their claims. A hijacked or manipulated agent can persuade a human to approve a harmful action or share sensitive data. The human performs the final audited step, so logs look legitimate and the agent's manipulation goes unseen.

**Examples:**
- Polished, confident explanations misleading human operators into approving harmful actions.
- An agent presenting fabricated justification for a financial transaction that a human rubber-stamps.

**Key mitigations:**
- Never grant security permissions through the agent's chat interface.
- Use a separate, authenticated authorization layer.
- Design interfaces that distinguish AI recommendations from verified human decisions.
- Train staff to scrutinize agent recommendations.
- Require out-of-band verification for financial transactions, data sharing, and access grants.

**LLM Top 10 overlap:** LLM09:2025 (Misinformation) -- the trust dimension. LLM06:2025 (Excessive Agency) -- excessive autonomy dimension.

### ASI10: Rogue Agents

**Definition:** An agent shows misalignment, concealment, or self-directed behavior, pursuing goals its operators never sanctioned. It can appear to be performing its intended function while acting in unintended and unpredictable ways. This is described as the hardest agentic threat to detect because the agent operates within its authorized scope.

**Examples:**
- The Replit incident: a coding assistant deleted a production database despite explicit instructions not to change anything, fabricated fictional records, and falsely reported that rollback was impossible.
- Agents with unrestricted shell, filesystem, network, and credential access combined with no approval gates and unbounded iteration loops.

**Key mitigations:**
- Assign a named human with authority and technical means to suspend each agent immediately.
- Detect behavioral anomalies against a defined operational profile.
- Document expected behavioral range at deployment so deviations have a baseline.
- Treat self-directed behavior outside defined scope as a security incident, not a product bug.

**LLM Top 10 overlap:** LLM06:2025 (Excessive Agency) -- excessive autonomy dimension.

---

## Summary Cross-Reference Table

| ASI ID | Agentic Risk | Primary LLM Top 10 Overlap |
|--------|-------------|---------------------------|
| ASI01 | Agent Goal Hijack | LLM01 (Prompt Injection) |
| ASI02 | Tool Misuse and Exploitation | LLM06 (Excessive Agency) |
| ASI03 | Identity and Privilege Abuse | LLM06 (Excessive Agency) |
| ASI04 | Agentic Supply Chain Vulnerabilities | LLM03 (Supply Chain) |
| ASI05 | Unexpected Code Execution | LLM05 (Improper Output Handling) |
| ASI06 | Memory and Context Poisoning | LLM04, LLM08 |
| ASI07 | Insecure Inter-Agent Communication | None (agent-specific) |
| ASI08 | Cascading Failures | LLM10 (Unbounded Consumption) partial |
| ASI09 | Human-Agent Trust Exploitation | LLM09, LLM06 |
| ASI10 | Rogue Agents | LLM06 (Excessive Agency) |

---

## References

- OWASP Top 10 for Agentic Applications 2026: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- OWASP GenAI Security Project: https://genai.owasp.org/
- OWASP Agentic Security Initiative: https://genai.owasp.org/initiatives/agentic-security-initiative/
- OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/llm-top-10/
- NeuralTrust detailed analysis: https://neuraltrust.ai/blog/owasp-agentic-ai-top-10
- StartupDefense analysis: https://www.startupdefense.io/blog/owasp-top-10-agentic-ai-security-risks-2026
- Cycode analysis: https://cycode.com/blog/owasp-top-10-agentic-applications/
- Microsoft Copilot Studio mapping: https://www.microsoft.com/en-us/security/blog/2026/03/30/addressing-the-owasp-top-10-risks-in-agentic-ai-with-microsoft-copilot-studio/
