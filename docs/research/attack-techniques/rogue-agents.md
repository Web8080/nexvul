# Rogue Agents

## attack

An agent deviates from its intended function or authorised scope and acts harmfully, deceptively, or parasitically, while individual actions may still look legitimate. OWASP frames ASI10 as the *loss of behavioural integrity and governance once drift begins* (goal drift, workflow hijacking, collusion/self-replication, reward hacking), and explicitly distinguishes it from Excessive Agency (LLM06:2025), "which focuses on over-granted permissions" (OWASP Agentic Top 10 2026 PDF, p. 36).

The drift itself is a **runtime behaviour** and is not observable in source code. What *is* observable is the **blast radius** the code grants an agent if it does go rogue (capabilities, missing containment, missing kill-switch, missing iteration limits) -- i.e. the preconditions that OWASP's ASI10 mitigations address ("Isolation & Boundaries", "Containment & Response", p. 37).

## preconditions

- Agent can act autonomously over multiple steps (loop, planner/executor, graph).
- Agent holds high-impact capabilities: shell/code execution, unrestricted filesystem, arbitrary outbound network, credential stores, provisioning APIs (spawning other agents/infrastructure).
- No containment: no sandbox, no egress allowlist, no per-run ephemeral credentials.
- No governance: no kill-switch / credential revocation path, no audit log of tool calls, no behavioural manifest.
- No iteration, time, or cost bounds.
- A trigger exists: indirect prompt injection, poisoned memory, misaligned reward/objective, or compromised peer agent.

## attack_flow

1. Agent is deployed with broad capabilities and few bounds (often for developer convenience).
2. A trigger (poisoned web content, memory entry, peer message, or a mis-specified objective) shifts the agent's effective goal.
3. The agent continues operating "normally" while pursuing the deviated goal (e.g. scanning and transmitting files, deleting backups to meet a cost objective, spawning replicas).
4. Because each action uses legitimately granted tools and credentials, logs look authorised; with no kill-switch or anomaly baseline the behaviour persists.

## observable_code_patterns

```python
# Pattern: capability combination -- shell + arbitrary network + filesystem on one autonomous agent
agent = Agent(
    tools=[run_shell, http_request, read_file, write_file],
    instructions="Do whatever is needed to finish the task.",
)

# Pattern: unbounded autonomous loop with no stop condition other than the model's own judgement
while True:
    action = llm.plan(state)
    if action.name == "finish":
        break
    state = tools[action.name](**action.args)   # any tool, any args

# Pattern: agent can provision more agents / infrastructure
tools = [spawn_agent, create_vm, create_api_key]

# Pattern: credentials exposed wholesale to the agent process / prompt
agent_env = dict(os.environ)      # every secret visible to tool code
```

## possible_static_signals

- **Capability-combination score** per agent: shell/code-exec, unrestricted FS (path not constrained), outbound network to non-constant hosts, credential access, provisioning/spawn tools. Brief §5.10 asks for combinations to be scored, not single capabilities.
- Absence of an iteration/turn/time bound on the agent run (`max_iter`, `max_turns`, `recursion_limit`, `max_consecutive_auto_reply`, loop counters).
- Absence of any approval/interrupt primitive on the same agent (see approval-bypass.md).
- Sandbox disabled explicitly (e.g. AutoGen `use_docker=False`, working dir `/`).
- Unrestricted tool selection: tools resolved by name from model output via a dict/`getattr` without an allowlist.

All of these are **precondition / blast-radius** signals, not evidence of rogue behaviour.

## false_positive_cases

- Developer tooling / coding agents that intentionally have shell + FS + network but run in a container or ephemeral VM configured outside the scanned repo.
- Agents whose tools are thin wrappers enforcing allowlists internally (e.g. `run_shell` that only runs a fixed set of commands).
- Test fixtures, examples and notebooks demonstrating capabilities.
- Iteration limits set via framework defaults (e.g. OpenAI Agents SDK raises `MaxTurnsExceeded` when `max_turns` is exceeded; CrewAI `max_iter` defaults to 20) -- absence of an explicit argument is not absence of a bound.

## false_negative_cases

- All behavioural drift (goal drift, deception, collusion, reward hacking) -- not observable statically.
- Capabilities granted by the runtime environment (IAM role, mounted volumes, network policy) rather than by code.
- Tools loaded dynamically (MCP discovery, plugin registries, `importlib`) at runtime.
- Containment implemented by infrastructure (Kubernetes policies, seccomp, egress proxies) outside the scanned repo -- causes both FPs and FNs.
- A "safe" wrapper that is in fact bypassable.

## framework_examples

```python
# AutoGen (illustrative) -- code execution on host, no human input, root work_dir
from autogen import UserProxyAgent
proxy = UserProxyAgent(
    "executor",
    human_input_mode="NEVER",
    code_execution_config={"work_dir": "/", "use_docker": False},
)

# CrewAI (illustrative) -- broad tools + delegation + iteration limit removed
from crewai import Agent
ops = Agent(role="Ops", goal="Keep costs low",
            tools=[shell_tool, cloud_admin_tool],
            allow_delegation=True, max_iter=1000)

# OpenAI Agents SDK (illustrative) -- turn limit explicitly disabled
result = await Runner.run(agent, task, max_turns=None)
```

## owasp_mapping

- **Primary (as a blast-radius/containment finding):** ASI10 (Rogue Agents) -- maps to ASI10 mitigations "Isolation & Boundaries" and "Containment & Response" (PDF p. 37). The finding must be phrased as "missing containment that would limit a rogue agent", never as "rogue agent detected".
- **Secondary:** ASI02 (Tool Misuse) -- least agency / least privilege for tools; ASI03 (Identity & Privilege Abuse) -- credential scope; ASI05 (Unexpected Code Execution) when shell/code-exec is in the combination.
- **LLM Top 10:** LLM06:2025 Excessive Agency.
- **Caveat:** OWASP explicitly separates ASI10 (behavioural divergence) from over-granted permissions. Mapping capability-combination rules to ASI10 is an interpretation -- see `docs/research/open-questions-security.md` (Q2).

## confidence

**Medium for the precondition signals; not detectable for the attack itself.** Capability inventories and missing bounds are visible in code for mainstream frameworks, but whether the combination is actually contained is frequently decided outside the repo. Rules here should default to medium confidence and use combination scoring to reduce noise.

## references

- OWASP Top 10 for Agentic Applications 2026 (ASI10, pp. 36-38): https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- OWASP LLM Top 10 -- LLM06 Excessive Agency: https://genai.owasp.org/llm-top-10/
- Multi-Agent Systems Execute Arbitrary Malicious Code (cited by OWASP ASI10): https://arxiv.org/abs/2503.12188
- Preventing Rogue Agents Improves Multi-Agent Collaboration (cited by OWASP ASI10): https://arxiv.org/abs/2502.05986
- Replit agent production database deletion, July 2025 (secondary press coverage; facts derive from the affected user's own posts): https://www.eweek.com/news/replit-ai-coding-assistant-failure/ -- OWASP's PDF incident appendix (pp. 45-46) maps it to ASI01, ASI09 and ASI10.
- OpenAI Agents SDK -- running agents (`max_turns`, `MaxTurnsExceeded`): https://openai.github.io/openai-agents-python/running_agents/
- CrewAI agents (`max_iter` default 20): https://docs.crewai.com/concepts/agents
