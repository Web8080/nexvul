# Unbounded Loops and Unbounded Consumption

## attack

An agent loop, graph cycle, retry, recursion or tool-call sequence has no effective upper bound on iterations, time, tokens or cost. An attacker (or a confused model) drives the agent into repeated tool calls or self-delegation, causing denial of service, bill spikes ("denial of wallet"), repeated side effects (e.g. many emails/refunds), or a window for exfiltration (OWASP ASI02 scenario 7 describes repeated "ping" calls exfiltrating data via DNS). OWASP lists "Loop amplification: Planner repeatedly calls costly APIs, causing DoS or bill spikes" as an ASI02 example (PDF p. 12) and "oscillating retries or feedback loops between agents" as an ASI08 symptom (p. 30).

## preconditions

- Agent control flow is decided by model output (ReAct-style loop, graph routing, handoffs).
- No iteration cap, or cap explicitly disabled/raised to a very high value.
- No wall-clock timeout, token budget, or cost budget.
- Tools have side effects or cost per call.

## attack_flow

1. Attacker supplies input that never satisfies the stop condition (e.g. "keep searching until you find X" where X does not exist), or injects content causing the agent to re-plan forever.
2. The loop calls tools / LLM repeatedly.
3. Cost, rate limits or side effects accumulate; other tenants are starved; data can trickle out per call.

## observable_code_patterns

```python
# Hand-rolled agent loop with model-controlled exit only
while True:
    step = llm.invoke(messages)
    if step.tool_calls:
        messages += run_tools(step.tool_calls)
    else:
        break

# Explicitly disabled / extreme limits
Runner.run(agent, task, max_turns=None)                 # OpenAI Agents SDK
app.invoke(s, config={"recursion_limit": 1_000_000})    # LangGraph
Agent(role="r", max_iter=10_000)                        # CrewAI
AssistantAgent("a", max_consecutive_auto_reply=None)    # AutoGen (illustrative)

# Self-recursive delegation
def solve(task):
    sub = llm.split(task)
    return [solve(s) for s in sub]                      # depth controlled by the model
```

## possible_static_signals

- `while True` / `while not done` whose loop body contains an LLM/agent/tool call and whose only exit depends on model output, with no counter compared against a constant.
- Recursive function whose recursion is gated by model output and has no depth parameter.
- Framework limit arguments set to `None`, `float("inf")`, `sys.maxsize`, or above a configurable threshold.
- Absence of timeout on the outer agent run (`asyncio.wait_for`, framework `max_execution_time`, HTTP client timeout).
- Retry decorators without stop conditions (see cascading-failures.md).

## false_positive_cases

- Server event loops / consumers (`while True: msg = queue.get()`) that are not agent reasoning loops.
- Loops bounded by framework defaults (OpenAI Agents SDK raises `MaxTurnsExceeded` when `max_turns` is exceeded; CrewAI `max_iter` defaults to 20; LangGraph raises `GraphRecursionError` at `recursion_limit`). Absence of an explicit argument is **not** a finding when a safe default exists.
- Interactive chat loops where each iteration waits for a human message.
- Loops bounded by a deadline variable or budget object the scanner fails to recognise.

## false_negative_cases

- Bounds that exist but are ineffective (cap of 10,000 with an expensive tool).
- Unboundedness across processes (queue re-enqueueing, cron re-triggering, webhook ping-pong).
- Token/cost explosion inside a single bounded step (huge context, large outputs).
- Framework defaults that change between versions (scanner must version its knowledge).

## framework_examples

```python
# LangChain AgentExecutor (illustrative, legacy API): limit removed
AgentExecutor(agent=agent, tools=tools, max_iterations=None)

# OpenAI Agents SDK (illustrative)
await Runner.run(agent, "monitor forever", max_turns=None)

# AutoGen group chat (illustrative)
GroupChat(agents=[a, b], messages=[], max_round=None)
```

## owasp_mapping

- **Primary:** ASI08 (Cascading Failures) -- for multi-agent cycles/feedback loops; brief §16 lists "unlimited agent iterations" and "unlimited retries" under ASI08.
- **Secondary:** ASI02 (Tool Misuse) -- "Loop amplification" (common example 5) and mitigation 5 "Adaptive Tool Budgeting"; ASI10 -- brief §16 "no execution/iteration limits" as a containment control.
- **LLM Top 10:** LLM10:2025 Unbounded Consumption.
- **CWE:** CWE-835 Loop with Unreachable Exit Condition (only when provably unreachable -- usually not), CWE-674 Uncontrolled Recursion, CWE-770 Allocation of Resources Without Limits or Throttling, CWE-400.
- Note: a single-agent loop with no peer is arguably ASI02/LLM10 rather than ASI08 (OWASP's ASI08 is about propagation across agents). See open-questions Q3.

## confidence

**High for explicit disablement** (`max_turns=None` etc. -- literal, unambiguous). **Medium** for hand-rolled `while True` loops (must distinguish agent loops from event loops). Requires a versioned table of framework defaults to avoid flagging safe defaults.

## references

- OWASP Top 10 for Agentic Applications 2026 (ASI02 p. 12, ASI08 p. 30): https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- OWASP LLM Top 10 (LLM10 Unbounded Consumption): https://genai.owasp.org/llm-top-10/
- OpenAI Agents SDK running agents (`max_turns`, `MaxTurnsExceeded`): https://openai.github.io/openai-agents-python/running_agents/
- CrewAI agents (`max_iter` default 20): https://docs.crewai.com/concepts/agents
- LangGraph GRAPH_RECURSION_LIMIT: https://docs.langchain.com/oss/python/langgraph/errors/GRAPH_RECURSION_LIMIT
- CWE-770: https://cwe.mitre.org/data/definitions/770.html
- CWE-674: https://cwe.mitre.org/data/definitions/674.html
