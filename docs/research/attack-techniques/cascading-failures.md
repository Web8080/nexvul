# Cascading Failures

## attack

A single fault -- hallucination, malicious input, corrupted tool, poisoned memory, spoofed message -- propagates across agents, tools and workflows and is amplified at each hop. OWASP is explicit that ASI08 is about **propagation and amplification**, not the origin: the initial defect is classified under ASI04/ASI06/ASI07, and ASI08 applies "only when that defect spreads across agents, sessions, or workflows" (PDF p. 30). Observable symptoms named by OWASP include rapid fan-out, oscillating retries or feedback loops between agents, and queue storms.

Statically, nexvul can only see the **structural amplifiers**: delegation cycles, unbounded fan-out, retries without limits/backoff, planner->executor coupling without a validation or policy step, and missing timeouts. Looping specifics are in unbounded-loops.md.

## preconditions

- Multiple agents, nodes or workflow steps connected so that one's output is another's input.
- No circuit breaker, fan-out cap, rate limit, or timeout between them.
- Executor acts on planner output without validation/policy check (OWASP ASI08 example 1, "Planner-executor coupling").
- Retry logic that re-issues failed calls without a bound or backoff.

## attack_flow

1. An upstream agent is fed a poisoned input or hallucinates.
2. Its output is consumed automatically by downstream agents (no validation gate).
3. Downstream agents act (tool calls, writes, delegations), possibly re-delegating back upstream (cycle).
4. Retries and fan-out multiply the bad action; shared memory persists it into later sessions.
5. Impact grows beyond the original agent's scope (cost blow-up, mass writes, outage).

## observable_code_patterns

```python
# Delegation cycle: A -> B -> C -> A
graph.add_edge("planner", "researcher")
graph.add_edge("researcher", "critic")
graph.add_conditional_edges("critic", route, {"again": "planner", "done": END})

# Retry with no ceiling and no backoff
while True:
    try:
        return call_tool(args)
    except Exception:
        continue

# tenacity retry with no stop condition
@retry()                                 # tenacity default: retry forever
def call_agent(): ...

# Unbounded fan-out driven by model output
for sub in llm_plan.subtasks:            # length controlled by the model
    asyncio.create_task(worker.run(sub))

# Executor runs planner output with no validation step
for step in planner.run(goal).steps:
    executor.execute(step)
```

## possible_static_signals

- Cycles in the agent/workflow graph (LangGraph edges, CrewAI hierarchical delegation, AutoGen group chat speaker transitions, custom `handoff` graphs) -- graph analysis, A->B->C->A.
- Cycles with **no** termination guard on the path (conditional edge to END, counter, recursion limit).
- `@retry` / retry loops without `stop_after_attempt`/`max_retries`/counter; `except: continue` inside `while True` around a tool/agent/LLM call.
- Fan-out over a model-controlled collection without a cap (`[:N]`, semaphore, `max_concurrency`).
- Missing timeout on agent/tool/LLM network calls (`timeout=None`, no `asyncio.wait_for`, no framework `max_execution_time`).
- Planner output iterated directly into an executor without an intervening validation/policy function.

## false_positive_cases

- Intentional reflection/critique loops that are bounded by the framework (e.g. LangGraph raises `GraphRecursionError` when `recursion_limit` is hit; the commonly cited default is 25 -- secondary source).
- Retries bounded by framework or HTTP client defaults that the scanner does not model.
- Fan-out over a constant or small, code-controlled list.
- Timeouts configured globally (client constructor, env var, infrastructure).

## false_negative_cases

- Cycles that only arise at runtime (dynamic routing chosen by the LLM, discovery-based peer selection).
- Cascades through shared memory or databases rather than direct calls.
- Cross-service cascades (queues, webhooks, other repos).
- Semantic cascades (a wrong fact accepted by every agent) -- not structurally visible.
- Retry storms caused by infrastructure (load balancers, SDK-level automatic retries).

## framework_examples

```python
# LangGraph (illustrative): cycle with recursion_limit raised very high
app = graph.compile()
app.invoke(state, config={"recursion_limit": 10_000})

# CrewAI (illustrative): hierarchical crew, all agents may delegate
crew = Crew(agents=[a, b, c], process=Process.hierarchical, manager_llm=llm)
# with a, b, c all allow_delegation=True

# AutoGen (illustrative): group chat with no max_round
from autogen import GroupChat
chat = GroupChat(agents=[a, b, c], messages=[], max_round=None)
```

## owasp_mapping

- **Primary:** ASI08 (Cascading Failures) -- structural amplifiers; OWASP mitigations "Rate limiting and monitoring" and "blast-radius guardrails such as quotas, progress caps, circuit breakers between planner and executor" (PDF pp. 31-32).
- **Secondary:** ASI02 (Tool Misuse) example 5 "Loop amplification: Planner repeatedly calls costly APIs" (PDF p. 12).
- **LLM Top 10:** LLM10:2025 Unbounded Consumption (partial).
- **CWE:** CWE-400 (cited by OWASP ASI08 references), CWE-674, CWE-770, CWE-835.

## confidence

**Medium for structural signals** (graph cycles, unbounded retries, missing timeouts are visible), **low for real cascade risk**, which depends on runtime data and infrastructure. Cycle rules must check for termination guards on the cycle path or they will be very noisy, because bounded reflection loops are a mainstream pattern.

## references

- OWASP Top 10 for Agentic Applications 2026 (ASI08 pp. 30-32): https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- Google SRE book -- Addressing Cascading Failures (cited by OWASP): https://sre.google/sre-book/addressing-cascading-failures/
- CWE-400 Uncontrolled Resource Consumption: https://cwe.mitre.org/data/definitions/400.html
- LangGraph GRAPH_RECURSION_LIMIT error: https://docs.langchain.com/oss/python/langgraph/errors/GRAPH_RECURSION_LIMIT
- Default `recursion_limit` of 25 (secondary, not confirmed on official page): https://github.com/langchain-ai/docs/issues/1121
