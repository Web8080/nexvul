# Approval Bypass

## attack

The application intends to put a human or a policy check in front of high-impact actions, but the control is missing, bypassable, or applied to the wrong path. Common forms: the approval gate wraps one code path while the same sink is reachable via another tool/handoff; approval is a parameter the model itself can set (`approved=True`); approval is globally disabled by a config flag or environment variable; the approval check happens at plan time and the executed action differs (TOCTOU, cf. OWASP ASI03 "Workflow Authorization Drift"); or auto-approve modes are enabled.

## preconditions

- The agent can reach a high-impact sink (see sensitivity classification in `docs/detection-taxonomy.md`).
- An approval mechanism exists or is expected (framework HITL primitive, custom confirm function, policy engine).
- One of: alternative path to the sink without the gate; gate condition controllable by model output or input data; gate disabled by configuration; gate evaluated on different arguments than those executed.

## attack_flow

1. Attacker injects instructions (direct or indirect) to perform a high-impact action.
2. Agent selects a path that avoids the gate (alternate tool, delegated agent, or sets the "approved" argument itself).
3. The sink executes with no human/policy decision, or with a decision made on different arguments.

## observable_code_patterns

```python
# Approval flag supplied by the model as a tool argument
@tool
def delete_records(table: str, approved: bool = False):
    if approved:                       # the LLM fills this argument
        db.execute(f"DELETE FROM {table}")

# Gate on one tool, same sink reachable from another
@tool
def safe_refund(order_id):  require_approval(); stripe.Refund.create(...)
@tool
def bulk_ops(ops):          for o in ops: stripe.Refund.create(**o)   # no gate

# Global kill of the gate
REQUIRE_APPROVAL = os.getenv("REQUIRE_APPROVAL", "false") == "true"

# Approve on plan, execute on different args
ok = ask_human(plan.summary)
if ok: execute(llm.replan(state))      # executed args not the ones approved
```

## possible_static_signals

- Tool parameter named like `approved|confirm|force|skip_confirmation|human_ok` that guards a sensitive sink (model-controlled guard).
- Sensitive sink reachable from ≥2 tool entry points where only a subset pass through an approval primitive (call-graph dominance check: does the gate dominate the sink on every path?).
- Approval primitive guarded by a config/env flag that defaults to off.
- Framework auto-approve settings: e.g. AutoGen `human_input_mode="NEVER"` on the agent executing code; OpenAI Agents SDK tool with sensitive sink and `needs_approval` absent/False; LangGraph graph containing sensitive node with no `interrupt()`/`interrupt_before` on the path.
- Approval decision compared to a value derived from LLM output.

## false_positive_cases

- `force`/`confirm` parameters on internal (non-tool) functions not exposed to the model.
- Gates enforced downstream (the payment API itself requires a second factor / dual control).
- Approval enforced at a gateway or policy engine outside the repo.
- Env-flag defaults that are overridden in deployment config not in the repo.

## false_negative_cases

- Gates implemented in UI or another service.
- Bypass via prompt injection that convinces a human (ASI09) -- structurally the gate is present.
- Dynamic tool registration creating new paths to the sink.
- TOCTOU where argument divergence happens inside opaque framework code.

## framework_examples

```python
# OpenAI Agents SDK (illustrative): approval only on one of two tools hitting the same sink
@function_tool(needs_approval=True)
def refund(order_id: str): ...
@function_tool
def run_admin_batch(cmds: list[str]): ...      # also issues refunds

# LangGraph (illustrative): interrupt_before on 'pay' node, but 'batch' node calls pay() directly
app = graph.compile(checkpointer=cp, interrupt_before=["pay"])

# AutoGen (illustrative): executor never asks
UserProxyAgent("exec", human_input_mode="NEVER", code_execution_config={"use_docker": False})
```

## owasp_mapping

- **Primary:** ASI02 (Tool Misuse) -- mitigation 2 "Action-Level Authentication and Approval" requires "human confirmation for high-impact or destructive actions (delete, transfer, publish)" (PDF p. 14) and mitigation 4 "Policy Enforcement Middleware".
- **Secondary:** ASI09 (common example 2 "Missing Confirmation for Sensitive Actions", p. 33); ASI03 (mitigation 4 "Human-in-the-Loop for Privilege Escalation", and "Workflow Authorization Drift" TOCTOU scenario, pp. 16-17).
- Primary-ASI choice is an open question -- see `docs/research/open-questions-security.md` Q1.
- **CWE:** CWE-862 Missing Authorization, CWE-863 Incorrect Authorization, CWE-807 Reliance on Untrusted Inputs in a Security Decision (model-set `approved`), CWE-367 (TOCTOU, approximate fit).

## confidence

**Medium.** Model-controlled approval parameters and framework-level "never ask" settings are concrete and detectable. Path-dominance checks (gate on every path to sink) need a call graph and are sound only within the analysed code. The largest FP driver is out-of-repo enforcement.

## references

- OWASP Top 10 for Agentic Applications 2026 (ASI02 pp. 12-14; ASI03 pp. 15-17; ASI09 pp. 33-35): https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- OpenAI Agents SDK human-in-the-loop (`needs_approval`): https://openai.github.io/openai-agents-python/human_in_the_loop/
- LangGraph interrupts: https://docs.langchain.com/oss/python/langgraph/interrupts
- CWE-807 Reliance on Untrusted Inputs in a Security Decision: https://cwe.mitre.org/data/definitions/807.html
- CWE-862 Missing Authorization: https://cwe.mitre.org/data/definitions/862.html
