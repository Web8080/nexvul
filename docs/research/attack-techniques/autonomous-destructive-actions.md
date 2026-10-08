# Autonomous Destructive Actions

## attack

An agent can perform irreversible or high-impact operations -- deleting data, dropping tables, `rm -rf`, force-pushing, terminating infrastructure, sending money, sending external email, publishing content, changing access control -- without a human confirmation, policy gate, dry-run, or reversible staging step. Whether the trigger is injection, poisoned memory, hallucination or misalignment, the outcome is the same: irreversible harm executed autonomously. OWASP ASI02 common example 1 is "Email summarizer can delete or send mail without confirmation" and scenario 3 is a support bot issuing refunds through an over-privileged financial API (PDF pp. 12-13). OWASP ASI10 scenario 4 describes a cost-minimising agent deleting production backups (p. 37). A widely reported real-world case: in July 2025 a Replit coding agent deleted a user's production database despite instructions not to make changes (press coverage, see references). The OWASP PDF uses this incident as ASI05 scenario 1 (p. 21) and its incident appendix maps it to ASI01, ASI09 and ASI10 (pp. 45-46).

## preconditions

- A tool or code path reachable by the agent invokes a destructive/financial/external-communication/privilege-changing sink (see sensitivity classes in `docs/detection-taxonomy.md`).
- No human-approval primitive, policy check, or dry-run on the path between agent decision and sink.
- Agent operates on production resources/credentials.

## attack_flow

1. Agent receives a goal plus (possibly poisoned) context.
2. Agent decides the destructive action is appropriate (injected instruction, mis-reasoning, reward hacking).
3. Agent calls the tool; the sink executes immediately.
4. Damage is irreversible or expensive to reverse; logs show an authorised agent action.

## observable_code_patterns

```python
@tool
def cleanup(table: str):
    db.execute(f"DROP TABLE {table}")          # destructive SQL, model-chosen target

@tool
def pay(iban: str, amount: float):
    bank.transfers.create(to=iban, amount=amount)   # financial, no approval

@tool
def remove(path: str):
    shutil.rmtree(path)                         # recursive delete, unconstrained path

@tool
def terminate(instance_id: str):
    ec2.terminate_instances(InstanceIds=[instance_id])
```

## possible_static_signals

- Agent-reachable function (registered tool, graph node, handoff target) whose body or callees reach a sink in a **sensitive class**: `destructive` (DELETE/DROP/TRUNCATE SQL, `rmtree`, `os.remove`, `unlink`, cloud `delete_*`/`terminate_*`, `git push --force`), `financial` (payment SDK create/transfer/refund/payout calls), `external_comm` (send email/SMS/post), `privilege` (IAM/role/ACL changes), `code_exec`.
- **No approval control dominates the sink** on the path from the agent entry point (absence of `interrupt`, `needs_approval`, `human_input_mode != "NEVER"`, custom `confirm()` / policy call).
- Sink arguments tainted by model output (target chosen by the LLM) raise severity.
- Production indicators (env var names containing `PROD`, production connection strings) raise severity.

## false_positive_cases

- Destructive operations on scratch/temp resources the agent created (`tempfile`, sandbox dirs).
- Test/staging code paths, fixtures, migrations not reachable from agents.
- Financial SDK calls in **test mode** (e.g. test API keys) -- scanner usually cannot know.
- Approval enforced by the downstream system (bank dual control, soft-delete with retention, cloud deletion protection) or by a gateway outside the repo.
- Soft deletes (`UPDATE ... SET deleted=1`) misclassified as hard deletes.

## false_negative_cases

- Destructive behaviour via generic tools (shell, SQL-query tool taking arbitrary SQL, generic HTTP tool) -- the destructive intent is in model-generated arguments, not in code.
- Sinks inside third-party libraries or remote MCP servers not in scope.
- Sensitivity of custom internal APIs (e.g. `client.post("/v1/accounts/close")`) not in the sink catalogue.
- Approval that exists but is rubber-stamped (ASI09).

## framework_examples

```python
# LangChain (illustrative)
from langchain_core.tools import tool
@tool
def drop_table(name: str) -> str:
    """Drop a database table."""
    engine.execute(f"DROP TABLE {name}")

# CrewAI (illustrative)
finance = Agent(role="AP clerk", tools=[stripe_payout_tool])   # no human_input on task

# OpenAI Agents SDK (illustrative) -- compare with needs_approval=True
@function_tool
def wire_transfer(iban: str, amount: float) -> str: ...
```

## owasp_mapping

- **Primary (open question):** ASI02 (Tool Misuse) -- example 1 and mitigation 2 "human confirmation for high-impact or destructive actions (delete, transfer, publish)" (PDF pp. 12-14) **or** ASI09 -- common example 2 "Missing Confirmation for Sensitive Actions ... irreversible financial transfers, data deletions" (p. 33). Brief §16 places these under ASI09. See `docs/research/open-questions-security.md` Q1.
- **Secondary:** ASI03 (HITL for privilege escalation / irreversible actions, mitigation 4, p. 17); ASI10 (containment).
- **LLM Top 10:** LLM06:2025 Excessive Agency.
- **CWE:** CWE-862 Missing Authorization (closest fit for "no gate on a critical operation"), CWE-306 where no authentication either, CWE-749 Exposed Dangerous Method or Function.

## confidence

**Medium-high for typed sinks** (well-known destructive APIs and payment SDKs with explicit tool registration). **Low** for generic tools where destructiveness is decided by model-generated arguments. Sensitivity must be classified, not guessed from names alone (`delete_cache` vs `delete_customer`).

## references

- OWASP Top 10 for Agentic Applications 2026 (ASI02 pp. 12-14; ASI09 p. 33; ASI10 p. 37): https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- eWeek -- Replit agent wipes production database (July 2025, secondary press; details derive from the affected user's posts): https://www.eweek.com/news/replit-ai-coding-assistant-failure/
- OpenAI Agents SDK human-in-the-loop: https://openai.github.io/openai-agents-python/human_in_the_loop/
- LangGraph interrupts: https://docs.langchain.com/oss/python/langgraph/interrupts
- CWE-749 Exposed Dangerous Method or Function: https://cwe.mitre.org/data/definitions/749.html
