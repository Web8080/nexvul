"""Sample data for the dashboard mock-up (assets/report-preview.html).

Design mock-up, sample data. The project, findings and paths are invented. Rule IDs and titles are from
docs/detection-taxonomy.md. The sample set extends terminal-mockups.md T04 (5 findings) to 9 findings and
3 rules not run, so every dashboard view has something to show.
"""

SCAN = {
    "target": "my-agent-project/",
    "commit": "3f2c1a9",
    "branch": "feature/refunds",
    "base": "main",
    "started": "2026-10-08 14:32:05 UTC",
    "ended": "2026-10-08 14:32:17 UTC",
    "duration": "11.6 s",
    "version": "0.1.0",
    "rules_pack": "2026.10.1",
    "rules_hash": "sha256:9c1e4f\u2026",
    "python": "3.12.6",
    "mode": "local",
    "fail_on": "high",
    "files_discovered": 312,
    "files_analysed": 312,
    "files_by_lang": "Python 241, TypeScript 56, configs 15",
    "excluded": 18,
    "rules_run": 22,
    "rules_total": 25,
    "dynamic_not_followed": 3,
    "command": "nexvul scan . --format html --output nexvul-report.html",
}

# Partial variant (design state switch): 4 of 312 files not analysed.
PARTIAL = {
    "analysed": 308,
    "not_analysed": 4,
    "reasons": [
        ("parse error", 2, ["agent/legacy.py", "agent/\u202etxt.py"]),
        ("over size limit (1 MB)", 1, ["data/fixtures.py (3.1 MB)"]),
        ("parser timeout (30 s)", 1, ["agent/huge_graph.py"]),
    ],
}

HOSTILE_FILE = "tools/<img src=x onerror=alert(1)>.py"

LONG_ID = ("retrieved_chunks_for_customer_support_escalation_workflow_with_extended_context_window_and_"
           "fallback_policy_v2")

FINDINGS = [
    {
        "id": "F1", "rule": "NEX018", "sev": "critical", "conf": "medium", "asi": ["ASI02", "ASI09"],
        "path": "agent/billing.py", "line": 58, "col": 9, "framework": "OpenAI Agents SDK",
        "msg": "Tool refund_order calls stripe.Refund.create() with an amount chosen by the model. No approval "
               "step was found on the path to the call in the scanned code; controls outside this repository "
               "are not visible to nexvul.",
        "flow": [
            ("source", "agent/billing.py", 31, "@function_tool def refund_order(order_id: str, amount: float):",
             "Tool argument chosen by the model"),
            ("step", "agent/billing.py", 44, "amt = int(amount * 100)", "Value converted, not bounded"),
            ("sink", "agent/billing.py", 58, "stripe.Refund.create(charge=order.charge_id, amount=amt)",
             "Financial action"),
        ],
        "searched": "needs_approval=True, a human-in-the-loop interrupt, an amount cap, a policy check",
        "why": "A model chooses the refund amount. Text the model reads (a customer email, a retrieved page) can "
               "steer that choice, and nothing in the scanned code asks a person before money moves.",
        "fix": "Require human approval before the call (needs_approval=True on the tool), or cap the amount in "
               "code and send larger refunds to a review queue.",
        "notdetect": "Approvals enforced outside this repository (a payment gateway rule, a Stripe Radar "
                     "policy). Whether a person who approves actually reads the request.",
    },
    {
        "id": "F2", "rule": "NEX020", "sev": "high", "conf": "medium", "asi": ["ASI10", "ASI05"],
        "path": "agent/tools.py", "line": 18, "col": 1, "framework": "LangGraph",
        "msg": "Agent research_agent can run shell commands (run_shell) and send HTTP requests to any host "
               "(fetch_url); no approval step or allowlist was found in the scanned code.",
        "flow": [
            ("source", "agent/graph.py", 40, "research_agent = create_react_agent(llm, tools=TOOLS)",
             "Agent definition"),
            ("step", "agent/tools.py", 18, "TOOLS = [search_web, fetch_url, index_docs, run_shell]",
             "Tool list"),
            ("sink", "agent/tools.py", 72, "subprocess.run(cmd, shell=True, capture_output=True)",
             "Shell execution"),
        ],
        "searched": "an approval interrupt before run_shell, a host allowlist on fetch_url, a sandbox wrapper",
        "why": "An agent that can both execute commands and reach any host can move data out of the machine it "
               "runs on if its instructions are steered.",
        "fix": "Split the tools across two agents, or require approval for run_shell and restrict fetch_url "
               "to an allowlist of hosts.",
        "notdetect": "Container, VM or network-policy sandboxes configured outside this repository.",
    },
    {
        "id": "F3", "rule": "NEX002", "sev": "high", "conf": "high", "asi": ["ASI06"],
        "path": "agent/ingest.py", "line": 42, "col": 5, "framework": "LangChain",
        "msg": "Content returned by requests.get() reaches vector_store.add_documents() without an identified "
               "validation or trust-boundary check.",
        "flow": [
            ("source", "agent/ingest.py", 30, "html = requests.get(url, timeout=10).text", "HTTP response body"),
            ("step", "agent/ingest.py", 35, "text = clean(html)", "Sanitiser not recognised"),
            ("step", "agent/ingest.py", 38, 'docs = [Document(page_content=text, metadata={"url": url})]', "step"),
            ("sink", "agent/ingest.py", 42, "vector_store.add_documents(docs)", "Vector store write"),
        ],
        "searched": "a source allowlist, a provenance or trust field checked at retrieval",
        "why": "Documents in a vector store are retrieved later and placed in the model's context. Text an "
               "attacker controls on a web page can carry instructions that the agent follows on a future, "
               "unrelated request.",
        "fix": "Allowlist the sources you index, record provenance on every stored document, and keep retrieved "
               "text out of system instructions.",
        "notdetect": "Poisoned documents already in the corpus. Validation helpers nexvul does not recognise "
                     "(treated as absent, which can cause a false positive).",
    },
    {
        "id": "F4", "rule": "NEX007", "sev": "high", "conf": "high", "asi": ["ASI07", "ASI04"],
        "path": "mcp.json", "line": 12, "col": 7, "framework": "MCP",
        "msg": 'MCP server "search" is reached over http:// at a non-loopback host with no authentication '
               "configured.",
        "flow": [],
        "searched": "an Authorization header, an OAuth block, an https:// URL",
        "why": "Without transport security or authentication, anyone on the network path can read or alter the "
               "tool results the agent trusts.",
        "fix": "Use https:// and configure authentication for remote MCP servers.",
        "notdetect": "Authentication added by a proxy or service mesh outside this repository.",
    },
    {
        "id": "F5", "rule": "NEX005", "sev": "high", "conf": "medium", "asi": ["ASI06", "ASI01"],
        "path": "agent/prompts.py", "line": 27, "col": 12, "framework": "LangChain",
        "msg": "Text returned by retriever.invoke() is concatenated into the system message without delimiters "
               "or a trust label.",
        "flow": [
            ("source", "agent/rag.py", 19, "chunks = retriever.invoke(question)", "Retrieved content"),
            ("step", "agent/prompts.py", 22, "ctx = \"\\n\".join(c.page_content for c in " + LONG_ID + ")",
             "step"),
            ("sink", "agent/prompts.py", 27, "SystemMessage(content=BASE_RULES + ctx)", "System instructions"),
        ],
        "searched": "delimiters around retrieved text, placement in a user or tool message",
        "why": "Content placed in system instructions is treated by the model as the developer's own rules.",
        "fix": "Move retrieved text into a user or tool message, wrapped in clear delimiters.",
        "notdetect": "Model-side defences. Prompt templates loaded at runtime from outside the repository.",
    },
    {
        "id": "F6", "rule": "NEX014", "sev": "medium", "conf": "high", "asi": ["ASI08"],
        "path": "agent/graph.py", "line": 91, "col": 12, "framework": "LangGraph",
        "msg": "graph.compile() result is invoked with recursion_limit=None.",
        "flow": [],
        "searched": "a finite recursion_limit in the invoke config",
        "why": "A run that never reaches its stop condition keeps calling the model and tools.",
        "fix": "Set a finite recursion_limit sized to the longest legitimate run.",
        "notdetect": "Limits applied by a job runner or timeout outside this repository.",
    },
    {
        "id": "F7", "rule": "NEX011", "sev": "medium", "conf": "medium", "asi": ["ASI08"],
        "path": "agent/supervisor.py", "line": 64, "col": 5, "framework": "LangGraph",
        "msg": "supervisor delegates to research_agent, which can route back to supervisor; no depth counter "
               "was found on this cycle in the scanned code.",
        "flow": [
            ("source", "agent/supervisor.py", 51, 'builder.add_edge("supervisor", "research_agent")', "Edge"),
            ("step", "agent/supervisor.py", 58, 'builder.add_conditional_edges("research_agent", route)', "Edge"),
            ("sink", "agent/supervisor.py", 64, 'return "supervisor"', "Cycle closes"),
        ],
        "searched": "a depth or hop counter in state checked by route()",
        "why": "Two agents that hand work back and forth without a bound can loop until a global limit stops "
               "them.",
        "fix": "Carry a hop counter in graph state and route to END when it passes a fixed bound.",
        "notdetect": "Bounds enforced by the caller of the graph.",
    },
    {
        "id": "F8", "rule": "NEX015", "sev": "low", "conf": "medium", "asi": ["ASI08"],
        "path": "agent/tools.py", "line": 45, "col": 16, "framework": "LangGraph",
        "msg": "httpx.get() inside tool search_web has no timeout argument.",
        "flow": [],
        "searched": "timeout= on the call or client, asyncio.wait_for around the tool",
        "why": "A tool call that never returns holds the agent run open.",
        "fix": "Pass timeout= to the client or wrap the tool in asyncio.wait_for().",
        "notdetect": "Timeouts set on a shared client created in another repository.",
    },
    {
        "id": "F9", "rule": "NEX015", "sev": "low", "conf": "medium", "asi": ["ASI08"],
        "path": HOSTILE_FILE, "line": 3, "col": 1, "framework": "LangGraph",
        "msg": "httpx.post() inside tool notify has no timeout argument.",
        "flow": [],
        "searched": "timeout= on the call or client",
        "why": "A tool call that never returns holds the agent run open.",
        "fix": "Pass timeout= to the client or wrap the tool in asyncio.wait_for().",
        "notdetect": "Timeouts set on a shared client created in another repository.",
    },
]

ASI_NAMES = {
    "ASI01": "Agent Goal Hijack", "ASI02": "Tool Misuse", "ASI03": "Identity & Privilege Abuse",
    "ASI04": "Agentic Supply Chain", "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory & Context Poisoning", "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures", "ASI09": "Human-Agent Trust Exploitation", "ASI10": "Rogue Agents",
}

# (id, title, asi list, class, default severity, provisional ASI label)
RULES = [
    ("NEX001", "External content written to persistent memory", ["ASI06"], "flow", "high", False),
    ("NEX002", "External content indexed into a vector store", ["ASI06"], "flow", "high", False),
    ("NEX003", "Untrusted tool output persisted into long-term context", ["ASI06", "ASI01"], "flow", "high", False),
    ("NEX004", "User-controlled content persisted into shared agent state", ["ASI06", "ASI03"], "flow", "medium", False),
    ("NEX005", "Retrieved content promoted to trusted instructions", ["ASI06", "ASI01"], "flow", "high", False),
    ("NEX006", "A2A / agent HTTP endpoint without authentication", ["ASI07"], "control-absence", "high", False),
    ("NEX007", "MCP connection without authentication or over cleartext", ["ASI07", "ASI04"], "config", "high", False),
    ("NEX008", "Remote agent identity not verified", ["ASI07", "ASI03"], "control-absence", "medium", False),
    ("NEX009", "Sensitive context sent to an untrusted / non-allowlisted agent", ["ASI07", "ASI03"], "flow", "high", False),
    ("NEX010", "Inter-agent request executed without authorisation check", ["ASI07", "ASI03"], "control-absence", "high", False),
    ("NEX011", "Recursive delegation without depth bound", ["ASI08"], "graph", "medium", False),
    ("NEX012", "Workflow cycle without termination guard", ["ASI08"], "graph", "medium", False),
    ("NEX013", "Unlimited retries around agent/tool/LLM calls", ["ASI08", "ASI02"], "config", "medium", False),
    ("NEX014", "Agent iteration limit disabled or unbounded", ["ASI08"], "config", "medium", False),
    ("NEX015", "Missing timeout around agent or tool execution", ["ASI08"], "control-absence", "low", False),
    ("NEX016", "High-impact tool without approval", ["ASI02", "ASI09"], "capability", "high", True),
    ("NEX017", "Destructive tool without confirmation", ["ASI02", "ASI09"], "capability", "high", True),
    ("NEX018", "Financial action without human oversight", ["ASI02", "ASI09"], "capability", "critical", True),
    ("NEX019", "Privileged operation without policy gate (incl. approval bypass)", ["ASI03", "ASI02", "ASI09"], "control-absence", "critical", True),
    ("NEX020", "Dangerous capability combination (shell/code-exec + unrestricted network)", ["ASI10", "ASI05"], "capability", "high", True),
    ("NEX021", "Arbitrary filesystem access from an agent tool", ["ASI02", "ASI10"], "flow", "high", True),
    ("NEX022", "Unrestricted credential access by an agent", ["ASI03", "ASI10"], "capability", "medium", True),
    ("NEX023", "Excessive tool permissions on a single agent", ["ASI02", "ASI10"], "capability", "medium", True),
    ("NEX024", "Unrestricted delegation", ["ASI03", "ASI10"], "graph", "medium", True),
    ("NEX025", "No execution / iteration limits on an autonomous agent with sensitive capabilities", ["ASI10", "ASI08"], "control-absence", "medium", True),
]

# Rule state in this run: (state word, source)
RULE_STATE = {
    "NEX004": ("off", "experimental, off by default"),
    "NEX023": ("off", "experimental, off by default"),
    "NEX022": ("off", "rules.disabled in .nexvul.yml:9"),
}

SUPPRESSIONS = [
    {"rule": "NEX006", "path": "agent/server.py", "line": 41, "kind": "inline",
     "just": "auth enforced by the API gateway (infra/gateway.tf, route /agents/*)",
     "status": "applied", "new": False},
    {"rule": "NEX002", "path": "scripts/seed.py", "line": 12, "kind": "inline",
     "just": "offline seed of first-party docs from our own S3 bucket; never user-supplied",
     "status": "applied", "new": True},
    {"rule": "NEX015", "path": "agent/tools.py", "line": 88, "kind": "inline", "just": "",
     "status": "applied-nojust", "new": True},
    {"rule": "NEX016", "path": "agent/admin.py", "line": 30, "kind": "inline",
     "just": "approved by \u202eneerg\u202c security team",
     "status": "rejected-hidden", "new": True},
    {"rule": "NEX014", "path": "agent/old.py", "line": 12, "kind": "inline",
     "just": "legacy graph, removed next sprint", "status": "stale", "new": False},
]

FRAMEWORKS = [
    ("LangGraph", "0.2.x", 9, "import langgraph.graph in 9 files; StateGraph built in agent/graph.py", 11),
    ("LangChain", "0.3.x", 6, "langchain_core and langchain_community imports; vector store in agent/ingest.py", 8),
    ("OpenAI Agents SDK", "0.4.x", 3, "@function_tool and Agent(...) in agent/billing.py", 6),
    ("MCP", "config", 1, "mcpServers block in mcp.json (2 servers)", 3),
]
NOT_RECOGNISED = "CrewAI, AutoGen (no imports found)"

AGENTS_TABLE = [
    ("supervisor", "LangGraph node", "(routes only)", "none", "recursion_limit=None (NEX014)",
     ["F6", "F7"]),
    ("research_agent", "LangGraph ReAct agent", "search_web, fetch_url, index_docs, run_shell",
     "shell execution, network (any host), vector store write", "none found", ["F2", "F3", "F8"]),
    ("billing_agent", "OpenAI Agents SDK", "refund_order", "financial action (stripe.Refund.create)",
     "none found", ["F1"]),
]

CONFIG = [
    # key, value, source, weakens, ci
    ("severity.fail_on", "high", "default", "", "applied"),
    ("rules.enabled", "[ASI06, ASI07, ASI08, ASI09, ASI10]", ".nexvul.yml:7 (local file)", "", "applied"),
    ("rules.disabled", "[NEX022]", ".nexvul.yml:9 (local file)", "weakens",
     "NOT APPLIED from a pull request head; applied only if the base branch has the same value"),
    ("exclude", '["gen/**", "vendor/**"]', ".nexvul.yml:12 (local file)", "weakens (18 files excluded, counted)",
     "NOT APPLIED from a pull request head; base-branch value used"),
    ("frameworks.auto_detect", "true", "default", "", "applied"),
    ("analysis.cross_file", "true", "default", "", "applied"),
    ("analysis.max_files", "10000", "default", "", "applied (may only be lowered by repo config)"),
    ("suppressions.require_justification", "false", "default for local runs", "weakens",
     "forced to true in CI unless set by trusted config"),
    ("output", "html \u2192 nexvul-report.html", "CLI flag --format html --output", "", "n/a"),
    ("color", "auto", "default", "", "plain output in CI logs"),
]

PHASES = [("Discovering", 0.4), ("Parsing", 3.1), ("Analysing", 7.8), ("Reporting", 0.3)]
