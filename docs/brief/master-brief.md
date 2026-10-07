# nexvul — Master Build Brief

> Source of truth for all agents. Supplied by the product owner (Victor Ibhafidon), 2026-10-08.
> The working title in the original brief was "AgentLatch"; the product is named **nexvul**.
> Naming conventions: CLI `nexvul`, PyPI package `nexvul`, rule IDs `NEX001…`, config file `.nexvul.yml`,
> agent workspace `.nexvul/`.

## 0. Prime directive

nexvul is a production-quality open-source **static** security scanner for AI-agent applications.

**The code being scanned is untrusted.** nexvul must be local-first, privacy-preserving, deterministic where
possible, explainable, fast, and conservative about what constitutes a vulnerability.

**A clean scan must NEVER be represented as proof that an AI-agent system is secure.**

The objective is not to build the largest scanner. It is to build a scanner that security engineers and AI
developers can actually trust.

## 1. Product

nexvul analyses: Python agent code; TypeScript/JavaScript agent code; prompts; tool definitions; MCP
configurations; agent manifests; agent workflow definitions; memory/vector-store integrations; agent-to-agent
communication; model/tool configuration; approval and human-oversight controls.

It identifies risky patterns associated with the **OWASP Top 10 for Agentic Applications 2026**, primarily:
ASI06 Memory & Context Poisoning · ASI07 Insecure Inter-Agent Communication · ASI08 Cascading Failures ·
ASI09 Human-Agent Trust Exploitation · ASI10 Rogue Agents — with an architecture extensible to the remaining
ASI risks.

## 2. Product principles

**Local-first.** Source never leaves the machine. No telemetry by default. No source collection. No external API
calls required to scan. Any network feature is explicitly opt-in.

**Security boundary.** Treat every scanned repo as hostile. Defend against: malicious source files, malicious
configuration, enormous files, deeply nested syntax, pathological regexes, resource exhaustion, symlink attacks,
archive bombs, malicious SARIF content, malicious filenames, prompt injection inside comments/docstrings, fake
framework metadata, malformed manifests.

**Never** execute scanned code, import the target project, instantiate its agents, execute its tools, execute its
prompts, or run arbitrary build scripts. No `exec`, `eval`, `subprocess.run(target code)`,
`importlib.import_module(target module)`. Static analysis only. Non-negotiable.

## 3. Development philosophy

Do not start coding first. Order: Research → Requirements → Threat model → Architecture → Detection taxonomy →
Agent responsibilities → Benchmark strategy → Test strategy → Acceptance criteria → Implement.
If information is uncertain, investigate rather than invent. Research sources to inspect: OWASP Agentic
Applications guidance, OWASP LLM Application Security guidance, LangChain, LangGraph, CrewAI, AutoGen, OpenAI
Agents SDK, MCP specification, A2A protocol, Semgrep architecture/patterns, CodeQL concepts, Bandit, SARIF,
GitHub code scanning, GitHub Actions, pre-commit. Record findings in `docs/research/`.

## 4. Multi-agent organisation

A virtual engineering organisation of specialised agents, each with: role, mission, authority,
responsibilities, inputs, outputs, acceptance criteria, review responsibilities, escalation rules.
Agents communicate through structured, inspectable artefacts in a shared workspace:

```
.nexvul/
  tasks/  decisions/  research/  findings/  reviews/  benchmarks/  security/
```

## 5. Required agent team

1. **Principal Supervisor** — chief architect, engineering manager, security gatekeeper. Roadmap, task
   decomposition, assignment, conflict resolution, architecture review, security enforcement, rejects weak work,
   prevents silent scope change, decides rule production-readiness, maintains ADRs, enforces quality gates.
   Never blindly accepts another agent's output; every detection needs independent review.
2. **Security Research** — how agent systems actually fail: indirect/direct prompt injection, tool poisoning,
   memory poisoning, context poisoning, excessive agency, insecure tool invocation, credential misuse, agent
   impersonation, rogue agents, agent identity, insecure MCP servers, malicious MCP tools, A2A risks, cascading
   failures, trust exploitation, approval bypass, unbounded loops, autonomous destructive actions. Per technique:
   `attack, preconditions, attack_flow, observable_code_patterns, possible_static_signals, false_positive_cases,
   false_negative_cases, framework_examples, owasp_mapping, confidence`. Not every theoretical attack becomes a rule.
3. **OWASP Mapping** — maintains `docs/owasp/`. Every rule: OWASP category, rationale, severity, confidence,
   CWE where appropriate, references, limitations. Never claim a detection proves exploitation.
4. **Python Static Analysis** — `ast`-based parsing, symbol resolution, call graph, CFG, data-flow, taint,
   cross-file, framework recognition. Not regex. Must understand `web_content -> parser -> memory.store()`,
   `request.user_input -> agent.run()`, `tool_result -> LLM -> privileged_tool()`.
5. **TypeScript/JavaScript Analysis** — real parser (not Python regex): imports/exports, calls, async flows,
   tool/agent definitions, MCP integrations, memory/vector-store calls.
6. **Framework Intelligence** — modular recognisers. LangChain (agents, tools, memory, retrievers, vector stores,
   callbacks, tool invocation); LangGraph (graphs, nodes, edges, state, checkpoints, memory, interrupts, human
   approval); CrewAI (agents, crews, tasks, tools, delegation, memory); AutoGen (agents, group chats, tools,
   function calls, inter-agent comms); OpenAI Agents SDK (agents, tools, handoffs, guardrails, sessions,
   approvals); MCP (clients, servers, tools, resources, prompts, auth, transport). Never hard-code around one
   framework.
7. **MCP Security** — unauthenticated servers, dangerous tools, arbitrary command execution, shell, filesystem,
   broad permissions, insecure transports, untrusted endpoints, missing auth, broad tool scopes, credential
   leakage, tool descriptions that steer model behaviour, dynamic tool discovery without controls. Distinguish
   "potentially dangerous" from confirmed-risky. Do not over-report.
8. **Agent-to-Agent Security (ASI07)** — endpoints, channels, authn, authz, identity, message integrity, trust
   boundaries, delegated authority, remote agent discovery. For `Agent A -> HTTP -> Agent B`: is B authenticated?
   A? authz checked? identity verified? messages trusted? sensitive context passed? can arbitrary agents connect?
9. **Memory Security (ASI06)** — flows like `untrusted web -> LLM -> memory -> future execution` and
   `user input -> vector store -> retrieval -> system prompt`. Vector DBs, long-term memory, checkpoints,
   conversation stores, embeddings, retrieval, persistent state. Missing provenance, trust boundaries,
   validation, sanitisation, isolation, expiration, access control. Must distinguish temporary context from
   persistent memory.
10. **Rogue Agent (ASI10)** — excessive permissions, shell, unrestricted FS, arbitrary HTTP, credential access,
    no approval, unlimited iteration, unrestricted delegation/tool selection, no execution boundary. Score
    **combinations** of capabilities (agent + shell + FS + network + no approval + unbounded loop ≫ any one).
11. **Cascading Failure (ASI08)** — unlimited chains, retry storms, recursive delegation, workflow cycles,
    uncontrolled retries, missing timeouts, unlimited tool calls, unbounded loops, failure propagation. Graph
    analysis (A→B→C→A is a potential cycle).
12. **Human Oversight (ASI09)** — high-impact ops without approval/confirmation/policy/HITL/limits/escalation
    (`agent -> delete_database()`, `agent -> send_payment()`). Do not flag every autonomous agent; reason about
    action sensitivity.
13. **Detection Rule Engineer** — standard rule structure (id, name, owasp, severity, confidence, sources, sinks,
    conditions, message, remediation, references). Rules-as-code where semantics require it; not everything is
    YAML.
14. **Data-Flow / Taint** — source → propagation → transformation → sink across locals, params, returns, imports,
    module boundaries, attributes, collections, async, callbacks. Cross-file, e.g.
    `web.py: fetch() returns requests.get(url).text`, `memory.py: save(c) -> memory.add(c)`,
    `agent.py: save(fetch())` must be connected.
15. **Benchmarking** — corpus of real OSS agent projects (licence permitting), vulnerable, safe, framework,
    synthetic adversarial. Measure TP/FP/FN, precision, recall, F1, runtime, memory. Don't optimise only for
    recall — noisy rules destroy trust.
16. **Adversarial Security** — try to make each rule miss: aliases, wrappers, indirection, dynamic imports,
    helpers, decorators, inheritance, callbacks, async, renaming, obfuscated strings, config changes, framework
    abstractions. Produce regression tests.
17. **False Positive Hunter** — find legitimate code that triggers each rule; classify TP / FP / acceptable
    warning / needs context. No rule ships until FP behaviour is understood.
18. **QA/Test** — unit, integration, regression, parser, framework, CLI, SARIF, Action, performance,
    malicious-input tests. High coverage on security-critical code.
19. **DevSecOps** — CI/CD, GitHub Actions, pre-commit hook, publishing, release automation, dependency scanning,
    SBOM, signing where practical, reproducible builds. nexvul itself is scanned and tested.
20. **Documentation** — README, install, CLI ref, architecture, rule ref, OWASP mappings, framework support, FP
    guidance, SARIF, Action, pre-commit, security policy, contribution guide. Must state: **a clean nexvul result
    does not prove an application is secure.**
21. **Release Engineer** — semver, changelog, packaging, PyPI prep, GitHub Marketplace action, Docker if
    justified, GitHub releases.

## 6. Supervisor lifecycle (per detection)

RESEARCH → THREAT MODEL → ARCHITECTURE → RULE DESIGN → IMPLEMENTATION → UNIT TESTS → ADVERSARIAL TESTING →
FALSE-POSITIVE TESTING → REAL-WORLD BENCHMARK → SECURITY REVIEW → SUPERVISOR APPROVAL → DOCUMENTATION → RELEASE.
No detection jumps from idea to production.

## 7. Core architecture (suggested)

CLI → Repository Discovery → Language Detection → {Python parser, JS/TS parser} → Intermediate Model
(AST/symbols/CFG/calls/data flow) → Taint/Dataflow engine → Framework detection → Rule engine → Finding
normaliser → {Terminal, JSON, SARIF}.

## 8. Stack

Python 3.12+, `ast`, dataclasses or Pydantic, typing, pathlib, asyncio where useful. CLI: Typer or Click + Rich.
Commands: `nexvul scan .`, `nexvul scan ./project`, `--format json|sarif`, `nexvul rules`,
`nexvul explain NEX001`, `nexvul doctor`, `nexvul version`, `--verbose`, `--explain NEX001`.

## 9. Package layout (suggested)

```
nexvul/
  cli/ core/
  parser/{python,javascript,typescript}/
  analysis/{ast,symbols,cfg,callgraph,taint}/
  frameworks/{langchain,langgraph,crewai,autogen,openai_agents,mcp}/
  rules/{asi06,asi07,asi08,asi09,asi10}/
  reporting/{terminal,json,sarif}/
  benchmarks/ config/
```
Rules independently testable; stable plugin architecture.

## 10. Finding model

```json
{ "rule_id": "NEX001", "title": "...", "severity": "high", "confidence": "high", "owasp": ["ASI06"],
  "file": "agent/memory.py", "line": 42, "column": 8, "message": "...", "evidence": [], "dataflow": [],
  "remediation": "...", "references": [] }
```
Messages must be specific: "Content returned by requests.get() reaches vector_store.add_documents() without an
identified validation or trust-boundary check" — never "This looks dangerous."

## 11–14. Integrations & config

- **SARIF** compatible with GitHub code scanning: rule metadata, severity, locations, fingerprints, help text,
  remediation, OWASP references. Tested against GitHub expectations.
- **pre-commit** hook (`id: nexvul`), staged-file scanning where practical.
- **GitHub Action** (`.github/actions/nexvul/` and/or reusable action): checkout, run, produce SARIF, upload
  SARIF, fail on configurable threshold (`fail-on: high`).
- **`.nexvul.yml`**: `severity.fail_on`, `rules.enabled` (e.g. ASI06…ASI10), `rules.disabled`, `exclude`,
  `frameworks.auto_detect`, `analysis.cross_file`, `analysis.max_files`.

## 15. Performance

Thousands of files. Parse each file once. File-discovery caching, AST caching, incremental analysis, rule
indexing, lazy framework detection, safe parallelism, bounded memory. Benchmark 100 / 1,000 / 5,000 / 10,000
files: runtime, CPU, memory, findings. Don't trade correctness for a benchmark number.

## 16. Initial detection targets (targets, not licence for noisy rules)

- **ASI06**: external content → persistent memory; external content → vector store; untrusted tool output →
  long-term context; user-controlled content → persistent agent state; retrieved content promoted to trusted
  instructions.
- **ASI07**: A2A HTTP without auth; MCP connection without auth; unverified remote agent identity; sensitive
  context sent to untrusted agent; agent communication without authorisation.
- **ASI08**: recursive delegation; workflow cycles; unlimited retries; unlimited agent iterations; missing
  timeout around agent/tool execution.
- **ASI09**: high-impact tool without approval; destructive tool without confirmation; financial action without
  human oversight; privileged operation without policy gate.
- **ASI10**: shell + unrestricted network; arbitrary FS access; unrestricted credential access; excessive tool
  permissions; unrestricted delegation; no execution/iteration limits.

## 17. Detection quality standard — every rule must answer

Source? Sink? Dangerous flow? What makes it dangerous? What legitimate code looks similar? How can an attacker
evade it? What evidence can we show? Confidence? What does it NOT detect? — If unanswerable, the rule is not ready.

## 18. Rule tests

`tests/{positive,negative,edge_cases,adversarial}/` per rule (wrapper, alias, documented-FP cases, etc.).

## 19. Security testing of nexvul itself

Malicious Python, malformed JS/TS, giant files, deep nesting, recursive structures, symlinks, path traversal,
malicious config, malformed SARIF, Unicode edge cases, binary files, generated code, huge strings, ReDoS, parser
crashes, memory exhaustion. Fail safely.

## 21. Development-agent boundaries

May: read/analyse/write source, run tests, run safe static tooling.
May NOT: deploy without Supervisor approval; publish without Release approval; access secrets unnecessarily;
upload scanned repos; execute untrusted project code; disable security tests; weaken a rule to pass tests;
delete benchmark failures.

## 22–23. Corpus & false-positive budget

```
benchmarks/{vulnerable,safe,frameworks,real_world,adversarial}/
```
Each example: `name, source, framework, owasp, expected_findings, expected_non_findings, license, notes`.
Respect licensing; don't blindly clone. Per-rule TP/FP/FN/precision/recall report. Noisy rule → improve
semantics, add context, reduce scope, lower confidence, or don't ship. **Never hide findings to improve metrics.**

## 24–25. Explainability & CLI UX

Each finding shows source, flow (step by step), why it matters, recommended action. CLI header shows repo,
file count, frameworks detected, findings grouped by severity with rule/ASI/location, and scan time.

## 26. Open-source files

LICENSE, README, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT, CHANGELOG. Rule contribution template: Threat, OWASP
mapping, Detection strategy, Positive examples, Negative examples, False positives, False negatives, Performance
impact, References.

## 27. Roadmap phases

0 Research (threat model, OWASP mapping, architecture, taxonomy, benchmark strategy) · 1 Foundation (CLI,
discovery, Python AST engine, finding model, terminal + JSON reporters, test framework) · 2 Initial rules
(ASI06–10) · 3 Data flow (symbols, call graph, cross-file, taint) · 4 Frameworks · 5 JS/TS · 6 Integrations
(SARIF, Action, pre-commit, CI thresholds) · 7 Benchmarking · 8 Hardening (red-team nexvul) · 9 Release.

## 28–29. Docs & ADRs

`docs/{architecture,threat-model,detection-engine,taint-analysis,framework-support,performance,security-model}.md`,
`docs/owasp/`, `docs/rules/NEX001.md…`, `docs/integrations/`. ADRs in `docs/adr/NNNN-*.md` with alternatives.

## 30. Quality gates (any critical fail ⇒ not complete)

Requirement understood · threat model considered · architecture reviewed · tests exist · positive, negative,
adversarial cases · FPs investigated · performance measured · docs · OWASP mapping · security reviewed.

## 32. Stop and ask the human when

1 major architectural decision with materially different options · 2 security trade-off that weakens the
product · 3 controversial OWASP interpretation · 4 dependency with significant supply-chain risk · 5 feature
that sends source off-machine · 6 irreversible production deployment · 7 unclear licensing · 8 unacceptable FPs
that can't be resolved safely.

## 33. Do not fake completion

Never say "implemented" unless it exists, "tested" unless tests ran, "OWASP compliant" without a defensible
basis. Never invent benchmark numbers or CVEs. Never claim framework support that hasn't been tested.

## 34. Phase reports

Each phase ends with: Completed · Files changed · Tests · Security findings · Known limitations · False
positives · Performance · OWASP coverage · Next tasks. Final: Release Readiness Report — be brutally honest.

## 35. Phase 0 deliverables (current)

1 `docs/research/` · 2 `docs/threat-model.md` · 3 `docs/architecture.md` · 4 `docs/detection-taxonomy.md` ·
5 `docs/owasp/` · 6 `.nexvul/` · 7 agent role definitions · 8 roadmap + product design (UX, screens, user
flows, identity) · 9 benchmark strategy · 10 ADR for parser/static-analysis architecture.
Then the Supervisor presents findings and a proposed implementation sequence. **No scanner implementation until
the foundation is reviewed.**
