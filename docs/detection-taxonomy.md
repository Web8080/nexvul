# nexvul Detection Taxonomy

> Phase 0 deliverable (brief §35 item 4). Owner: Security Research + OWASP Mapping agent. Date: 2026-10-08.
> Status: **design only**. No rule in this document is implemented, tested, benchmarked or approved.
> Inputs: `docs/brief/master-brief.md` §§5, 10, 16, 17; `docs/research/attack-techniques/`; `docs/architecture.md`
> §2 (intermediate-model facts); `docs/benchmark-strategy.md` §8.3 (FP budget, pending human approval).
> OWASP labels follow `docs/owasp/mapping.md`; several are **pending a human decision** (see
> `docs/research/open-questions-security.md` Q1-Q3).

**A nexvul finding reports a risky construct. It never proves exploitability, and a clean scan never proves an
agent system is secure.**

---

## 1. Detection classes

Every rule declares exactly one *primary* detection class (and optionally supporting classes). The class
determines which engine component evaluates it and what evidence the finding can show.

| Class | Question it answers | Engine component (architecture.md) | Evidence shown to user | Typical confidence ceiling |
|---|---|---|---|---|
| **source** | Where does untrusted / attacker-influenceable data enter? | Framework recognisers + source catalogue | Source location and source kind | n/a (never a finding on its own) |
| **sink** | Where can data or a decision cause impact? | Sink catalogue + sensitivity classifier (§2) | Sink call, sensitivity class | n/a (never a finding on its own) |
| **flow** (source -> sink) | Does untrusted data reach a sensitive sink without an identified validation / trust-boundary step? | Taint engine (intra-, then inter-procedural, then cross-file) | Step-by-step dataflow path | high (intra-procedural, concrete APIs) -> medium (cross-file, wrappers) |
| **capability** | What can this agent do? Which tools, which sinks are reachable from its tools? | Tool/agent recognisers + call graph reachability | Agent, tool list, reachable sensitive sinks | medium (inventory is factual; risk depends on context) |
| **graph** | Is the agent/workflow/delegation topology cyclic, unbounded in fan-out, or missing termination guards? | Workflow graph builder (LangGraph edges, CrewAI delegation, AutoGen group chat, handoffs) | Cycle path A->B->C->A, missing guard | medium |
| **config** | Is a literal configuration value insecure? (URL scheme, `verify=False`, `max_turns=None`, missing auth block) | Config/manifest parsers + constant evaluation of call arguments | The literal key/value | high (literal values) |
| **control-absence** | On the path from agent decision to a sensitive sink, is there **no** approval / policy / limit / timeout / auth control? | Call graph + dominance analysis over `ControlFact`s | Path from entry to sink, list of controls searched for and not found | medium (absence is only absence *within analysed code*) |

**Composite rules.** Many rules combine classes, e.g. NEX016 = capability (sink reachable from tool) +
control-absence (no gate dominates it); NEX020 = capability combination scoring. Composite rules inherit the
*lowest* confidence of their components unless the rule's tests demonstrate otherwise.

**Control-absence caveat.** A control-absence finding means "nexvul found no control *in the scanned code*".
Controls in gateways, IAM, service meshes, sandboxes or other repositories are invisible. Messages must say so
explicitly (brief §10: specific, not "this looks dangerous").

---

## 2. Sensitivity classification of tool actions

Brief §5.12: "Do not flag every autonomous agent; reason about action sensitivity." Sinks reachable from an
agent's tools are classified as follows. The catalogue is **versioned data with tests**, not code in rules
(open question Q6).

| Class | Code | Examples (illustrative, not exhaustive) | Default impact |
|---|---|---|---|
| Read-only, internal | `S0` | local pure computation, reading project-owned constants | none -> no finding |
| Read, sensitive data | `S1` | DB `SELECT` on user tables, reading files outside workdir, secret-manager reads | medium (exfiltration potential) |
| External communication | `S2` | send email/SMS/chat, outbound HTTP POST to non-constant host, publish/post | high (exfiltration, impersonation) |
| State-changing, reversible | `S3` | `INSERT`/`UPDATE`, create ticket, write file in workdir | medium |
| Destructive / irreversible | `S4` | `DELETE`/`DROP`/`TRUNCATE`, `shutil.rmtree`, `os.remove`, cloud `delete_*`/`terminate_*`, force push | high -> critical with production indicators |
| Financial | `S5` | payment/transfer/refund/payout/charge APIs of payment SDKs | critical |
| Privilege / identity | `S6` | IAM role/policy changes, user/role grants, API-key creation, ACL changes | critical |
| Code / command execution | `S7` | `subprocess`, `os.system`, `eval`/`exec`, notebook/code interpreter tools | critical |
| Agent / infra provisioning | `S8` | spawning agents, creating VMs/containers, registering new tools/servers | high |

Modifiers (raise or lower severity by one step, never confidence):
- **+1** sink arguments are tainted by model output or untrusted input (target chosen by the LLM).
- **+1** production indicators (`PROD`/`production` in connection-string/env-var names, prod hostnames).
- **−1** scoped target (constant path inside a temp/sandbox dir; constant table name of an agent-owned table).
- **−1** test-mode indicators (test keys, `sandbox=True`), only when explicit in code.

Generic tools (shell, raw SQL, generic HTTP) are classified by their **maximum** possible class (S7 / S4 / S2),
because destructiveness is chosen by model-generated arguments at runtime. Findings on generic tools must say
that the classification is the worst case.

---

## 3. Severity and confidence model

Two independent axes. **Severity** = impact *if* the pattern is exploitable. **Confidence** = how likely the
finding is a correct identification of the pattern (not of exploitability).

### 3.1 Severity

| Severity | Meaning |
|---|---|
| critical | Reachable S5/S6/S7 sink, or S4 with production indicator, with no control found, and model-/untrusted-controlled arguments |
| high | Untrusted data into persistent memory/instructions; unauthenticated inter-agent/MCP channel; S4 without gate; dangerous capability combination |
| medium | Structural amplifiers (cycles, unbounded retries, missing timeouts); S1/S3 sinks without gate; sensitive context to a non-allowlisted peer |
| low | Hygiene / defence-in-depth (e.g. limit set very high but finite) |
| info | Inventory facts (agent has shell tool) shown in report context, never fails a build |

### 3.2 Confidence

| Confidence | Criteria |
|---|---|
| high | Literal config value **or** intra-procedural flow between catalogue-listed source and sink APIs, no unresolved calls on the path |
| medium | Inter-procedural / cross-file flow; control-absence findings; capability findings; framework defaults resolved from a versioned table |
| low | Heuristic name matching, unresolved dynamic dispatch on the path, wrappers not modelled. **Off by default** (benchmark-strategy.md §8.3, pending approval) |

Rules: confidence may only be lowered by context, never raised above the rule's declared ceiling; a rule that
cannot meet its precision budget follows brief §23 (improve semantics -> add context -> reduce scope -> lower
confidence -> don't ship). Findings are never hidden to improve metrics.

### 3.3 Brief §17 checklist

Every rule entry in §4 answers: Source? Sink? Dangerous flow? What makes it dangerous? Legitimate look-alikes
(FP)? Evasion (FN)? Evidence? Confidence? What it does NOT detect? Entries with unanswered items are marked
**not ready**. *All* entries are currently **design only** regardless.

---

## 4. Candidate rules (from brief §16)

Format per rule: ID · name · ASI (per `docs/owasp/mapping.md`; ⚠ = pending human decision) · detection class ·
sources · sinks · key FP risks · does NOT detect · readiness.

Common FP note for all ASI06 rules: content that is legitimately meant to be stored (the user's own notes) is
indistinguishable from attacker content statically; rules must target *external / tool-sourced* content first.

### ASI06 -- Memory & Context Poisoning

**NEX001 -- External content written to persistent memory**
- ASI: ASI06 · Class: flow · Default: high severity / high (intra) -> medium (cross-file) confidence
- Sources: HTTP responses (`requests`, `httpx`, `urllib`, `aiohttp`), web loaders/scrapers, email/IMAP readers, file uploads, document loaders.
- Sinks: long-term memory writes (LangGraph store `put`, framework memory `save_context`/`add`, Mem0-style `add`, checkpoint writes of message content, DB tables used as agent memory).
- FP risks: trusted internal URLs; content passed through a sanitiser/validator nexvul doesn't model; ephemeral per-session buffers misclassified as persistent.
- Does NOT detect: whether content is malicious; poisoning via channels outside the code (manual DB edits); memory writes inside opaque framework internals.
- Readiness: design only.

**NEX002 -- External content indexed into a vector store**
- ASI: ASI06 · Class: flow · high / high->medium
- Sources: as NEX001.
- Sinks: `add_documents`, `add_texts`, `upsert`, `from_documents` on vector-store clients (Chroma, Pinecone, pgvector, FAISS wrappers, etc.).
- FP risks: ingestion pipelines over curated, first-party corpora; offline ETL jobs not reachable by agents; provenance metadata attached (a mitigating control the rule should recognise).
- Does NOT detect: poisoned documents already in the corpus; poisoning of embeddings/model; retrieval-time manipulation.
- Readiness: design only. (Roadmap thin-slice S1.)

**NEX003 -- Untrusted tool output persisted into long-term context**
- ASI: ASI06 (secondary ASI01) · Class: flow · high / medium
- Sources: tool call results (esp. MCP `call_tool` results, web/search tools), sub-agent outputs.
- Sinks: memory/vector/checkpoint writes; persisted system-prompt or "facts" stores.
- FP risks: tool outputs from first-party, deterministic tools (calculator); outputs validated against a schema.
- Does NOT detect: transient in-context injection that is never persisted (that is ASI01); poisoned tool descriptions.
- Readiness: design only.

**NEX004 -- User-controlled content persisted into shared agent state**
- ASI: ASI06 (secondary ASI03 for cross-user leakage) · Class: flow · medium / medium
- Sources: request bodies, chat messages, form inputs.
- Sinks: memory/state stores **shared across users or sessions** (no user/tenant key in the write).
- FP risks: per-user memory keyed by authenticated user ID (correct design); single-user local apps.
- Does NOT detect: tenant isolation enforced in the DB layer; semantic poisoning of the user's *own* memory.
- Readiness: design only. Needs a model of "shared vs per-user" keys -- **not ready** until that exists.

**NEX005 -- Retrieved content promoted to trusted instructions**
- ASI: ASI06 (secondary ASI01) · Class: flow · high / medium
- Sources: retriever / vector-store query results, memory reads (`MemorySource.used_as`).
- Sinks: system prompt / system message / `instructions=` construction, tool-selection or routing logic.
- FP risks: RAG that places retrieved text in a user/tool message with delimiters (standard, lower-risk pattern -- not the sink); first-party, read-only policy corpora.
- Does NOT detect: injection effectiveness; prompt-level mitigations (spotlighting) quality.
- Readiness: design only.

### ASI07 -- Insecure Inter-Agent Communication

**NEX006 -- A2A / agent HTTP endpoint without authentication**
- ASI: ASI07 · Class: control-absence (+config) · high / medium
- Sources: inbound HTTP request body on routes whose handler invokes an agent (`agent.run`/`invoke`/`Runner.run`), A2A server handlers.
- Sinks: the agent invocation.
- FP risks: auth in API gateway/ingress/mesh; app-level middleware not recognised; internal-only networks.
- Does NOT detect: broken auth (wrong audience, accept-all tokens); replay; semantic manipulation by authenticated peers.
- Readiness: design only.

**NEX007 -- MCP connection without authentication or over cleartext**
- ASI: ASI07 (secondary ASI04) · Class: config · high / high (literal) 
- Sources: n/a (config).
- Sinks: MCP client configs (`mcpServers` entries, SDK client constructors) with non-loopback `http://` URL, or remote server with no auth/headers/OAuth configuration; MCP HTTP servers bound to `0.0.0.0` with no auth.
- FP risks: loopback dev servers; env-driven URLs (treated as FN, not FP); auth supplied by a wrapper.
- Does NOT detect: client configs outside the repo (user home, IDE); malicious tool content (see tool-poisoning); token passthrough (separate future rule).
- Readiness: design only. (Roadmap thin-slice S3.)

**NEX008 -- Remote agent identity not verified**
- ASI: ASI07 (secondary ASI03) · Class: control-absence · medium / medium
- Sources: remote agent descriptors (A2A Agent Card fetches, discovery/registry responses), URLs from model output.
- Sinks: outbound task delegation to that agent.
- FP risks: hard-coded, allowlisted peer URLs over HTTPS (should not fire); verification in a shared client library.
- Does NOT detect: forged-but-validly-signed cards; compromised legitimate peers.
- Readiness: design only.

**NEX009 -- Sensitive context sent to an untrusted / non-allowlisted agent**
- ASI: ASI07 (secondary ASI03, LLM02) · Class: flow · high / medium
- Sources: secrets/credentials variables, full conversation history/state, PII-labelled fields.
- Sinks: outbound inter-agent message bodies (HTTP/A2A/MCP calls) where the destination is non-constant or not allowlisted.
- FP risks: peers in the same trust domain; redaction helpers not modelled.
- Does NOT detect: what the remote agent does with data; PII the scanner cannot label.
- Readiness: design only.

**NEX010 -- Inter-agent request executed without authorisation check**
- ASI: ASI07 (secondary ASI03 confused deputy) · Class: control-absence · high / medium
- Sources: authenticated-but-unauthorised peer messages (caller identity available but not checked against an allowlist/policy).
- Sinks: privileged tool calls (S4-S8) triggered from inbound agent messages.
- FP risks: authorisation delegated to downstream API; policy engine call not recognised.
- Does NOT detect: correctness of the policy; transitive delegation across services.
- Readiness: design only. Overlaps NEX006 -- dedupe so one finding per route.

### ASI08 -- Cascading Failures

**NEX011 -- Recursive delegation without depth bound**
- ASI: ASI08 · Class: graph (+control-absence) · medium / medium
- Sources: n/a. Sinks: delegation/handoff edges (CrewAI `allow_delegation`, handoffs, self-recursive agent functions).
- FP risks: framework-imposed depth limits (must be in versioned defaults table).
- Does NOT detect: recursion arising from runtime LLM routing across services.
- Readiness: design only.

**NEX012 -- Workflow cycle without termination guard**
- ASI: ASI08 · Class: graph · medium / medium
- Sources/Sinks: graph edges (LangGraph `add_edge`/`add_conditional_edges`, AutoGen speaker transitions).
- FP risks: bounded reflection loops (counter in state, conditional edge to END, recursion limit) -- the rule must look for guards on the cycle path or it will be very noisy.
- Does NOT detect: cycles created dynamically at runtime; cross-service cycles.
- Readiness: design only.

**NEX013 -- Unlimited retries around agent/tool/LLM calls**
- ASI: ASI08 (secondary ASI02) · Class: config + control-absence · medium / high (decorator without stop) -> medium (hand-rolled)
- Sinks: `@retry` without stop condition; `while True` + `except: continue` around agent/tool/LLM calls; client `max_retries` set to unbounded.
- FP risks: library defaults that are bounded; retries bounded by an outer deadline.
- Does NOT detect: infrastructure-level retries (load balancers, SDK internals).
- Readiness: design only.

**NEX014 -- Agent iteration limit disabled or unbounded**
- ASI: ASI08 when ≥2 agents/nodes involved, else ASI02 + LLM10 (open question Q3) · Class: config · medium / high
- Sinks: `max_turns=None`, `max_iter`/`max_iterations` None or above threshold, `recursion_limit` above threshold, `max_round=None`, `max_consecutive_auto_reply=None`, hand-rolled agent `while True` loops with model-only exit.
- FP risks: event/consumer loops misread as agent loops; interactive loops gated by human input.
- Does NOT detect: cost explosion within bounded runs; framework default changes across versions (needs versioned table).
- Readiness: design only. (Roadmap thin-slice S2.) Framework semantics of `None`/unset must be verified per version before implementation.

**NEX015 -- Missing timeout around agent or tool execution**
- ASI: ASI08 (secondary LLM10) · Class: control-absence · low-medium / medium
- Sinks: agent runs, outbound HTTP in tools, subprocess in tools with no `timeout=`, no `asyncio.wait_for`, no framework `max_execution_time`.
- FP risks: global client timeouts set elsewhere; infrastructure timeouts.
- Does NOT detect: timeouts that are too long to matter.
- Readiness: design only. Likely noisy -- candidate for low confidence / opt-in.

### ASI09 rules (⚠ ASI label pending human decision, see Q1)

Shared logic: capability (sensitive sink reachable from an agent-callable entry point) + control-absence (no
`ApprovalGate` dominates the sink on that path). Recognised controls include LangGraph `interrupt()` /
`interrupt_before`, OpenAI Agents SDK `needs_approval`, AutoGen `human_input_mode` other than `"NEVER"`, CrewAI
`human_input=True` on the task, and project-declared approval functions via `.nexvul.yml` (future).

**NEX016 -- High-impact tool without approval**
- ASI: ⚠ ASI02 + ASI09 (proposed) · Class: capability + control-absence · high / medium
- Sources: agent-callable entry (tool, node, handoff). Sinks: S2, S4-S8 classes.
- FP risks: gate enforced downstream (dual control, gateway); admin/dev agents by design; test mode.
- Does NOT detect: rubber-stamp approvals; approval UX quality (ASI09 core); destructiveness via generic tools (worst-case only).
- Readiness: design only. Depends on sensitivity catalogue (Q6).

**NEX017 -- Destructive tool without confirmation**
- ASI: ⚠ ASI02 + ASI09 · Class: capability + control-absence · high (critical with prod indicator) / medium
- Sinks: S4.
- FP risks: soft deletes; temp/sandbox targets; deletion protection/retention outside code.
- Does NOT detect: `DROP` issued through a generic SQL tool with model-written SQL (reported only as generic-tool worst case).
- Readiness: design only. Specialisation of NEX016 -- report one finding per sink, not both.

**NEX018 -- Financial action without human oversight**
- ASI: ⚠ ASI02 + ASI09 · Class: capability + control-absence · critical / medium
- Sinks: S5 (payment SDK create/transfer/refund/payout).
- FP risks: test-mode keys; provider-side approval workflows; amounts capped by code (mitigating control to recognise).
- Does NOT detect: fraud where a human approves a manipulated request (the actual ASI09 scenario).
- Readiness: design only.

**NEX019 -- Privileged operation without policy gate (incl. approval bypass)**
- ASI: ⚠ ASI03 + ASI02 + ASI09 · Class: control-absence (+flow for bypass) · critical / medium
- Sinks: S6, and any sink guarded only by a model-controlled parameter (`approved`, `force`, `skip_confirmation`) or by an approval flag defaulting off.
- FP risks: `force`-style params on non-tool internal functions; policy enforced in IAM.
- Does NOT detect: policy correctness; TOCTOU inside opaque framework code.
- Readiness: design only.

### ASI10 rules (⚠ ASI label pending human decision, see Q2)

All ASI10 findings are phrased as **missing containment**, never as "rogue agent detected".

**NEX020 -- Dangerous capability combination (shell/code-exec + unrestricted network)**
- ASI: ⚠ ASI10 + ASI05 · Class: capability (combination score) · high / medium
- Sources/Sinks: one agent's reachable sinks include S7 **and** outbound network to non-constant hosts; score raised by FS write, credential access, missing limits, missing approval (brief §5.10).
- FP risks: sandboxed coding agents (container config outside repo); allowlisting wrappers.
- Does NOT detect: behavioural drift; containment in infra.
- Readiness: design only. Scoring weights need benchmark calibration.

**NEX021 -- Arbitrary filesystem access from an agent tool**
- ASI: ⚠ ASI02 + ASI10 · Class: flow · high / high (intra) -> medium
- Sources: tool parameters (model-controlled). Sinks: `open`, `pathlib` read/write, `os.remove`, `shutil` with unconstrained path (no base-dir check / `resolve()` + prefix check).
- FP risks: path validation helpers not modelled; tools intended for a sandbox dir enforced by container.
- Does NOT detect: FS access via shell tool (covered by NEX020 as worst case).
- Readiness: design only. CWE-22.

**NEX022 -- Unrestricted credential access by an agent**
- ASI: ⚠ ASI03 + ASI10 · Class: capability + flow · medium / low-medium
- Sources: `os.environ` wholesale, secret-manager reads with non-constant keys, credential files.
- Sinks: values available to tool code/prompt/LLM context or outbound messages.
- FP risks: reading a single, purpose-specific key (normal); scope of keys unknowable.
- Does NOT detect: real credential scope (identity-provider knowledge).
- Readiness: design only. Likely low confidence.

**NEX023 -- Excessive tool permissions on a single agent**
- ASI: ⚠ ASI02 + ASI10 · Class: capability · medium / medium
- Sources/Sinks: agent tool inventory spanning many sensitivity classes (e.g. S1 + S2 + S4 -- read sensitive, exfiltrate, destroy).
- FP risks: general-purpose admin agents by design; per-tool authorisation at backend.
- Does NOT detect: permissions granted by credential scope rather than tools.
- Readiness: design only. **Not ready**: "excessive" requires a declared task scope nexvul doesn't have; consider report-only inventory.

**NEX024 -- Unrestricted delegation**
- ASI: ⚠ ASI03 + ASI10 · Class: graph + capability · medium / medium
- Sources/Sinks: agent can delegate/hand off to any agent (no allowlist), and a delegate has higher-class sinks than the delegator (privilege inheritance, OWASP ASI03 ex. 1).
- FP risks: small closed crews where all agents are trusted.
- Does NOT detect: delegation across services.
- Readiness: design only.

**NEX025 -- No execution / iteration limits on an autonomous agent with sensitive capabilities**
- ASI: ⚠ ASI10 + ASI08 · Class: control-absence + capability · medium / medium
- Sinks: agent with S4-S8 reachable sinks **and** no iteration/time/budget bound.
- FP risks: as NEX014.
- Does NOT detect: as NEX014.
- Readiness: design only. Must dedupe with NEX014 (NEX014 = config literal; NEX025 = absence combined with capability).

---

## 5. What the taxonomy deliberately excludes (initial scope)

- Standalone ASI01 prompt-injection rules (injection is modelled as a *source class* feeding ASI06/ASI02 flows).
- ASI04 supply-chain dependency scanning (version pinning/CVE lookups) beyond MCP startup-command shape -- better served by existing SCA tools.
- ASI05 classic code-injection SAST in tool bodies beyond NEX020/NEX021 -- overlaps Bandit/CodeQL; dedupe before adding.
- Human-factors aspects of ASI09 and behavioural aspects of ASI10 -- not statically detectable (see
  `docs/research/attack-techniques/README.md`, "What static analysis CANNOT detect").
