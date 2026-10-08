# Attack Techniques -- Index and Static-Detectability Assessment

> Phase 0 research. Owner: Security Research agent. Date: 2026-10-08.
> OWASP source of truth: OWASP Top 10 for Agentic Applications 2026 (PDF, genai.owasp.org), summarised in
> `../owasp-agentic-top10-2026.md`. Page references below are to that PDF.

Every file in this directory uses the same sections: `attack, preconditions, attack_flow,
observable_code_patterns, possible_static_signals, false_positive_cases, false_negative_cases,
framework_examples (illustrative, not taken from real projects), owasp_mapping, confidence, references`.

**Not every technique becomes a rule** (brief §5.2). The "recommended action" column is a research
recommendation only; the Principal Supervisor decides what is designed and shipped.

## Index

Legend -- *Statically detectable?* **yes** = the risky construct itself is visible in source/config;
**partially** = preconditions or structural amplifiers are visible, the attack is not; **no** = the risk lives
in runtime behaviour, human cognition, or infrastructure outside the repository.

| Technique | Primary ASI | Statically detectable? | Why | Recommended action |
|---|---|---|---|---|
| [direct-prompt-injection](direct-prompt-injection.md) | ASI01 | partially | Attacker input is the user's own input; static signal is limited to restrictions living only in the system prompt with no backend enforcement | document only (feeds NEX rules as a source class) |
| [indirect-prompt-injection](indirect-prompt-injection.md) | ASI01 | partially | Source->LLM-context taint flow is visible; whether content is malicious is not | candidate rule (as a source class for ASI06 / ASI02 flows; standalone ASI01 rule out of initial scope) |
| [context-poisoning](context-poisoning.md) | ASI06 | partially | Mixed-trust context assembly visible; trust level of each source often not expressible in code | candidate rule (NEX005 "retrieved content promoted to instructions") |
| [memory-poisoning](memory-poisoning.md) | ASI06 | yes (flow) | Taint: untrusted source -> persistent memory/vector-store sink is a classic data-flow problem | candidate rule (NEX001-NEX004) |
| [tool-poisoning](tool-poisoning.md) | ASI04 in file; OWASP PDF places runtime tool-interface poisoning in ASI02 (p. 13) -- see open questions Q4 | partially | Untrusted server config and unvalidated tool output are visible; malicious description/response content is not (unless scanning a server's source) | config-only check + candidate rule on tool-output -> privileged sink |
| [insecure-mcp](insecure-mcp.md) | ASI07 / ASI04 | yes (config), partially (server code) | URL scheme, host, auth fields, startup commands are literal; server tool->sink is taint | config-only check (NEX007) + candidate rule (server tool param -> dangerous sink) |
| [insecure-tool-invocation](insecure-tool-invocation.md) | ASI02 | yes | `shell=True`, string-built SQL, unconstrained paths in tool bodies are classic SAST targets | candidate rule (beyond initial §16 list; overlaps Bandit -- dedupe) |
| [excessive-agency](excessive-agency.md) | ASI10 in file; arguably ASI02/ASI03 per OWASP (see Q2) | yes (inventory), partially (risk) | Tool lists, credentials and limits are visible; actual scope often set in IAM/infra | candidate rule (NEX020-NEX023, combination-scored) |
| [credential-misuse](credential-misuse.md) | ASI03 | partially | Hard-coded/broad credential names visible; real scope lives at the identity provider | candidate rule (NEX022, low-medium confidence) |
| [agent-impersonation](agent-impersonation.md) | ASI07 | partially | Missing auth/verification of peers visible; infra-layer identity invisible | candidate rule (NEX008) |
| [a2a-risks](a2a-risks.md) | ASI07 | partially | Unauthenticated routes, cleartext, `verify=False`, secrets in outbound payload visible; integrity/replay/semantics not | candidate rule (NEX006, NEX009, NEX010) |
| [rogue-agents](rogue-agents.md) | ASI10 | no (behaviour) / partially (containment) | Drift, deception, collusion are runtime; only blast-radius preconditions are visible | candidate rule on containment only (NEX020, NEX025); never claim rogue detection |
| [cascading-failures](cascading-failures.md) | ASI08 | partially | Graph cycles, unbounded retries, fan-out, missing timeouts visible; actual propagation is runtime | candidate rule (NEX011-NEX015) |
| [unbounded-loops](unbounded-loops.md) | ASI08 (multi-agent) / ASI02 (single agent) | yes (explicit disablement), partially (hand-rolled loops) | `max_turns=None` etc. are literal; hand-rolled loops need loop/exit analysis | candidate rule (NEX014) |
| [trust-exploitation](trust-exploitation.md) | ASI09 | no (core) / partially (narrow slice) | Core risk is human over-reliance and UI persuasion; only "no confirmation" / "rationale-only approval" / "preview with side effects" are code-visible | document only, except the missing-confirmation slice (covered by NEX016-NEX019) |
| [approval-bypass](approval-bypass.md) | ASI02 (with ASI09/ASI03 secondary; see Q1) | partially | Model-controlled `approved` params, framework "never ask" modes, and gate-dominance are visible within analysed code | candidate rule (NEX019 and dominance logic shared by NEX016-NEX018) |
| [autonomous-destructive-actions](autonomous-destructive-actions.md) | ASI02 or ASI09 (open, Q1) | yes (typed sinks), no (generic tools) | Known destructive/financial sinks reachable from tools without a gate are visible; destructiveness via free-form shell/SQL args is not | candidate rule (NEX016-NEX018) |

## What static analysis CANNOT detect

nexvul reads code and configuration; it does not run the agent, call the model, or observe production. Therefore
it cannot detect, and must never imply it detects:

1. **Whether an attack succeeds.** A finding means a risky construct is present, not that exploitation is
   possible or has happened. A clean scan is not evidence of security (brief §0).
2. **Malicious content.** Whether a web page, document, memory entry, tool description or peer message actually
   contains an injection. nexvul sees *flows*, not payloads.
3. **Model behaviour.** Goal drift, deception, scheming, collusion, reward hacking, hallucination (ASI10, ASI08
   triggers). These are runtime properties of the model + context.
4. **Human factors.** Automation bias, persuasive explanations, confirmation fatigue, emotional manipulation,
   operator training (the core of ASI09).
5. **Out-of-repo controls.** IAM policies, API-gateway auth, service-mesh mTLS, network egress policy, container
   sandboxes, Kubernetes policies, bank-side dual control, cloud deletion protection. Their absence from the repo
   causes false positives; their presence elsewhere cannot be credited.
6. **Runtime-discovered capabilities.** Tools from dynamic MCP discovery, plugin registries, A2A discovery, or
   `importlib`-style loading; MCP "rug pulls" where descriptions change after review.
7. **Correctness of controls.** That an auth check validates the right audience, that an approval gate is not
   rubber-stamped, that a sanitiser actually neutralises injection. nexvul can see that a control is *present
   on the path*; it cannot prove the control is *effective*.
8. **Cross-repository / cross-service flows.** Cascades and data flows through queues, webhooks, shared databases
   or other services outside the scanned tree.
9. **Credentials' real scope.** An env var named `API_KEY` may be read-only or admin; only the identity provider
   knows.
10. **Covert/side channels** (timing, metadata inference) named in OWASP ASI07.

## Notes on existing files

- The nine pre-existing files were not rewritten. Their factual claims (e.g. CVE identifiers and the MCPTox
  figures cited in `indirect-prompt-injection.md` and `tool-poisoning.md`) were **not re-verified** in this pass
  and should be re-checked before being quoted in user-facing docs.
- `tool-poisoning.md` maps tool poisoning primarily to ASI04; the OWASP PDF (ASI02 scenario 1, p. 13) states that
  runtime manipulation of a legitimate tool's interface belongs under ASI02 and only tools malicious at source
  belong under ASI04. Logged as open question Q4.
- `excessive-agency.md` maps primarily to ASI10; the OWASP PDF (p. 36) states ASI10 is distinct from
  "Excessive Agency (LLM06:2025), which focuses on over-granted permissions". Logged as open question Q2.
