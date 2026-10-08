# Rule -> OWASP ASI Mapping

> Phase 0. Owner: OWASP Mapping agent. Date: 2026-10-08. Status of every row: **design only**.
> Read `README.md` first. "PDF p. N" = OWASP Top 10 for Agentic Applications 2026 official PDF
> (https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).
> ⚠ = ASI label pending human decision (`docs/research/open-questions-security.md` Q1/Q2/Q3). The ⚠ value shown is
> the *proposed* label (Option C, multi-label); the brief's original label is noted.
> **No row claims that a detection proves exploitation.** Severity/confidence definitions:
> `docs/detection-taxonomy.md` §3. CWE links: `https://cwe.mitre.org/data/definitions/<n>.html`.

## Mapping table

| Rule | Name | ASI (primary first) | Rationale (OWASP anchor) | Severity | Confidence | CWE | Limitations |
|---|---|---|---|---|---|---|---|
| NEX001 | External content written to persistent memory | ASI06; LLM04 | ASI06 covers corruption of stored context/long-term memory (PDF p. 24); mitigations call for validating memory entries and provenance (secondary summary in research file) | high | high (intra-proc.) / medium (cross-file) | CWE-501, CWE-345 | Cannot tell if content is malicious; sanitisers not modelled cause FPs; out-of-code memory edits invisible |
| NEX002 | External content indexed into a vector store | ASI06; LLM08 | ASI06 persistent knowledge poisoning; LLM08 Vector & Embedding Weaknesses | high | high / medium | CWE-501, CWE-345 | Curated first-party corpora look identical; existing poisoned corpus invisible |
| NEX003 | Untrusted tool output persisted into long-term context | ASI06; ASI01 | Tool output is an ASI01 injection vector (p. 9 ff.); persisting it makes it ASI06 | high | medium | CWE-501, CWE-1427 | Transient (non-persisted) injection not covered; tool trust level often unknown |
| NEX004 | User-controlled content persisted into shared agent state | ASI06; ASI03 | ASI06 cross-session persistence; ASI03 example 2 "Memory-Based Privilege Retention & Data Leakage" across users (pp. 15-16) | medium | medium | CWE-501, CWE-668 | Requires shared-vs-per-user key model (not yet designed); DB-level tenant isolation invisible |
| NEX005 | Retrieved content promoted to trusted instructions | ASI06; ASI01 | Corrupted context alters goal interpretation (ASI06 description, p. 24, cross-ref ASI01) | high | medium | CWE-1427, CWE-501 | Delimited RAG in user/tool role is not this sink; injection effectiveness unknowable |
| NEX006 | A2A / agent HTTP endpoint without authentication | ASI07 | ASI07: exchanges lacking authentication allow spoofing (p. 27); mitigation 1 mutual authentication (p. 28) | high | medium | CWE-306 | Gateway/mesh auth invisible -> FP; broken auth not detected; replay/integrity not detected |
| NEX007 | MCP connection without auth or over cleartext | ASI07; ASI04 | ASI07 scenario 1 "Semantic injection via unencrypted communications" and scenario 5 MCP descriptor poisoning (p. 28); mitigation 6 names MCP protocol pinning (p. 29); MCP spec security best practices | high | high (literal config) | CWE-306, CWE-319 | Configs outside repo (user home/IDE) not scanned; env-driven URLs are FNs; tool content not inspected |
| NEX008 | Remote agent identity not verified | ASI07; ASI03 | ASI07 scenario 6 "A2A registration spoofing" and mitigation 8 "signed agent cards" (pp. 28-29); ASI03 scenario 6 "Forged Agent Persona" (p. 16) | medium | medium | CWE-345, CWE-346 | Validly signed malicious agents and compromised legitimate peers not detected |
| NEX009 | Sensitive context sent to untrusted agent | ASI07; ASI03; LLM02 | ASI07 example 2 "cross-context contamination ... data leakage" (p. 27) | high | medium | CWE-201, CWE-200 | PII/secret labelling is heuristic; remote handling of data invisible |
| NEX010 | Inter-agent request executed without authorisation | ASI07; ASI03 | ASI03 example 3 "Cross-Agent Trust Exploitation (Confused Deputy)" (p. 16); ASI07 description "authorization" (p. 27) | high | medium | CWE-862, CWE-441 | Policy correctness and downstream authz invisible |
| NEX011 | Recursive delegation without depth bound | ASI08 | ASI08 symptoms "oscillating retries or feedback loops between agents" (p. 30); mitigation 7 "progress caps, circuit breakers" (p. 32) | medium | medium | CWE-674 | Runtime-chosen routing; cross-service recursion |
| NEX012 | Workflow cycle without termination guard | ASI08 | ASI08 example 7 "Feedback-loop amplification" (p. 31) | medium | medium | CWE-835 (only when exit provably unreachable; otherwise CWE-834) | Bounded reflection loops are common -> must detect guards; dynamic cycles missed |
| NEX013 | Unlimited retries around agent/tool/LLM calls | ASI08; ASI02 | ASI08 "oscillating retries", "queue storms" (p. 30); OWASP ASI08 cites CWE-400 (p. 32) | medium | high (decorator) / medium (hand-rolled) | CWE-400, CWE-770 | Infra/SDK-internal retries invisible |
| NEX014 | Agent iteration limit disabled or unbounded | ⚠ ASI08 (multi-agent) or ASI02 + LLM10 (single agent) -- Q3 | ASI02 example 5 "Loop amplification" (p. 12) and mitigation 5 "Adaptive Tool Budgeting" (p. 14); ASI08 applies only on cross-agent spread (p. 30) | medium | high (literal) | CWE-834, CWE-770 | Framework defaults change by version (needs versioned table); cost blow-up inside bounded runs |
| NEX015 | Missing timeout around agent/tool execution | ASI08; LLM10 | ASI08 mitigation 6 "throttle or pause on anomalies", mitigation 7 circuit breakers (p. 32) | low-medium | medium | CWE-1088, CWE-400 | Global/infra timeouts invisible -> noisy; likely opt-in |
| NEX016 | High-impact tool without approval | ⚠ ASI02; ASI09 (brief: ASI09) | ASI02 mitigation 2 "human confirmation for high-impact or destructive actions" (p. 14); ASI09 example 2 "Missing Confirmation for Sensitive Actions" (p. 33) | high | medium | CWE-862, CWE-749 | Downstream/gateway gates invisible; rubber-stamp approvals and approval UX (ASI09 core) not detected |
| NEX017 | Destructive tool without confirmation | ⚠ ASI02; ASI09 (brief: ASI09) | ASI02 example 1 "can delete or send mail without confirmation" (p. 12); ASI09 example 2 "data deletions" (p. 33); OWASP incident appendix maps the Replit DB deletion to ASI01/ASI09/ASI10 (pp. 45-46) | high (critical with prod indicator) | medium | CWE-862, CWE-749 | Destructive SQL/shell via generic tools reported only as worst case; soft deletes may be misclassified |
| NEX018 | Financial action without human oversight | ⚠ ASI02; ASI09 (brief: ASI09) | ASI02 scenario 3 refunds via over-privileged financial API (p. 13), mitigation 2 "transfer" (p. 14); ASI09 example 2 "irreversible financial transfers" (p. 33) | critical | medium | CWE-862 | Test-mode keys and provider-side approvals invisible; human-approved fraud (the actual ASI09 scenario) not detectable |
| NEX019 | Privileged operation without policy gate (incl. approval bypass) | ⚠ ASI03; ASI02; ASI09 (brief: ASI09) | ASI03 mitigations 3 "Per-Action Authorization ... policy engine" and 4 "Human-in-the-Loop for Privilege Escalation" (p. 17); ASI02 mitigation 4 "Intent Gate" (p. 14) | critical | medium | CWE-862, CWE-807, CWE-269 | Policy correctness, IAM-level enforcement, TOCTOU in framework internals |
| NEX020 | Dangerous capability combination (shell + unrestricted network) | ⚠ ASI10; ASI05 (brief: ASI10) | ASI10 mitigation 2 "Isolation & Boundaries ... restricted execution environments" (p. 37); ASI05 code execution; OWASP states ASI10 is behavioural divergence distinct from over-granted permissions (p. 36) -- finding is *missing containment*, not rogue behaviour | high | medium | CWE-250 (CWE-78 when tainted args) | Behaviour not detectable; container/sandbox config outside repo |
| NEX021 | Arbitrary filesystem access from an agent tool | ⚠ ASI02; ASI10 (brief: ASI10) | ASI02 example 2 "Over-scoped tool access" and mitigation 1 least privilege (pp. 12-13) | high | high (intra) / medium | CWE-22, CWE-73 | Path validators not modelled; FS via shell tool covered only by NEX020 |
| NEX022 | Unrestricted credential access by an agent | ⚠ ASI03; ASI10 (brief: ASI10) | ASI03 description: credentials/API keys/OAuth tokens as agent identity; mitigation 1 task-scoped, time-bound permissions (pp. 15-17) | medium | low-medium | CWE-250, CWE-200 | Real credential scope is identity-provider knowledge |
| NEX023 | Excessive tool permissions on a single agent | ⚠ ASI02; ASI10 (brief: ASI10) | ASI02 mitigation 1 "Least Agency and Least Privilege for Tools" (p. 13); LLM06 | medium | medium | CWE-250, CWE-272 | "Excessive" needs a declared task scope nexvul lacks -- **not ready**; consider inventory-only |
| NEX024 | Unrestricted delegation | ⚠ ASI03; ASI10 (brief: ASI10) | ASI03 example 1 "Un-scoped Privilege Inheritance" and scenario 1 "Delegated Privilege Abuse" (pp. 15-16) | medium | medium | CWE-269, CWE-441 | Cross-service delegation; closed trusted crews -> FP |
| NEX025 | No execution/iteration limits on autonomous agent with sensitive capabilities | ⚠ ASI10; ASI08 (brief: ASI10) | ASI10 mitigation 4 "Containment & Response" (p. 37); ASI08 mitigation 7 "progress caps" (p. 32) | medium | medium | CWE-770, CWE-834 | As NEX014; must dedupe with NEX014 |

## Secondary LLM Top 10 tags (2025)

ASI06 rules: LLM04, LLM08 · ASI07: none direct (LLM02 for NEX009) · ASI08: LLM10 · NEX016-NEX019: LLM06 ·
NEX020-NEX025: LLM06 (LLM05 for NEX020). Source: OWASP PDF Appendix A mapping matrix (p. 39 ff.) and
https://genai.owasp.org/llm-top-10/ .

## References

- OWASP Top 10 for Agentic Applications 2026: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/llm-top-10/
- MCP Security Best Practices: https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices
- A2A Protocol Specification: https://a2a-protocol.org/latest/specification/
- MITRE CWE: https://cwe.mitre.org/ (entries used: 22, 73, 78, 200, 201, 250, 269, 272, 306, 319, 345, 346, 400,
  441, 501, 668, 674, 749, 770, 807, 834, 835, 862, 1088, 1427)
- Per-technique research: `docs/research/attack-techniques/`
- Rule design: `docs/detection-taxonomy.md`

## Change control

A row's ASI label, severity or confidence changes only via the Supervisor with a recorded rationale. ⚠ rows
change only after the human decision on Q1/Q2/Q3. Benchmark results (benchmark-strategy.md) may lower
confidence; they never justify hiding findings.
