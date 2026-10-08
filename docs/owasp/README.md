# nexvul and the OWASP Top 10 for Agentic Applications (2026)

> Maintained by the OWASP Mapping agent (brief §5.3). Phase 0. Date: 2026-10-08.
> Status: **design only** -- no nexvul rule is implemented yet. Nothing here is a coverage claim.

## Source of truth

- **OWASP Top 10 for Agentic Applications for 2026**, OWASP GenAI Security Project, published December 2025:
  https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ . Page numbers in nexvul docs
  refer to the official PDF downloaded from that page on 2026-10-08.
- Research summary: `docs/research/owasp-agentic-top10-2026.md` (note: some items there come from secondary
  sources; where it differs from the PDF, the PDF wins -- see `docs/research/open-questions-security.md` Q5).
- OWASP Top 10 for LLM Applications 2025 (secondary tags `LLM01`-`LLM10`): https://genai.owasp.org/llm-top-10/
- CWE (MITRE): https://cwe.mitre.org/ -- every CWE number used in `mapping.md` is a real CWE entry; CWE tags are
  "closest weakness class", not a claim that MITRE classifies agent risks this way.

## Files

| File | Purpose |
|---|---|
| `README.md` | Principles, how mappings are made, and what they mean |
| `mapping.md` | Formal rule -> ASI mapping table (rule, ASI, rationale, severity, confidence, CWE, references, limitations) |

Related: `docs/detection-taxonomy.md` (rule design), `docs/research/attack-techniques/` (per-technique research),
`docs/research/open-questions-security.md` (contested interpretations escalated to the human).

## Mapping principles

1. **A mapping is a classification, not a verdict.** A finding tagged `ASI06` means "this construct is a known
   precondition for, or contributor to, ASI06". It does **not** mean ASI06 exploitation is possible, occurred, or
   was proven. nexvul never claims a detection proves exploitation.
2. **A clean scan is not compliance.** nexvul does not make any application "OWASP compliant" and must never be
   described that way (brief §33). Large parts of several ASI risks are not statically detectable (behavioural
   drift in ASI10, human factors in ASI09, runtime propagation in ASI08, malicious payload content in ASI01/ASI06).
3. **Quote the OWASP text.** Each mapping rationale cites the specific ASI common example, scenario or mitigation
   (with PDF page) it relies on. Mappings without a textual anchor are not accepted.
4. **Multi-label when OWASP overlaps.** OWASP's entries overlap by design (e.g. ASI02/ASI03/ASI09 all recommend
   human confirmation for high-impact actions). The finding model already carries a list (`"owasp": [...]`,
   brief §10). The first entry is the primary category; the rest are secondary.
5. **Contested mappings are escalated, not decided silently.** Brief §32 item 3. Current escalations: Q1 (ASI09
   rules) and Q2 (ASI10 rules) in `docs/research/open-questions-security.md`. Affected rows in `mapping.md` are
   marked ⚠ and must not ship with a final label until the human decides.
6. **Severity and confidence are nexvul's, not OWASP's.** OWASP does not assign severities to these patterns.
   Definitions are in `docs/detection-taxonomy.md` §3.
7. **Limitations are part of the mapping.** Every row states what the rule does not detect; the same text must
   appear in `docs/rules/NEXxxx.md` and in `nexvul explain`.

## Coverage statement (honest, Phase 0)

| ASI | nexvul candidate rules | What part of the risk they touch | What remains uncovered |
|---|---|---|---|
| ASI01 Goal Hijack | none standalone (source class only) | untrusted-content sources feeding other rules | the injection itself |
| ASI02 Tool Misuse | NEX016-NEX019, NEX021, NEX023 (⚠ co-labels) | missing confirmation / policy gates, over-scoped tools | runtime misuse of correctly-gated tools; chaining semantics |
| ASI03 Identity & Privilege | NEX019, NEX022, NEX024 (⚠ co-labels) | privileged ops without gate; credential exposure; delegation inheritance | real credential scope; TOCTOU; identity-provider config |
| ASI04 Supply Chain | NEX007 (secondary) | MCP startup command / remote server config | dependency CVEs, model provenance, rug pulls |
| ASI05 Unexpected Code Execution | NEX020 (secondary) | shell/code-exec capability in combination | sandbox escape, payloads |
| ASI06 Memory & Context Poisoning | NEX001-NEX005 | untrusted data flows into persistent memory / instructions | malicious content detection; out-of-code poisoning |
| ASI07 Inter-Agent Communication | NEX006-NEX010 | missing auth/authz, cleartext, unverified peers, context leakage | message integrity, replay, semantic manipulation, side channels |
| ASI08 Cascading Failures | NEX011-NEX015 | structural amplifiers (cycles, retries, limits, timeouts) | actual runtime propagation; cross-service cascades |
| ASI09 Human-Agent Trust | NEX016-NEX019 (⚠ secondary label proposed) | "Missing Confirmation for Sensitive Actions" only | everything about human perception, persuasion, UI |
| ASI10 Rogue Agents | NEX020-NEX025 (⚠) | missing containment / limits (blast radius) | behavioural drift, deception, collusion |
