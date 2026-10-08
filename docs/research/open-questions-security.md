# Open Questions -- Security Research / OWASP Mapping

> Phase 0. Owner: Security Research + OWASP Mapping agent. Date: 2026-10-08.
> Status: **ESCALATED TO HUMAN** (brief §32 item 3: "controversial OWASP interpretation").
> Primary evidence: OWASP Top 10 for Agentic Applications 2026, official PDF downloaded from
> https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ (page numbers refer to that
> PDF). Quotes are kept short; read the PDF for full context.

The Supervisor should not let rule IDs NEX016-NEX025 reach "rule design approved" until Q1 and Q2 are decided,
because the ASI label is part of the rule's public contract (SARIF tags, docs, `rules.enabled: [ASI09]` config).

---

## Q1 (escalation). Do the brief's ASI09 rules match OWASP's ASI09?

### The brief

§16 lists under ASI09: *high-impact tool without approval; destructive tool without confirmation; financial
action without human oversight; privileged operation without policy gate*. §5.12 describes the Human Oversight
agent as finding "high-impact ops without approval/confirmation/policy/HITL/limits/escalation".

### What OWASP actually says

**ASI09 Human-Agent Trust Exploitation (pp. 33-35).**
- Description centres on humans over-trusting agents: anthropomorphism, automation bias, "persuasive
  explainability", the human performing "the final, audited action". OWASP states: "This entry is about human
  misperception or over-reliance whereas ASI10 is agent intent deviation."
- **However**, common example 2 is literally "Missing Confirmation for Sensitive Actions": lack of a final
  verification step "converts user trust into immediate execution", leading to irreversible financial
  transfers, data deletions, privilege escalations or configuration changes (p. 33).
- Mitigation 1 "Explicit confirmations: Require multi-step approval or 'human in the loop' before accessing
  extra sensitive data or performing risky actions" (p. 34).

**ASI02 Tool Misuse and Exploitation (pp. 12-14).**
- Common example 1: "Email summarizer can delete or send mail without confirmation" (p. 12).
- Scenario 3: a customer-service bot "also issues refunds because the tool had full financial API access" (p. 13).
- Mitigation 2 "Action-Level Authentication and Approval ... human confirmation for high-impact or destructive
  actions (delete, transfer, publish)" (p. 14).
- Mitigation 4 "Policy Enforcement Middleware ('Intent Gate')" -- a pre-execution PEP/PDP (p. 14).
- Scope note: ASI02 is misuse of *legitimately granted* tools, e.g. "deleting valuable data" (p. 12).

**ASI03 Identity and Privilege Abuse (pp. 15-17).**
- Mitigation 3 "Mandate Per-Action Authorization ... centralized policy engine" and mitigation 4 "Apply
  Human-in-the-Loop for Privilege Escalation: Require human approval for high-privilege or irreversible
  actions" (p. 17).

**OWASP's own incident mapping (appendix, pp. 45-46).** The PDF's incident table maps the July 2025 Replit
production-database deletion to ASI01, **ASI09** and ASI10. This is evidence that OWASP itself is willing to tag
an autonomous destructive action with ASI09 -- it supports keeping ASI09 as *a* label, though not necessarily
the primary one.

### Assessment

| Brief ASI09 rule | Best OWASP fit | Reasoning |
|---|---|---|
| high-impact tool without approval | **ASI02** primary, ASI09 secondary | ASI02 mitigation 2 is the most direct textual match; ASI09 ex. 2 also matches |
| destructive tool without confirmation | **ASI02** primary, ASI09 secondary | ASI02 ex. 1 ("delete ... without confirmation") and mitigation 2 ("delete") |
| financial action without human oversight | **ASI02 or ASI09** (genuinely split) | ASI02 mitigation 2 names "transfer"; ASI09 scenarios 3 & 7 are payment fraud -- but in those the human *did* approve; the ASI09 harm is the persuasion, not the missing gate |
| privileged operation without policy gate | **ASI03** primary, ASI02 secondary | "privileged" + "policy engine" + "HITL for privilege escalation" are ASI03 mitigations 3-4; ASI02 mitigation 4 is the intent gate |

Honest summary: the brief's ASI09 rules are **defensible but not the best fit**. They correspond to one ASI09
common example (#2) and one ASI09 mitigation (#1). The rest of ASI09 -- the risk OWASP actually describes as
its core -- is about human perception and is **not statically detectable** (see
`attack-techniques/trust-exploitation.md`). Labelling these rules ASI09 risks implying nexvul covers human-trust
exploitation, which it does not. Meanwhile ASI02's text matches the missing-gate pattern more directly and more
often.

### Options

- **A. Keep ASI09 as primary (brief as written).** Pros: matches brief §1/§16 focus list (ASI06-ASI10); OWASP ASI09
  ex. 2 supports it. Cons: weaker textual fit; may mislead users into thinking human-trust risks are covered;
  peers/reviewers may challenge the mapping.
- **B. Re-map primary to ASI02 (NEX016-NEX018) and ASI03 (NEX019), ASI09 as secondary tag.** Pros: best textual
  fit; SARIF can carry both tags. Cons: moves rules outside the brief's stated ASI06-ASI10 focus; `rules.enabled:
  [ASI09]` users would see fewer rules.
- **C. Multi-label with no "primary".** Emit `owasp: ["ASI02", "ASI09"]` (and ASI03 for NEX019) and document why.
  Pros: honest about the overlap; the finding model already allows a list (`"owasp": ["ASI06"]`, brief §10).
  Cons: config filtering by ASI becomes ambiguous; a rule appears under two categories in reports.

**Research recommendation:** Option C with an explicit ordering (ASI02 first for NEX016-NEX018, ASI03 first for
NEX019, ASI09 always included), and a docs note that nexvul covers only the "missing confirmation" slice of
ASI09. **Decision required from the human product owner.** `docs/owasp/mapping.md` currently records Option C as
"proposed, pending decision".

---

## Q2 (escalation). Do the brief's ASI10 rules match OWASP's ASI10?

The brief §16 ASI10 rules are capability/permission checks (shell + network, arbitrary FS, credential access,
excessive tool permissions, unrestricted delegation, no limits). OWASP (p. 36): ASI10 "focuses on the loss of
behavioral integrity and governance once the drift begins" and is "a distinct risk of behavioral divergence,
unlike Excessive Agency (LLM06:2025), which focuses on over-granted permissions."

Supporting the brief: ASI10 mitigations 2 ("Isolation & Boundaries ... restricted execution environments ... API
scopes based on least privilege") and 4 ("kill-switches and credential revocation") are containment controls
whose absence is partly visible in code (p. 37).

Better textual fits for the individual rules: shell/code execution -> ASI05; over-scoped tools -> ASI02
(examples 1-2, mitigation 1); credential access / delegation privilege inheritance -> ASI03 (example 1
"Un-scoped Privilege Inheritance").

**Options:** (A) keep ASI10, phrase findings strictly as "missing containment that would limit a rogue agent";
(B) re-map per rule to ASI02/ASI03/ASI05 with ASI10 secondary; (C) multi-label as in Q1.
**Research recommendation:** C, and only the *combination* rule (NEX020) and the limits rule (NEX025) keep ASI10
first. **Decision required from the human.**

---

## Q3 (non-blocking). Single-agent unbounded loops: ASI08 or ASI02?

OWASP ASI08 applies "only when that defect spreads across agents, sessions, or workflows" (p. 30). A single
agent loop with no peers is better described by ASI02 example 5 "Loop amplification" (p. 12) and LLM10:2025.
Recommendation: NEX014 tags ASI08 only when the loop spans ≥2 agents/nodes; otherwise ASI02 + LLM10. Supervisor
can decide without human escalation unless Q1/Q2 decisions change the multi-label policy.

## Q4 (non-blocking, affects existing file). Tool poisoning: ASI04 or ASI02?

`attack-techniques/tool-poisoning.md` maps primarily to ASI04. OWASP ASI02 scenario 1 (p. 13) says runtime
manipulation of a legitimate tool's interface "belongs under ASI02", and "only cases where the tool itself is
malicious or compromised at the source fall under ASI04". Recommendation: the Supervisor asks the original
author to add ASI02 as co-primary. Not rewritten here per instructions.

## Q5 (non-blocking). Secondary-source items in `owasp-agentic-top10-2026.md`

The research summary lists the Replit incident as an ASI10 example. In the official PDF the ASI10 section
(pp. 36-38) does not mention Replit; Replit appears instead as ASI05 scenario 1 ("Replit 'Vibe Coding' Runaway
Execution", p. 21) and in the PDF's incident appendix table mapped to ASI01, ASI09 and ASI10 (pp. 45-46). The
ASI10 definition text in the summary also differs from the PDF wording. Recommendation: update that file to
quote the PDF directly with page numbers.

## Q6 (non-blocking). Sensitivity classification ownership

Rules NEX016-NEX019 depend on a sink catalogue classifying APIs as destructive / financial / privileged. This
catalogue will drive most FP/FN behaviour. Recommend the Supervisor assign ownership (Framework Intelligence +
Human Oversight agents) and require it to be versioned data with tests, not hard-coded in rules.
