# Rule proposal: <working title>  (TASK-NNNN)

| Field | Value |
|-------|-------|
| Proposed rule ID | NEXNNN (assigned on approval in docs/detection-taxonomy.md) |
| Lifecycle stage (brief §6) | research \| threat_model \| architecture \| rule_design \| … \| released |
| OWASP | ASI0N (+ rationale below) |
| CWE | CWE-NNN or "none defensible" |
| Proposed severity / confidence | critical\|high\|medium\|low / high\|medium\|low |
| Languages | python \| javascript \| typescript \| config |
| Frameworks claimed | list with versions, or "framework-agnostic" |
| Analysis needed | pattern \| intra-procedural taint \| summaries \| cross-file \| graph \| capability scoring |
| Author | NN <role> |
| Reviewers | 01 Supervisor + 16 Adversarial and/or 17 FP Hunter + domain agent |
| Research source | docs/research/attack-techniques/<file>.md |

## Brief §17 — mandatory questions (unanswerable ⇒ rule not ready)

1. **Source?** Exactly which APIs / constructs introduce the untrusted or risky input.
2. **Sink?** Exactly which APIs / constructs are the harmful destination.
3. **Dangerous flow?** The path from source to sink, including propagation steps the rule must follow.
4. **What makes it dangerous?** The concrete attack and its preconditions (link to research entry).
5. **What legitimate code looks similar?** Enumerated look-alikes; each becomes a negative test.
6. **How can an attacker evade it?** Enumerated evasions; each becomes an adversarial test or a documented known miss.
7. **What evidence can we show?** The finding message, flow steps and snippets a user will see. Draft the message
   (specific: names the source and sink — brief §10).
8. **Confidence?** Why this confidence level; what would raise/lower it.
9. **What does it NOT detect?** Explicit limitations that will appear in `docs/rules/<ID>.md`.

## Brief §26 rule-contribution sections
- **Threat:**
- **OWASP mapping:** (category, rationale, limitations — no claim that a finding proves exploitation)
- **Detection strategy:**
- **Positive examples:** (paths under tests/rules/<ID>/positive/)
- **Negative examples:**
- **False positives:** (known / expected; link FP-triage FND)
- **False negatives:**
- **Performance impact:** (expected cost; measured later)
- **References:**

## Sanitisers / mitigations recognised
What validation, allow-lists, approval gates or framework controls suppress the finding — and why each is trusted.

## Benchmark plan
Cases to add per category (benchmark-strategy §4 minimums) and target FP budget row (§8.3).

## Decision
- [ ] Supervisor: proceed to implementation (REV-NNNN)
- [ ] Rejected / parked — reason:

## Comments
