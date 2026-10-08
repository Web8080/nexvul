# Handoff: Security Research + OWASP Mapping + Detection Taxonomy

**Date:** 2026-10-08
**Author:** Security Research / OWASP Mapping agent
**Status:** Complete for Phase 0 -- with two **human escalations** open (Q1, Q2)
**Git:** no commits made (per instruction)

## Summary

Completed the attack-technique catalogue, an honest static-detectability index, the detection taxonomy with 25
candidate rules (NEX001-NEX025, all "design only"), and the formal OWASP mapping. The OWASP mapping was checked
against the **official OWASP Agentic Top 10 2026 PDF** (downloaded from genai.owasp.org and text-extracted
locally), not only the research summary. This surfaced mapping disagreements with the brief, escalated below.

## Files written

| File | Content |
|---|---|
| `docs/research/attack-techniques/rogue-agents.md` | ASI10; containment preconditions only -- behaviour not detectable |
| `docs/research/attack-techniques/insecure-mcp.md` | MCP config/server weaknesses; anchored on MCP spec security best practices |
| `docs/research/attack-techniques/a2a-risks.md` | ASI07 channel risks; A2A spec security schemes / card signing |
| `docs/research/attack-techniques/cascading-failures.md` | ASI08 structural amplifiers |
| `docs/research/attack-techniques/trust-exploitation.md` | ASI09; mostly not statically detectable |
| `docs/research/attack-techniques/approval-bypass.md` | model-controlled approval params, gate dominance |
| `docs/research/attack-techniques/unbounded-loops.md` | loop/limit disablement; framework defaults |
| `docs/research/attack-techniques/autonomous-destructive-actions.md` | sensitive sinks without gates |
| `docs/research/attack-techniques/README.md` | index, detectability, recommended action, "what static analysis cannot detect" |
| `docs/research/open-questions-security.md` | Q1-Q6 incl. escalations |
| `docs/detection-taxonomy.md` | detection classes, sensitivity classes S0-S8, severity/confidence model, NEX001-NEX025 |
| `docs/owasp/README.md` | mapping principles, honest coverage statement |
| `docs/owasp/mapping.md` | rule -> ASI table with rationale (PDF page anchors), severity, confidence, CWE, limitations |

## Escalations to the human (brief §32 item 3)

- **Q1 -- ASI09 rules.** OWASP's ASI09 is about human over-reliance/persuasion. Its common example 2 ("Missing
  Confirmation for Sensitive Actions") supports the brief, and OWASP's incident appendix tags the Replit DB
  deletion with ASI09 -- but ASI02 (example 1, mitigation 2) matches "no confirmation on destructive/financial
  tools" more directly, and ASI03 fits "privileged op without policy gate". Proposed: multi-label (ASI02/ASI03
  first, ASI09 always included). Needs decision.
- **Q2 -- ASI10 rules.** OWASP says ASI10 is behavioural divergence, "unlike Excessive Agency ... over-granted
  permissions". Capability rules fit ASI02/ASI03/ASI05 better; proposed multi-label with findings phrased as
  "missing containment". Needs decision.

## Non-blocking issues for the Supervisor

- Q3: single-agent loops -> ASI02/LLM10, not ASI08.
- Q4: existing `tool-poisoning.md` maps to ASI04; OWASP PDF puts runtime tool-interface poisoning in ASI02.
- Q5: `owasp-agentic-top10-2026.md` has secondary-source wording; should quote PDF with page numbers.
- Q6: assign an owner for the versioned sink-sensitivity catalogue; it drives most FP/FN behaviour of NEX016-NEX019.
- Pre-existing technique files' CVE/statistics claims were not re-verified in this pass.
- NEX004 and NEX023 are marked **not ready** in the taxonomy (missing models: shared-vs-per-user keys; declared task scope).
- Roadmap thin-slice candidates map to: S1 -> NEX002, S2 -> NEX014, S3 -> NEX007.

## Unverified / secondary items flagged in docs

- LangGraph default `recursion_limit` = 25 (secondary sources only; official error page does not state it).
- Replit incident facts come from press coverage of the affected user's posts.
