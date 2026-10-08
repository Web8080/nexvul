# FND-NNNN: FP triage — <rule ID> on <project/case>

| Field | Value |
|-------|-------|
| Status | new \| triaged \| confirmed \| fixed \| verified \| wont_fix \| accepted_risk \| not_an_issue |
| Rule | NEXNNN @ nexvul <version / git SHA> |
| Triaged by | 17 False Positive Hunter (or other non-author role) |
| Second opinion | NN <role> (required when classification is "acceptable warning" or "needs context") |
| Source of report | benchmark run \| real_world scan \| user issue \| internal test |
| Target | repo + commit + path:line, or benchmark case ID (no large code dumps) |
| Date | YYYY-MM-DD |

## Finding as reported
Rule message, severity, confidence, flow steps (copy from JSON output).

## Classification (brief §5.17)
- [ ] **TP** — real risky pattern; the rule is right
- [ ] **FP** — the rule is wrong
- [ ] **Acceptable warning** — pattern is present but mitigated or low impact in context; rule doc should say so
- [ ] **Needs context** — cannot decide statically; what information would decide it?

## Reasoning
Why. Point to the exact sanitiser, trust boundary, constant source, test-only code, etc.

## Root cause (if FP)
- [ ] Missing sanitiser model  - [ ] Over-broad source  - [ ] Over-broad sink  - [ ] Taint over-approximation
- [ ] Framework misrecognition  - [ ] Test/example code  - [ ] Other:

## Proposed remedy (brief §23 order — never "hide the finding")
1. Improve semantics → 2. add context → 3. reduce scope → 4. lower confidence → 5. don't ship.
Chosen: … Regression test to add: `tests/rules/<ID>/negative/case_…` and benchmark case `BM-…`.

## Comments
