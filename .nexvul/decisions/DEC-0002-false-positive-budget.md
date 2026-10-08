# DEC-0002: False-positive budget per severity/confidence

| Field | Value |
|-------|-------|
| Status | accepted (Option A, amended) |
| Decider | Human product owner |
| Proposed by | 15 Benchmarking |
| Consulted | 01 Supervisor, 17 FP Hunter |
| Date proposed / decided | 2026-10-08 / 2026-10-08 |
| Escalation trigger (brief §32) | 2 (security trade-off: recall vs noise) and 8 (FP acceptability) |
| Links | docs/benchmark-strategy.md §8.3; TASK-0014 |

## Context
Brief §5.15 and §23: noisy rules destroy trust; a rule that misses its budget must be improved, narrowed,
down-graded or not shipped. A numeric budget is needed before Phase 2 can exit.

## Options considered
| Option | Summary |
|--------|---------|
| A (proposed) | Table in benchmark-strategy §8.3: high-confidence high/critical ≥ 0.90 dev / ≥ 0.85 held-out, zero high-confidence FPs on `safe/`; medium ≥ 0.75; low-confidence off by default; recall floor 0.60 |
| B | Stricter: high-confidence ≥ 0.95 — fewer rules ship in Phase 2 |
| C | Looser: ≥ 0.80 — more coverage, more noise |

## Decision
Option A approved by the product owner, who delegated the call to the Supervisor on 2026-10-08. Amendments:

1. **Minimum sample size.** A precision threshold is enforced for a rule only once the corpus holds at least 20
   labelled true-or-false-positive-candidate cases for it (benign look-alikes plus real positives). Below that, the
   rule may ship only as `confidence: low` or `experimental`, and the report states the raw TP/FP/FN counts, never
   a bare percentage.
2. **Report raw counts and an interval** (e.g. Wilson 95%) next to every precision and recall figure in docs and CI.
3. **Zero high-confidence FPs on `safe/`** stays a hard gate.
4. Thresholds may be tightened per release; loosening needs a new decision record.
5. Hiding findings, excluding cases, or relabelling ground truth to meet the budget remains prohibited (brief §23).

## Reversibility
Reversible; budget can be tightened per release.

## Comments
