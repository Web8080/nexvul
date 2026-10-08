# DEC-0002: False-positive budget per severity/confidence

| Field | Value |
|-------|-------|
| Status | escalated |
| Decider | Human product owner |
| Proposed by | 15 Benchmarking |
| Consulted | 01 Supervisor, 17 FP Hunter |
| Date proposed / decided | 2026-10-08 / — |
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
Pending human decision. Phase 2 cannot exit until decided.

## Reversibility
Reversible; budget can be tightened per release.

## Comments
