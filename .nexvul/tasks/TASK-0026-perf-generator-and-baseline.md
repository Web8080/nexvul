# TASK-0026: Synthetic perf generator and Phase 1 baseline

| Field | Value |
|-------|-------|
| Status | proposed |
| Phase | 1 |
| Size | S |
| Owner | 15 Benchmarking |
| Reviewer(s) | 04 Python Static Analysis, 18 QA/Test |
| Depends on | TASK-0018, TASK-0019 |
| Blocks | Phase 1 exit |
| Links | docs/benchmark-strategy.md §8.2, brief §15 |

## Acceptance criteria
- [ ] Deterministic, seeded generator for 100 / 1k / 5k / 10k file repos with realistic size distribution
- [ ] Records wall time (median/p90 of 5 after warm-up), CPU time, peak RSS (unit-normalised), files/sec, cold vs warm
- [ ] Runner spec recorded in report
- [ ] Baseline report committed; numbers come only from the generated report
- [ ] Reviewed: REV-NNNN
