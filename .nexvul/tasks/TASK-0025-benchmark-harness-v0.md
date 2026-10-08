# TASK-0025: Benchmark harness v0 (schema validation + scorer)

| Field | Value |
|-------|-------|
| Status | proposed |
| Phase | 1 |
| Size | M |
| Owner | 15 Benchmarking |
| Reviewer(s) | 17 False Positive Hunter, 18 QA/Test, 16 Adversarial (never-execute guarantees) |
| Depends on | TASK-0009, TASK-0020, TASK-0022 |
| Blocks | Phase 2 seed benchmark |
| Links | docs/benchmark-strategy.md §2–9, benchmarks/schema/example.schema.json |

## Acceptance criteria
- [ ] Validates every `case.yaml` against the schema; refuses to score an invalid corpus
- [ ] Matching and metrics exactly per benchmark-strategy §8.1, with Wilson intervals and "insufficient data" marking
- [ ] Emits `metrics.json` + generated `report.md`; compares against `benchmarks/baseline/metrics.json`
- [ ] Execution-sentinel test proves corpus code is never run
- [ ] Unit tests for the scorer with hand-computed expectations
- [ ] Reviewed: REV-NNNN
