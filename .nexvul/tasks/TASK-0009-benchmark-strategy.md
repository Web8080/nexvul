# TASK-0009: Benchmark strategy and case schema

| Field | Value |
|-------|-------|
| Status | in_review |
| Phase | 0 |
| Size | M |
| Owner | 15 Benchmarking |
| Reviewer(s) | 01 Principal Supervisor, 17 False Positive Hunter, 16 Adversarial |
| Depends on | none |
| Blocks | TASK-0014, TASK-0025, TASK-0026 |
| Created / Updated | 2026-10-08 / 2026-10-08 |
| Links | docs/benchmark-strategy.md, benchmarks/schema/example.schema.json, DEC-0002, DEC-0003 |

## Acceptance criteria
- [x] Layout, metadata schema (brief §22 fields), licence policy, never-execute rules, double-review labelling, metrics, CI gating, held-out — evidence: docs/benchmark-strategy.md §2–10
- [x] JSON Schema is valid Draft 2020-12 and accepts the doc's YAML example; rejects `../` paths — evidence: validated with `jsonschema` 4.x in a scratch venv on 2026-10-08
- [x] Candidate real-world list with licences verified via GitHub API / licence files on 2026-10-08 — evidence: §11
- [ ] FP budget approved by human (DEC-0002)
- [ ] Reviewed: REV-NNNN
