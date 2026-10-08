# TASK-0027: CI pipeline for nexvul itself

| Field | Value |
|-------|-------|
| Status | proposed |
| Phase | 1 |
| Size | M |
| Owner | 19 DevSecOps |
| Reviewer(s) | 01 Principal Supervisor, 21 Release Engineer |
| Depends on | TASK-0017, TASK-0022 |
| Blocks | Phase 1 exit |
| Links | docs/test-strategy.md §10, docs/research/tooling/github-actions-and-precommit.md |

## Acceptance criteria
- [ ] Lint, type-check, tests, coverage floors, benchmark gate stub, dependency audit, SBOM generation
- [ ] Actions pinned by full commit SHA; least-privilege `permissions:`; no secrets in test jobs
- [ ] nexvul scans its own source (excluding `benchmarks/` and `tests/rules/`)
- [ ] Nightly workflow skeleton
- [ ] No deployment or publishing steps (those need Release + Supervisor approval later)
- [ ] Reviewed: REV-NNNN
