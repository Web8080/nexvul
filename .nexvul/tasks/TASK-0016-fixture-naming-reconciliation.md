# TASK-0016: Reconcile rule-fixture naming (pytest would execute `test_*.py` fixtures)

| Field | Value |
|-------|-------|
| Status | ready |
| Phase | 0 |
| Size | S |
| Owner | 18 QA/Test |
| Reviewer(s) | 01 Principal Supervisor (architecture owner), 16 Adversarial |
| Depends on | TASK-0004, TASK-0010 |
| Blocks | TASK-0022 |
| Created / Updated | 2026-10-08 / 2026-10-08 |
| Links | docs/architecture.md §6.4, docs/test-strategy.md §4.1, docs/benchmark-strategy.md §6 |

## Context
`docs/architecture.md` §6.4 shows a fixture named `test_positive_001.py` containing vulnerable code. pytest collects and imports files matching `test_*.py`, which would **execute** fixture code — contrary to brief §2 ("never execute scanned code").

## Acceptance criteria
- [ ] Architecture owner updates §6.4 example to `case_<nnn>_<slug>.py` (EngOps does not edit architecture.md)
- [ ] Phase 1 meta-test planned that fails on `test_*.py` / `*_test.py` / `conftest.py` under `tests/rules/` and `benchmarks/`
- [ ] Reviewed: REV-NNNN
