# TASK-0022: Test framework scaffold and meta-tests

| Field | Value |
|-------|-------|
| Status | proposed |
| Phase | 1 |
| Size | S |
| Owner | 18 QA/Test |
| Reviewer(s) | 19 DevSecOps, 01 Principal Supervisor |
| Depends on | TASK-0017, TASK-0016 |
| Blocks | TASK-0023, TASK-0024 |
| Links | docs/test-strategy.md §3, §4.1, §10 |

## Acceptance criteria
- [ ] `tests/` layout per test-strategy §3; `collect_ignore_glob` for `tests/rules/**` and `benchmarks/**`
- [ ] Meta-test: no `test_*.py`/`*_test.py`/`conftest.py` under fixture/corpus trees
- [ ] Sockets blocked by default in tests; execution sentinel test
- [ ] Hypothesis CI and nightly profiles; seeds logged
- [ ] Coverage floors configured per package
- [ ] Golden update flag `--update-golden`
- [ ] Reviewed: REV-NNNN
