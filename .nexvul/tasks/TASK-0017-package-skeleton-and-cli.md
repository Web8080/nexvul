# TASK-0017: Package skeleton and CLI commands

| Field | Value |
|-------|-------|
| Status | proposed |
| Phase | 1 |
| Size | S |
| Owner | 04 Python Static Analysis |
| Reviewer(s) | 18 QA/Test, 01 Principal Supervisor |
| Depends on | TASK-0015 (Phase 0 exit), TASK-0004 |
| Blocks | TASK-0018 … TASK-0024 |
| Links | brief §8–9, docs/architecture.md |

## Acceptance criteria
- [ ] Layout per brief §9 / architecture; Python ≥ 3.12; `pyproject.toml` with pinned, reviewed deps
- [ ] `nexvul scan <path>`, `--format json`, `nexvul version`, `nexvul rules`, `nexvul doctor` exist; documented exit codes
- [ ] No network imports in the scan path (test asserts with sockets blocked)
- [ ] CLI tests in `tests/e2e/cli/`
- [ ] Reviewed: REV-NNNN
